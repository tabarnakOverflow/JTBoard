#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <icmpapi.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

#include "resource.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace {
const wchar_t kAppName[] = L"JTBoard";
const wchar_t kRegPath[] = L"Software\\JTBoard";
const wchar_t kRegValue[] = L"ServerAddress";

const int kClientWidth = 800;
const int kClientHeight = 600;

const int kPingTimeoutMs = 1000;
const int kTcpTimeoutMs = 1000;
const int kFallbackPort = 32400;

HINSTANCE g_instance = nullptr;
std::wstring g_serverAddress;
int g_windowWidth = 0;
int g_windowHeight = 0;

HWND g_btnPlex = nullptr;
HWND g_btnRadarr = nullptr;
HWND g_btnSonarr = nullptr;
HWND g_btnQuit = nullptr;

std::wstring TrimWhitespace(const std::wstring& input) {
    size_t start = 0;
    while (start < input.size() && iswspace(input[start])) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && iswspace(input[end - 1])) {
        --end;
    }
    return input.substr(start, end - start);
}

std::wstring NormalizeHost(const std::wstring& input) {
    std::wstring trimmed = TrimWhitespace(input);
    if (trimmed.rfind(L"http://", 0) == 0) {
        trimmed = trimmed.substr(7);
    } else if (trimmed.rfind(L"https://", 0) == 0) {
        trimmed = trimmed.substr(8);
    }
    size_t slash = trimmed.find(L'/');
    if (slash != std::wstring::npos) {
        trimmed = trimmed.substr(0, slash);
    }
    size_t colon = trimmed.find(L':');
    if (colon != std::wstring::npos) {
        trimmed = trimmed.substr(0, colon);
    }
    return TrimWhitespace(trimmed);
}

std::wstring BuildServiceUrl(const std::wstring& host, int port) {
    std::wstring cleaned = NormalizeHost(host);
    if (cleaned.empty()) {
        return L"";
    }
    std::wstring url = L"http://" + cleaned + L":" + std::to_wstring(port) + L"/";
    return url;
}

bool LoadServerAddress(std::wstring* out) {
    if (!out) {
        return false;
    }

    DWORD type = 0;
    DWORD size = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, kRegPath, kRegValue, RRF_RT_REG_SZ, &type, nullptr, &size);
    if (status != ERROR_SUCCESS || size == 0) {
        return false;
    }

    std::wstring buffer(size / sizeof(wchar_t), L'\0');
    status = RegGetValueW(HKEY_CURRENT_USER, kRegPath, kRegValue, RRF_RT_REG_SZ, &type, &buffer[0], &size);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    size_t chars = size / sizeof(wchar_t);
    if (chars > 0) {
        buffer.resize(chars - 1);
    } else {
        buffer.clear();
    }

    buffer = NormalizeHost(buffer);
    if (buffer.empty()) {
        return false;
    }

    *out = buffer;
    return true;
}

bool SaveServerAddress(const std::wstring& address) {
    HKEY key = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kRegPath, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    std::wstring cleaned = NormalizeHost(address);
    if (cleaned.empty()) {
        RegCloseKey(key);
        return false;
    }

    DWORD bytes = static_cast<DWORD>((cleaned.size() + 1) * sizeof(wchar_t));
    status = RegSetValueExW(key, kRegValue, 0, REG_SZ, reinterpret_cast<const BYTE*>(cleaned.c_str()), bytes);
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

struct PromptContext {
    std::wstring value;
};

INT_PTR CALLBACK ServerPromptProc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    PromptContext* ctx = reinterpret_cast<PromptContext*>(GetWindowLongPtrW(dialog, GWLP_USERDATA));

    switch (message) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dialog, GWLP_USERDATA, lparam);
        ctx = reinterpret_cast<PromptContext*>(lparam);
        if (ctx) {
            SetDlgItemTextW(dialog, IDC_SERVER_EDIT, ctx->value.c_str());
        }
        return TRUE;
    }
    case WM_COMMAND: {
        switch (LOWORD(wparam)) {
        case IDOK: {
            wchar_t buffer[256] = {};
            GetDlgItemTextW(dialog, IDC_SERVER_EDIT, buffer, static_cast<int>(_countof(buffer)));
            std::wstring normalized = NormalizeHost(buffer);
            if (normalized.empty()) {
                MessageBoxW(dialog, L"Please enter a server IP or domain.", kAppName, MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            if (ctx) {
                ctx->value = normalized;
            }
            EndDialog(dialog, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        default:
            return FALSE;
        }
    }
    default:
        return FALSE;
    }
}

bool PromptForServerAddress(HWND owner, std::wstring* out) {
    PromptContext ctx;
    if (out) {
        ctx.value = *out;
    }

    INT_PTR result = DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_SERVER_PROMPT), owner, ServerPromptProc, reinterpret_cast<LPARAM>(&ctx));
    if (result == IDOK && out) {
        *out = ctx.value;
        return true;
    }

    return false;
}

bool ResolveIPv4Address(const std::wstring& host, IPAddr* address) {
    if (!address) {
        return false;
    }

    addrinfoW hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfoW* result = nullptr;
    if (GetAddrInfoW(host.c_str(), nullptr, &hints, &result) != 0) {
        return false;
    }

    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    *address = addr->sin_addr.S_un.S_addr;
    FreeAddrInfoW(result);
    return true;
}

bool PingHost(const std::wstring& host, DWORD timeoutMs) {
    IPAddr address = 0;
    if (!ResolveIPv4Address(host, &address)) {
        return false;
    }

    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        return false;
    }

    const char payload[] = "JTBoard";
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(payload);
    std::vector<char> reply(replySize);

    DWORD result = IcmpSendEcho(icmp, address, const_cast<char*>(payload), sizeof(payload), nullptr, reply.data(), replySize, timeoutMs);
    IcmpCloseHandle(icmp);

    return result != 0;
}

bool TcpCheck(const std::wstring& host, int port, int timeoutMs) {
    addrinfoW hints = {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfoW* result = nullptr;
    std::wstring portStr = std::to_wstring(port);
    if (GetAddrInfoW(host.c_str(), portStr.c_str(), &hints, &result) != 0) {
        return false;
    }

    bool connected = false;
    for (addrinfoW* ptr = result; ptr && !connected; ptr = ptr->ai_next) {
        SOCKET sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        u_long nonBlocking = 1;
        ioctlsocket(sock, FIONBIO, &nonBlocking);

        int rc = connect(sock, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen));
        if (rc == 0) {
            connected = true;
        } else {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(sock, &writeSet);

                timeval tv = {};
                tv.tv_sec = timeoutMs / 1000;
                tv.tv_usec = (timeoutMs % 1000) * 1000;

                rc = select(0, nullptr, &writeSet, nullptr, &tv);
                if (rc > 0 && FD_ISSET(sock, &writeSet)) {
                    int soError = 0;
                    int soErrorLen = sizeof(soError);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soErrorLen);
                    if (soError == 0) {
                        connected = true;
                    }
                }
            }
        }

        closesocket(sock);
    }

    FreeAddrInfoW(result);
    return connected;
}

bool IsServerReachable(const std::wstring& host) {
    if (PingHost(host, kPingTimeoutMs)) {
        return true;
    }
    return TcpCheck(host, kFallbackPort, kTcpTimeoutMs);
}

bool EnsureServerAddress(HWND owner) {
    std::wstring candidate;
    bool haveSaved = LoadServerAddress(&candidate);

    if (!haveSaved) {
        if (!PromptForServerAddress(owner, &candidate)) {
            return false;
        }
    }

    while (true) {
        if (IsServerReachable(candidate)) {
            SaveServerAddress(candidate);
            g_serverAddress = candidate;
            return true;
        }

        int choice = MessageBoxW(owner,
            L"Unable to reach the server. Ping and the TCP check on port 32400 both failed.\n\n"
            L"Yes = use this address anyway. No = enter a new address. Cancel = quit.",
            kAppName,
            MB_YESNOCANCEL | MB_ICONWARNING);

        if (choice == IDYES) {
            SaveServerAddress(candidate);
            g_serverAddress = candidate;
            return true;
        }
        if (choice == IDNO) {
            if (!PromptForServerAddress(owner, &candidate)) {
                return false;
            }
            continue;
        }
        return false;
    }
}

void LaunchService(HWND owner, int port) {
    std::wstring url = BuildServiceUrl(g_serverAddress, port);
    if (url.empty()) {
        return;
    }
    ShellExecuteW(owner, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void ApplyButtonFont(HWND button) {
    HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

void LayoutButtons(HWND hwnd) {
    RECT rect = {};
    GetClientRect(hwnd, &rect);

    int clientWidth = rect.right - rect.left;
    int clientHeight = rect.bottom - rect.top;

    const int buttonWidth = 120;
    const int buttonHeight = 32;
    const int buttonGap = 12;
    const int rowGap = 10;
    const int bottomMargin = 20;

    int totalWidth = (buttonWidth * 3) + (buttonGap * 2);
    int row2Y = clientHeight - bottomMargin - buttonHeight;
    int row1Y = row2Y - rowGap - buttonHeight;
    int startX = (clientWidth - totalWidth) / 2;

    MoveWindow(g_btnPlex, startX, row1Y, buttonWidth, buttonHeight, TRUE);
    MoveWindow(g_btnRadarr, startX + buttonWidth + buttonGap, row1Y, buttonWidth, buttonHeight, TRUE);
    MoveWindow(g_btnSonarr, startX + (buttonWidth + buttonGap) * 2, row1Y, buttonWidth, buttonHeight, TRUE);

    int quitX = (clientWidth - buttonWidth) / 2;
    MoveWindow(g_btnQuit, quitX, row2Y, buttonWidth, buttonHeight, TRUE);
}

void CreateButtons(HWND hwnd) {
    g_btnPlex = CreateWindowW(L"BUTTON", L"Plex", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_PLEX), g_instance, nullptr);
    g_btnRadarr = CreateWindowW(L"BUTTON", L"Radarr", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_RADARR), g_instance, nullptr);
    g_btnSonarr = CreateWindowW(L"BUTTON", L"Sonarr", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_SONARR), g_instance, nullptr);
    g_btnQuit = CreateWindowW(L"BUTTON", L"Quit", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_QUIT), g_instance, nullptr);

    ApplyButtonFont(g_btnPlex);
    ApplyButtonFont(g_btnRadarr);
    ApplyButtonFont(g_btnSonarr);
    ApplyButtonFont(g_btnQuit);

    LayoutButtons(hwnd);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        CreateButtons(hwnd);
        return 0;
    case WM_SIZE:
        LayoutButtons(hwnd);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case ID_BTN_PLEX:
            LaunchService(hwnd, 32400);
            return 0;
        case ID_BTN_RADARR:
            LaunchService(hwnd, 7878);
            return 0;
        case ID_BTN_SONARR:
            LaunchService(hwnd, 8989);
            return 0;
        case ID_BTN_QUIT:
            DestroyWindow(hwnd);
            return 0;
        default:
            return 0;
        }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lparam);
        if (mmi) {
            mmi->ptMinTrackSize.x = g_windowWidth;
            mmi->ptMinTrackSize.y = g_windowHeight;
            mmi->ptMaxTrackSize.x = g_windowWidth;
            mmi->ptMaxTrackSize.y = g_windowHeight;
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int cmdShow) {
    g_instance = instance;

    WSADATA wsaData = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBoxW(nullptr, L"Winsock initialization failed.", kAppName, MB_OK | MB_ICONERROR);
        return 0;
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"JTBoardMainWindow";

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Window registration failed.", kAppName, MB_OK | MB_ICONERROR);
        WSACleanup();
        return 0;
    }

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    DWORD exStyle = 0;

    RECT rect = { 0, 0, kClientWidth, kClientHeight };
    AdjustWindowRectEx(&rect, style, FALSE, exStyle);
    g_windowWidth = rect.right - rect.left;
    g_windowHeight = rect.bottom - rect.top;

    HWND hwnd = CreateWindowExW(
        exStyle,
        wc.lpszClassName,
        kAppName,
        style,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        g_windowWidth,
        g_windowHeight,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!hwnd) {
        MessageBoxW(nullptr, L"Window creation failed.", kAppName, MB_OK | MB_ICONERROR);
        WSACleanup();
        return 0;
    }

    ShowWindow(hwnd, cmdShow);
    UpdateWindow(hwnd);

    if (!EnsureServerAddress(hwnd)) {
        DestroyWindow(hwnd);
        WSACleanup();
        return 0;
    }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    return static_cast<int>(msg.wParam);
}

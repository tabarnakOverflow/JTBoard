#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <shellapi.h>
#include <shlobj.h>

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
const int kStatusTimeoutMs = 500;
const int kStatusRefreshMs = 5000;
const UINT_PTR kStatusTimerId = 1;

const int kTitleHeight = 22;
const int kTitleTopMargin = 16;
const int kTitleUnderlineOffset = 6;
const int kTitleToServicesGap = 10;

const int kServiceButtonWidth = 140;
const int kServiceButtonHeight = 32;
const int kStatusSize = 14;
const int kStatusGap = 12;
const int kServiceRowGap = 12;
const int kLeftMargin = 24;

const int kUtilityColumnButtonWidth = 190;
const int kUtilityButtonWidth = 140;
const int kUtilityButtonHeight = 32;
const int kUtilityGap = 16;
const int kBottomMargin = 20;
const int kSeparatorGap = 6;

HINSTANCE g_instance = nullptr;
std::wstring g_serverAddress;
int g_windowWidth = 0;
int g_windowHeight = 0;

HWND g_btnPlex = nullptr;
HWND g_btnRadarr = nullptr;
HWND g_btnSonarr = nullptr;
HWND g_btnChangeIp = nullptr;
HWND g_btnHardwareReport = nullptr;
HWND g_btnQuit = nullptr;

HWND g_lblServices = nullptr;
HWND g_lblUtilities = nullptr;
HFONT g_titleFont = nullptr;

HWND g_statusPlex = nullptr;
HWND g_statusRadarr = nullptr;
HWND g_statusSonarr = nullptr;

bool g_statusPlexOk = false;
bool g_statusRadarrOk = false;
bool g_statusSonarrOk = false;

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

bool AcquireServerAddress(HWND owner, const std::wstring& initialValue, bool forcePrompt, std::wstring* out) {
    std::wstring candidate = initialValue;

    if (forcePrompt || candidate.empty()) {
        if (!PromptForServerAddress(owner, &candidate)) {
            return false;
        }
    }

    while (true) {
        if (IsServerReachable(candidate)) {
            SaveServerAddress(candidate);
            if (out) {
                *out = candidate;
            }
            return true;
        }

        int choice = MessageBoxW(owner,
            L"Unable to reach the server. Ping and the TCP check on port 32400 both failed.\n\n"
            L"Yes = use this address anyway. No = enter a new address. Cancel = quit.",
            kAppName,
            MB_YESNOCANCEL | MB_ICONWARNING);

        if (choice == IDYES) {
            SaveServerAddress(candidate);
            if (out) {
                *out = candidate;
            }
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

bool EnsureServerAddress(HWND owner) {
    std::wstring candidate;
    bool haveSaved = LoadServerAddress(&candidate);
    std::wstring resolved;
    if (!AcquireServerAddress(owner, candidate, !haveSaved, &resolved)) {
        return false;
    }
    g_serverAddress = resolved;
    return true;
}

bool ChangeServerAddress(HWND owner) {
    std::wstring updated;
    if (!AcquireServerAddress(owner, g_serverAddress, true, &updated)) {
        return false;
    }
    g_serverAddress = updated;
    return true;
}

std::wstring AppendPath(const std::wstring& base, const std::wstring& leaf) {
    if (base.empty()) {
        return leaf;
    }
    if (base.back() == L'\\' || base.back() == L'/') {
        return base + leaf;
    }
    return base + L"\\" + leaf;
}

std::wstring GetDocumentsPath() {
    wchar_t path[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL | CSIDL_FLAG_CREATE, nullptr, SHGFP_TYPE_CURRENT, path))) {
        return path;
    }

    wchar_t current[MAX_PATH] = {};
    if (GetCurrentDirectoryW(static_cast<DWORD>(std::size(current)), current) > 0) {
        return current;
    }
    return L".";
}

std::wstring BuildReportDirectory() {
    std::wstring docs = GetDocumentsPath();
    std::wstring base = AppendPath(docs, L"JTBoard");
    CreateDirectoryW(base.c_str(), nullptr);
    std::wstring reports = AppendPath(base, L"Reports");
    CreateDirectoryW(reports.c_str(), nullptr);
    return reports;
}

std::wstring FormatTimestamp() {
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t buffer[32] = {};
    swprintf_s(buffer, L"%04u%02u%02u_%02u%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

bool WriteTextFile(const std::wstring& path, const std::string& content) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(file, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == content.size();
}

std::string NarrowFromWide(const std::wstring& input) {
    if (input.empty()) {
        return std::string();
    }
    int len = WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return std::string();
    }
    std::string output(len - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, &output[0], len, nullptr, nullptr);
    return output;
}

bool RunCommandScript(const std::wstring& scriptPath, DWORD* exitCode) {
    wchar_t comspec[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"COMSPEC", comspec, static_cast<DWORD>(std::size(comspec)));
    if (len == 0 || len >= std::size(comspec)) {
        wcscpy_s(comspec, L"C:\\Windows\\System32\\cmd.exe");
    }

    std::wstring cmdLine = L"\"";
    cmdLine += comspec;
    cmdLine += L"\" /c \"";
    cmdLine += scriptPath;
    cmdLine += L"\"";

    std::vector<wchar_t> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(comspec, cmdBuffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    if (exitCode) {
        *exitCode = code;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

bool GenerateHardwareReport(HWND owner, std::wstring* outPath) {
    std::wstring reportsDir = BuildReportDirectory();
    std::wstring timestamp = FormatTimestamp();
    std::wstring reportPath = AppendPath(reportsDir, L"JTBoard_Report_" + timestamp + L".txt");
    std::wstring scriptPath = AppendPath(reportsDir, L"JTBoard_Report_" + timestamp + L".cmd");

    std::string reportPathAnsi = NarrowFromWide(reportPath);
    if (reportPathAnsi.empty()) {
        return false;
    }

    std::string script;
    script += "@echo off\r\n";
    script += "setlocal\r\n";
    script += "set \"OUT=";
    script += reportPathAnsi;
    script += "\"\r\n";
    script += "echo JTBoard Hardware/Software Report> \"%OUT%\"\r\n";
    script += "echo Generated: %DATE% %TIME%>> \"%OUT%\"\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== SYSTEMINFO ====>> \"%OUT%\"\r\n";
    script += "systeminfo >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== COMPUTER SYSTEM ====>> \"%OUT%\"\r\n";
    script += "wmic computersystem get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== OS ====>> \"%OUT%\"\r\n";
    script += "wmic os get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== BIOS ====>> \"%OUT%\"\r\n";
    script += "wmic bios get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== BASEBOARD ====>> \"%OUT%\"\r\n";
    script += "wmic baseboard get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== CPU ====>> \"%OUT%\"\r\n";
    script += "wmic cpu get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== MEMORY ====>> \"%OUT%\"\r\n";
    script += "wmic memorychip get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== DISKS ====>> \"%OUT%\"\r\n";
    script += "wmic diskdrive get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== LOGICAL DISKS ====>> \"%OUT%\"\r\n";
    script += "wmic logicaldisk get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== NETWORK ADAPTERS ====>> \"%OUT%\"\r\n";
    script += "wmic nic get /format:list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== IP CONFIG ====>> \"%OUT%\"\r\n";
    script += "ipconfig /all >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== DRIVERS ====>> \"%OUT%\"\r\n";
    script += "driverquery /v >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== SERVICES ====>> \"%OUT%\"\r\n";
    script += "wmic service list brief >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== STARTUP ====>> \"%OUT%\"\r\n";
    script += "wmic startup list full >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== INSTALLED UPDATES ====>> \"%OUT%\"\r\n";
    script += "wmic qfe list >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== RUNNING TASKS ====>> \"%OUT%\"\r\n";
    script += "tasklist /v >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== NETWORK CONNECTIONS ====>> \"%OUT%\"\r\n";
    script += "netstat -ano >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== INSTALLED PROGRAMS (HKLM 64-bit) ====>> \"%OUT%\"\r\n";
    script += "reg query \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== INSTALLED PROGRAMS (HKLM 32-bit) ====>> \"%OUT%\"\r\n";
    script += "reg query \"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== INSTALLED PROGRAMS (HKCU) ====>> \"%OUT%\"\r\n";
    script += "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== ENVIRONMENT ====>> \"%OUT%\"\r\n";
    script += "set >> \"%OUT%\" 2>&1\r\n";
    script += "echo.>> \"%OUT%\"\r\n";
    script += "echo ==== DONE ====>> \"%OUT%\"\r\n";
    script += "endlocal\r\n";

    if (!WriteTextFile(scriptPath, script)) {
        return false;
    }

    DWORD exitCode = 0;
    bool ok = RunCommandScript(scriptPath, &exitCode);
    DeleteFileW(scriptPath.c_str());
    if (ok && outPath) {
        *outPath = reportPath;
    }
    return ok;
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

HFONT CreateTitleFont(HWND hwnd, int pointSize, int weight) {
    HFONT baseFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    LOGFONTW lf = {};
    if (GetObjectW(baseFont, sizeof(lf), &lf) == 0) {
        return nullptr;
    }

    HDC hdc = GetDC(hwnd);
    if (hdc) {
        lf.lfHeight = -MulDiv(pointSize, GetDeviceCaps(hdc, LOGPIXELSY), 72);
        ReleaseDC(hwnd, hdc);
    }
    lf.lfWeight = weight;
    return CreateFontIndirectW(&lf);
}

int GetUtilityRowY(int clientHeight) {
    return clientHeight - kBottomMargin - kUtilityButtonHeight;
}

int GetSeparatorY(int clientHeight) {
    return GetUtilityRowY(clientHeight) - kSeparatorGap;
}

int GetTitleUnderlineY() {
    return kTitleTopMargin + kTitleHeight + kTitleUnderlineOffset;
}

void SetIndicatorStatus(HWND indicator, bool* current, bool value) {
    if (!indicator || !current) {
        return;
    }
    if (*current != value) {
        *current = value;
        InvalidateRect(indicator, nullptr, TRUE);
    }
}

bool CheckServicePort(int port, int timeoutMs) {
    if (g_serverAddress.empty()) {
        return false;
    }
    return TcpCheck(g_serverAddress, port, timeoutMs);
}

void UpdateServiceStatus() {
    SetIndicatorStatus(g_statusPlex, &g_statusPlexOk, CheckServicePort(32400, kStatusTimeoutMs));
    SetIndicatorStatus(g_statusRadarr, &g_statusRadarrOk, CheckServicePort(7878, kStatusTimeoutMs));
    SetIndicatorStatus(g_statusSonarr, &g_statusSonarrOk, CheckServicePort(8989, kStatusTimeoutMs));
}

void DrawStatusIndicator(const DRAWITEMSTRUCT* dis, bool ok) {
    if (!dis) {
        return;
    }

    HDC hdc = dis->hDC;
    RECT rect = dis->rcItem;

    HBRUSH background = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
    FillRect(hdc, &rect, background);
    DeleteObject(background);

    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    int size = std::min(width, height);
    int left = rect.left + (width - size) / 2;
    int top = rect.top + (height - size) / 2;

    COLORREF color = ok ? RGB(46, 204, 113) : RGB(231, 76, 60);
    HBRUSH fill = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(70, 70, 70));

    HBRUSH oldBrush = static_cast<HBRUSH>(SelectObject(hdc, fill));
    HPEN oldPen = static_cast<HPEN>(SelectObject(hdc, pen));
    Ellipse(hdc, left, top, left + size, top + size);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);

    DeleteObject(fill);
    DeleteObject(pen);
}

void LayoutControls(HWND hwnd) {
    RECT rect = {};
    GetClientRect(hwnd, &rect);

    int clientWidth = rect.right - rect.left;
    int clientHeight = rect.bottom - rect.top;

    int col1Width = clientWidth / 3;
    int col2X = col1Width;
    int col2Width = (clientWidth * 2) / 3 - col2X;

    MoveWindow(g_lblServices, 0, kTitleTopMargin, col1Width, kTitleHeight, TRUE);
    MoveWindow(g_lblUtilities, col2X, kTitleTopMargin, col2Width, kTitleHeight, TRUE);

    int servicesY = GetTitleUnderlineY() + kTitleToServicesGap;
    int statusX = kLeftMargin + kServiceButtonWidth + kStatusGap;

    MoveWindow(g_btnPlex, kLeftMargin, servicesY, kServiceButtonWidth, kServiceButtonHeight, TRUE);
    MoveWindow(g_statusPlex, statusX, servicesY + (kServiceButtonHeight - kStatusSize) / 2, kStatusSize, kStatusSize, TRUE);

    int row2Y = servicesY + kServiceButtonHeight + kServiceRowGap;
    MoveWindow(g_btnRadarr, kLeftMargin, row2Y, kServiceButtonWidth, kServiceButtonHeight, TRUE);
    MoveWindow(g_statusRadarr, statusX, row2Y + (kServiceButtonHeight - kStatusSize) / 2, kStatusSize, kStatusSize, TRUE);

    int row3Y = row2Y + kServiceButtonHeight + kServiceRowGap;
    MoveWindow(g_btnSonarr, kLeftMargin, row3Y, kServiceButtonWidth, kServiceButtonHeight, TRUE);
    MoveWindow(g_statusSonarr, statusX, row3Y + (kServiceButtonHeight - kStatusSize) / 2, kStatusSize, kStatusSize, TRUE);

    int utilitiesX = col2X + kLeftMargin;
    MoveWindow(g_btnHardwareReport, utilitiesX, servicesY, kUtilityColumnButtonWidth, kServiceButtonHeight, TRUE);

    int utilityRowY = GetUtilityRowY(clientHeight);
    int totalWidth = (kUtilityButtonWidth * 2) + kUtilityGap;
    int startX = (clientWidth - totalWidth) / 2;

    MoveWindow(g_btnChangeIp, startX, utilityRowY, kUtilityButtonWidth, kUtilityButtonHeight, TRUE);
    MoveWindow(g_btnQuit, startX + kUtilityButtonWidth + kUtilityGap, utilityRowY, kUtilityButtonWidth, kUtilityButtonHeight, TRUE);
}

void CreateControls(HWND hwnd) {
    g_lblServices = CreateWindowW(L"STATIC", L"Services", WS_CHILD | WS_VISIBLE | SS_CENTER,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_LABEL_SERVICES), g_instance, nullptr);
    g_lblUtilities = CreateWindowW(L"STATIC", L"Utilities", WS_CHILD | WS_VISIBLE | SS_CENTER,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_LABEL_UTILITIES), g_instance, nullptr);
    g_btnPlex = CreateWindowW(L"BUTTON", L"Plex", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_PLEX), g_instance, nullptr);
    g_btnRadarr = CreateWindowW(L"BUTTON", L"Radarr", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_RADARR), g_instance, nullptr);
    g_btnSonarr = CreateWindowW(L"BUTTON", L"Sonarr", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_SONARR), g_instance, nullptr);
    g_btnHardwareReport = CreateWindowW(L"BUTTON", L"Pull Hardware Report", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_HW_REPORT), g_instance, nullptr);
    g_btnChangeIp = CreateWindowW(L"BUTTON", L"Change IP", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_CHANGE_IP), g_instance, nullptr);
    g_btnQuit = CreateWindowW(L"BUTTON", L"Quit", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_BTN_QUIT), g_instance, nullptr);

    g_statusPlex = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_STATUS_PLEX), g_instance, nullptr);
    g_statusRadarr = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_STATUS_RADARR), g_instance, nullptr);
    g_statusSonarr = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(ID_STATUS_SONARR), g_instance, nullptr);

    if (!g_titleFont) {
        g_titleFont = CreateTitleFont(hwnd, 16, FW_SEMIBOLD);
    }
    if (g_titleFont) {
        SendMessageW(g_lblServices, WM_SETFONT, reinterpret_cast<WPARAM>(g_titleFont), TRUE);
        SendMessageW(g_lblUtilities, WM_SETFONT, reinterpret_cast<WPARAM>(g_titleFont), TRUE);
    } else {
        ApplyButtonFont(g_lblServices);
        ApplyButtonFont(g_lblUtilities);
    }
    ApplyButtonFont(g_btnPlex);
    ApplyButtonFont(g_btnRadarr);
    ApplyButtonFont(g_btnSonarr);
    ApplyButtonFont(g_btnHardwareReport);
    ApplyButtonFont(g_btnChangeIp);
    ApplyButtonFont(g_btnQuit);

    LayoutControls(hwnd);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        CreateControls(hwnd);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps = {};
        HDC hdc = BeginPaint(hwnd, &ps);

        RECT rect = {};
        GetClientRect(hwnd, &rect);
        int clientWidth = rect.right - rect.left;
        int clientHeight = rect.bottom - rect.top;

        int separatorY = GetSeparatorY(clientHeight);
        if (separatorY < 0) {
            separatorY = 0;
        } else if (separatorY >= clientHeight) {
            separatorY = clientHeight - 1;
        }

        int underlineY = GetTitleUnderlineY();
        if (underlineY < 0) {
            underlineY = 0;
        } else if (underlineY >= clientHeight) {
            underlineY = clientHeight - 1;
        }

        int col1 = clientWidth / 3;
        int col2 = (clientWidth * 2) / 3;

        HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
        HPEN oldPen = static_cast<HPEN>(SelectObject(hdc, pen));

        int maxX = std::max(0, clientWidth - 1);
        MoveToEx(hdc, 0, separatorY, nullptr);
        LineTo(hdc, maxX, separatorY);

        MoveToEx(hdc, 0, underlineY, nullptr);
        LineTo(hdc, maxX, underlineY);

        MoveToEx(hdc, col1, 0, nullptr);
        LineTo(hdc, col1, separatorY);

        MoveToEx(hdc, col2, 0, nullptr);
        LineTo(hdc, col2, separatorY);

        SelectObject(hdc, oldPen);
        DeleteObject(pen);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_SIZE:
        LayoutControls(hwnd);
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
        case ID_BTN_HW_REPORT: {
            EnableWindow(g_btnHardwareReport, FALSE);
            std::wstring reportPath;
            bool ok = GenerateHardwareReport(hwnd, &reportPath);
            EnableWindow(g_btnHardwareReport, TRUE);
            SetForegroundWindow(hwnd);
            if (ok) {
                std::wstring message = L"Hardware report saved to:\n" + reportPath;
                MessageBoxW(hwnd, message.c_str(), kAppName, MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(hwnd, L"Failed to generate the hardware report.", kAppName, MB_OK | MB_ICONERROR);
            }
            return 0;
        }
        case ID_BTN_CHANGE_IP:
            if (ChangeServerAddress(hwnd)) {
                UpdateServiceStatus();
            }
            return 0;
        case ID_BTN_QUIT:
            DestroyWindow(hwnd);
            return 0;
        default:
            return 0;
        }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lparam);
        if (!dis || dis->CtlType != ODT_STATIC) {
            return FALSE;
        }
        switch (dis->CtlID) {
        case ID_STATUS_PLEX:
            DrawStatusIndicator(dis, g_statusPlexOk);
            return TRUE;
        case ID_STATUS_RADARR:
            DrawStatusIndicator(dis, g_statusRadarrOk);
            return TRUE;
        case ID_STATUS_SONARR:
            DrawStatusIndicator(dis, g_statusSonarrOk);
            return TRUE;
        default:
            return FALSE;
        }
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = reinterpret_cast<HDC>(wparam);
        HWND control = reinterpret_cast<HWND>(lparam);
        if (control == g_lblServices || control == g_lblUtilities) {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
            return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
        }
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    case WM_TIMER:
        if (wparam == kStatusTimerId) {
            UpdateServiceStatus();
            return 0;
        }
        return DefWindowProcW(hwnd, message, wparam, lparam);
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
        KillTimer(hwnd, kStatusTimerId);
        if (g_titleFont) {
            DeleteObject(g_titleFont);
            g_titleFont = nullptr;
        }
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

    UpdateServiceStatus();
    SetTimer(hwnd, kStatusTimerId, kStatusRefreshMs, nullptr);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    WSACleanup();
    return static_cast<int>(msg.wParam);
}

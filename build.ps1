param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("Win32", "x64")]
    [string]$Platform = "x64",

    [string]$Solution = "JTBoard.sln"
)

$ErrorActionPreference = "Stop"

function Get-MSBuildPath {
    $vswhere = "$env:ProgramFiles(x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $result = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\\**\\Bin\\MSBuild.exe"
        if ($result) {
            return $result | Select-Object -First 1
        }
    }

    $known = @(
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles(x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles(x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    )

    foreach ($path in $known) {
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

if (-not (Test-Path $Solution)) {
    throw "Solution not found: $Solution"
}

$msbuild = Get-MSBuildPath
if (-not $msbuild) {
    throw "MSBuild.exe not found. Install Visual Studio or Build Tools, or run from a Developer PowerShell." 
}

Write-Host "Using MSBuild: $msbuild"
& $msbuild $Solution /m /p:Configuration=$Configuration /p:Platform=$Platform
exit $LASTEXITCODE

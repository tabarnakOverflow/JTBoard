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
    $candidates = @()
    if (Test-Path $vswhere) {
        $installs = & $vswhere -all -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        foreach ($install in $installs) {
            if ($install) {
                $candidates += (Join-Path $install "MSBuild\Current\Bin\MSBuild.exe")
                $candidates += (Join-Path $install "MSBuild\Current\Bin\amd64\MSBuild.exe")
            }
        }
    }

    $roots = @(
        "$env:ProgramFiles\Microsoft Visual Studio",
        "$env:ProgramFiles(x86)\Microsoft Visual Studio"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $versions = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
        foreach ($version in $versions) {
            $editions = Get-ChildItem -Path $version.FullName -Directory -ErrorAction SilentlyContinue
            foreach ($edition in $editions) {
                $candidates += (Join-Path $edition.FullName "MSBuild\Current\Bin\MSBuild.exe")
                $candidates += (Join-Path $edition.FullName "MSBuild\Current\Bin\amd64\MSBuild.exe")
            }
        }
    }

    $known = @(
        "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles(x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
        "$env:ProgramFiles(x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )

    $candidates += $known

    foreach ($path in $candidates) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    $dotNetMsbuild = @(
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

    if ($dotNetMsbuild) {
        throw "Found .NET Framework MSBuild at $dotNetMsbuild, but C++ projects require Visual Studio Build Tools. Install VS Build Tools or run from a Developer PowerShell."
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

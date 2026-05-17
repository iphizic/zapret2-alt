$ErrorActionPreference = "Stop"

$Converter = ".\flowseal_winws_to_nfqws2_smart_v2_dedup_newlines.py"
$OutDir = ".\converted_alt"

$BinDir = "/opt/zapret2/binaries"
$ListsDir = "/opt/zapret2/ipset"

$BaseUrl = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main"


$Files = @(
    "general (ALT).bat",
    "general (ALT2).bat",
    "general (ALT3).bat",
    "general (ALT4).bat",
    "general (ALT5).bat",
    "general (ALT6).bat",
    "general (ALT7).bat",
    "general (ALT8).bat",
    "general (ALT9).bat",
    "general (ALT10).bat",
    "general (ALT11).bat",
    "general (FAKE TLS AUTO ALT).bat",
    "general (FAKE TLS AUTO ALT2).bat",
    "general (FAKE TLS AUTO ALT3).bat",
    "general (FAKE TLS AUTO).bat",
    "general (SIMPLE FAKE ALT).bat",
    "general (SIMPLE FAKE ALT2).bat",
    "general (SIMPLE FAKE).bat"
)

if (-not (Test-Path $Converter)) {
    throw "Converter not found: $Converter"
}

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    throw "Python not found in PATH"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "[*] Running converter self-test"
& $PythonCmd.Source $Converter --self-test

if ($LASTEXITCODE -ne 0) {
    throw "Converter self-test failed"
}

foreach ($File in $Files) {
    Write-Host ""
    Write-Host "[*] Processing: $File"

    $EncodedFile = [uri]::EscapeDataString($File)
    $Url = "$BaseUrl/$EncodedFile"

    $LocalBat = Join-Path $OutDir $File

    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($File)
    $OutConf = Join-Path $OutDir "$BaseName.nfqws2.conf"
    $Report = Join-Path $OutDir "$BaseName.report.md"

    Write-Host "    Download: $Url"
    Invoke-WebRequest -Uri $Url -OutFile $LocalBat -UseBasicParsing

    Write-Host "    Convert: $OutConf"

    & $PythonCmd.Source $Converter `
        $LocalBat `
        --config-style `
        --bin-dir $BinDir `
        --lists-dir $ListsDir `
        -o $OutConf `
        --report $Report

    if ($LASTEXITCODE -ne 0) {
        throw "Conversion failed: $File"
    }

    $BadPatterns = @(
        "%BIN%",
        "%LISTS%",
        "%GameFilterTCP%",
        "%GameFilterUDP%",
        "--wf-tcp",
        "--wf-udp",
        "winws.exe",
        "start `"",
        "@echo",
        "chcp",
        "cd /d"
    )

    $Content = Get-Content $OutConf -Raw
    $FoundBad = @()

    foreach ($Pattern in $BadPatterns) {
        if ($Content.Contains($Pattern)) {
            $FoundBad += $Pattern
        }
    }

    if ($Content -match "\^") {
        $FoundBad += "^"
    }

    if ($Content -match '--[^=\s]+="[^"]+"') {
        $FoundBad += 'quoted --key="value"'
    }

    if ($FoundBad.Count -gt 0) {
        Write-Warning "Suspicious leftovers in $OutConf"
        foreach ($Bad in $FoundBad) {
            Write-Warning "  $Bad"
        }
    }
    else {
        Write-Host "    OK"
    }
}

$ZipPath = ".\converted_alt.zip"

if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}

Compress-Archive -Path "$OutDir\*" -DestinationPath $ZipPath

Write-Host ""
Write-Host "[+] Done"
Write-Host "    Folder:  $OutDir"
Write-Host "    Archive: $ZipPath"

$ErrorActionPreference = "Stop"

$Converter = ".\flowseal_winws_to_nfqws2_no_hostlists.py"
$OutDir = ".\converted_alt"

$BinDir = "/opt/zapret2/files/fake/"
$ListsDir = "/opt/zapret2/ipset"
$StrategyTemplate = "safe"
$PreferDefaultBlobs = $true

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

$UvCmd = Get-Command uv -ErrorAction SilentlyContinue
$PythonCmd = $null

if (-not $UvCmd) {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCmd) {
        $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
    }
}

if (-not $UvCmd -and -not $PythonCmd) {
    throw "Python not found in PATH"
}

function Invoke-ConverterPython {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $Args
    )

    if ($UvCmd) {
        & $UvCmd.Source run --no-project python @Args
    }
    else {
        & $PythonCmd.Source @Args
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "[*] Running converter self-test"
Invoke-ConverterPython $Converter --self-test

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

    $ConvertArgs = @(
        $Converter,
        $LocalBat,
        "--config-style",
        "--strategy-template", $StrategyTemplate,
        "--bin-dir", $BinDir,
        "--lists-dir", $ListsDir,
        "-o", $OutConf,
        "--report", $Report
    )

    if ($PreferDefaultBlobs) {
        $ConvertArgs += "--prefer-default-blobs"
    }

    Invoke-ConverterPython @ConvertArgs

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
        "--dpi-desync",
        "--payload=unknown",
        "--payload=unknown_udp",
        "@!",
        "winws.exe",
        "start `"",
        "@echo",
        "chcp",
        "cd /d"
    )

    $Content = Get-Content $OutConf -Raw
    $ContentToCheck = (($Content -split "`r?`n") |
        Where-Object { -not $_.TrimStart().StartsWith("#") }) -join "`n"
    $FoundBad = @()

    foreach ($Pattern in $BadPatterns) {
        if ($ContentToCheck.Contains($Pattern)) {
            $FoundBad += $Pattern
        }
    }

    if ($ContentToCheck -match "\^") {
        $FoundBad += "^"
    }

    if ($ContentToCheck -match '--[^=\s]+="[^"]+"') {
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

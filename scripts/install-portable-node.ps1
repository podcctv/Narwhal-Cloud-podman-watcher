$ErrorActionPreference = 'Stop'
$targetDir = Join-Path $env:LOCALAPPDATA 'Programs\nodejs'

if (Test-Path "$targetDir\node.exe") {
    Write-Output "Node already installed at $targetDir"
} else {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    $zipPath = Join-Path $env:TEMP 'node-lts.zip'
    if (!(Test-Path $zipPath) -or ((Get-Item $zipPath).Length -lt 20000000)) {
        Write-Output "Downloading portable Node.js via curl..."
        curl.exe -L -o $zipPath "https://npmmirror.com/mirrors/node/v20.18.0/node-v20.18.0-win-x64.zip"
    }
    Write-Output "Extracting Node.js with tar..."
    tar.exe -xf $zipPath -C $targetDir --strip-components=1
    Write-Output "Extracted successfully!"
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$targetDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$targetDir;$userPath", 'User')
    Write-Output "Added $targetDir to User PATH"
}

$env:Path = "$targetDir;$env:Path"

& "$targetDir\node.exe" -v
& "$targetDir\npm.cmd" -v
Write-Output "Portable Node.js setup complete!"

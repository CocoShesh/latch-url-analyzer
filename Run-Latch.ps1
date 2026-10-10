$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
try {
    $nodeText = (& node --version 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or $nodeText -notmatch '^v(\d+)\.') { throw 'Node.js 22 or newer is required. Install Node.js LTS, then run this file again.' }
    if ([int]$Matches[1] -lt 22) { throw "Found Node $nodeText; install Node.js 22 or newer first." }
    if (-not (Test-Path (Join-Path $root '.env'))) { Copy-Item (Join-Path $root '.env.example') (Join-Path $root '.env') }
    Write-Host 'Installing Latch dependencies...' -ForegroundColor Cyan
    Push-Location $root
    try {
        & npm install
        if ($LASTEXITCODE -ne 0) { throw 'npm install failed. Check the network connection and errors above.' }
        Write-Host 'Installing the Playwright Firefox runtime (first run downloads Firefox)...' -ForegroundColor Cyan
        & npx playwright install firefox
        if ($LASTEXITCODE -ne 0) { throw 'Firefox install failed. Check network access and Windows compatibility.' }
        $pythonCommand = Get-Command 'py.exe' -ErrorAction SilentlyContinue
        $pythonArgs = @('-3')
        if (-not $pythonCommand) { $pythonCommand = Get-Command 'python.exe' -ErrorAction SilentlyContinue; $pythonArgs = @() }
        if ($pythonCommand) {
            $venvPython = Join-Path $root '.dnstwist-venv\Scripts\python.exe'
            if (-not (Test-Path $venvPython)) { & $pythonCommand.Source @pythonArgs -m venv (Join-Path $root '.dnstwist-venv') }
            if (Test-Path $venvPython) {
                & $venvPython -c 'import dnstwist' 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Write-Host 'Installing optional DNSTwist lookalike-domain analysis...' -ForegroundColor Cyan
                    & $venvPython -m pip install dnstwist
                    if ($LASTEXITCODE -ne 0) { Write-Warning 'DNSTwist install failed. Main URL analysis will still run; lookalike analysis stays disabled.' }
                }
            } else { Write-Warning 'Could not create the DNSTwist Python environment. Main URL analysis will still run.' }
        } else { Write-Warning 'Python 3 was not found. Install Python 3 to enable optional DNSTwist analysis; main URL analysis will still run.' }
    } finally { Pop-Location }
    $escapedRoot = $root.Replace("'", "''")
    $command = "Set-Location -LiteralPath '$escapedRoot'; npm start"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoExit', '-EncodedCommand', $encoded) | Out-Null
    Write-Host 'Latch is starting with Playwright Firefox in a separate PowerShell window.' -ForegroundColor Green
    Write-Host 'Wait for the service window to show Latch listening, then use the browser at http://127.0.0.1:8787.'
    Write-Host 'AI stays off. Keep the service window open while scanning.'
    Start-Sleep -Seconds 4
    Start-Process 'http://127.0.0.1:8787' | Out-Null
} catch {
    Write-Host "`nSETUP DID NOT FINISH: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Fix the issue above and run Run-Latch.bat again. This window will stay open.'
    Read-Host 'Press Enter to close'
    exit 1
}

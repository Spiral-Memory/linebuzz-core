$ErrorActionPreference = "Stop"

foreach ($cmd in "node", "npm") {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Error: $cmd is required but not installed."
        Exit 1
    }
}

if (-not (Test-Path "node_modules") -or -not (Test-Path "node_modules/pg") -or -not (Test-Path "node_modules/dotenv")) {
    Write-Host "Installing database dependencies..."
    npm install
}

Write-Host "Welcome to LineBuzz Core Setup Suite!"
Write-Host "Select Setup Option:"
Write-Host "1) Setup local self-hosted Supabase and deploy schema (Linux only)"
Write-Host "2) Deploy schema to an existing database (local dev, self-hosted, or cloud)"
$choice = Read-Host -Prompt "Choice"

if ($choice -eq "1") {
    Write-Warning "Setting up local self-hosted Supabase via setup script is only supported on Linux."
    Write-Warning "For Windows, please refer to the official guides: https://supabase.com/docs/guides/self-hosting"
    Exit 1
} elseif ($choice -eq "2") {
    node .\deploy-linebuzz.js
} else {
    Write-Error "Invalid choice."
    Exit 1
}

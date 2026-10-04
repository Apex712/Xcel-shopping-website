$ErrorActionPreference = 'Stop'

$clientId = $null
$secureSecret = $null
$pointer = [IntPtr]::Zero
$secret = $null

try {
    $clientId = Read-Host 'Enter the new Google OAuth client ID'
    if ($clientId -notmatch '^\d+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$') {
        throw 'That does not look like a Google OAuth client ID. No files were changed.'
    }

    $secureSecret = Read-Host 'Enter the NEW Google OAuth client secret (hidden)' -AsSecureString
    if ($secureSecret.Length -lt 12) {
        throw 'The value is too short. No files were changed.'
    }

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
    $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ($secret -notmatch '^GOCSPX-[A-Za-z0-9_-]+$') {
        throw 'That does not look like a Google OAuth client secret. No files were changed.'
    }

    $envPath = Join-Path $PSScriptRoot '.env'
    if (-not (Test-Path -LiteralPath $envPath)) {
        throw 'The local .env file was not found. No files were changed.'
    }

    $lines = [Collections.Generic.List[string]]::new()
    $clientIdWritten = $false
    $secretWritten = $false
    foreach ($line in [IO.File]::ReadAllLines($envPath)) {
        $separator = $line.IndexOf('=')
        $key = if ($separator -ge 0) { ($line.Substring(0, $separator).Trim() -replace '\s+', '_').ToUpperInvariant() } else { '' }
        if ($key -eq 'GOOGLE_CLIENT_ID') {
            if (-not $clientIdWritten) {
                $lines.Add('GOOGLE_CLIENT_ID=' + $clientId)
                $clientIdWritten = $true
            }
        } elseif ($key -eq 'GOOGLE_CLIENT_SECRET') {
            if (-not $secretWritten) {
                $lines.Add('GOOGLE_CLIENT_SECRET=' + $secret)
                $secretWritten = $true
            }
        } else {
            $lines.Add($line)
        }
    }

    if (-not $clientIdWritten) {
        $lines.Add('GOOGLE_CLIENT_ID=' + $clientId)
    }
    if (-not $secretWritten) {
        $lines.Add('GOOGLE_CLIENT_SECRET=' + $secret)
    }

    [IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host 'Google OAuth client ID and secret saved to ignored .env. The secret was not displayed.'
} catch {
    Write-Host $_.Exception.Message
    exit 1
} finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($secureSecret) { $secureSecret.Dispose() }
    $secret = $null
}
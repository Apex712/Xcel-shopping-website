$ErrorActionPreference = 'Stop'

$secureUri = $null
$securePassword = $null
$uriPointer = [IntPtr]::Zero
$passwordPointer = [IntPtr]::Zero
$uriText = $null
$passwordText = $null

try {
    $secureUri = Read-Host 'Paste the Supabase Session Pooler URI template (hidden)' -AsSecureString
    $securePassword = Read-Host 'Enter the NEW Supabase database password (hidden)' -AsSecureString

    if ($secureUri.Length -eq 0 -or $securePassword.Length -eq 0) {
        throw 'Both values are required. No files were changed.'
    }

    $uriPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUri)
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $uriText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($uriPointer).Trim()
    $passwordText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)

    $pattern = '^(?<scheme>postgres(?:ql)?://)(?<user>[^:/@]+):(?<oldPassword>[^@]*)@(?<host>[^/:]+\.pooler\.supabase\.com)(?<port>:\d+)(?<path>/[^?]+)(?<query>\?.*)?$'
    $match = [regex]::Match($uriText, $pattern)
    if (-not $match.Success) {
        throw 'That is not a Supabase Session Pooler URI. No files were changed.'
    }

    $encodedPassword = [Uri]::EscapeDataString($passwordText)
    $connection = $match.Groups['scheme'].Value +
        $match.Groups['user'].Value + ':' + $encodedPassword + '@' +
        $match.Groups['host'].Value + $match.Groups['port'].Value +
        $match.Groups['path'].Value + $match.Groups['query'].Value

    $envPath = Join-Path $PSScriptRoot '.env'
    $lines = [Collections.Generic.List[string]]::new()
    $written = $false

    if (Test-Path -LiteralPath $envPath) {
        foreach ($line in [IO.File]::ReadAllLines($envPath)) {
            $separator = $line.IndexOf('=')
            $key = if ($separator -ge 0) { $line.Substring(0, $separator).Trim().ToUpperInvariant() } else { '' }
            if ($key -eq 'SUPABASE_CONNECTION_STRING') {
                if (-not $written) {
                    $lines.Add('SUPABASE_CONNECTION_STRING=' + $connection)
                    $written = $true
                }
            } else {
                $lines.Add($line)
            }
        }
    }

    if (-not $written) {
        $lines.Add('SUPABASE_CONNECTION_STRING=' + $connection)
    }

    [IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host 'Supabase connection saved to the ignored .env file. Values were not displayed.'
} catch {
    Write-Host $_.Exception.Message
    exit 1
} finally {
    if ($uriPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($uriPointer) }
    if ($passwordPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
    if ($secureUri) { $secureUri.Dispose() }
    if ($securePassword) { $securePassword.Dispose() }
    $uriText = $null
    $passwordText = $null
}
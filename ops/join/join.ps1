#Requires -Version 5.1
# Public bootstrap. No credentials are embedded in this file.
[CmdletBinding()]
param(
  [string]$Hub = '@@CLAWCTL_PUBLIC_URL@@',
  [string]$LogFile = (Join-Path $env:ProgramData 'clawctl\join.log'),
  [switch]$JobsEnabled
)
Set-PSDebug -Off
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

function Assert-NoReparsePoint([string]$Path) {
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'A managed path contains a reparse point.'
      }
    }
    $current = Split-Path -Parent $current
  }
}
function Set-JoinPrivate([string]$Path, [bool]$Directory) {
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $inheritance = [Security.AccessControl.InheritanceFlags]::None
  if ($Directory) { $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
  $acl.SetOwner($sid)
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inheritance, 'None', 'Allow')
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}
function Write-JoinProgress([string]$Message) {
  Write-Host $Message
  Add-Content -LiteralPath $LogFile -Value ("{0:u} {1}" -f [DateTime]::UtcNow, $Message)
}
function Read-JoinBlock([IO.Stream]$Stream, [byte[]]$Buffer) {
  $offset = 0
  while ($offset -lt $Buffer.Length) {
    $n = $Stream.Read($Buffer, $offset, $Buffer.Length - $offset)
    if ($n -eq 0) { throw 'Truncated agent archive.' }
    $offset += $n
  }
}
# Accept only the four flat regular files emitted by build-agent-bundles.sh.
# No external tar invocation, links, directories, prefixes, duplicate names,
# absolute paths or traversal are accepted, including Windows path separators.
function Expand-JoinBundle([string]$Archive, [string]$Destination) {
  $expected = @('VERSION', 'clawctl-agent.exe', 'install-agent-windows.ps1', 'clawctl-agent.task.xml')
  $seen = @{}
  $inputStream = [IO.File]::OpenRead($Archive)
  $gzip = New-Object IO.Compression.GZipStream($inputStream, [IO.Compression.CompressionMode]::Decompress)
  try {
    $total = 0L
    while ($true) {
      $header = New-Object byte[] 512
      Read-JoinBlock $gzip $header
      if (@($header | Where-Object { $_ -ne 0 }).Count -eq 0) { break }
      $name = [Text.Encoding]::ASCII.GetString($header, 0, 100).TrimEnd([char]0)
      $prefix = [Text.Encoding]::ASCII.GetString($header, 345, 155).TrimEnd([char]0)
      if ($name -cnotin $expected -or $seen.ContainsKey($name) -or $prefix -ne '' -or $header[156] -notin @(0, 48)) {
        throw 'Unsafe agent archive member.'
      }
      $sizeText = [Text.Encoding]::ASCII.GetString($header, 124, 12).Trim([char]0, [char]32)
      if ($sizeText -notmatch '^[0-7]{1,11}$') { throw 'Invalid archive size.' }
      $size = [Convert]::ToInt64($sizeText, 8)
      $total += $size
      if ($size -gt 64MB -or $total -gt 128MB) { throw 'Agent archive is too large.' }
      $outputStream = [IO.File]::Open((Join-Path $Destination $name), [IO.FileMode]::CreateNew)
      try {
        $remaining = $size
        while ($remaining -gt 0) {
          $buffer = New-Object byte[] ([int][Math]::Min(65536, $remaining))
          Read-JoinBlock $gzip $buffer
          $outputStream.Write($buffer, 0, $buffer.Length)
          $remaining -= $buffer.Length
        }
      } finally { $outputStream.Dispose() }
      $padding = [int]((512 - ($size % 512)) % 512)
      if ($padding -gt 0) { Read-JoinBlock $gzip (New-Object byte[] $padding) }
      $seen[$name] = $true
    }
    if ($seen.Count -ne $expected.Count) { throw 'Incomplete agent archive.' }
  } finally { $gzip.Dispose(); $inputStream.Dispose() }
}

$work = $null
$started = $null
$approved = $null
$headers = $null
$step = 'preflight'
try {
  if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator.'
  }
  $uri = [uri]$Hub
  if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/' -or $Hub -match '\s') {
    throw 'Provide a public HTTPS Hub URL.'
  }
  $Hub = $Hub.TrimEnd('/')
  $arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    default { throw 'Supported architectures are amd64 and arm64.' }
  }
  # Windows PowerShell 5.1 can otherwise select obsolete TLS defaults.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Assert-NoReparsePoint $LogFile
  $logParent = Split-Path -Parent ([IO.Path]::GetFullPath($LogFile))
  [void][IO.Directory]::CreateDirectory($logParent)
  if (-not (Test-Path -LiteralPath $LogFile)) { [IO.File]::WriteAllText($LogFile, '') }
  Set-JoinPrivate $LogFile $false
  $work = Join-Path ([IO.Path]::GetTempPath()) ('clawctl-join-' + [guid]::NewGuid().ToString('N'))
  Assert-NoReparsePoint $work
  [void][IO.Directory]::CreateDirectory($work)
  Set-JoinPrivate $work $true
  if (Test-Path -LiteralPath (Join-Path $env:APPDATA 'clawctl\agent.json')) { throw 'An agent is already enrolled for this user.' }
  $step = 'starting join'
  Write-JoinProgress 'Starting Windows join.'
  $body = @{hostname = [Environment]::MachineName; os = 'windows'; arch = $arch; user = [Environment]::UserName} | ConvertTo-Json -Compress
  $started = Invoke-RestMethod -Uri "$Hub/v1/join/start" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 30 -MaximumRedirection 0
  if ($started.join_code -cnotmatch '^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$' -or $started.device_secret -cnotmatch '^[A-Za-z0-9_-]{43}$' -or $started.poll_seconds -lt 1 -or $started.poll_seconds -gt 60) { throw 'Invalid join response.' }
  $expires = [DateTimeOffset]::Parse($started.expires_at)
  Write-JoinProgress "Join code: $($started.join_code)"
  Write-JoinProgress "Open $Hub/machines/join and approve this code. Expires: $($expires.ToString('u'))"
  $step = 'downloading bundle'
  # Download before poll redemption ends device-secret authority, exactly as join.sh.
  $archive = Join-Path $work 'bundle.tar.gz'
  $headers = @{Authorization = 'Bearer ' + $started.device_secret}
  Invoke-WebRequest -UseBasicParsing -Uri "$Hub/v1/join/bundle/windows-$arch" -Headers $headers -OutFile $archive -TimeoutSec 120 -MaximumRedirection 0 | Out-Null
  if ((Get-Item -LiteralPath $archive).Length -gt 64MB) { throw 'Agent bundle is too large.' }
  $step = 'waiting for approval'
  $pollBody = @{device_secret = $started.device_secret} | ConvertTo-Json -Compress
  while ([DateTimeOffset]::UtcNow -lt $expires) {
    Start-Sleep -Seconds $started.poll_seconds
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri "$Hub/v1/join/poll" -Method Post -ContentType 'application/json' -Body $pollBody -TimeoutSec 30 -MaximumRedirection 0
    } catch {
      if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 410) { throw 'Join rejected or expired; run the join command again.' }
      throw 'The Hub could not check this join.'
    }
    if ([int]$response.StatusCode -eq 202) { continue }
    if ([int]$response.StatusCode -ne 200) { throw 'Unexpected join state.' }
    $approved = $response.Content | ConvertFrom-Json
    break
  }
  if ($null -eq $approved) { throw 'Join expired; run the join command again.' }
  $step = 'verifying approved bundle'
  if ($approved.state -ne 'approved' -or $approved.hub_url -cne $Hub -or $approved.bundle.url -cne "$Hub/v1/join/bundle/windows-$arch" -or $approved.bundle.sha256 -cnotmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrWhiteSpace($approved.enroll_token)) { throw 'Invalid approval response.' }
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $approved.bundle.sha256) { throw 'Agent bundle checksum does not match.' }
  $stage = Join-Path $work 'bundle'
  [void][IO.Directory]::CreateDirectory($stage)
  Expand-JoinBundle $archive $stage
  $tokenFile = Join-Path $work 'token'
  [IO.File]::WriteAllText($tokenFile, $approved.enroll_token, (New-Object Text.UTF8Encoding($false)))
  Set-JoinPrivate $tokenFile $false
  $step = 'installing agent'
  Write-JoinProgress 'Installing agent scheduled task.'
  $jobs = 'false'
  if ($JobsEnabled) { $jobs = 'true' }
  # One-time enrollment token from approval, never an operator token or argv secret.
  # Suppress downstream output; errors can contain credential-bearing objects.
  & (Join-Path $stage 'install-agent-windows.ps1') --hub $Hub --token-file $tokenFile --jobs-enabled $jobs *> $null
  if (-not $?) { throw 'Agent installer failed.' }
  Write-JoinProgress "Joined. jobs_enabled=$jobs. Progress: $Hub/readiness"
} catch {
  # Never serialize exceptions/responses: they may contain device/enrollment secrets.
  $message = "Windows join failed during $step."
  if ($step -eq 'preflight') { $message += ' Run as Administrator with a public HTTPS Hub and writable local log path.' }
  [Console]::Error.WriteLine($message)
  if ($work) { Add-Content -LiteralPath $LogFile -Value $message -ErrorAction SilentlyContinue }
  throw $message
} finally {
  $headers = $null; $started = $null; $approved = $null; $pollBody = $null; $response = $null
  if ($work -and (Test-Path -LiteralPath $work)) {
    # Best-effort overwrite and deletion; private ACLs protect files on all paths.
    $secretPath = Join-Path $work 'token'
    if (Test-Path -LiteralPath $secretPath) {
      try {
        $secretLength = [int](Get-Item -LiteralPath $secretPath).Length
        [IO.File]::WriteAllBytes($secretPath, (New-Object byte[] $secretLength))
      } catch { }
    }
    Remove-Item -LiteralPath $work -Recurse -Force
  }
}

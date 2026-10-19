# Parse without executing platform/install actions, then exercise the real safe
# extractor, redactor and child-process logging. Runs on any host with pwsh.
param([string]$Fixtures)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'join.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'join.ps1 has PowerShell parse errors.' }
$null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\install-agent-windows.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Windows installer has PowerShell parse errors.' }
foreach ($name in @('Read-JoinBlock', 'Expand-JoinBundle', 'Protect-JoinInstallerOutput', 'Invoke-JoinInstaller')) {
  $function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $true)
  Invoke-Expression $function.Extent.Text
}
foreach ($mode in @('valid', 'traversal', 'backslash', 'absolute', 'symlink', 'hardlink', 'duplicate', 'missing', 'truncated')) {
  $destination = Join-Path $Fixtures $mode
  [void][IO.Directory]::CreateDirectory($destination)
  $rejected = $false
  try { Expand-JoinBundle (Join-Path $Fixtures "$mode.tar.gz") $destination } catch { $rejected = $true }
  if ($mode -eq 'valid') {
    if ($rejected -or -not (Test-Path -LiteralPath (Join-Path $destination 'clawctl-agent.exe'))) { throw 'Valid bundle did not extract.' }
  } elseif (-not $rejected) { throw "Unsafe archive accepted: $mode" }
}

# Exercise the real redactor with bare literals, regex metacharacters, quoted
# JSON/assignments, mixed case, multiple credentials and useful error context.
$secrets = @('enroll.+[fixture]$value', 'device.*(fixture)^value')
$cases = @(
  'unable to switch the encoding (1,40)',
  "bare $($secrets[0]) and $($secrets[1])",
  'Authorization: Bearer fixture-bearer',
  'BEARER=fixture-bearer-equals',
  'token=fixture-token secret=fixture-secret',
  'enroll_token = "fixture quoted token"; device_secret=''fixture quoted secret''',
  '{"enroll_token":"fixture-json-token","device_secret":"fixture-json-secret"}',
  'access-token=fixture-access-token; client_secret: fixture-client-secret',
  'TOKEN=fixture-upper-token, SECRET=fixture-upper-secret',
  'token="" secret='''''
)
foreach ($text in $cases) {
  $redacted = Protect-JoinInstallerOutput $text $secrets
  foreach ($secret in $secrets) {
    if ($redacted.Contains($secret)) { throw 'Literal credential leaked by redactor.' }
  }
  if ($redacted -match 'fixture') { throw 'Pattern credential leaked by redactor.' }
}
if ((Protect-JoinInstallerOutput $cases[0] @('', $null)) -ne $cases[0]) { throw 'Redactor removed useful diagnostic text.' }

# Invoke the real child-process capture with direct Console stdout/stderr, as
# used by Fail in the installer. Neither stream may escape to the console.
$Installer = Join-Path $Fixtures 'fixture installer.ps1'
@'
if ($args.Count -ne 6 -or $args[0] -ne '--hub' -or $args[1] -ne 'https://hub.example.com' -or $args[2] -ne '--token-file' -or $args[4] -ne '--jobs-enabled' -or $args[5] -ne 'false') { exit 91 }
if ($args[3] -notmatch 'token file$') { exit 92 }
[Console]::WriteLine('stdout encoding diagnostic; bare enroll.+[fixture]$value')
[Console]::Error.WriteLine('stderr unable to switch the encoding; bare device.*(fixture)^value')
Write-Output 'token=fixture-token secret="fixture quoted secret" Authorization: Bearer fixture-bearer'
for ($i = 1; $i -le 15; $i++) { Write-Output "installer diagnostic $i" }
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'fail-installer')) { exit 23 }
'@ | Set-Content -LiteralPath $Installer
foreach ($fail in @($false, $true)) {
  if ($fail) { [IO.File]::WriteAllText((Join-Path $Fixtures 'fail-installer'), '') }
  $LogFile = Join-Path $Fixtures "installer-$fail.log"
  $failed = $false
  $console = @()
  try {
    $console = @(Invoke-JoinInstaller $Installer 'https://hub.example.com' (Join-Path $Fixtures 'token file') 'false' $secrets *>&1)
  } catch {
    $failed = $true
    if ($_.Exception.Message -ne 'Agent installer failed. See the join log for redacted diagnostics.') { throw 'Unexpected installer failure.' }
  }
  if ($failed -ne $fail) { throw "Installer exit status was not preserved: expected failure=$fail, got failure=$failed." }
  if ($console.Count -ne 0) { throw 'Installer output escaped to console.' }
  $log = Get-Content -LiteralPath $LogFile -Raw
  if ($log -match 'fixture|enroll\.\+|device\.\*') { throw 'Credential leaked to installer log.' }
  if ($log -notmatch 'stdout encoding diagnostic' -or $log -notmatch 'stderr unable to switch the encoding') { throw 'Installer output was lost.' }
  if ($log -notmatch '\[REDACTED\]') { throw 'Installer credentials were not redacted.' }
  if ($fail) {
    $tail = ($log -split 'Last redacted output lines:', 2)[1]
    if ($tail -notmatch 'installer diagnostic 15' -or $tail -match 'installer diagnostic 5\r?\n') { throw 'Installer failure tail was not bounded.' }
  } elseif ($log -match 'Agent installer failed') { throw 'Successful installer reported failure.' }
}
Write-Output 'Windows bootstrap: PowerShell parsing, safe extraction, redaction and installer diagnostics passed.'

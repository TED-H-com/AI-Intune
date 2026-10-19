# Parse without executing platform/install actions, then exercise the real safe
# extractor on benign and malicious archives. Runs on any host with pwsh.
param([string]$Fixtures)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'join.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'join.ps1 has PowerShell parse errors.' }
$null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\install-agent-windows.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Windows installer has PowerShell parse errors.' }
foreach ($name in @('Read-JoinBlock', 'Expand-JoinBundle')) {
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
Write-Output 'Windows bootstrap: PowerShell parsing and safe extraction passed.'

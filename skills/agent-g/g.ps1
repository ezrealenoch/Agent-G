# g.ps1 - PowerShell wrapper for Agent-G's provisioned Ghidra HTTP server.
#
# Reads URL + bearer token from .\ghidra_session.json (written by
# provision_ghidra.py in the same directory) and forwards the rest of the
# args as authenticated GET parameters.
#
# Usage:
#   .\g.ps1 plugin-version
#   .\g.ps1 imports offset=0 limit=50
#   .\g.ps1 strings filter=http limit=200
#   .\g.ps1 decompile_function address=0x180001000

param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Endpoint,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Params
)

$ErrorActionPreference = "Stop"

# Find the session file: env var -> CWD -> script dir
$sessFile = $env:AGENT_G_SESSION_FILE
if (-not $sessFile) {
    $cwdSess = Join-Path (Get-Location) "ghidra_session.json"
    if (Test-Path $cwdSess) {
        $sessFile = $cwdSess
    } else {
        $sessFile = Join-Path $PSScriptRoot "ghidra_session.json"
    }
}

if (-not (Test-Path $sessFile)) {
    Write-Error @"
ghidra_session.json not found at $sessFile

The provisioner is not running, or you ran g.ps1 from the wrong directory.
Start a Ghidra instance first:

    python (Join-Path `$PSScriptRoot 'provision_ghidra.py') 'C:\path\to\binary'

Wait for ghidra_session.json to appear, then re-run g.ps1.
"@
    exit 2
}

$session = Get-Content $sessFile -Raw | ConvertFrom-Json
$url = $session.base_url
$tok = $session.auth_token

if (-not $Endpoint -or $Endpoint -eq "--help" -or $Endpoint -eq "-h") {
    Write-Host @"
Usage: g.ps1 <endpoint> [k=v ...]

Common endpoints:
  plugin-version
  imports                     [offset=N] [limit=N]
  exports                     [offset=N] [limit=N]
  segments
  strings                     [offset=N] [limit=N] [filter=substr]
  list_functions              [offset=N] [limit=N]
  searchFunctions             query=<name> [offset=N] [limit=N]
  decompile_function          address=0x...
  disassemble_function        address=0x...
  xrefs_to / xrefs_from       address=0x... [offset=N] [limit=N]
  function_xrefs              name=<name> [offset=N] [limit=N]
  get_function_by_address     address=0x...
  read_bytes                  address=0x... length=N [format=hex|ascii|raw]

Session: $sessFile
URL    : $url
"@
    exit 0
}

$qs = ""
foreach ($kv in $Params) {
    if ($qs) { $qs = "$qs&$kv" } else { $qs = $kv }
}

$target = if ($qs) { "$url/$Endpoint`?$qs" } else { "$url/$Endpoint" }

try {
    $resp = Invoke-WebRequest -Uri $target `
                              -Headers @{ Authorization = "Bearer $tok" } `
                              -TimeoutSec 120 `
                              -UseBasicParsing
    Write-Output $resp.Content
} catch {
    Write-Error "Request failed: $_"
    exit 1
}

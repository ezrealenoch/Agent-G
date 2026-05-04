# Install Agent-G + Claude Code skill on this machine.
#   - pip install -e . (so the `agent-g` CLI is on PATH)
#   - link skills\agent-g\ into %USERPROFILE%\.claude\skills\agent-g\
#   - set AGENT_G_HOME for the skill's helper scripts
$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillSrc = Join-Path $RepoDir "skills\agent-g"
$SkillsDir = Join-Path $env:USERPROFILE ".claude\skills"
$SkillDst = Join-Path $SkillsDir "agent-g"

Write-Host "[agent-g] installing CLI (force-reinstall to refresh stale copies)..."
python -m pip install --force-reinstall --no-deps -e $RepoDir
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Write-Host "[agent-g] linking skill into $SkillDst"
New-Item -ItemType Directory -Force -Path $SkillsDir | Out-Null
if (Test-Path $SkillDst) {
    Write-Host "[agent-g] $SkillDst already exists - removing it"
    Remove-Item -Recurse -Force $SkillDst
}

$linked = $false
try {
    New-Item -ItemType SymbolicLink -Path $SkillDst -Target $SkillSrc -ErrorAction Stop | Out-Null
    Write-Host "[agent-g] linked"
    $linked = $true
} catch {
    Write-Host "[agent-g] symlink failed (need Developer Mode or admin) - copying instead"
    Copy-Item -Recurse $SkillSrc $SkillDst
}

# Persist AGENT_G_HOME at user scope so the helper scripts can find the repo
$existing = [Environment]::GetEnvironmentVariable("AGENT_G_HOME", "User")
if ($existing -ne $RepoDir) {
    [Environment]::SetEnvironmentVariable("AGENT_G_HOME", $RepoDir, "User")
    $env:AGENT_G_HOME = $RepoDir
    Write-Host "[agent-g] set AGENT_G_HOME=$RepoDir (user scope)"
} else {
    Write-Host "[agent-g] AGENT_G_HOME already set"
}

Write-Host "[agent-g] verifying CLI..."
$v = & agent-g --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[agent-g] OK: $v"
} else {
    Write-Host "[agent-g] WARNING: 'agent-g' is not on PATH. Make sure your pip Scripts dir is in PATH."
}

Write-Host ""
Write-Host "[agent-g] Done. Restart Claude Code and the 'agent-g' skill will be available."
Write-Host "[agent-g] Try: claude  ->  'investigate C:\path\to\some\binary'"
Write-Host "[agent-g] Or for the internal-LLM CLI mode: agent-g doctor; agent-g analyze C:\path\to\binary"

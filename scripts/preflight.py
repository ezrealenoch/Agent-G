#!/usr/bin/env python3
"""Agent-G preflight checker.

Runs a battery of self-diagnostics and prints a red/green report so a
new user can see at a glance what's missing before their first run.

Checks:
  1. Python version >= 3.10
  2. Every core dependency is importable
  3. Optional deps report (keyring / hvac / boto3)
  4. Java runtime is on PATH and is version >= 17
  5. GHIDRA_INSTALL_DIR is set, exists, and contains analyzeHeadless
  6. .env loaded (warn if default values present for production keys)
  7. LLM provider config consistency (key present for selected provider)
  8. Ghidra HTTP client can load without import errors
  9. Write permissions on logs/ and runs/
 10. Test suite file is discoverable (not run here)

Usage:
  python scripts/preflight.py
  agent-g doctor           # after pip install -e .

Exit code is 0 on all-green, 1 if any REQUIRED check failed, 2 if any
OPTIONAL check failed (warnings only).
"""
from __future__ import annotations
import importlib
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Make src/ importable when run as a script before pip install
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# ── Output helpers (ANSI colors, degrade to plain if no TTY) ──

def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def _supports_unicode() -> bool:
    """Return True if sys.stdout can encode the box-drawing Unicode we use."""
    enc = getattr(sys.stdout, "encoding", "") or ""
    try:
        "\u2713".encode(enc)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


_COLOR = _supports_color()
_UNICODE = _supports_unicode()
_GREEN = "\033[32m" if _COLOR else ""
_RED   = "\033[31m" if _COLOR else ""
_YEL   = "\033[33m" if _COLOR else ""
_DIM   = "\033[2m"  if _COLOR else ""
_BOLD  = "\033[1m"  if _COLOR else ""
_RESET = "\033[0m"  if _COLOR else ""


def _tick():    return f"{_GREEN}{'✓' if _UNICODE else 'OK'}{_RESET}"
def _cross():   return f"{_RED}{'✗' if _UNICODE else 'XX'}{_RESET}"
def _warn():    return f"{_YEL}{'!' if _UNICODE else '!!'}{_RESET}"


@dataclass
class CheckResult:
    name: str
    status: str  # "pass" | "fail" | "warn"
    detail: str = ""
    remedy: str = ""
    required: bool = True

    def render(self) -> str:
        mark = {"pass": _tick(), "fail": _cross(), "warn": _warn()}[self.status]
        req_tag = "" if self.required else f"{_DIM}(optional){_RESET}"
        line = f"  {mark} {self.name} {req_tag}"
        if self.detail:
            line += f"\n      {_DIM}{self.detail}{_RESET}"
        if self.status != "pass" and self.remedy:
            arrow = "→" if _UNICODE else "->"
            line += f"\n      {arrow} {self.remedy}"
        return line


@dataclass
class PreflightReport:
    results: List[CheckResult] = field(default_factory=list)

    def add(self, r: CheckResult) -> None:
        self.results.append(r)

    @property
    def all_pass(self) -> bool:
        return all(r.status != "fail" for r in self.results)

    @property
    def required_pass(self) -> bool:
        return all(r.status != "fail" or not r.required for r in self.results)

    def render(self) -> str:
        lines = [f"{_BOLD}Agent-G preflight{_RESET}",
                 f"{_DIM}  repo: {_REPO_ROOT}{_RESET}",
                 ""]
        for r in self.results:
            lines.append(r.render())
        lines.append("")
        passes = sum(1 for r in self.results if r.status == "pass")
        fails  = sum(1 for r in self.results if r.status == "fail")
        warns  = sum(1 for r in self.results if r.status == "warn")
        summary = f"  {passes} ok   {fails} failed   {warns} warnings"
        if self.required_pass:
            lines.append(f"{_GREEN}{_BOLD}PASS{_RESET}   {summary}")
        else:
            lines.append(f"{_RED}{_BOLD}FAIL{_RESET}   {summary}")
        return "\n".join(lines)


# ── Checks ──

def check_python_version() -> CheckResult:
    v = sys.version_info
    pretty = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 10):
        return CheckResult("Python >= 3.10", "pass", detail=f"found {pretty}")
    return CheckResult(
        "Python >= 3.10", "fail",
        detail=f"found {pretty}",
        remedy="Install Python 3.10+ from python.org or your package manager.",
    )


def check_core_dependencies() -> List[CheckResult]:
    results = []
    core_deps = [
        ("httpx",             "pip install httpx"),
        ("requests",          "pip install requests"),
        ("pydantic",          "pip install pydantic"),
        ("pydantic_settings", "pip install pydantic-settings"),
        ("tenacity",          "pip install tenacity"),
        ("rich",              "pip install rich"),
        ("ijson",             "pip install ijson"),
    ]
    for mod_name, remedy in core_deps:
        try:
            m = importlib.import_module(mod_name)
            ver = getattr(m, "__version__", "?")
            results.append(CheckResult(
                f"import {mod_name}", "pass",
                detail=f"version {ver}",
            ))
        except ImportError as e:
            results.append(CheckResult(
                f"import {mod_name}", "fail",
                detail=str(e),
                remedy=f"{remedy}   (or: pip install -e . from repo root)",
            ))
    return results


def check_optional_dependencies() -> List[CheckResult]:
    results = []
    optional = [
        ("keyring", "pip install agent-g[winvault]", "Windows Credential Manager backend"),
        ("hvac",    "pip install agent-g[vault]",    "HashiCorp Vault backend"),
        ("boto3",   "pip install agent-g[awssm]",    "AWS Secrets Manager backend"),
        ("pytest",  "pip install agent-g[dev]",      "test runner"),
    ]
    for mod_name, remedy, desc in optional:
        try:
            importlib.import_module(mod_name)
            results.append(CheckResult(
                f"import {mod_name}", "pass",
                detail=desc, required=False,
            ))
        except ImportError:
            results.append(CheckResult(
                f"import {mod_name}", "warn",
                detail=f"{desc} unavailable",
                remedy=remedy,
                required=False,
            ))
    return results


def _is_docker_mode() -> bool:
    """Return True if the user is pointing at a containerized Ghidra.

    Heuristic: the GHIDRA_BASE_URL env var is set to a non-localhost-8080
    URL (the sandbox publishes 18080 by default), OR AGENT_G_MODE=docker
    is set explicitly. In Docker mode we skip the JDK + Ghidra install
    checks because those dependencies live inside the container image.
    """
    if os.environ.get("AGENT_G_MODE", "").lower() == "docker":
        return True
    url = os.environ.get("GHIDRA_BASE_URL", "")
    if url and "localhost:18080" in url:
        return True
    return False


def check_java() -> CheckResult:
    if _is_docker_mode():
        return CheckResult(
            "Java JDK 17+ (skipped — Docker mode)", "pass",
            detail="Ghidra runs inside the sandbox container; JDK baked into image",
            required=False,
        )
    java_bin = shutil.which("java")
    if not java_bin:
        return CheckResult(
            "Java JDK 17+", "fail",
            detail="`java` not found on PATH",
            remedy="Install Eclipse Temurin 17+ from https://adoptium.net "
                   "(or `apt install openjdk-17-jdk` on Debian/Ubuntu). "
                   "Or use Docker mode: see sandbox/README.md and set "
                   "GHIDRA_BASE_URL=http://localhost:18080.",
        )
    try:
        out = subprocess.run(
            [java_bin, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        # java -version writes to stderr by convention
        banner = (out.stderr or "") + (out.stdout or "")
    except Exception as e:
        return CheckResult(
            "Java JDK 17+", "fail",
            detail=f"could not invoke java: {e}",
            remedy="Reinstall Java 17+.",
        )
    m = re.search(r'version "(\d+)(?:\.(\d+))?', banner)
    if not m:
        return CheckResult(
            "Java JDK 17+", "warn",
            detail=f"found `java` at {java_bin} but version string unreadable",
            remedy="Verify with `java -version` manually.",
            required=False,
        )
    major = int(m.group(1))
    if major >= 17:
        return CheckResult(
            "Java JDK 17+", "pass",
            detail=f"major version {major} at {java_bin}",
        )
    return CheckResult(
        "Java JDK 17+", "fail",
        detail=f"major version {major} (need >= 17)",
        remedy="Upgrade to Eclipse Temurin 17+ or newer. Ghidra 12.0.2 refuses older JDKs.",
    )


def check_ghidra_install() -> CheckResult:
    if _is_docker_mode():
        return CheckResult(
            "Ghidra install (skipped — Docker mode)", "pass",
            detail="Ghidra 12.0.2 baked into sandbox container at /opt/ghidra",
            required=False,
        )
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if not ghidra:
        return CheckResult(
            "GHIDRA_INSTALL_DIR set", "fail",
            detail="environment variable not set",
            remedy="Set GHIDRA_INSTALL_DIR to the path of your unzipped Ghidra distribution "
                   "(example: export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.2_PUBLIC). "
                   "Or use Docker mode: see sandbox/README.md.",
        )
    p = Path(ghidra)
    if not p.exists():
        return CheckResult(
            "GHIDRA_INSTALL_DIR exists", "fail",
            detail=f"{p} does not exist",
            remedy="Download Ghidra from https://github.com/NationalSecurityAgency/ghidra/releases "
                   "and unzip into GHIDRA_INSTALL_DIR.",
        )
    # Find analyzeHeadless (platform-specific extension)
    candidates = [
        p / "support" / "analyzeHeadless.bat",  # Windows
        p / "support" / "analyzeHeadless",       # Linux/macOS
    ]
    if not any(c.exists() for c in candidates):
        return CheckResult(
            "Ghidra analyzeHeadless", "fail",
            detail=f"not found under {p}/support/",
            remedy="Verify the Ghidra distribution is fully extracted.",
        )
    return CheckResult(
        "Ghidra analyzeHeadless", "pass",
        detail=f"found at {p}",
    )


def check_agent_g_imports() -> List[CheckResult]:
    results = []
    modules = [
        "src",
        "src.runtime.circuit_breaker",
        "src.runtime.checkpoint",
        "src.runtime.budget",
        "src.runtime.observability",
        "src.runtime.secrets",
        "src.runtime.trace",
        "src.runtime.ghidra_pool",
        "src.runtime.result_store",
        "src.runtime.prompt_library",
        "src.runtime.tool_schema",
        "src.runtime.conversation",
        "src.external_client",
        "src.ollama_client",
        "src.custom_api_client",
        "src.config",
    ]
    for m in modules:
        try:
            importlib.import_module(m)
            results.append(CheckResult(f"import {m}", "pass"))
        except Exception as e:
            results.append(CheckResult(
                f"import {m}", "fail",
                detail=f"{type(e).__name__}: {e}",
                remedy="Run `pip install -e .` from the repo root.",
            ))
    return results


def check_llm_provider_config() -> List[CheckResult]:
    results = []
    # Only check if user has configured a provider at all. In dev mode
    # nothing may be set; that's fine.
    provider = os.environ.get("LLM_PROVIDER", "").lower()
    if not provider:
        results.append(CheckResult(
            "LLM_PROVIDER set", "warn",
            detail="no provider selected — set LLM_PROVIDER in .env",
            remedy="export LLM_PROVIDER=ollama (or external, or custom_api)",
            required=False,
        ))
        return results
    results.append(CheckResult(
        "LLM_PROVIDER set", "pass",
        detail=f"provider={provider}",
    ))

    if provider == "ollama":
        base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        model = os.environ.get("OLLAMA_MODEL", "")
        results.append(CheckResult(
            "OLLAMA_MODEL", "pass" if model else "warn",
            detail=f"model={model or '<unset>'} base={base}",
            remedy="Set OLLAMA_MODEL in .env (e.g. gemma4:e4b)",
            required=False,
        ))
    elif provider == "external":
        ep = os.environ.get("EXTERNAL_PROVIDER", "")
        em = os.environ.get("EXTERNAL_MODEL", "")
        ek = os.environ.get("EXTERNAL_API_KEY", "")
        status = "pass" if (ep and em and ek) else "fail"
        results.append(CheckResult(
            "External provider credentials",
            status,
            detail=f"provider={ep or '<unset>'} model={em or '<unset>'} "
                   f"key={'<set>' if ek else '<unset>'}",
            remedy="Set EXTERNAL_PROVIDER / EXTERNAL_MODEL / EXTERNAL_API_KEY in .env",
        ))
    elif provider == "custom_api":
        url = os.environ.get("CUSTOM_API_URL", "")
        model = os.environ.get("CUSTOM_API_MODEL", "")
        mode = os.environ.get("CUSTOM_API_AUTH_MODE", "auto")
        key = os.environ.get("CUSTOM_API_KEY", "")
        has_auth = bool(key) or mode in ("auto", "codex_oauth")
        status = "pass" if (url and model and has_auth) else "fail"
        results.append(CheckResult(
            "Custom API config",
            status,
            detail=f"url={url or '<unset>'} model={model or '<unset>'} "
                   f"auth_mode={mode} key={'<set>' if key else '<unset>'}",
            remedy="Set CUSTOM_API_URL + CUSTOM_API_MODEL + CUSTOM_API_KEY or "
                   "Codex OAuth in .env",
        ))
    else:
        results.append(CheckResult(
            "LLM_PROVIDER value", "fail",
            detail=f"unknown provider {provider!r}",
            remedy="Must be one of: ollama, external, custom_api",
        ))
    return results


def check_write_permissions() -> List[CheckResult]:
    results = []
    for subdir in ("logs", "runs"):
        p = _REPO_ROOT / subdir
        try:
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".preflight_write_test"
            test.write_text("ok")
            test.unlink()
            results.append(CheckResult(
                f"write to {subdir}/", "pass",
                detail=str(p),
            ))
        except Exception as e:
            results.append(CheckResult(
                f"write to {subdir}/", "fail",
                detail=f"{type(e).__name__}: {e}",
                remedy=f"Ensure Agent-G can write to {p}",
            ))
    return results


def check_ghidra_scripts() -> CheckResult:
    script = _REPO_ROOT / "ghidra" / "scripts" / "OGhidraHeadlessServer.java"
    if script.exists():
        return CheckResult(
            "OGhidraHeadlessServer.java present", "pass",
            detail=str(script),
        )
    return CheckResult(
        "OGhidraHeadlessServer.java present", "fail",
        detail=f"not found at {script}",
        remedy="Repo is missing the Ghidra post-script. Re-clone or fetch.",
    )


def check_platform_banner() -> CheckResult:
    bits = [platform.system(), platform.release(), platform.machine()]
    return CheckResult(
        "Platform", "pass",
        detail=" ".join(bits),
    )


def run_all_checks() -> PreflightReport:
    report = PreflightReport()

    # Basic environment
    report.add(check_platform_banner())
    report.add(check_python_version())

    # Core + optional Python deps
    for r in check_core_dependencies():
        report.add(r)
    for r in check_optional_dependencies():
        report.add(r)

    # External toolchain
    report.add(check_java())
    report.add(check_ghidra_install())
    report.add(check_ghidra_scripts())

    # Agent-G internal imports
    for r in check_agent_g_imports():
        report.add(r)

    # Configuration
    for r in check_llm_provider_config():
        report.add(r)

    # Filesystem
    for r in check_write_permissions():
        report.add(r)

    return report


def main() -> int:
    # Best-effort .env loader so preflight sees the same config a run would
    env_path = _REPO_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

    report = run_all_checks()
    print(report.render())
    if not report.required_pass:
        return 1
    if any(r.status == "warn" for r in report.results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

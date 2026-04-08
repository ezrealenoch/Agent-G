"""Secrets manager abstraction.

Single ``get_secret(name)`` function that resolves a credential from a
configurable backend, never from disk-state Agent-G writes itself. Backends
chain in priority order so a deployment can fall through to env vars if its
preferred backend (Vault, Windows Credential Manager, AWS Secrets Manager,
1Password CLI, etc.) is unavailable.

Backend selection is via the ``AGENT_G_SECRETS_BACKEND`` env var:

  - ``env``      → environment variables only (default, dev mode)
  - ``winvault`` → Windows Credential Manager (cred vault) via the
                   ``keyring`` module if installed
  - ``vault``    → HashiCorp Vault via VAULT_ADDR + VAULT_TOKEN env
  - ``awssm``    → AWS Secrets Manager via boto3 if installed
  - ``file``     → JSON file at $AGENT_G_SECRETS_FILE (dev only, NOT prod)

Multiple backends can be chained via a colon-separated list:
``AGENT_G_SECRETS_BACKEND=winvault:env``

API keys are looked up by canonical name (``ANTHROPIC_API_KEY``,
``OPENAI_API_KEY``, ``GOOGLE_API_KEY``, etc.). The lookup is
case-insensitive but is normalized to upper-case for backend dispatch.
"""
from __future__ import annotations
import json
import logging
import os
import sys
from pathlib import Path
from typing import Callable, List, Optional

logger = logging.getLogger("agent-g.secrets")


# ── Backend implementations ──────────────────────────────────────────

def _backend_env(name: str) -> Optional[str]:
    """Read from environment variables. Always available, always last resort."""
    val = os.environ.get(name)
    if val:
        return val
    # Also try lower-case (some legacy tooling sets lowercase env vars)
    return os.environ.get(name.lower())


def _backend_file(name: str) -> Optional[str]:
    """Read from a JSON file at $AGENT_G_SECRETS_FILE.

    File format::

        {
          "ANTHROPIC_API_KEY": "sk-ant-...",
          "OPENAI_API_KEY": "sk-..."
        }

    Marked dev-only because keys live in a file the OS can't enforce
    rotation/audit on. Always wrap with appropriate filesystem ACLs and
    NEVER commit to git. Suitable for laptop dev only.
    """
    path = os.environ.get("AGENT_G_SECRETS_FILE")
    if not path or not Path(path).exists():
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get(name) or data.get(name.lower())
    except Exception as e:
        logger.warning("file backend read failed: %s", e)
        return None


def _backend_winvault(name: str) -> Optional[str]:
    """Windows Credential Manager via the ``keyring`` module.

    Stores credentials under service ``agent-g`` with the secret name as
    the username. Use the OS-level ``cmdkey`` or ``Credential Manager`` GUI
    to provision values, or call ``set_secret(name, value)`` from a
    one-time setup script.
    """
    try:
        import keyring  # type: ignore
    except ImportError:
        return None
    try:
        return keyring.get_password("agent-g", name)
    except Exception as e:
        logger.debug("winvault backend miss for %s: %s", name, e)
        return None


def _backend_vault(name: str) -> Optional[str]:
    """HashiCorp Vault via the ``hvac`` module.

    Reads from ``$VAULT_ADDR`` using ``$VAULT_TOKEN``. Default mount path
    is ``secret/data/agent-g`` (KV v2). The secret name maps to a key
    inside that single document, so a typical Vault doc looks like::

        {
          "ANTHROPIC_API_KEY": "...",
          "OPENAI_API_KEY": "..."
        }
    """
    try:
        import hvac  # type: ignore
    except ImportError:
        return None
    addr = os.environ.get("VAULT_ADDR")
    tok = os.environ.get("VAULT_TOKEN")
    if not addr or not tok:
        return None
    try:
        c = hvac.Client(url=addr, token=tok)
        if not c.is_authenticated():
            logger.warning("vault: token rejected")
            return None
        path = os.environ.get("AGENT_G_VAULT_PATH", "secret/data/agent-g")
        # KV v2 nests the actual data under ``data.data``
        resp = c.read(path)
        if not resp:
            return None
        data = resp.get("data", {}).get("data", {})
        return data.get(name) or data.get(name.lower())
    except Exception as e:
        logger.warning("vault backend error: %s", e)
        return None


def _backend_awssm(name: str) -> Optional[str]:
    """AWS Secrets Manager via boto3.

    Stores all Agent-G credentials in a single secret named ``agent-g``
    (overridable via ``AGENT_G_AWS_SECRET_NAME``) whose ``SecretString``
    is a JSON document keyed by canonical name.
    """
    try:
        import boto3  # type: ignore
    except ImportError:
        return None
    try:
        sm = boto3.client("secretsmanager")
        secret_name = os.environ.get("AGENT_G_AWS_SECRET_NAME", "agent-g")
        resp = sm.get_secret_value(SecretId=secret_name)
        raw = resp.get("SecretString")
        if not raw:
            return None
        data = json.loads(raw)
        return data.get(name) or data.get(name.lower())
    except Exception as e:
        logger.warning("awssm backend error: %s", e)
        return None


# Registry of backend lookup callables
_BACKEND_REGISTRY: dict = {
    "env":      _backend_env,
    "file":     _backend_file,
    "winvault": _backend_winvault,
    "vault":    _backend_vault,
    "awssm":    _backend_awssm,
}


# ── Public API ──────────────────────────────────────────────────────

def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    """Resolve a secret by canonical name through the configured backends.

    The name is matched case-insensitively but normalized to UPPER_CASE
    before dispatch. Backends are tried in the order specified by
    ``AGENT_G_SECRETS_BACKEND`` (default: env). Returns ``default`` if
    no backend has the value.

    Example::

        from src.runtime.secrets import get_secret
        key = get_secret("ANTHROPIC_API_KEY")
    """
    canon = name.strip().upper()
    chain = os.environ.get("AGENT_G_SECRETS_BACKEND", "env").split(":")
    for backend_name in chain:
        backend_name = backend_name.strip().lower()
        fn = _BACKEND_REGISTRY.get(backend_name)
        if fn is None:
            logger.debug("unknown secrets backend: %s", backend_name)
            continue
        try:
            v = fn(canon)
        except Exception as e:
            logger.warning("secrets backend %s raised: %s", backend_name, e)
            continue
        if v:
            logger.debug("resolved %s via %s", canon, backend_name)
            return v
    return default


def set_secret(name: str, value: str, backend: str = "winvault") -> bool:
    """Provision a secret in a specific backend (one-time setup helper).

    Only ``winvault`` is currently supported for writes — Vault and AWS
    Secrets Manager have richer write semantics that should be done via
    their dedicated CLIs (``vault kv put``, ``aws secretsmanager
    update-secret``).
    """
    canon = name.strip().upper()
    if backend == "winvault":
        try:
            import keyring  # type: ignore
        except ImportError:
            logger.error("winvault backend requires the 'keyring' package")
            return False
        try:
            keyring.set_password("agent-g", canon, value)
            return True
        except Exception as e:
            logger.error("winvault set failed: %s", e)
            return False
    logger.error("set_secret: backend '%s' is read-only here", backend)
    return False


def list_backends() -> List[str]:
    """List backends that are actually loadable in the current process."""
    available = []
    for name, fn in _BACKEND_REGISTRY.items():
        if name == "env":
            available.append(name)
            continue
        if name == "file":
            if os.environ.get("AGENT_G_SECRETS_FILE"):
                available.append(name)
            continue
        if name == "winvault":
            try:
                import keyring  # noqa: F401
                available.append(name)
            except ImportError:
                pass
            continue
        if name == "vault":
            try:
                import hvac  # noqa: F401
                if os.environ.get("VAULT_ADDR"):
                    available.append(name)
            except ImportError:
                pass
            continue
        if name == "awssm":
            try:
                import boto3  # noqa: F401
                available.append(name)
            except ImportError:
                pass
            continue
    return available

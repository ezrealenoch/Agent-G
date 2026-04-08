#!/usr/bin/env python3
"""Agent-G: Standalone headless binary analysis agent.

Usage:
    python main.py <binary_path> [options]

Examples:
    python main.py C:\\samples\\malware.exe
    python main.py C:\\samples\\binary.exe --ghidra-install C:\\ghidra_12.0.2_PUBLIC
    python main.py C:\\samples\\binary.exe --port 9090 --model gemma4:e4b
"""

import argparse
import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO"):
    """Configure logging for terminal output."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(
        description="Agent-G: Headless binary analysis agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "binary", type=str,
        help="Path to the binary file to analyze",
    )
    parser.add_argument(
        "--ghidra-install", type=str, default=None,
        help="Path to Ghidra installation (auto-detected if not set)",
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Starting port for headless Ghidra HTTP server (default: 8080)",
    )
    parser.add_argument(
        "--log-level", type=str, default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    # Validate binary exists
    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        print(f"Error: Binary not found: {binary_path}")
        return 1

    # Import here to defer heavy module loading
    from src.headless_launcher import HeadlessGhidraLauncher
    from src.headless_repl import HeadlessREPL
    from src.config import get_config
    from src.bridge_lite import BridgeLite

    config = get_config()

    try:
        with HeadlessGhidraLauncher(
            str(binary_path),
            ghidra_install=args.ghidra_install,
            port=args.port,
        ) as launcher:
            # Override Ghidra URL to point to headless server
            config.ghidra.base_url = f"http://localhost:{launcher.port}"

            # Create lightweight bridge (no tkinter, no UI)
            bridge = BridgeLite(config=config, binary_name=binary_path.name)

            # Launch interactive REPL
            repl = HeadlessREPL(
                bridge, config,
                binary_name=binary_path.name,
            )
            repl.run()

    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nFatal error: {e}")
        logging.getLogger("agent-g").exception("Fatal error")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

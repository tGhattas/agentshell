"""CLI entry point for AgentShell."""

import argparse
import asyncio
import getpass
import logging
import sys
from pathlib import Path

from agentshell import __version__
from agentshell.config import Config


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="agentshell",
        description="Secure remote control server for CLI AI agents",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Override configuration directory",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── init ──────────────────────────────────────────────────────────
    init_p = sub.add_parser("init", help="Initialize server configuration")
    init_p.add_argument(
        "--hostname",
        default="localhost",
        help="Hostname for TLS certificate (default: localhost)",
    )
    init_p.add_argument(
        "--shell-command",
        default="claude",
        help="Shell command to run for agent sessions (default: claude)",
    )
    init_p.add_argument(
        "--port",
        type=int,
        default=7920,
        help="Server port (default: 7920)",
    )
    init_p.add_argument(
        "--enable-totp",
        action="store_true",
        help="Enable TOTP two-factor authentication",
    )

    # ── server ────────────────────────────────────────────────────────
    server_p = sub.add_parser("server", help="Start the AgentShell server")
    server_p.add_argument(
        "--host", default=None, help="Override bind address"
    )
    server_p.add_argument(
        "--port", type=int, default=None, help="Override port"
    )

    # ── connect ───────────────────────────────────────────────────────
    conn_p = sub.add_parser("connect", help="Connect to a remote AgentShell")
    conn_p.add_argument("host", help="Server hostname or IP")
    conn_p.add_argument(
        "--port", type=int, default=7920, help="Server port (default: 7920)"
    )
    conn_p.add_argument(
        "--fingerprint",
        default=None,
        help="Expected TLS certificate fingerprint for pinning",
    )
    conn_p.add_argument(
        "--ca-cert",
        type=Path,
        default=None,
        help="Path to CA certificate for verification",
    )
    conn_p.add_argument(
        "--totp",
        default=None,
        help="TOTP code (prompted interactively if omitted and server requires it)",
    )

    # ── totp-setup ────────────────────────────────────────────────────
    totp_p = sub.add_parser(
        "totp-setup", help="Enable or reset TOTP two-factor authentication"
    )

    # ── change-password ───────────────────────────────────────────────
    chpw_p = sub.add_parser("change-password", help="Change the server password")

    # ── show-fingerprint ──────────────────────────────────────────────
    fp_p = sub.add_parser(
        "show-fingerprint",
        help="Show the TLS certificate fingerprint (for client pinning)",
    )

    args = parser.parse_args(argv)
    config_dir = Config.config_dir(args.config_dir)

    if args.command == "init":
        _cmd_init(args, config_dir)
    elif args.command == "server":
        _cmd_server(args, config_dir)
    elif args.command == "connect":
        _cmd_connect(args, config_dir)
    elif args.command == "totp-setup":
        _cmd_totp_setup(config_dir)
    elif args.command == "change-password":
        _cmd_change_password(config_dir)
    elif args.command == "show-fingerprint":
        _cmd_show_fingerprint(config_dir)


# ── Command implementations ──────────────────────────────────────────────


def _cmd_init(args: argparse.Namespace, config_dir: Path) -> None:
    from agentshell.auth import hash_password, generate_totp_secret, get_totp_provisioning_uri
    from agentshell.tls import generate_self_signed_cert

    print("=== AgentShell Initialization ===\n")

    # Set password
    while True:
        pw = getpass.getpass("Set server password: ")
        if len(pw) < 8:
            print("Password must be at least 8 characters.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match.")
            continue
        break

    pw_hash = hash_password(pw)

    # Generate TLS certificate
    cert_path = Config.cert_path(config_dir)
    key_path = Config.key_path(config_dir)
    print(f"\nGenerating TLS certificate for '{args.hostname}'...")
    fingerprint = generate_self_signed_cert(
        cert_path, key_path, hostname=args.hostname
    )
    print(f"  Certificate: {cert_path}")
    print(f"  Private key: {key_path}")
    print(f"  Fingerprint: {fingerprint}")

    # TOTP setup
    totp_secret = ""
    totp_enabled = args.enable_totp
    if totp_enabled:
        totp_secret = generate_totp_secret()
        uri = get_totp_provisioning_uri(totp_secret)
        print(f"\n=== TOTP Two-Factor Authentication ===")
        print(f"Secret key: {totp_secret}")
        print(f"Provisioning URI: {uri}")
        try:
            import qrcode
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(uri)
            qr.make(fit=True)
            print("\nScan this QR code with your authenticator app:")
            qr.print_ascii(invert=True)
        except ImportError:
            print("(Install 'qrcode' package for QR code display)")

    # Save config
    config = Config()
    config.server.host = "0.0.0.0"
    config.server.port = args.port
    config.server.shell_command = args.shell_command
    config.server.password_hash = pw_hash
    config.server.totp_secret = totp_secret
    config.server.totp_enabled = totp_enabled
    config.server.cert_fingerprint = fingerprint
    config.client.server_port = args.port
    config.client.cert_fingerprint = fingerprint

    config_file = config.save(config_dir)
    print(f"\nConfiguration saved to: {config_file}")
    print(f"\nTo start the server:  agentshell server")
    print(f"To connect remotely:  agentshell connect <host> --fingerprint \"{fingerprint}\"")


def _cmd_server(args: argparse.Namespace, config_dir: Path) -> None:
    from agentshell.server import AgentShellServer

    config = Config.load(config_dir)

    if not config.server.password_hash:
        print("Server not initialized. Run 'agentshell init' first.", file=sys.stderr)
        sys.exit(1)

    if args.host:
        config.server.host = args.host
    if args.port:
        config.server.port = args.port

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    server = AgentShellServer(config, config_dir)

    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        print("\nServer stopped.")


def _cmd_connect(args: argparse.Namespace, config_dir: Path) -> None:
    from agentshell.client import connect

    config = Config.load(config_dir)
    fingerprint = args.fingerprint or config.client.cert_fingerprint or None
    ca_cert = args.ca_cert

    # Prompt for TOTP if not given
    totp_code = args.totp
    if totp_code is None:
        totp_input = input("TOTP code (leave empty if not enabled): ").strip()
        totp_code = totp_input if totp_input else ""

    password = getpass.getpass("Password: ")

    try:
        asyncio.run(connect(
            host=args.host,
            port=args.port,
            password=password,
            totp_code=totp_code,
            fingerprint=fingerprint,
            ca_cert=ca_cert,
        ))
    except KeyboardInterrupt:
        print("\nDisconnected.")


def _cmd_totp_setup(config_dir: Path) -> None:
    from agentshell.auth import generate_totp_secret, get_totp_provisioning_uri

    config = Config.load(config_dir)

    if not config.server.password_hash:
        print("Server not initialized. Run 'agentshell init' first.", file=sys.stderr)
        sys.exit(1)

    # Verify current password before allowing TOTP changes
    pw = getpass.getpass("Current password (to confirm identity): ")
    from agentshell.auth import verify_password
    if not verify_password(config.server.password_hash, pw):
        print("Incorrect password.", file=sys.stderr)
        sys.exit(1)

    secret = generate_totp_secret()
    uri = get_totp_provisioning_uri(secret)

    print(f"\n=== TOTP Two-Factor Authentication ===")
    print(f"Secret key: {secret}")
    print(f"Provisioning URI: {uri}")

    try:
        import qrcode
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(uri)
        qr.make(fit=True)
        print("\nScan this QR code with your authenticator app:")
        qr.print_ascii(invert=True)
    except ImportError:
        print("(Install 'qrcode' package for QR code display)")

    # Verify the user can generate a valid code
    print()
    code = input("Enter a TOTP code to verify setup: ").strip()
    from agentshell.auth import verify_totp
    if not verify_totp(secret, code):
        print("Invalid code. TOTP not enabled.", file=sys.stderr)
        sys.exit(1)

    config.server.totp_secret = secret
    config.server.totp_enabled = True
    config.save(config_dir)
    print("TOTP enabled successfully.")


def _cmd_change_password(config_dir: Path) -> None:
    from agentshell.auth import hash_password, verify_password

    config = Config.load(config_dir)

    if not config.server.password_hash:
        print("Server not initialized. Run 'agentshell init' first.", file=sys.stderr)
        sys.exit(1)

    old_pw = getpass.getpass("Current password: ")
    if not verify_password(config.server.password_hash, old_pw):
        print("Incorrect password.", file=sys.stderr)
        sys.exit(1)

    while True:
        new_pw = getpass.getpass("New password: ")
        if len(new_pw) < 8:
            print("Password must be at least 8 characters.")
            continue
        new_pw2 = getpass.getpass("Confirm new password: ")
        if new_pw != new_pw2:
            print("Passwords do not match.")
            continue
        break

    config.server.password_hash = hash_password(new_pw)
    config.save(config_dir)
    print("Password changed successfully.")


def _cmd_show_fingerprint(config_dir: Path) -> None:
    cert_path = Config.cert_path(config_dir)
    if not cert_path.exists():
        print("No certificate found. Run 'agentshell init' first.", file=sys.stderr)
        sys.exit(1)

    from agentshell.tls import get_cert_fingerprint
    fp = get_cert_fingerprint(cert_path)
    print(f"TLS Certificate Fingerprint (SHA-256):\n  {fp}")
    print(f"\nUse this with the client:  agentshell connect <host> --fingerprint \"{fp}\"")


if __name__ == "__main__":
    main()

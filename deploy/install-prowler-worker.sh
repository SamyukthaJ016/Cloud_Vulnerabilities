#!/bin/sh
set -eu

# Installs or upgrades Prowler CLI on a Debian/Ubuntu-style worker host.
# Based on Prowler's official pipx installation guidance:
# https://docs.prowler.com/getting-started/installation/prowler-cli

export PATH="$HOME/.local/bin:$PATH"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but was not found." >&2
  exit 1
fi

python3 - <<'PY'
import sys
major, minor = sys.version_info[:2]
if (major, minor) < (3, 10) or (major, minor) > (3, 12):
    raise SystemExit(
        f"Unsupported Python version {major}.{minor}. "
        "Prowler requires Python >= 3.10 and <= 3.12."
    )
print(f"Using Python {major}.{minor}")
PY

if ! command -v pipx >/dev/null 2>&1; then
  echo "Installing pipx..."
  sudo apt-get update
  sudo apt-get install -y pipx
fi

python3 -m pipx ensurepath >/dev/null 2>&1 || true
export PATH="$HOME/.local/bin:$PATH"

if pipx list 2>/dev/null | grep -q "package prowler "; then
  echo "Upgrading existing Prowler installation..."
  pipx upgrade prowler
else
  echo "Installing Prowler..."
  pipx install prowler
fi

echo "Installed Prowler version:"
prowler -v

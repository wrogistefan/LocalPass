import hashlib
import importlib.metadata

import requests  # type: ignore[import-untyped]


def sha1_prefix(password: str) -> tuple[str, str]:
    """Compute SHA-1 hash of password and return (first 5 chars, remaining 35 chars)."""
    hash_obj = hashlib.sha1(password.encode("utf-8"))
    full_hash = hash_obj.hexdigest().upper()
    return full_hash[:5], full_hash[5:]


def check_pwned_password(password: str) -> int:
    """Check if password appears in HIBP database using k-anonymity API."""
    prefix, suffix = sha1_prefix(password)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        version = importlib.metadata.version("localpass")
    except importlib.metadata.PackageNotFoundError:
        version = "unknown"

    response = requests.get(
        url,
        headers={"User-Agent": f"localpass/{version} (manual HIBP check)"},
        timeout=(2, 5),
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        parts = line.strip().split(":", 1)
        if len(parts) != 2:
            continue
        hash_suffix, count_str = parts
        if hash_suffix == suffix:
            return int(count_str)
    return 0

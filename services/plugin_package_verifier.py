# ABOUTME: Canonical digest and Ed25519 signature verification for plugin packages.
# ABOUTME: Digest spec must stay byte-identical to trakbridge-plugins-premium/tools/plugin_package_format.py.

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from services.logging_service import get_module_logger

logger = get_module_logger(__name__)

SIGNATURE_FILENAME = "signature.sig"


def canonical_package_digest(root: Path) -> bytes:
    """Compute the canonical sha256 digest of a plugin package directory.

    Spec (must match tools/plugin_package_format.py in the premium repo):
    - All regular files under root, recursively, EXCLUDING signature.sig.
    - Symlinks anywhere in the tree raise ValueError.
    - Files ordered by their POSIX relative path, sorted bytewise on UTF-8.
    - For each file, feed to sha256: len(path_utf8) as 8-byte big-endian,
      path_utf8, len(content) as 8-byte big-endian, content.
    """
    root = Path(root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                raise ValueError(f"Package contains symlink: {full}")
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel == SIGNATURE_FILENAME:
                continue
            entries.append((rel, full))

    entries.sort(key=lambda item: item[0].encode("utf-8"))

    digest = hashlib.sha256()
    for rel, full in entries:
        path_bytes = rel.encode("utf-8")
        content = full.read_bytes()
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.digest()


def verify_package_signature(
    root: Path, public_key_b64: Optional[str] = "__EMBEDDED__"
) -> str:
    """Verify a package's signature.sig against the signing public key.

    Returns "verified", "unsigned" (no signature.sig), or "invalid"
    (bad encoding, wrong key, tampered contents, or no key available).
    """
    root = Path(root)
    sig_path = root / SIGNATURE_FILENAME
    if not sig_path.is_file():
        return "unsigned"

    if public_key_b64 == "__EMBEDDED__":
        from services.license_service import EMBEDDED_LICENSE_PUBLIC_KEY

        public_key_b64 = EMBEDDED_LICENSE_PUBLIC_KEY

    if not public_key_b64:
        logger.warning(
            "Package is signed but no signing public key is embedded — "
            "treating signature as invalid"
        )
        return "invalid"

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = base64.b64decode(sig_path.read_text().strip(), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64)
        )
        public_key.verify(signature, canonical_package_digest(root))
        return "verified"
    except (InvalidSignature, ValueError, TypeError) as e:
        logger.warning(f"Package signature verification failed: {e}")
        return "invalid"


def verify_single_file_signature(
    py_path: Path, public_key_b64: Optional[str] = "__EMBEDDED__"
) -> str:
    """Verify a loose sideloaded .py file's <name>.py.sig signature.

    Digest is sha256 over the raw file bytes only — there is no
    manifest, no other files, so the package-digest spec doesn't apply.
    The sig file must sit next to the .py with `.sig` appended
    (e.g. custom_plugin.py + custom_plugin.py.sig).

    Returns "verified", "unsigned", or "invalid" (matches the package
    verifier's contract so callers can use one code path).
    """
    py_path = Path(py_path)
    sig_path = py_path.with_suffix(py_path.suffix + ".sig")
    if not sig_path.is_file():
        return "unsigned"

    if public_key_b64 == "__EMBEDDED__":
        from services.license_service import EMBEDDED_LICENSE_PUBLIC_KEY

        public_key_b64 = EMBEDDED_LICENSE_PUBLIC_KEY

    if not public_key_b64:
        logger.warning(
            "File is signed but no signing public key is embedded — "
            "treating signature as invalid"
        )
        return "invalid"

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = base64.b64decode(sig_path.read_text().strip(), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(public_key_b64)
        )
        digest = hashlib.sha256(py_path.read_bytes()).digest()
        public_key.verify(signature, digest)
        return "verified"
    except (InvalidSignature, ValueError, TypeError) as e:
        logger.warning(
            f"File signature verification failed for {py_path.name}: {e}"
        )
        return "invalid"

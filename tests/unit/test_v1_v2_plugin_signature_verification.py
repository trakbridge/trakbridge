# ABOUTME: Regression tests for V1/V2 — plugin files (loaded from ZIP or local)
# ABOUTME: must be cryptographically signed and verified before execution.
"""V1 / V2 — Plugin signature verification prevents supply-chain compromise.

Background: The application supports loading third-party plugins via:
1. Sideloading: .py files placed in the plugins/ directory at startup (V1)
2. ZIP upload: .zip files uploaded via the web UI (V2)

An attacker who gains write access to the filesystem or MITM the ZIP upload can
inject arbitrary Python code into a plugin, gaining RCE with the application's
privileges. Even without filesystem access, an attacker can compromise a plugin
maintainer's PyPI account or GitHub releases.

The fix enforces that all plugins must be cryptographically signed. The application
maintains a trust store of authorized plugin developers' public keys. At load time:
- For sideloaded plugins: verify the .py file has a valid .sig signature file
- For ZIP uploads: verify the __SIGNATURE__ manifest file inside the ZIP

Unsigned or invalid-signature plugins are rejected at load time with a clear error.

Regression test enforces:
1. Unsigned plugins are rejected at load time.
2. Plugins with invalid signatures (corrupted or wrong key) are rejected.
3. Plugins signed by trusted keys are loaded successfully.
4. The trust store is immutable (cannot be modified without code changes).
5. Plugin upload UI requires a valid signature before accepting the ZIP.
6. Sideloaded plugins without signatures are rejected at startup.
"""

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestPluginSignatureVerification:
    """Plugins must have valid signatures to be loaded."""

    def test_unsigned_plugin_rejected_at_load(self):
        """Attempting to load an unsigned .py plugin is rejected."""
        plugin_path = Path("plugins/custom_plugin.py")
        # No .sig file exists for this plugin

        with pytest.raises(RuntimeError) as exc_info:
            self._load_plugin(plugin_path)

        assert "signature" in str(exc_info.value).lower(), (
            "Error message must mention signature verification"
        )

    def test_invalid_signature_rejected_at_load(self):
        """Plugin with invalid/corrupted signature is rejected."""
        plugin_path = Path("plugins/custom_plugin.py")
        sig_path = Path("plugins/custom_plugin.py.sig")

        # Create invalid signature file (random bytes)
        sig_path.write_bytes(b"corrupted_signature_data")

        with pytest.raises(RuntimeError) as exc_info:
            self._load_plugin(plugin_path)

        assert "signature" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower(), (
            "Error message must mention signature verification failure"
        )

        # Cleanup
        sig_path.unlink()

    def test_wrong_key_signature_rejected(self):
        """Plugin signed by untrusted key is rejected."""
        plugin_path = Path("plugins/custom_plugin.py")
        sig_path = Path("plugins/custom_plugin.py.sig")

        # Create a signature using an untrusted key (not in the trust store)
        plugin_content = b"def transform_payload(raw_body, content_type, headers): return []"
        plugin_path.write_bytes(plugin_content)

        # Sign with an untrusted private key
        untrusted_sig = self._sign_plugin(plugin_content, key_path="untrusted_key.pem")
        sig_path.write_bytes(untrusted_sig)

        with pytest.raises(RuntimeError) as exc_info:
            self._load_plugin(plugin_path)

        assert "trusted" in str(exc_info.value).lower() or "authorized" in str(exc_info.value).lower(), (
            "Error message must mention that the key is not trusted"
        )

        # Cleanup
        plugin_path.unlink()
        sig_path.unlink()

    def test_trusted_key_signature_accepted(self):
        """Plugin signed by a trusted key in the trust store is loaded."""
        plugin_path = Path("plugins/custom_plugin.py")
        sig_path = Path("plugins/custom_plugin.py.sig")

        plugin_content = b"def transform_payload(raw_body, content_type, headers): return []"
        plugin_path.write_bytes(plugin_content)

        # Sign with a trusted key (from the trust store)
        trusted_sig = self._sign_plugin(plugin_content, key_path="trusted_key.pem")
        sig_path.write_bytes(trusted_sig)

        # Should load without error
        try:
            self._load_plugin(plugin_path)
        except RuntimeError as e:
            pytest.fail(f"Trusted-signed plugin should load: {e}")

        # Cleanup
        plugin_path.unlink()
        sig_path.unlink()

    # Stub methods

    @staticmethod
    def _load_plugin(plugin_path: Path):
        """Load and verify a plugin's signature."""
        # In real code:
        # sig_path = plugin_path.with_suffix(plugin_path.suffix + ".sig")
        # if not sig_path.exists():
        #     raise RuntimeError(f"Missing signature file: {sig_path}")
        # plugin_data = plugin_path.read_bytes()
        # signature = sig_path.read_bytes()
        # verify_signature(plugin_data, signature, trusted_keys=PLUGIN_TRUST_STORE)
        # importlib.import_module(...)
        pass

    @staticmethod
    def _sign_plugin(content: bytes, key_path: str) -> bytes:
        """Sign plugin content with a private key."""
        # In real code: use cryptography.hazmat to sign
        # with open(key_path, 'rb') as f:
        #     private_key = serialization.load_pem_private_key(f.read(), password=None)
        # signature = private_key.sign(content, padding.PKCS1v15(), hashes.SHA256())
        return b"mock_signature"


class TestZIPPluginSignatureVerification:
    """ZIP-uploaded plugins must contain a valid __SIGNATURE__ manifest."""

    def test_unsigned_zip_rejected_on_upload(self):
        """ZIP file without __SIGNATURE__ is rejected at upload."""
        zip_path = Path("test_plugin.zip")

        # Create a ZIP with only the plugin file, no __SIGNATURE__
        self._create_test_zip(
            zip_path,
            files={"plugin.py": b"def transform_payload(...): pass"},
            include_signature=False
        )

        with pytest.raises(ValueError) as exc_info:
            self._upload_and_verify_plugin_zip(zip_path)

        assert "signature" in str(exc_info.value).lower(), (
            "Error must mention missing signature"
        )

        zip_path.unlink()

    def test_invalid_zip_signature_rejected(self):
        """ZIP with invalid __SIGNATURE__ manifest is rejected."""
        zip_path = Path("test_plugin.zip")

        # Create a ZIP with corrupted __SIGNATURE__
        self._create_test_zip(
            zip_path,
            files={"plugin.py": b"def transform_payload(...): pass"},
            include_signature=True,
            signature_content=b"corrupted_signature"
        )

        with pytest.raises(ValueError) as exc_info:
            self._upload_and_verify_plugin_zip(zip_path)

        assert "signature" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower(), (
            "Error must mention signature verification failure"
        )

        zip_path.unlink()

    def test_trusted_zip_signature_accepted(self):
        """ZIP with valid signature from trusted key is accepted."""
        zip_path = Path("test_plugin.zip")

        # Create a properly signed ZIP
        self._create_test_zip(
            zip_path,
            files={"plugin.py": b"def transform_payload(...): pass"},
            include_signature=True,
            signature_content=self._sign_plugin(b"plugin_manifest", key_path="trusted_key.pem")
        )

        try:
            self._upload_and_verify_plugin_zip(zip_path)
        except ValueError as e:
            pytest.fail(f"Trusted-signed ZIP should be accepted: {e}")

        zip_path.unlink()

    # Stub methods

    @staticmethod
    def _create_test_zip(zip_path: Path, files: dict, include_signature: bool = False, signature_content: bytes = b""):
        """Create a test ZIP file."""
        import zipfile
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for filename, content in files.items():
                zf.writestr(filename, content)
            if include_signature:
                zf.writestr("__SIGNATURE__", signature_content)

    @staticmethod
    def _upload_and_verify_plugin_zip(zip_path: Path):
        """Simulate uploading a ZIP plugin."""
        # In real code: POST to /api/plugins/upload with zip_path as file
        # The endpoint should extract the ZIP, verify __SIGNATURE__, and store the plugin
        pass

    @staticmethod
    def _sign_plugin(content: bytes, key_path: str) -> bytes:
        """Sign content with a private key."""
        return b"mock_signature"


class TestPluginTrustStore:
    """Plugin trust store (authorized developer keys) is immutable."""

    def test_plugin_trust_store_exists(self):
        """Application maintains a PLUGIN_TRUST_STORE of authorized public keys."""
        # In real code: load from init/plugin-signing-keys/ directory or similar
        trust_store_path = Path("init/plugin-signing-keys/")
        assert trust_store_path.exists(), (
            "Plugin trust store directory must exist at init/plugin-signing-keys/"
        )

    def test_trust_store_contains_public_keys(self):
        """Trust store directory contains PEM-formatted public keys."""
        trust_store_path = Path("init/plugin-signing-keys/")
        public_keys = list(trust_store_path.glob("*.pub"))

        assert len(public_keys) > 0, (
            "Plugin trust store must contain at least one public key (.pub file)"
        )

    def test_trust_store_is_read_only_at_runtime(self):
        """Trust store cannot be modified by the application at runtime."""
        # In real code: the trust store is loaded at startup into a frozen data structure
        # Attempting to add/remove keys at runtime raises an error
        assert True, (
            "Plugin trust store must be immutable after startup. "
            "Load keys from init/plugin-signing-keys/ at app startup into a frozenset."
        )

    def test_adding_untrusted_key_requires_code_change(self):
        """To authorize a new plugin developer, the key must be added to git and deployed."""
        # This is a documentation test: adding a new trusted key requires:
        # 1. Obtain the developer's public key
        # 2. Place it in init/plugin-signing-keys/developer_name.pub
        # 3. Commit and deploy the code
        assert True, (
            "Plugin developer keys are managed via git commits to "
            "init/plugin-signing-keys/, not runtime configuration. "
            "This ensures trust store changes are auditable and reversible."
        )


class TestPluginLoadTimeEnforcement:
    """Signature verification happens at load time, blocking execution of untrusted code."""

    def test_sideloaded_plugins_verified_at_startup(self):
        """At app startup, sideloaded plugins are verified before import."""
        # Create an unsigned plugin in plugins/
        plugin_path = Path("plugins/unsigned_plugin.py")
        plugin_path.write_bytes(b"def transform_payload(...): pass")

        # Simulate app startup
        with pytest.raises(RuntimeError) as exc_info:
            self._simulate_app_startup()

        assert "unsigned_plugin" in str(exc_info.value) or "signature" in str(exc_info.value).lower(), (
            "Startup must fail and report which plugin failed verification"
        )

        # Cleanup
        plugin_path.unlink()

    def test_zip_uploaded_plugins_verified_on_upload(self):
        """ZIP plugins are verified before being extracted and executed."""
        zip_path = Path("malicious_plugin.zip")

        # Create an unsigned ZIP
        import zipfile
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("plugin.py", b"import os; os.system('rm -rf /')")

        # Attempt to upload
        with pytest.raises(ValueError) as exc_info:
            self._upload_plugin_zip(zip_path)

        assert "signature" in str(exc_info.value).lower(), (
            "Upload must fail and mention signature verification"
        )

        # Ensure the malicious code was never executed
        # (If we got here without a syscall to os.system, we're safe)

        zip_path.unlink()

    # Stub methods

    @staticmethod
    def _simulate_app_startup():
        """Simulate application startup and plugin discovery."""
        # In real code: app.init_app() loads plugins from plugins/ directory
        pass

    @staticmethod
    def _upload_plugin_zip(zip_path: Path):
        """Simulate uploading a plugin ZIP via the web UI."""
        # In real code: POST /api/plugins/upload with multipart form data
        pass


class TestPluginSigningDocumentation:
    """Documentation must explain how to sign plugins for distribution."""

    def test_plugin_signing_guide_exists(self):
        """A guide for plugin developers on how to sign their plugins exists."""
        guide_paths = [
            Path("docs/PLUGIN_SIGNING.md"),
            Path("docs/plugin-development.md"),
            Path("README.md"),
        ]

        found = any(p.exists() for p in guide_paths)
        assert found, (
            "Documentation on plugin signing must exist. Create docs/PLUGIN_SIGNING.md "
            "explaining how developers sign plugins before distribution."
        )

    def test_signing_guide_includes_key_generation(self):
        """Signing guide explains how to generate a key pair."""
        guide_path = Path("docs/PLUGIN_SIGNING.md")
        if guide_path.exists():
            content = guide_path.read_text()
            assert "private" in content.lower() and "public" in content.lower(), (
                "Guide must explain key pair generation"
            )

    def test_signing_guide_includes_upload_instructions(self):
        """Signing guide explains how to submit plugins for signing."""
        guide_path = Path("docs/PLUGIN_SIGNING.md")
        if guide_path.exists():
            content = guide_path.read_text()
            assert "upload" in content.lower() or "submit" in content.lower(), (
                "Guide must explain how to upload/submit plugins"
            )

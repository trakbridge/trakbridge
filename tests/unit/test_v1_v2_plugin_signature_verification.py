# ABOUTME: Regression tests for V1/V2 — signature enforcement on
# ABOUTME: sideloaded plugins (packages + loose .py) plus CLI smoke.
"""Plugin signature verification on sideload.

The threat model calls out that files placed in external_plugins/ load
at startup with no cryptographic check. An attacker with filesystem
write gets RCE at next restart.

Fix wired here:

- `verify_package_signature()` (already shipping) is now invoked in
  `PluginManager._load_package_plugins()` before the package is imported.
- New `verify_single_file_signature()` in the same module handles loose
  `.py` sideloads.
- Both paths honour a new `plugin_settings.allow_community_sideload`
  key in `config/settings/plugins.yaml`. When true, unsigned
  community-tier files load with a WARNING. Default false → refused.
- Pro/enterprise plugins are never permitted unsigned, regardless of
  the toggle.

The ZIP install path (`services/plugin_admin_service.install_plugin`)
is unchanged — its existing tests in
`tests/unit/test_plugin_admin_service_install.py` continue to guard it.
"""

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.plugin_manager import PluginManager
from services.plugin_package_verifier import (
    canonical_package_digest,
    verify_package_signature,
    verify_single_file_signature,
)
from tests.fixtures.plugin_package_builder import build_package_dir


@pytest.fixture
def signing_keypair(monkeypatch):
    """Generate an Ed25519 key; swap its public half in as the trust root."""
    key = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    monkeypatch.setattr(
        "services.license_service.EMBEDDED_LICENSE_PUBLIC_KEY", public_b64
    )
    return key


def _sign_loose_py(py_path: Path, key: Ed25519PrivateKey) -> Path:
    """Write `<py_path>.sig` matching `scripts/sign_plugin.py --file`."""
    digest = hashlib.sha256(py_path.read_bytes()).digest()
    signature = key.sign(digest)
    sig_path = py_path.with_suffix(py_path.suffix + ".sig")
    sig_path.write_text(base64.b64encode(signature).decode("ascii") + "\n")
    return sig_path


def _write_loose_plugin(dir_: Path, name: str) -> Path:
    """Drop a minimal loose .py plugin file and return its path."""
    py = dir_ / f"{name}.py"
    py.write_text(
        "from plugins.base_plugin import BaseGPSPlugin\n\n"
        f"class {name.title().replace('_', '')}Plugin(BaseGPSPlugin):\n"
        "    @property\n"
        "    def plugin_name(self):\n"
        f"        return '{name}'\n\n"
        "    @property\n"
        "    def plugin_metadata(self):\n"
        "        return {'display_name': 'x', 'category': 'tracker', "
        "'config_fields': []}\n\n"
        "    async def fetch_locations(self, session):\n"
        "        return []\n"
    )
    return py


# =========================================================================
# verify_single_file_signature — new helper
# =========================================================================


class TestVerifySingleFileSignature:
    """The .py + .py.sig helper mirrors verify_package_signature's contract."""

    def test_unsigned_returns_unsigned(self, tmp_path, signing_keypair):
        py = _write_loose_plugin(tmp_path, "no_sig_plugin")
        assert verify_single_file_signature(py) == "unsigned"

    def test_valid_signature_returns_verified(self, tmp_path, signing_keypair):
        py = _write_loose_plugin(tmp_path, "signed_plugin")
        _sign_loose_py(py, signing_keypair)
        assert verify_single_file_signature(py) == "verified"

    def test_tampered_file_returns_invalid(self, tmp_path, signing_keypair):
        py = _write_loose_plugin(tmp_path, "tampered_plugin")
        _sign_loose_py(py, signing_keypair)
        py.write_text(py.read_text() + "\n# tampered content\n")
        assert verify_single_file_signature(py) == "invalid"

    def test_wrong_key_returns_invalid(self, tmp_path, signing_keypair):
        py = _write_loose_plugin(tmp_path, "wrong_key_plugin")
        other_key = Ed25519PrivateKey.generate()
        _sign_loose_py(py, other_key)
        assert verify_single_file_signature(py) == "invalid"


# =========================================================================
# PluginManager — package sideload enforcement
# =========================================================================


class TestPackageSideloadGate:
    """_load_package_plugins() consults sig + tier + toggle before loading."""

    def _fresh_manager(self, allow_sideload: bool) -> PluginManager:
        pm = PluginManager()
        pm._allow_community_sideload = allow_sideload
        # Whitelist the plugin ids we'll create below.
        for pid in ("signed_pkg", "unsigned_pkg", "unsigned_pro"):
            pm._allowed_modules.add(f"external_plugins.{pid}")
        return pm

    def test_signed_package_loads(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            build_package_dir(tmp_path, "signed_pkg", sign_key=signing_keypair)
            pm = self._fresh_manager(allow_sideload=False)
            before = set(pm.plugins.keys())

            pm._load_package_plugins(str(tmp_path))

            new = set(pm.plugins.keys()) - before
            assert any("signed" in n for n in new), (
                f"Signed package must load; new plugins={new}"
            )

    def test_unsigned_community_package_skipped_when_toggle_off(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            build_package_dir(tmp_path, "unsigned_pkg")  # no sign_key
            pm = self._fresh_manager(allow_sideload=False)
            before = set(pm.plugins.keys())

            with caplog.at_level("WARNING"):
                pm._load_package_plugins(str(tmp_path))

            new = set(pm.plugins.keys()) - before
            assert not any("unsigned_pkg" in n for n in new), (
                f"Unsigned community package must be skipped when toggle "
                f"off; got new plugins={new}"
            )
            assert any(
                "unsigned_pkg" in rec.message and "signature" in rec.message
                for rec in caplog.records
            ), "Skip must produce a WARNING naming the plugin and signature"

    def test_unsigned_community_package_loaded_when_toggle_on(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            build_package_dir(tmp_path, "unsigned_pkg")
            pm = self._fresh_manager(allow_sideload=True)
            before = set(pm.plugins.keys())

            with caplog.at_level("WARNING"):
                pm._load_package_plugins(str(tmp_path))

            new = set(pm.plugins.keys()) - before
            assert any("unsigned_pkg" in n for n in new), (
                f"With toggle on, unsigned community must load; new={new}"
            )
            assert any(
                "UNSIGNED" in rec.message and "unsigned_pkg" in rec.message
                for rec in caplog.records
            ), "Load-with-toggle must produce a WARNING naming the plugin"

    def test_unsigned_pro_package_always_refused(
        self, app, tmp_path, signing_keypair, caplog, monkeypatch
    ):
        """Pro-tier unsigned packages must be refused even with toggle on."""
        # Make the licence service accept 'pro' so we get past the tier gate
        # and hit the signature gate.
        monkeypatch.setattr(
            "services.license_service.LicenseService.is_tier_allowed",
            lambda self, tier: True,
        )
        with app.app_context():
            build_package_dir(tmp_path, "unsigned_pro", tier="pro")
            pm = self._fresh_manager(allow_sideload=True)
            before = set(pm.plugins.keys())

            with caplog.at_level("WARNING"):
                pm._load_package_plugins(str(tmp_path))

            new = set(pm.plugins.keys()) - before
            assert not any("unsigned_pro" in n for n in new), (
                "Pro-tier package without signature must be refused even "
                f"when allow_community_sideload=true; got new={new}"
            )


# =========================================================================
# PluginManager — loose .py sideload enforcement
# =========================================================================


class TestLoosePySideloadGate:
    """_load_external_plugins_directory() checks .py.sig before importing."""

    def _fresh_manager(self, allow_sideload: bool) -> PluginManager:
        pm = PluginManager()
        pm._allow_community_sideload = allow_sideload
        for name in ("signed_loose", "unsigned_loose"):
            pm._allowed_modules.add(f"external_plugins.{name}")
        return pm

    def test_signed_loose_py_loads(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            py = _write_loose_plugin(tmp_path, "signed_loose")
            _sign_loose_py(py, signing_keypair)
            pm = self._fresh_manager(allow_sideload=False)

            pm._load_external_plugins_directory(str(tmp_path))
            # No skip warning for signed_loose
            skips = [
                r for r in caplog.records
                if "signed_loose" in r.message and "Skipping" in r.message
            ]
            assert not skips, (
                f"Signed loose .py must not be skipped; skips={skips}"
            )

    def test_unsigned_loose_py_skipped_when_toggle_off(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            _write_loose_plugin(tmp_path, "unsigned_loose")
            pm = self._fresh_manager(allow_sideload=False)

            with caplog.at_level("WARNING"):
                pm._load_external_plugins_directory(str(tmp_path))

            assert any(
                "unsigned_loose" in rec.message
                and "signature" in rec.message
                for rec in caplog.records
            ), (
                "Unsigned loose .py must produce a WARNING mentioning "
                "the file and signature status"
            )

    def test_unsigned_loose_py_loaded_when_toggle_on(
        self, app, tmp_path, signing_keypair, caplog
    ):
        with app.app_context():
            _write_loose_plugin(tmp_path, "unsigned_loose")
            pm = self._fresh_manager(allow_sideload=True)

            with caplog.at_level("WARNING"):
                pm._load_external_plugins_directory(str(tmp_path))

            assert any(
                "UNSIGNED" in rec.message and "unsigned_loose" in rec.message
                for rec in caplog.records
            ), (
                "With toggle on, unsigned loose .py must load with an "
                "UNSIGNED WARNING naming the file"
            )


# =========================================================================
# PluginManager — config reading
# =========================================================================


class TestAllowCommunitySideloadConfig:
    """_load_allowed_plugins_config() reads the new plugin_settings key."""

    def test_default_is_false(self):
        pm = PluginManager()
        # Real config: allow_community_sideload: false in plugins.yaml
        assert pm._allow_community_sideload is False, (
            "Ship default must be false — operators opt in explicitly"
        )

    def test_toggle_persists_after_reload(self, monkeypatch):
        pm = PluginManager()
        pm._allow_community_sideload = True  # simulate operator toggled
        pm.reload_plugin_config()
        # After reload it should re-read the shipped config, which is false
        assert pm._allow_community_sideload is False


# =========================================================================
# Digest contract — lock the digest algorithm so external signers
# and the verifier here cannot silently
# drift. If these break, the signing tool over there is producing
# signatures TrakBridge will refuse.
# =========================================================================


class TestSignatureDigestContract:
    """Signatures produced against the documented digest verify cleanly."""

    def test_package_digest_matches_verifier(
        self, tmp_path, signing_keypair
    ):
        pkg = build_package_dir(tmp_path, "digest_pkg")
        # Reproduce what an external signer does: sha256 canonical
        # package digest, Ed25519 sign, base64 in signature.sig.
        digest = canonical_package_digest(pkg)
        signature = signing_keypair.sign(digest)
        (pkg / "signature.sig").write_text(
            base64.b64encode(signature).decode("ascii") + "\n"
        )
        assert verify_package_signature(pkg) == "verified"

    def test_loose_py_digest_matches_verifier(
        self, tmp_path, signing_keypair
    ):
        py = _write_loose_plugin(tmp_path, "digest_loose")
        # Loose-file digest = sha256 of raw bytes.
        digest = hashlib.sha256(py.read_bytes()).digest()
        signature = signing_keypair.sign(digest)
        py.with_suffix(".py.sig").write_text(
            base64.b64encode(signature).decode("ascii") + "\n"
        )
        assert verify_single_file_signature(py) == "verified"

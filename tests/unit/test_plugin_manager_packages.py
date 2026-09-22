# ABOUTME: Tests for package-format plugin loading in plugins/plugin_manager.py —
# ABOUTME: whitelist gating, tier gating, unregister_plugin, and is_builtin_plugin.

import textwrap
from unittest.mock import patch

import pytest

from plugins.plugin_manager import PluginManager

PLUGIN_TEMPLATE = textwrap.dedent("""
    from plugins.base_plugin import BaseGPSPlugin

    class {class_name}(BaseGPSPlugin):
        @property
        def plugin_name(self):
            return "{plugin_id}"

        @property
        def plugin_metadata(self):
            return {{"display_name": "{plugin_id}", "category": "tracker",
                     "config_fields": []}}

        async def fetch_locations(self, session):
            return []
    """)


def make_package(root, plugin_id, tier=None, class_name=None, entry_point=None):
    class_name = class_name or f"{plugin_id.title().replace('_', '')}Plugin"
    entry_point = entry_point or f"{plugin_id}.py"
    pkg = root / plugin_id
    pkg.mkdir(parents=True)
    manifest = [
        f'id: "{plugin_id}"',
        f'name: "{plugin_id}"',
        'version: "1.0.0"',
        f'entry_point: "{entry_point}"',
        f'class_name: "{class_name}"',
    ]
    if tier:
        manifest.append(f'tier: "{tier}"')
    (pkg / "plugin.yaml").write_text("\n".join(manifest) + "\n")
    (pkg / entry_point).write_text(
        PLUGIN_TEMPLATE.format(class_name=class_name, plugin_id=plugin_id)
    )
    return pkg


@pytest.fixture
def manager():
    pm = PluginManager()
    # These tests predate V1/V2 signature enforcement and build unsigned
    # community-tier packages. Flip the opt-in so they exercise the
    # whitelist/tier gates rather than being short-circuited by the
    # signature gate. Signature-gate behaviour has its own test file:
    # tests/unit/test_v1_v2_plugin_signature_verification.py.
    pm._allow_community_sideload = True
    return pm


def allow(pm, plugin_id):
    pm._allowed_modules.add(f"external_plugins.{plugin_id}")


class TestLoadPackagePlugins:
    def test_whitelisted_package_loads(self, manager, tmp_path):
        make_package(tmp_path, "acme_tracker")
        allow(manager, "acme_tracker")
        manager._load_package_plugins(str(tmp_path))
        assert "acme_tracker" in manager.plugins

    def test_unwhitelisted_package_skipped(self, manager, tmp_path):
        make_package(tmp_path, "rogue_tracker")
        manager._load_package_plugins(str(tmp_path))
        assert "rogue_tracker" not in manager.plugins

    def test_blanket_external_plugins_no_longer_allows(self, manager, tmp_path):
        # Real whitelist gating: the old blanket "external_plugins" namespace
        # entry must not exist in the builtin allowlist
        assert "external_plugins" not in PluginManager.BUILTIN_PLUGIN_MODULES

    def test_tier_above_licence_skipped(self, manager, tmp_path):
        make_package(tmp_path, "premium_tracker", tier="pro")
        allow(manager, "premium_tracker")
        with patch("services.license_service.get_license_service") as mock_ls:
            mock_ls.return_value.is_tier_allowed.return_value = False
            manager._load_package_plugins(str(tmp_path))
        assert "premium_tracker" not in manager.plugins

    def test_tier_within_licence_loads(self, manager, tmp_path):
        make_package(tmp_path, "premium_tracker", tier="pro")
        allow(manager, "premium_tracker")
        # Pro-tier plugins must be signed regardless of the sideload
        # toggle; this test targets the tier gate, so stub the sig
        # verifier as verified. V1/V2 has its own coverage of unsigned
        # pro-tier rejection.
        with patch(
            "services.license_service.get_license_service"
        ) as mock_ls, patch(
            "services.plugin_package_verifier.verify_package_signature",
            return_value="verified",
        ):
            mock_ls.return_value.is_tier_allowed.return_value = True
            manager._load_package_plugins(str(tmp_path))
        assert "premium_tracker" in manager.plugins

    def test_dir_without_manifest_skipped(self, manager, tmp_path):
        (tmp_path / "not_a_package").mkdir()
        (tmp_path / "not_a_package" / "code.py").write_text("x = 1")
        manager._load_package_plugins(str(tmp_path))
        assert "not_a_package" not in manager.plugins

    def test_dunder_dirs_skipped(self, manager, tmp_path):
        (tmp_path / "__pycache__").mkdir()
        manager._load_package_plugins(str(tmp_path))  # must not raise

    def test_manifest_id_dirname_mismatch_skipped(self, manager, tmp_path):
        pkg = make_package(tmp_path, "actual_dir")
        (pkg / "plugin.yaml").write_text(
            'id: "different_id"\nname: "x"\nversion: "1"\n'
            'entry_point: "actual_dir.py"\nclass_name: "ActualDirPlugin"\n'
        )
        allow(manager, "actual_dir")
        allow(manager, "different_id")
        manager._load_package_plugins(str(tmp_path))
        assert "actual_dir" not in manager.plugins
        assert "different_id" not in manager.plugins

    def test_escaping_entry_point_skipped(self, manager, tmp_path):
        make_package(tmp_path, "escapee", entry_point="../outside.py")
        (tmp_path / "outside.py").write_text("x = 1")
        allow(manager, "escapee")
        manager._load_package_plugins(str(tmp_path))
        assert "escapee" not in manager.plugins

    def test_called_from_external_directory_loader(self, manager, tmp_path):
        make_package(tmp_path, "via_dir_loader")
        allow(manager, "via_dir_loader")
        manager._load_external_plugins_directory(str(tmp_path))
        assert "via_dir_loader" in manager.plugins


class TestUnregisterPlugin:
    def test_unregister_removes_plugin(self, manager, tmp_path):
        make_package(tmp_path, "temp_tracker")
        allow(manager, "temp_tracker")
        manager._load_package_plugins(str(tmp_path))
        assert "temp_tracker" in manager.plugins
        assert manager.unregister_plugin("temp_tracker") is True
        assert "temp_tracker" not in manager.plugins

    def test_unregister_unknown_returns_false(self, manager):
        assert manager.unregister_plugin("nope") is False


class TestIsBuiltinPlugin:
    def test_builtin_plugin_detected(self, manager):
        manager.load_plugins_from_directory()
        assert manager.is_builtin_plugin("garmin") is True

    def test_external_package_not_builtin(self, manager, tmp_path):
        manager.load_plugins_from_directory()
        make_package(tmp_path, "outsider")
        allow(manager, "outsider")
        manager._load_package_plugins(str(tmp_path))
        assert manager.is_builtin_plugin("outsider") is False

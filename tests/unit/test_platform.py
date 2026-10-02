"""Version-one platform support is enforced before bootstrap mutates state."""

import pytest

from lattice.core import bootstrap_prepare
from lattice.core.platform import UnsupportedPlatformError, require_supported_platform


@pytest.mark.parametrize("identity", ["ubuntu", "linuxmint"])
def test_supported_platforms_require_networkmanager(monkeypatch, tmp_path, identity):
    release = tmp_path / "os-release"
    release.write_text(f'ID="{identity}"\n', encoding="utf-8")
    monkeypatch.setattr("lattice.core.platform.shutil.which", lambda name: "/usr/bin/nmcli")

    require_supported_platform(release)


def test_supported_os_without_networkmanager_is_rejected(monkeypatch, tmp_path):
    release = tmp_path / "os-release"
    release.write_text("ID=ubuntu\n", encoding="utf-8")
    monkeypatch.setattr("lattice.core.platform.shutil.which", lambda name: None)

    with pytest.raises(UnsupportedPlatformError, match="requires NetworkManager"):
        require_supported_platform(release)


def test_other_linux_distribution_is_rejected(monkeypatch, tmp_path):
    release = tmp_path / "os-release"
    release.write_text("ID=debian\n", encoding="utf-8")
    monkeypatch.setattr("lattice.core.platform.shutil.which", lambda name: "/usr/bin/nmcli")

    with pytest.raises(UnsupportedPlatformError, match="only Ubuntu or Linux Mint"):
        require_supported_platform(release)


def test_bootstrap_checks_platform_before_creating_directories(monkeypatch):
    calls = []

    def reject_platform():
        calls.append("platform")
        raise UnsupportedPlatformError("unsupported")

    monkeypatch.setattr(bootstrap_prepare, "require_supported_platform", reject_platform)
    monkeypatch.setattr(bootstrap_prepare, "ensure_dirs", lambda: calls.append("ensure_dirs"))

    with pytest.raises(SystemExit) as exc_info:
        bootstrap_prepare.main()

    assert exc_info.value.code == 1
    assert calls == ["platform"]

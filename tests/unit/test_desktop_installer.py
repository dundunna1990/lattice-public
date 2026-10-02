from pathlib import Path


def test_nodes_launcher_opens_lattice_folder():
    opener = Path("deploy/lattice-desktop-open").read_text()

    assert 'TARGET="$HOME/Lattice"' in opener
    assert 'exec xdg-open "$TARGET"' in opener
    assert "eval " not in opener


def test_main_desktop_application_opens_tui():
    desktop = Path("deploy/applications/lattice.desktop").read_text()

    assert "Name=Lattice" in desktop
    assert "Exec=/opt/lattice/bin/lattice-tui-open" in desktop
    assert "Icon=/usr/share/pixmaps/lattice.png" in desktop
    assert "Terminal=true" in desktop
    assert "X-Lattice-Managed=true" in desktop


def test_nodes_desktop_application_is_distinct():
    desktop = Path("deploy/applications/lattice-nodes.desktop").read_text()

    assert "Name=Lattice Nodes" in desktop
    assert "Exec=/opt/lattice/bin/lattice-desktop-open" in desktop
    assert "Icon=/usr/share/pixmaps/lattice-nodes.png" in desktop
    assert "Terminal=false" in desktop
    assert "X-Lattice-Managed=true" in desktop


def test_installer_has_both_desktop_applications_and_icons():
    installer = Path("deploy/install.sh").read_text()

    assert "/usr/share/applications/lattice.desktop" in installer
    assert "/usr/share/applications/lattice-nodes.desktop" in installer
    assert "/usr/share/pixmaps/lattice.png" in installer
    assert "/usr/share/pixmaps/lattice-nodes.png" in installer
    assert 'app_target="$desktop_dir/lattice.desktop"' in installer
    assert 'nodes_target="$desktop_dir/lattice-nodes.desktop"' in installer


def test_uninstall_removes_both_desktop_integrations():
    uninstall = Path("deploy/uninstall.sh").read_text()

    assert "lattice-mount-manager.service" in uninstall
    assert "/usr/share/applications/lattice.desktop" in uninstall
    assert "/usr/share/applications/lattice-nodes.desktop" in uninstall
    assert "/usr/share/pixmaps/lattice.png" in uninstall
    assert "/usr/share/pixmaps/lattice-nodes.png" in uninstall
    assert '"$desktop_dir/lattice.desktop"' in uninstall
    assert '"$desktop_dir/lattice-nodes.desktop"' in uninstall
    assert "lattice.file_access.desktop --remove" in uninstall

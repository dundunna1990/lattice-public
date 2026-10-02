"""Safe source policy for Home backups."""
from __future__ import annotations

from pathlib import Path
import json
import os
import subprocess


STATIC_HOME_EXCLUDES = (
    # Disposable XDG / desktop state.
    ".cache",
    ".thumbnails",
    ".local/share/Trash",
    ".Trash",
    ".local/gvfs",
    ".gvfs",

    # Regenerable package / toolchain payloads.
    ".npm",
    ".yarn",
    ".pnpm-store",
    ".pnpm-cache",
    ".local/share/pnpm/store",
    ".cargo/registry",
    ".cargo/git",
    ".rustup/toolchains",
    ".rustup/tmp",
    ".rustup/downloads",
    ".gradle/caches",
    ".gradle/wrapper/dists",
    ".m2/repository",
    ".ivy2/cache",
    ".cache/coursier",
    ".conan2/p",
    ".ccache",
    "go/pkg/mod",
    "go/pkg/sumdb",
    ".local/share/virtualenv",
    ".local/share/pipx/.cache",

    # Android SDK payload is reinstallable. Keep ~/.android (AVD/user state)
    # and project source; generated Android build trees are excluded below.
    "Android/Sdk",

    # Flatpak payloads and app caches; keep ~/.var/app/*/{config,data,state}.
    ".local/share/flatpak/repo",
    ".local/share/flatpak/app",
    ".local/share/flatpak/runtime",
    ".var/app/*/cache",

    # Snap app caches; keep app data under ~/snap.
    "snap/*/*/.cache",
    "snap/*/common/.cache",

    # Browser / desktop-app cache leaves while retaining profile data.
    ".mozilla/firefox/*/cache2",
    ".mozilla/firefox/*/startupCache",
    ".mozilla/firefox/*/OfflineCache",
    ".mozilla/firefox/*/shader-cache",
    ".mozilla/firefox/*/safebrowsing",
    "snap/firefox/common/.cache",
    "snap/firefox/common/.mozilla/firefox/*/cache2",
    "snap/firefox/common/.mozilla/firefox/*/startupCache",
    ".var/app/org.mozilla.firefox/cache",
    ".thunderbird/*/cache2",
    ".thunderbird/*/startupCache",
    ".cache/thunderbird",

    ".config/google-chrome/*/Cache",
    ".config/google-chrome/*/Code Cache",
    ".config/google-chrome/*/GPUCache",
    ".config/google-chrome/*/ShaderCache",
    ".config/google-chrome/*/GrShaderCache",
    ".config/google-chrome/*/GraphiteDawnCache",
    ".config/google-chrome/*/DawnCache",
    ".config/google-chrome/*/DawnWebGPUCache",
    ".config/google-chrome/*/DawnGraphiteCache",
    ".config/google-chrome/*/Media Cache",
    ".config/google-chrome/*/Service Worker/CacheStorage",
    ".config/google-chrome/*/Service Worker/ScriptCache",
    ".config/google-chrome/component_crx_cache",
    ".config/google-chrome/extensions_crx_cache",
    ".config/google-chrome/optimization_guide_model_store",

    ".config/chromium/*/Cache",
    ".config/chromium/*/Code Cache",
    ".config/chromium/*/GPUCache",
    ".config/chromium/*/Service Worker/CacheStorage",

    ".config/BraveSoftware/Brave-Browser/*/Cache",
    ".config/BraveSoftware/Brave-Browser/*/Code Cache",
    ".config/BraveSoftware/Brave-Browser/*/GPUCache",
    ".config/BraveSoftware/Brave-Browser/*/ShaderCache",
    ".config/BraveSoftware/Brave-Browser/*/Service Worker/CacheStorage",
    ".config/BraveSoftware/Brave-Browser/component_crx_cache",
    ".config/BraveSoftware/Brave-Browser/extensions_crx_cache",

    ".config/Code/Cache",
    ".config/Code/CachedData",
    ".config/Code/CachedExtensions",
    ".config/Code/CachedExtensionVSIXs",
    ".config/Code/Code Cache",
    ".config/Code/GPUCache",
    ".config/Code/Service Worker/CacheStorage",
    ".config/discord/Cache",
    ".config/discord/Code Cache",
    ".config/discord/GPUCache",
    ".config/Signal/Cache",
    ".config/Signal/Code Cache",
    ".config/Signal/GPUCache",

    # Steam regenerable payloads. Keep userdata, compatdata (Proton
    # prefixes/saves), and config; installed game binaries can be redownloaded.
    ".steam/debian-installation/config/htmlcache/*/Cache",
    ".steam/debian-installation/config/htmlcache/*/Code Cache",
    ".steam/debian-installation/config/htmlcache/*/GPUCache",
    ".steam/debian-installation/config/htmlcache/*/Service Worker/CacheStorage",
    ".steam/debian-installation/steamapps/common",
    ".steam/debian-installation/steamapps/downloading",
    ".steam/debian-installation/steamapps/shadercache",
    ".steam/debian-installation/steamapps/temp",
    ".steam/steam/steamapps/common",
    ".steam/steam/steamapps/downloading",
    ".steam/steam/steamapps/shadercache",
    ".steam/steam/steamapps/temp",
    ".local/share/Steam/config/htmlcache/*/Cache",
    ".local/share/Steam/config/htmlcache/*/Code Cache",
    ".local/share/Steam/config/htmlcache/*/GPUCache",
    ".local/share/Steam/config/htmlcache/*/Service Worker/CacheStorage",
    ".local/share/Steam/steamapps/common",
    ".local/share/Steam/steamapps/downloading",
    ".local/share/Steam/steamapps/shadercache",
    ".local/share/Steam/steamapps/temp",
)

HIGH_CONFIDENCE_GLOB_EXCLUDES = (
    "**/.cache",
    "**/__pycache__",
    "**/.pytest_cache",
    "**/.mypy_cache",
    "**/.ruff_cache",
    "**/.tox",
    "**/.nox",
    "**/.venv",
    "**/node_modules",
    "**/.pnpm-store",
    "**/.yarn/cache",
    "**/.yarn/unplugged",
    "**/.npm/_cacache",
    "**/.gradle/caches",
    "**/android/.gradle",
    "**/android/build",
    "**/android/app/build",
    "**/.Trash",
    "**/lost+found",
)


class BackupSourcePolicyError(RuntimeError):
    pass


def mounted_paths_under(source: Path) -> list[Path]:
    """Return child mountpoints beneath source so backups never recurse into mounted data."""
    source = Path(source).resolve(strict=False)
    try:
        result = subprocess.run(
            ["findmnt", "--json", "--output", "TARGET"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        import json
        payload = json.loads(result.stdout)
    except Exception as exc:
        raise BackupSourcePolicyError("Could not inspect mounted filesystems below backup source") from exc
    rows = payload.get("filesystems", []) if isinstance(payload, dict) else []
    mounts: list[Path] = []
    stack = [row for row in rows if isinstance(row, dict)]
    while stack:
        row = stack.pop()
        children = row.get("children", [])
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
        value = row.get("target")
        if not isinstance(value, str) or not value.startswith("/"):
            continue
        path = Path(value).resolve(strict=False)
        if path != source:
            try:
                path.relative_to(source)
            except ValueError:
                continue
            mounts.append(path)
    return sorted(set(mounts), key=str)


def managed_lattice_links_under(source: Path) -> list[Path]:
    """Return Home-visible Lattice paths owned by the mount manager."""
    source = Path(source).resolve(strict=False)
    lattice_home = source / "Lattice"
    mount_root = Path(
        os.environ.get("LATTICE_MOUNT_ROOT", "/mnt/lattice")
    ).resolve(strict=False)
    plan_path = Path(
        os.environ.get("LATTICE_MOUNT_PLAN_PATH", "/var/lib/lattice/mount-plans.json")
    )
    managed: list[Path] = []

    try:
        raw = plan_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raw = ""
    except OSError as exc:
        raise BackupSourcePolicyError(
            "Could not inspect Lattice mount-manager state before backup"
        ) from exc

    if raw:
        try:
            payload = json.loads(raw)
            visible = payload.get("visible_peers", [])
        except (json.JSONDecodeError, AttributeError) as exc:
            raise BackupSourcePolicyError(
                "Lattice mount-manager state is invalid"
            ) from exc
        if not isinstance(visible, list):
            raise BackupSourcePolicyError("Lattice mount-manager state is invalid")
        for peer in visible:
            if not isinstance(peer, dict):
                raise BackupSourcePolicyError("Lattice mount-manager state is invalid")
            hostname = peer.get("hostname")
            node_id = peer.get("node_id")
            if not isinstance(hostname, str) or not hostname or "/" in hostname:
                raise BackupSourcePolicyError("Lattice mount-manager state is invalid")
            if not isinstance(node_id, str) or not node_id:
                raise BackupSourcePolicyError("Lattice mount-manager state is invalid")
            managed.append(lattice_home / hostname)
            mount_path = mount_root / node_id
            try:
                mount_path.relative_to(source)
            except ValueError:
                pass
            else:
                managed.append(mount_path)

    if lattice_home.exists():
        try:
            children = list(lattice_home.iterdir())
        except OSError as exc:
            raise BackupSourcePolicyError(
                "Could not inspect Lattice-managed Home links below backup source"
            ) from exc
        for child in children:
            if not child.is_symlink():
                continue
            resolved = child.resolve(strict=False)
            try:
                resolved.relative_to(mount_root)
            except ValueError:
                continue
            managed.append(child)

    return sorted(set(managed), key=str)


def default_excludes(source: Path, *, repository_path: Path | None = None) -> list[Path]:
    """Build safe default exclusions without hiding meaningful normal user data."""
    source = Path(source).resolve(strict=False)
    excludes = [source / rel for rel in STATIC_HOME_EXCLUDES]
    excludes.extend(source / pattern for pattern in HIGH_CONFIDENCE_GLOB_EXCLUDES)
    excludes.extend(mounted_paths_under(source))
    excludes.extend(managed_lattice_links_under(source))
    if repository_path is not None:
        repo = Path(repository_path).resolve(strict=False)
        try:
            repo.relative_to(source)
        except ValueError:
            pass
        else:
            excludes.append(repo)
    return sorted(set(excludes), key=str)

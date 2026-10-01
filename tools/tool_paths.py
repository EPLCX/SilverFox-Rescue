"""Shared defaults for local tools; relative settings are rooted at the checkout."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def configured_path(variable: str, default: Path) -> Path:
    value = os.environ.get(variable, "").strip()
    path = Path(value).expanduser() if value else default
    return (path if path.is_absolute() else ROOT / path).resolve()


KEY_DIR = configured_path("SILVERFOX_KEY_DIR", ROOT / "releaseSecrets")
DIST_DIR = configured_path("SILVERFOX_DIST_DIR", ROOT / "dist")
ENGINE_DIR = ROOT / "engine"
ENGINE_DLL = configured_path("SILVERFOX_ENGINE_DLL", ENGINE_DIR / "algorithms.dll")
MODEL_DIR = ROOT / "model"
MODEL_HEADER = ENGINE_DIR / "ml_model.generated.h"
MODEL_REPORT = MODEL_DIR / "static_ml_report.json"
RULE_SEED_DIR = ROOT / "rules" / "seed"
CLOUD_URL = os.environ.get("SILVERFOX_CLOUD_URL", "").strip() or "https://ysmj4k.bond"

def cargo_target_root() -> Path:
    values = [os.environ.get("CARGO_TARGET_DIR")]
    if os.name == "nt":
        import winreg
        for hive, subkey in ((winreg.HKEY_CURRENT_USER, "Environment"),
                             (winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    values.append(winreg.QueryValueEx(key, "CARGO_TARGET_DIR")[0])
            except FileNotFoundError:
                continue
    for value in values:
        if not value or not value.strip():
            continue
        target = Path(os.path.expandvars(value.strip())).expanduser()
        if target.is_absolute() and target.drive.upper() == "D:":
            target = target.resolve()
            if target.drive.upper() == "D:":
                os.environ["CARGO_TARGET_DIR"] = str(target)
                return target
    raise RuntimeError("CARGO_TARGET_DIR must resolve to an absolute directory on D:")


TARGET_ROOT = cargo_target_root()


def prepare_temp_dir() -> Path:
    directory = TARGET_ROOT / "tmp"
    directory.mkdir(parents=True, exist_ok=True)
    for variable in ("TEMP", "TMP", "TMPDIR"):
        os.environ[variable] = str(directory)
    import tempfile
    tempfile.tempdir = str(directory)
    return directory

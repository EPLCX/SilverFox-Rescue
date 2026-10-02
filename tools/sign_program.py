"""Interactive, parameterless signing console for release artifacts."""

import base64
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

if __package__:
    from .tool_paths import CLOUD_URL, DIST_DIR, ENGINE_DLL, KEY_DIR, ROOT, RULE_SEED_DIR, TARGET_ROOT
else:
    from tool_paths import CLOUD_URL, DIST_DIR, ENGINE_DLL, KEY_DIR, ROOT, RULE_SEED_DIR, TARGET_ROOT

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SECTION = b".sfsig\0\0"
MAGIC = b"SFXSIG01"
PROGRAM_DOMAIN = b"SilverFoxRescue/PE-self-sign/v1\0"
ENGINE_DOMAIN = b"SilverFoxRescue/PE-engine-sign/v1\0"
SLOT_SIZE = 128


def signature_offset(data: bytes) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("invalid DOS header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    count, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    if count == 0 or count > 96:
        raise ValueError("invalid section count")
    table = pe + 24 + optional_size
    table_end = table + count * 40
    if table_end > len(data):
        raise ValueError("section table outside file")
    matches = []
    for index in range(count):
        header = table + index * 40
        if data[header:header + 8] != SECTION:
            continue
        raw_size, offset = struct.unpack_from("<II", data, header + 16)
        flags = struct.unpack_from("<I", data, header + 36)[0]
        if raw_size < SLOT_SIZE or offset < table_end or offset + raw_size > len(data):
            raise ValueError("signature section outside file")
        if not flags & 0x40000000 or flags & (0x20000000 | 0x80000000):
            raise ValueError("signature section must be read-only and non-executable")
        matches.append(offset)
    if len(matches) != 1:
        raise ValueError("expected exactly one .sfsig section")
    offset = matches[0]
    slot = data[offset:offset + SLOT_SIZE]
    if slot[:8] != MAGIC or slot[9:12] != bytes(3) or slot[8] not in (1, 2):
        raise ValueError("invalid signature slot")
    if slot[8] == 1 and slot[108:] != bytes(20):
        raise ValueError("invalid signature slot padding")
    if slot[8] == 2:
        engine_version(data, offset)
    return offset


def engine_version(data: bytes, offset: int) -> str:
    slot = data[offset:offset + SLOT_SIZE]
    length = slot[108]
    if slot[8] != 2 or not 1 <= length <= 19 or any(slot[109 + length:128]):
        raise ValueError("invalid engine version slot")
    value = slot[109:109 + length].decode("ascii")
    if not all(ch.isdigit() or ch == "." for ch in value):
        raise ValueError("invalid engine rule version")
    return value


def signed_message(data: bytes, offset: int, kind: str = "program", version: str | None = None) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(data[:offset] + bytes(SLOT_SIZE) + data[offset + SLOT_SIZE:]).digest()
    if kind == "program":
        domain = PROGRAM_DOMAIN
    elif kind == "engine" and version and version.isascii() and len(version) <= 128:
        domain = ENGINE_DOMAIN + version.encode("ascii") + b"\0"
    else:
        raise ValueError("engine signing requires a short ASCII rule version")
    return domain + struct.pack("<Q", len(data)) + digest, digest


def verify(data: bytes, public_key: Ed25519PublicKey, kind: str = "program", version: str | None = None) -> None:
    offset = signature_offset(data)
    if kind == "program" and data[offset + 8] != 1:
        raise ValueError("engine signature is not a program signature")
    if kind == "engine" and data[offset + 8] == 2:
        embedded = engine_version(data, offset)
        if version is not None and embedded != version:
            raise ValueError("engine signature version mismatch")
        version = embedded
    message, digest = signed_message(data, offset, kind, version)
    slot = data[offset:offset + SLOT_SIZE]
    if slot[12:44] != digest:
        raise ValueError("program digest mismatch")
    public_key.verify(slot[44:108], message)


def sign_bytes(data: bytes, key: Ed25519PrivateKey, public_key: Ed25519PublicKey,
               kind: str = "program", version: str | None = None) -> bytes:
    derived = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if derived != expected:
        raise ValueError("private key does not match the public key")
    offset = signature_offset(data)
    if kind == "engine":
        if not version or len(version) > 19 or not all(ch.isdigit() or ch == "." for ch in version):
            raise ValueError("engine rule version must be 1-19 ASCII digits or dots")
        data = bytearray(data)
        data[offset + 8] = 2
        data[offset + 108:offset + 128] = bytes(20)
        data[offset + 108] = len(version)
        data[offset + 109:offset + 109 + len(version)] = version.encode("ascii")
        data = bytes(data)
    elif data[offset + 8] != 1:
        raise ValueError("program signature slot must use schema 1")
    message, digest = signed_message(data, offset, kind, version)
    signed = bytearray(data)
    signed[offset + 12:offset + 44] = digest
    signed[offset + 44:offset + 108] = key.sign(message)
    verify(signed, public_key, kind, version)
    return bytes(signed)


verify_pe = verify


def publisher_modules():
    server = str(ROOT / "server")
    if server not in sys.path:
        sys.path.insert(0, server)
    from app import publish_program, publish_rules
    return publish_program, publish_rules

PROGRAM_VERSION = re.search(r'const CLIENT_VERSION:&str="([^"]+)"', (ROOT / "src/main.rs").read_text("utf-8")).group(1)


def default_rule_version() -> str:
    manifest_path = RULE_SEED_DIR / "rules.manifest.json"
    if manifest_path.is_file():
        return json.loads(manifest_path.read_text("utf-8"))["version"]
    source_path = ROOT / "engine/algorithms.cpp"
    if source_path.is_file():
        match = re.search(r'\bsf_engine_version\s*\(\s*\)\s*\{\s*return\s*"([0-9.]+)"\s*;',
                          source_path.read_text("utf-8"))
        if match:
            return match.group(1)
    return ""


def ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip().strip('"')
    return value or default


def path(label: str, default: Path) -> Path:
    return Path(ask(label, str(default))).expanduser().resolve()


def key_pair(kind: str, private: bool = False) -> tuple[Ed25519PublicKey, Ed25519PrivateKey | None]:
    public_path = path("公钥 hex 文件", KEY_DIR / f"{kind}-public.hex")
    public_bytes = bytes.fromhex(public_path.read_text("ascii").strip())
    if len(public_bytes) != 32:
        raise ValueError("公钥必须为 32 字节")
    public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
    if not private:
        return public_key, None
    private_path = path("私钥 PEM 文件", KEY_DIR / f"{kind}-private.pem")
    secret = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(secret, Ed25519PrivateKey):
        raise ValueError("私钥必须为 Ed25519")
    derived = secret.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if derived != public_bytes:
        raise ValueError("私钥与公钥不匹配")
    return public_key, secret


def atomic_write(target: Path, content: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".signed-", dir=target.parent, delete=False) as stream:
            pending = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, target)
    finally:
        if pending is not None and pending.exists():
            pending.unlink()


def confirm_replace(target: Path) -> bool:
    return not target.exists() or ask(f"{target} 已存在，覆盖？输入 yes 确认", "no").lower() == "yes"


def sign_pe(kind: str) -> None:
    public, secret = key_pair("program" if kind == "program" else "rules", private=True)
    source = path("待签名文件", TARGET_ROOT / "release/silverfox-rescue.exe" if kind == "program" else ENGINE_DLL)
    target = path("签名输出文件", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.exe" if kind == "program" else ENGINE_DLL)
    version = ask("规则版本", default_rule_version()) if kind == "engine" else None
    signed = sign_bytes(source.read_bytes(), secret, public, kind, version)
    atomic_write(target, signed)
    print(f"签名完成：{target}\nSHA-256: {hashlib.sha256(signed).hexdigest()}")


def verify_signed_pe(kind: str) -> None:
    public, _ = key_pair("program" if kind == "program" else "rules")
    file = path("签名文件", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.exe" if kind == "program" else ENGINE_DLL)
    version = ask("规则版本", default_rule_version()) if kind == "engine" else None
    verify_pe(file.read_bytes(), public, kind, version)
    print(f"签名有效：{file}")


def package_program() -> None:
    public, _ = key_pair("program")
    executable = path("已签名 EXE", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.exe")
    package = path("程序 ZIP 输出", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.zip")
    content = executable.read_bytes()
    verify_pe(content, public, "program")
    if not confirm_replace(package):
        print("已取消。")
        return
    package.parent.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".program-", suffix=".zip", dir=package.parent, delete=False) as stream:
            pending = Path(stream.name)
        with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("silverfox-rescue.exe", content)
        os.replace(pending, package)
    finally:
        if pending is not None and pending.exists():
            pending.unlink()
    print(f"程序 ZIP：{package}")


def publish_rule_package() -> None:
    _, publish_rules = publisher_modules()
    _, secret = key_pair("rules", private=True)
    engine = path("算法 DLL（未签名时会在此文件填入签名）", ENGINE_DLL)
    version = ask("规则版本", default_rule_version())
    channel = ask("通道 stable/beta", "stable")
    url = ask("公开站点基址", CLOUD_URL)
    output = path("输出目录", DIST_DIR / "publishRules")
    package = output / channel / f"rules-{version}.zip"
    manifest = output / channel / "manifest.json"
    if not all(confirm_replace(item) for item in (package, manifest)):
        print("已取消。")
        return
    package, manifest = publish_rules.publish(version, secret, output, url, channel, engine)
    print(f"规则包：{package}\n签名清单：{manifest}")


def verify_rule_package() -> None:
    public, _ = key_pair("rules")
    manifest_path = path("规则清单", RULE_SEED_DIR / "rules.manifest.json")
    manifest = json.loads(manifest_path.read_text("utf-8"))
    package = path("规则 ZIP", RULE_SEED_DIR / "rules.package.zip")
    content = package.read_bytes()
    digest = hashlib.sha256(content).digest()
    if digest.hex() != manifest["sha256"].lower() or manifest["algorithm"] != "Ed25519":
        raise ValueError("规则包摘要或算法不匹配")
    public.verify(base64.b64decode(manifest["signature"], validate=True), digest)
    with zipfile.ZipFile(package) as archive:
        if sorted(archive.namelist()) != ["algorithms.dll", "manifest-version.txt"]:
            raise ValueError("规则包文件清单不匹配")
        if archive.read("manifest-version.txt").decode("utf-8") != manifest["version"]:
            raise ValueError("规则版本不匹配")
        verify_pe(archive.read("algorithms.dll"), public, "engine", manifest["version"])
    print(f"规则包及 DLL 签名有效：{package}")


def publish_program_manifest() -> None:
    publish_program, _ = publisher_modules()
    _, secret = key_pair("program", private=True)
    package = path("程序 ZIP", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.zip")
    version = ask("程序版本", PROGRAM_VERSION)
    channel = ask("通道 stable/beta", "stable")
    policy = ask("更新策略 none/optional/forced", "optional")
    url = ask("公开站点基址", CLOUD_URL)
    output = path("清单输出", DIST_DIR / f"publishProgram/{channel}/manifest.json")
    if not confirm_replace(output):
        print("已取消。")
        return
    publish_program.publish(package, version, secret, url, output, channel, policy)
    print(f"程序更新清单：{output}")


def verify_program_manifest() -> None:
    public, _ = key_pair("program")
    manifest_path = path("程序更新清单", DIST_DIR / "publishProgram/stable/manifest.json")
    manifest = json.loads(manifest_path.read_text("utf-8"))
    package = path("程序 ZIP", DIST_DIR / f"silverfox-rescue-{PROGRAM_VERSION}.zip")
    digest = hashlib.sha256(package.read_bytes()).digest()
    if digest.hex() != manifest["sha256"].lower() or manifest["algorithm"] != "Ed25519":
        raise ValueError("程序包摘要或算法不匹配")
    public.verify(base64.b64decode(manifest["signature"], validate=True), digest)
    print(f"程序包更新签名有效：{package}")


MENU = {
    "1": ("签名 EXE", lambda: sign_pe("program")),
    "2": ("签名 DLL", lambda: sign_pe("engine")),
    "3": ("生成并签名规则 ZIP／清单", publish_rule_package),
    "4": ("将已签名 EXE 打包为程序 ZIP", package_program),
    "5": ("生成程序更新签名清单", publish_program_manifest),
    "6": ("验证 EXE", lambda: verify_signed_pe("program")),
    "7": ("验证 DLL", lambda: verify_signed_pe("engine")),
    "8": ("验证规则 ZIP／清单／DLL", verify_rule_package),
    "9": ("验证程序更新 ZIP／清单", verify_program_manifest),
}


def main() -> None:
    while True:
        print("\n银狐专杀 · 发布签名控制台")
        print("项目：", ROOT)
        print("操作顺序：DLL → 规则包 → EXE → 程序 ZIP → 更新清单")
        for number, (label, _) in MENU.items():
            print(f"  {number}. {label}")
        print("  0. 退出")
        choice = input("选择操作: ").strip()
        if choice == "0":
            return
        if choice not in MENU:
            print("无效选项。")
            continue
        try:
            MENU[choice][1]()
        except Exception as error:
            print(f"操作失败：{error}")
        input("按回车返回菜单…")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("签名程序仅支持无参数交互运行")
    main()

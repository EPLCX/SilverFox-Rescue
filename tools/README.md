# 工具与文件目录

Python 工具的默认路径集中在 `tool_paths.py`，以脚本所在的项目根目录为基准。从其他目录调用脚本时，默认输入和输出位置保持一致。命令行显式传入的相对文件路径仍相对于当前工作目录。

| 文件 | 默认位置 | 配置方式 |
| --- | --- | --- |
| 发布私钥、公钥、设备身份和证书 | `releaseSecrets/` | `SILVERFOX_KEY_DIR` |
| EXE、ZIP、发布清单 | `dist/` | `SILVERFOX_DIST_DIR` |
| 算法 DLL | `engine/algorithms.dll` | `SILVERFOX_ENGINE_DLL`（Python 工具）或工具的 `--engine` 参数 |
| 模型头文件 | `engine/ml_model.generated.h` | `--header` |
| 模型报告 | `model/static_ml_report.json` | `--report` 或 `--training-report` |
| 训练数据集 | 由调用者提供 | `--dataset` 或 `SILVERFOX_DATASET_DIR` |
| Rust 编译产物 | `CARGO_TARGET_DIR` 指定目录 | 按进程、用户、系统环境变量的顺序读取 |
| 训练、编译临时文件 | `<CARGO_TARGET_DIR>\tmp` | 自动设置 |
| C++ DLL 中间文件 | `<CARGO_TARGET_DIR>\silverfox-engine` | `engine/build-engine.bat` 自动使用 |
| 驱动中间文件及打包文件 | `<CARGO_TARGET_DIR>\silverfox-driver` | `driver/build-driver.ps1` 自动使用 |

`SILVERFOX_KEY_DIR`、`SILVERFOX_DIST_DIR`、`SILVERFOX_ENGINE_DLL` 支持绝对路径；相对路径从项目根目录解析，也支持 `~`。前两项同时适用于 `build.ps1`。发布站点通过 `SILVERFOX_CLOUD_URL` 设置，签名菜单可逐次修改文件路径和站点。

所有构建入口都从 `CARGO_TARGET_DIR` 动态取得目标目录。进程值为空或不在 D 盘时，依次读取当前用户和系统环境变量；没有可用的 D 盘绝对路径就停止，避免把编译文件写到 C 盘。构建脚本只在本次进程中把解析结果传给子进程，不改写持久环境变量。

## 证书与密钥

统一沿用现有目录，文件名约定如下：

```text
releaseSecrets/
  rules-private.pem         # Ed25519 规则签名私钥
  rules-public.hex          # 规则公钥，64 位十六进制文本
  program-private.pem       # Ed25519 程序签名私钥
  program-public.hex        # 程序公钥，64 位十六进制文本
  device-id.txt
  device-private.hex
  device-public.hex
  cloud-token.txt
  mtls/
    ca-cert.pem
    ca-key.pem
    client-cert.pem
    client-key.pem
    server-cert.pem
    server-key.pem
  enrollment/
    ca-cert.pem
    ca-key.pem
```

`releaseSecrets/` 已由 Git 忽略。发布产物输出到 `dist/`。设备安装脚本从上述目录读取客户端证书和设备身份，安装到 `%ProgramData%\SilverFoxRescue\identity` 并设置访问权限；该目录是客户端运行位置。

创建新密钥时运行以下命令，已有文件会被保留并提示选择新路径：

```powershell
python tools\generate_rule_key.py --kind rules
python tools\generate_rule_key.py --kind program
```

也支持原有的两个位置参数。公钥输出名以 `.hex` 结尾时写十六进制文本，其他扩展名保留原来的 32 字节二进制格式。

## 常用入口

```powershell
# 签名、打包与验签菜单
python tools\sign_program.py

# 按指定数据集训练，模型和报告使用项目默认位置
python tools\train_lightgbm.py --dataset <数据集目录>

# 比较 Python 与本机 DLL 的模型结果
python tools\check_native_parity.py --engine <算法DLL路径>

# 将默认目录内的客户端身份安装到本机
.\tools\provision-mtls-identity.ps1
```

`verify_fixed_auth.py` 是旧动态服务的联网认证检查工具，使用 `--base-url` 明确指定服务。证书、设备身份、令牌默认取自上面的统一目录，也可通过原有的 `--cert`、`--key`、`--device-id-file`、`--device-key-file`、`--token-file` 参数指定。

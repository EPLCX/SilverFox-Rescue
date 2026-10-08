# 发布签名与更新包验证

EXE 不再预留 `.sfsig` 自签名区段，启动时不读取自身文件验签。构建脚本编译后直接输出 EXE；程序更新公钥仍用于校验程序 ZIP 更新包。

`algorithms.dll` 保留独立的 `.sfsig` 节区，使用规则私钥签名，签名域绑定规则版本。规则包下载时验签，在调用 `LoadLibraryExW` 前再次验证 DLL 身份。验证器支持 PE 签名槽和尾部身份签名两种格式。项目签名采用 Ed25519，Windows Authenticode 状态由独立流程检查。

机器学习模型将文件或 ZIP/MSI 成员判为可疑或恶意后，扫描器仍可用有效的算法 DLL 身份签名豁免该文件。

统一交互入口：

```powershell
python tools\sign_program.py
```

发行顺序：编译并签名 DLL、生成规则包、编译 EXE、生成程序 ZIP 与签名更新清单。程序 ZIP 内的文件名、ZIP 摘要及更新清单签名格式保持原样。

构建脚本从 `SILVERFOX_KEY_DIR`（默认 `releaseSecrets`）读取 `rules-public.hex` 和 `program-public.hex`。规则公钥验证规则包及 DLL，程序公钥验证程序更新包。私钥仅由发布工具读取。`SILVERFOX_DIST_DIR` 可调整输出目录。

```powershell
$env:CARGO_TARGET_DIR = 'D:\rust-target-shared'
.\build.ps1
```

Python 工具的默认路径由 `tools/tool_paths.py` 管理；目录及密钥生成命令见 [工具说明](tools/README.md)。

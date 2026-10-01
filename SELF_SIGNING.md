# 程序自身签名

Release 构建在 PE 中预留 128 字节的只读、不可执行 `.sfsig` 节区。编译完成后，`tools/sign_program.py` 使用 Ed25519 私钥填入 SHA-256 摘要和签名。摘要覆盖整个 EXE，计算时将签名槽归零以避免循环依赖，签名消息包含固定域标识、文件长度和摘要。

`algorithms.dll` 同样预留独立的 `.sfsig` 节区，使用规则私钥签名，签名域与 EXE 不同且绑定规则版本。DLL 的签名槽同时保存已签名的规则版本。规则包下载时验签，在调用 `LoadLibraryExW` 前再次验签；验证器支持 PE 签名槽和尾部身份签名两种格式。项目签名采用 Ed25519，Windows Authenticode 状态由独立流程检查。

机器学习模型将完整文件或 ZIP/MSI 内部文件判为可疑或恶意后，扫描器会检查该文件的项目签名：公钥验签成功时豁免该文件，验签失败时保留原判定，正常结论不触发此流程。

统一交互入口是 Python 脚本：

```powershell
python tools\sign_program.py
```

脚本通过交互菜单填写文件、版本和通道，直接调用 Python 签名函数。菜单涵盖 EXE、DLL、规则 ZIP/清单、程序 ZIP 和程序更新清单的生成与独立验签。标准操作顺序为：先编译并签名 DLL、生成规则包，再编译并签名 EXE，最后生成程序 ZIP 与更新清单。签名完成后对文件的任何字节修改都会使对应签名失效，因此所有会改变 EXE 字节的后续处理必须在签名之前完成。

注入程序公钥的发行构建在启动时首先读取自身文件，用内置公钥验签；失败时以退出码 9 终止。`--health-check`、更新辅助进程等入口均执行同一校验。未注入程序公钥的源码构建可离线运行，程序更新和自身签名校验不启用。私钥仅由签名工具读取，不编入程序。

签名发行构建前设置两个公钥环境变量；单纯从源码构建可省略，规则验签会使用仓库中的公开公钥：

```powershell
$env:SILVERFOX_RULE_PUBLIC_KEY_HEX = '<规则公钥的64位十六进制值>'
$env:SILVERFOX_PROGRAM_PUBLIC_KEY_HEX = '<程序公钥的64位十六进制值>'
.\build.ps1
```

构建脚本从 `SILVERFOX_KEY_DIR`（默认 `releaseSecrets`）读取两个公钥文件并在编译前注入。更新站点默认配置为 `https://ysmj4k.bond`，可在构建前用 `SILVERFOX_CLOUD_URL` 设置。编译和临时目录从 `CARGO_TARGET_DIR` 动态取得，并要求目录位于 D 盘。

目录内存在 `program-private.pem` 时，构建后自动调用现有签名工具的 Ed25519 签名与验签函数，输出 `dist/silverfox-rescue.exe` 和带版本号的 EXE。`SILVERFOX_DIST_DIR` 可统一调整构建与签名工具的发布目录。未签名的编译产物保存在 `<CARGO_TARGET_DIR>`。交互菜单继续用于单独签名、打包及清单验签。

Python 工具的默认文件路径统一由 `tools/tool_paths.py` 管理；`SILVERFOX_KEY_DIR` 和 `SILVERFOX_DIST_DIR` 的相对路径均从项目根目录解析。证书、设备身份和签名密钥的目录约定及生成命令见 [工具说明](tools/README.md)。

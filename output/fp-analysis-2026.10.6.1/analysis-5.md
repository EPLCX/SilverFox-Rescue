# 第5组：8例误报静态分析

判定阈值：可疑0.6770026820，恶意0.9003467306。OOF分数来自该文件所在折的模型；最终模型分数来自训练样本，仅用于观察拟合差异。全程读取文件与签名，不执行样本，不修改模型或样本。

8例中3例具有效企业签名；2例具明确CPython或EasiNote组件身份；2例无签名/版本且带RWX节的向导；1例是接口完整的Phoenix Rust SDK。除POraKs.exe外，其余7例最终训练模型分数均低于可疑阈值。

**关键发现：POraKs.exe与V9YWjN.exe完全同内容，但落在fold5和fold4。** SHA256为676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7，大小139088，327/327个模型特征完全一致，最大差0。主agent重复审计还发现相同SHA存在于SilverFox.W目录的AU0V5T.exe、PpR0B1.exe、Qs14Ad.exe、V9YWjN.exe、xMVah6.exe。这是同内容跨折及白黑标签冲突。

该文件腾讯Authenticode签名Valid，PDB指向UxEnhanceHost、导入UxEnhance64.dll UI增强接口，其他尾部0字节。身份为腾讯签名UxEnhanceHost宿主，依赖外部UxEnhance64.dll。SilverFox.W目录是语料标签，侧载场景可借用合法宿主；应统一宿主字节的文件级标签，并另外保留恶意DLL和侧载上下文。持续高恶意分数与冲突训练标签相符。

|文件|OOF恶意概率|OOF家族|最终训练模型概率|白标签可信度|
|---|---:|---|---:|---|
|POraKs.exe|0.976823|SilverFox.W|0.963375|高：有效腾讯签名、UxEnhanceHost调试身份、无RWX；同时存在数据集标签冲突。|
|uninstall_3.exe|0.964364|SilverFox|0.107853|高：有效网易签名，资源明确标识网易发烧游戏与Inno Setup。|
|wininst-14.0.exe|0.914675|Extortion|0.054964|较高：CPython distutils安装器身份有PDB、PythonCore注册表路径和一致安装器文本互相支持；无签名。|
|NsisHelper.dll|0.886326|Generic|0.086681|中高：EasiNote5/广州视睿版本资源与.NET卸载UI字符串一致；无签名。|
|应用程序向导.exe|0.850238|Extortion|0.060642|中低：缺签名、版本和明确厂商；“向导”身份主要由文件名和结构支持。|
|1531-2026-05-28100058-1779933658632.exe|0.753733|SilverFox|0.066373|高：有效Hainan YouQu签名、ToDesk资源和NSIS manifest互相一致。|
|SOCKS5网络代理向导.exe|0.708700|Extortion|0.035615|中低：代理向导文本/FlySky易语言注册表路径支持用途，缺签名和版本资源。|
|phoenix_core.dll|0.677003|Generic|0.058748|中高：导出接口和配置/HTTPDNS字符串一致指向Phoenix SDK，但无签名或产品资源。|

以下相似特征是静态解释候选。原OOF模型没有保存，未把候选描述为特定树的已证实贡献。

## POraKs.exe

路径：`F:\sliverfox-file\safe\POraKs.exe`；SHA256：`676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7`；大小：139088字节。

OOF fold5，分组`safe-filename:poraks.exe`。OOF概率0.9768229346，预测家族SilverFox.W；最终训练模型概率0.9633752269。

导入 UxEnhance64.dll 的 EnableUxEnhance/DisableUxEnhance，PDB为 D:\qci_workspace\root-workspaces\__qci-pipeline-237585-1\output\platforms_output\Windows\bin\Release\UxEnhanceHost.pdb。身份为腾讯签名UxEnhanceHost宿主，依赖外部UxEnhance64.dll。可能在侧载语料中作为宿主出现，文件字节身份应与恶意依赖DLL上下文分开记录。模型特征缺少签名主体，且把完整证书表计入高熵overlay。

签名状态：Valid；签名主体：CN=Tencent Technology (Shenzhen) Company Limited, O=Tencent Technology (Shenzhen) Company Limited, L=Shenzhen, S=Guangdong Province, C=CN。版本资源：{}。

导入：82项，DLL为UxEnhance64.dll, KERNEL32.dll, SHELL32.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 73728 / 6.4616 / R-X
- .rdata / 42496 / 5.0541 / R--
- .data / 3072 / 2.1548 / RW-
- .pdata / 5120 / 4.6518 / R--
- .tls / 512 / 0.0204 / RW-
- .gfids / 512 / 1.5771 / R--
- .rsrc / 512 / 4.7177 / R--
- .reloc / 2048 / 4.8858 / R--

overlay从129024开始，共10064字节；证书表offset=129024、size=10064、结构有效=True；扣除结构有效证书表后的其他尾部0字节。

相似特征：此样本同SHA在safe和SilverFox.W两种标签中出现，文件级标签冲突是持续高分的重要解释候选。证书表10064字节占文件7.24%，模型overlay_entropy=7.6436，实际其他尾部0字节。

白标签可信度：高：有效腾讯签名、UxEnhanceHost调试身份、无RWX；同时存在数据集标签冲突。

## uninstall_3.exe

路径：`F:\sliverfox-file\safe\uninstall_3.exe`；SHA256：`c08f728f3eb6d3ff818f311751d7a824639d1cdbf0cd11f3c82f0dc888363d15`；大小：2504320字节。

OOF fold1，分组`safe-filename:uninstall_3.exe`。OOF概率0.9643641959，预测家族SilverFox；最终训练模型概率0.1078534525。

Inno Setup卸载器：版本Comments及大量Uninstall/Compression.LZMA1SmallDecompressor字符串一致。CreateProcessW、VirtualAlloc/VirtualProtect和文件注册表API符合安装卸载功能。

签名状态：Valid；签名主体：CN="NetEase (Hangzhou) Network Co., Ltd", O="NetEase (Hangzhou) Network Co., Ltd", L=杭州市, S=浙江省, C=CN, SERIALNUMBER=91330000788831167A, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=浙江省, OID.1.3.6.1.4.1.311.60.2.1.3=CN。版本资源：{"Comments": "This installation was built with Inno Setup.", "CompanyName": "                                                            ", "FileDescription": "网易发烧游戏                                                      ", "FileVersion": "                    ", "LegalCopyright": "                                                                                                    ", "OriginalFileName": "                                                  ", "ProductName": "网易发烧游戏                                                      ", "ProductVersion": "1.0.0.2                                           "}。

导入：150项，DLL为kernel32.dll, comctl32.dll, user32.dll, oleaut32.dll, advapi32.dll；导出2项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 698368 / 6.3905 / R-X
- .itext / 6144 / 6.2487 / R-X
- .data / 15360 / 4.9608 / RW-
- .bss / 0 / 0.0000 / RW-
- .idata / 4608 / 4.8167 / RW-
- .didata / 512 / 2.7588 / RW-
- .edata / 512 / 1.3269 / R--
- .tls / 0 / 0.0000 / RW-
- .rdata / 512 / 1.4002 / R--
- .reloc / 70656 / 6.7112 / R--
- .rsrc / 197120 / 5.7326 / R--

overlay从994816开始，共1509504字节；证书表offset=2499584、size=4736、结构有效=True；扣除结构有效证书表后的其他尾部1504768字节。

相似特征：非证书overlay1504768字节约占60.09%，模型overlay_entropy=7.9998；压缩安装数据和加载/分配API形成恶意打包器相似结构。11节但无RWX。

白标签可信度：高：有效网易签名，资源明确标识网易发烧游戏与Inno Setup。

## wininst-14.0.exe

路径：`F:\sliverfox-file\safe\wininst-14.0.exe`；SHA256：`cd8e84c1f8d1ee3a7014343e3fb236329d2b67c1ec233ea4b208d99e3f95105b`；大小：458240字节。

OOF fold4，分组`safe-filename:wininst-14.0.exe`。OOF概率0.9146749716，预测家族Extortion；最终训练模型概率0.0549642956。

PDB E:\CPython\cpython35\lib\distutils\command\wininst-14.0.pdb；加载python%d%d.dll并执行安装前后脚本。含Python安装目录查找、卸载注册表项。

签名状态：NotSigned；签名主体：无。版本资源：{}。

导入：173项，DLL为COMCTL32.dll, KERNEL32.dll, USER32.dll, GDI32.dll, ADVAPI32.dll, SHELL32.dll, ole32.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 367616 / 6.6058 / R-X
- .rdata / 68608 / 6.2555 / R--
- .data / 3072 / 2.7049 / RW-
- .gfids / 512 / 3.5074 / R--
- .rsrc / 5120 / 4.0283 / R--
- .reloc / 12288 / 6.6138 / R--

overlay从458240开始，共0字节；证书表offset=0、size=0、结构有效=False；扣除结构有效证书表后的其他尾部0字节。

相似特征：173项导入、执行安装脚本/进程与注册表写入、无版本/签名，容易落入功能相近恶意类；6节无RWX、无overlay，不像高熵压缩壳。

白标签可信度：较高：CPython distutils安装器身份有PDB、PythonCore注册表路径和一致安装器文本互相支持；无签名。

## NsisHelper.dll

路径：`F:\sliverfox-file\safe\NsisHelper.dll`；SHA256：`35f5a53689cd433b1ad0f1bd200f0f6b77135e6f13bc91955d6df81e337d962d`；大小：562176字节。

OOF fold1，分组`safe-component:["广州视睿电子科技有限公司 (guangzhou shirui electronics co.)", "easinote5", "nsishelper.dll"]`。OOF概率0.8863258925，预测家族Generic；最终训练模型概率0.0866806434。

仅导入mscoree.dll的_CorDllMain，典型托管.NET模块。NsisHelper、StartUninstall、BtnUninstall_OnClick等字符串与产品卸载辅助界面一致。

签名状态：NotSigned；签名主体：无。版本资源：{"CompanyName": "广州视睿电子科技有限公司 (Guangzhou Shirui Electronics Co.)", "FileDescription": "NsisHelper", "FileVersion": "5.2.4.0", "InternalName": "NsisHelper.dll", "LegalCopyright": "Copyright © 2011-2025 Guangzhou Shirui Electronics Co.,Ltd, All Rights Reserved.", "OriginalFilename": "NsisHelper.dll", "ProductName": "EasiNote5", "ProductVersion": "5.2.4", "Assembly Version": "5.2.4.0"}。

导入：1项，DLL为mscoree.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 252416 / 7.4497 / R-X
- .rsrc / 308736 / 7.5484 / R--
- .reloc / 512 / 0.0980 / R--

overlay从562176开始，共0字节；证书表offset=0、size=0、结构有效=False；扣除结构有效证书表后的其他尾部0字节。

相似特征：text熵7.45、rsrc熵7.55，高熵节2个，托管资源和数据形成壳/恶意载荷统计相似性。无RWX、无overlay、无本机导出。

白标签可信度：中高：EasiNote5/广州视睿版本资源与.NET卸载UI字符串一致；无签名。

## 应用程序向导.exe

路径：`F:\sliverfox-file\safe\应用程序向导.exe`；SHA256：`d860623f7cd1bdfe17c5664587ef1273c692b930f23c9c21f56d26bd8eaa17a9`；大小：1498624字节。

OOF fold5，分组`safe-filename:应用程序向导.exe`。OOF概率0.8502376643，预测家族Extortion；最终训练模型概率0.0606422752。

导入只有USER32/KERNEL32/ADVAPI32，11项API；包含LoadLibraryA/GetProcAddress和注册表读取API，与同组SOCKS5向导共享简小启动器结构。

签名状态：NotSigned；签名主体：无。版本资源：{}。

导入：11项，DLL为USER32.dll, KERNEL32.dll, ADVAPI32.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 1024 / 7.0726 / RWX
- .rdata / 512 / 3.6407 / R--
- .data / 1492992 / 6.9224 / RWX
- .rsrc / 3072 / 3.0387 / R--

overlay从1498624开始，共0字节；证书表offset=0、size=0、结构有效=False；扣除结构有效证书表后的其他尾部0字节。

相似特征：text与data均RWX；text熵7.07，data熵6.92；没有版本资源，稀疏导入/动态API解析/可写可执行节容易与壳或加载器混淆。

白标签可信度：中低：缺签名、版本和明确厂商；“向导”身份主要由文件名和结构支持。

## 1531-2026-05-28100058-1779933658632.exe

路径：`F:\sliverfox-file\safe\1531-2026-05-28100058-1779933658632.exe`；SHA256：`33b930c63412f4173bda8dd5c9fb822247f49081f09a1aab7a575ff1a33ead02`；大小：122733088字节。

OOF fold4，分组`safe-component:["海南有趣科技有限公司", "todesk", "todesk_setup_4.8.9.0_2082.exe"]`。OOF概率0.7537331347，预测家族SilverFox；最终训练模型概率0.0663733910。

ToDesk 4.8.9.0安装器，OriginalFilename ToDesk_Setup_4.8.9.0_2082.exe，NSIS v3.05 manifest。

签名状态：Valid；签名主体：CN="Hainan YouQu Technology Co., Ltd", O="Hainan YouQu Technology Co., Ltd", L=Sanya, S=Hainan, C=CN, SERIALNUMBER=91460000MA5T92TJ7C, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Hainan, OID.1.3.6.1.4.1.311.60.2.1.3=CN。版本资源：{"CompanyName": "海南有趣科技有限公司", "FileDescription": "ToDesk", "ProductName": "ToDesk", "FileVersion": "4.8.9.0", "InternalName": "ToDesk.exe", "LegalCopyright": "Hainan YouQu Technology Co., Ltd", "OriginalFilename": "ToDesk_Setup_4.8.9.0_2082.exe", "ProductVersion": "4.8.9.0"}。

导入：164项，DLL为KERNEL32.dll, USER32.dll, GDI32.dll, SHELL32.dll, ADVAPI32.dll, COMCTL32.dll, ole32.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 26624 / 6.4695 / R-X
- .rdata / 5632 / 5.0061 / R--
- .data / 1536 / 4.0409 / RW-
- .ndata / 0 / 0.0000 / RW-
- .rsrc / 423424 / 3.2023 / R--

overlay从458240开始，共122274848字节；证书表offset=122719776、size=13312、结构有效=True；扣除结构有效证书表后的其他尾部122261536字节。

相似特征：文件122733088字节，非证书尾部122261536字节，占99.62%；overlay_entropy=7.9986，安装包压缩数据是主要相似特征。5节无RWX；文件中偶然upx子串只记录为字节匹配，未用于认定UPX壳。

白标签可信度：高：有效Hainan YouQu签名、ToDesk资源和NSIS manifest互相一致。

## SOCKS5网络代理向导.exe

路径：`F:\sliverfox-file\safe\SOCKS5网络代理向导.exe`；SHA256：`2139ad3c77e9dd65adfab2ae0858a991c89a1508f67413c3079909807c57217a`；大小：187904字节。

OOF fold5，分组`safe-filename:socks5网络代理向导.exe`。OOF概率0.7087003826，预测家族Extortion；最终训练模型概率0.0356150232。

Software\FlySky\E\Install；大量SOCKS5功能文本和http://www.proxycn.com/socks5/page1.htm。仅11个导入，以LoadLibraryA/GetProcAddress动态解析为主。

签名状态：NotSigned；签名主体：无。版本资源：{}。

导入：11项，DLL为USER32.dll, KERNEL32.dll, ADVAPI32.dll；导出0项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 1024 / 3.5620 / R-X
- .rdata / 512 / 3.6407 / R--
- .data / 180736 / 6.4281 / RWX
- .rsrc / 4608 / 4.0063 / R--

overlay从187904开始，共0字节；证书表offset=0、size=0、结构有效=False；扣除结构有效证书表后的其他尾部0字节。

相似特征：data为RWX、导入稀疏、无版本、动态加载，形成壳/加载器相似结构。总熵6.368，无overlay。网络字符串对应向导功能；网络/URL相关元数据已从模型特征中排除。

白标签可信度：中低：代理向导文本/FlySky易语言注册表路径支持用途，缺签名和版本资源。

## phoenix_core.dll

路径：`F:\sliverfox-file\safe\phoenix_core.dll`；SHA256：`966821c2a1e138decd4d9d07cbc7459a3cb2e860ae044d7552283f2e3ac4a854`；大小：2508800字节。

OOF fold4，分组`safe-filename:phoenix_core.dll`。OOF概率0.6770026820，预测家族Generic；最终训练模型概率0.0587476561。

81导出含UNIFFI_META_NAMESPACE_PHOENIX、init/report_metrics/resolve/shutdown以及Rust未来对象接口。PhoenixConfig、HTTPDNS配置、vigil-gateway.cvtapi.com与httpdns-bootstrap.cvtapi.com字符串互相吻合。

签名状态：NotSigned；签名主体：无。版本资源：{}。

导入：132项，DLL为kernel32.dll, bcrypt.dll, ADVAPI32.dll, KERNEL32.dll, ntdll.dll, WS2_32.dll；导出81项。完整API/导出/字符串在evidence-5.json。

节结构（节名 / 原始大小 / 熵 / 权限）：

- .text / 1924096 / 6.5214 / R-X
- .rdata / 525312 / 6.0316 / R--
- .data / 3072 / 2.4813 / RW-
- .fptable / 512 / 0.0000 / RW-
- .reloc / 54784 / 6.6273 / R--

overlay从2508800开始，共0字节；证书表offset=0、size=0、结构有效=False；扣除结构有效证书表后的其他尾部0字节。

相似特征：Rust运行时带315条路径字符串、加密API BCryptGenRandom/SystemFunction036、无版本，可能贡献Generic统计相似性。5节正常无RWX、无overlay、无高熵节；网络字符串本身不参与当前模型。

白标签可信度：中高：导出接口和配置/HTTPDNS字符串一致指向Phoenix SDK，但无签名或产品资源。

## 建议

优先按SHA256解决同内容白黑标签冲突并归入同一折，同时保留侧载宿主与恶意DLL的场景关联；把合法证书表从overlay统计中区分出来。安装/卸载器、托管高熵资源、疑似易语言启动器与Rust SDK是本组主要误报类型。对无签名向导样本补充来源记录，保持标签有依据。

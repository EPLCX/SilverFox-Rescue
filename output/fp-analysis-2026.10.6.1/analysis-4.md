# 第4组误报样本静态分析

样本8例：3例OOF达到恶意阈值，5例达到可疑阈值。可疑阈值0.6770026820，恶意阈值0.9003467306。最终模型分数来自已参与训练的样本，用于定位持续冲突；误报计数采用OOF。读取文件、PE结构、版本和Windows签名，未运行样本。结构相似解释是静态推断；原OOF模型未保存，未做SHAP。

|文件|OOF|OOF家族|最终训练分数|签名|白标签证据|
|---|---:|---|---:|---|---|
|Updater.dll|0.980157|Generic|0.092321|NotSigned/None|中|
|V9YWjN.exe|0.967577|SilverFox.W|0.963375|Valid/Authenticode|标签冲突|
|kaspersky4win202121.23.6.614zh-Hans_46411.exe|0.922943|Generic|0.065195|Valid/Authenticode|高|
|v2rayN.exe|0.891782|SilverFox|0.073279|NotSigned/None|中偏高|
|360zip.sfx|0.852033|Extortion|0.052315|NotSigned/None|中|
|通用密码登录管理向导.exe|0.763078|Extortion|0.040109|NotSigned/None|低|
|VMProtect.exe|0.714443|SilverFox.W|0.084541|Valid/Authenticode|高|
|akshhl.sys|0.688810|Generic|0.046818|Valid/Catalog|高|

## 主要发现

1. V9YWjN.exe 的同SHA内容跨白/病毒标签，同时跨fold：safe/V9YWjN.exe（fold4）、safe/POraKs.exe（fold5）与 virus/SilverFox.W/{AU0V5T,PpR0B1,Qs14Ad,V9YWjN,xMVah6}.exe 同SHA、139088字节。主体是腾讯签名UxEnhanceHost组件，优先统一内容标签与按SHA分组。主agent提供duplicate-audit.json，报告记录该证据。
2. 四例的尾部全部是合法范围且结构有效的WIN_CERTIFICATE：V9YWjN、Kaspersky、VMProtect、akshhl。额外非证书尾部均0。现有PE模型overlay_entropy/overlay_ratio仍包含证书字节，会把签名数据误当高熵尾部。
3. v2rayN巨大overlay有.NET单文件bundle签名（偏移8346472）和依赖名称支持；VMProtect是有效签名的保护软件。封装/压缩结构应增加相应白样本覆盖，而非单凭节名或高熵给恶意标签。
4. 通用密码登录管理向导.exe 只有目录白标签与封装结构，身份依据最弱，建议核对原始来源。7例最终训练分数均低于0.10，V9YWjN仍0.963375，与标签冲突吻合。

## Updater.dll

- 路径：`F:\sliverfox-file\safe\Updater.dll`
- SHA256：`fb6097a0baead6c8a840fbf930825dac6a55c84f7b157f0158b3e71c3371a201`
- 大小：3869184 字节；Machine=0x014c；EntryRVA=0x3a89ce；Subsystem=2。
- OOF=0.980157029，家族=Generic，fold=2；最终训练分数=0.092321225。
- 签名：NotSigned / None；主体：无。
- Overlay：起点3869184，总长0；证书偏移0、长0、结构有效=False；非证书尾部0、熵0.0000。
- 白标签：中。版本资源完整，自述广州视睿 Updater 6.6.2.0；导入仅 mscoree.dll!_CorExeMain，资源中有 WPF XAML 结构。白标签有产品一致性支持，文件无数字签名。
- 相似特征：接近全文件的 .text（3828224 字节）熵7.973，全文件熵7.961，托管程序仅1个导入且文件DLL扩展名对应的PE并未设置DLL特征位。密集托管内容/嵌入资源可能与封装载荷分布相似，具体是否混淆需进一步解析CLI结构。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|3828224|3828180|7.9732|RX|
|.rsrc|39936|39824|4.5986|R|
|.reloc|512|12|0.1019|R|

导入DLL/函数数：mscoree.dll/1。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{"CompanyName": "广州视睿电子科技有限公司 (Guangzhou Shirui Electronics Co.,Ltd)", "FileDescription": "Updater", "FileVersion": "6.6.2.0", "InternalName": "Updater.dll", "LegalCopyright": "Copyright © 2015-2022 Guangzhou Shirui Electronics Co.,Ltd, All Rights Reserved.", "OriginalFilename": "Updater.dll", "ProductName": "Updater", "ProductVersion": "6.6.2-alpha66", "Assembly Version": "6.6.2.0"}`。

## V9YWjN.exe

- 路径：`F:\sliverfox-file\safe\V9YWjN.exe`
- SHA256：`676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7`
- 大小：139088 字节；Machine=0x8664；EntryRVA=0x22ac；Subsystem=2。
- OOF=0.967576601，家族=SilverFox.W，fold=4；最终训练分数=0.963375227。
- 签名：Valid / Authenticode；主体：CN=Tencent Technology (Shenzhen) Company Limited, O=Tencent Technology (Shenzhen) Company Limited, L=Shenzhen, S=Guangdong Province, C=CN。
- Overlay：起点129024，总长10064；证书偏移129024、长10064、结构有效=True；非证书尾部0、熵0.0000。
- 白标签：标签冲突。腾讯有效签名、UxEnhance64.dll 的 Enable/DisableUxEnhance 导入、明文“UX enhancement was enabled successfully”、调试路径 UxEnhanceHost.pdb 共同支持其为腾讯UX增强宿主组件。
- 相似特征：0.963375 的最终训练分数持续偏高，与两个safe、五个SilverFox.W标签的同内容混用一致。此例先归入标签冲突而非普通误报；普通8节结构、无RWX、无额外非证书载荷，不支持仅凭文件结构把它归为病毒。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|73728|73684|6.4616|RX|
|.rdata|42496|42470|5.0541|R|
|.data|3072|7716|2.1548|RW|
|.pdata|5120|4644|4.6518|R|
|.tls|512|9|0.0204|RW|
|.gfids|512|196|1.5771|R|
|.rsrc|512|480|4.7177|R|
|.reloc|2048|1632|4.8858|R|

导入DLL/函数数：UxEnhance64.dll/2, KERNEL32.dll/79, SHELL32.dll/1。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{}`。

## kaspersky4win202121.23.6.614zh-Hans_46411.exe

- 路径：`F:\sliverfox-file\safe\kaspersky4win202121.23.6.614zh-Hans_46411.exe`
- SHA256：`40921b7262e1136c85ae1de03fabde0eb138adbffa98badbb508e2b914c40c92`
- 大小：5765344 字节；Machine=0x014c；EntryRVA=0x3b80；Subsystem=2。
- OOF=0.922942511，家族=Generic，fold=2；最终训练分数=0.065195168。
- 签名：Valid / Authenticode；主体：CN=AO Kaspersky Lab, O=AO Kaspersky Lab, STREET="sh Leningradskoye, 39A / str 2", L=Moscow, S=Moscow, C=RU, OID.1.3.6.1.4.1.311.60.2.1.2=Moscow, OID.1.3.6.1.4.1.311.60.2.1.3=RU, SERIALNUMBER=1027739867473, OID.2.5.4.15=Private Organization。
- Overlay：起点5749248，总长16096；证书偏移5749248、长16096、结构有效=True；非证书尾部0、熵0.0000。
- 白标签：高。有效 AO Kaspersky Lab 签名，版本/公司/产品/原文件名 Setup.exe 一致，白标签支持充分。
- 相似特征：安装器 .rsrc 达5398016字节（熵7.906）、整体熵7.874，占文件约94%。CreateProcessW/VirtualAlloc/VirtualProtect等是安装器正常机制也常见于Loader。证书表16096字节全部被模型计入overlay特征。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|255488|255370|6.6484|RX|
|.rdata|76288|76144|5.3442|R|
|.data|5120|19756|3.3921|RW|
|.didat|512|64|0.5577|RW|
|.rsrc|5398016|5397852|7.9063|R|
|.reloc|12800|12732|6.6358|R|

导入DLL/函数数：KERNEL32.dll/139。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{"CompanyName": "卡巴斯基", "FileDescription": "卡巴斯基 [21.23.6.614.0.258.0]", "FileVersion": "21.23.6.614", "LegalCopyright": "© 2025 AO Kaspersky Lab", "LegalTrademarks": "注册商标和服务标志均为其各自拥有者的财产", "ProductName": "卡巴斯基", "ProductVersion": "21.23.6.614", "InternalName": "Setup", "OriginalFilename": "Setup.exe"}`。

## v2rayN.exe

- 路径：`F:\sliverfox-file\safe\v2rayN.exe`
- SHA256：`76b86e36d2abc605d7aaba7d075ea8aa3b1a82d7891017508cc5e559792a7213`
- 大小：105412447 字节；Machine=0x8664；EntryRVA=0x5c6e50；Subsystem=2。
- OOF=0.891782239，家族=SilverFox，fold=4；最终训练分数=0.073278659。
- 签名：NotSigned / None；主体：无。
- Overlay：起点10033664，总长95378783；证书偏移0、长0、结构有效=False；非证书尾部95378783、熵6.6992。
- 白标签：中偏高。版本资源自述2dust/v2rayN 7.22.5，有 .NET 单文件bundle签名及 v2rayN.dll、deps/runtimeconfig名称；NotSigned，身份一致性支持白标签。
- 相似特征：95,378,783字节非证书overlay占90.48%，但识别到.NET单文件bundle结构，含托管依赖。模型只见overlay长度/熵/嵌入PE等粗特征，容易与携带载荷的Loader/SilverFox相似；原OOF家族SilverFox。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|6703104|6702940|6.4635|RX|
|.CLR_UEF|512|215|3.0864|RX|
|.rdata|1626112|1625670|5.7059|R|
|.data|20992|102248|2.6765|RW|
|.pdata|233984|233820|6.4783|R|
|.didat|512|56|0.4269|RW|
|Section|512|8|-0.0000|RW|
|.rsrc|1415680|1415460|6.4112|R|
|.reloc|31232|30952|5.4476|R|

导入DLL/函数数：KERNEL32.dll/192, ADVAPI32.dll/20, ole32.dll/17, OLEAUT32.dll/27, USER32.dll/2, SHELL32.dll/1, api-ms-win-crt-string-l1-1-0.dll/31, api-ms-win-crt-heap-l1-1-0.dll/8, api-ms-win-crt-convert-l1-1-0.dll/10, api-ms-win-crt-stdio-l1-1-0.dll/28, api-ms-win-crt-environment-l1-1-0.dll/1, api-ms-win-crt-utility-l1-1-0.dll/1, api-ms-win-crt-runtime-l1-1-0.dll/25, api-ms-win-crt-filesystem-l1-1-0.dll/2, api-ms-win-crt-math-l1-1-0.dll/59, api-ms-win-crt-time-l1-1-0.dll/3, api-ms-win-crt-locale-l1-1-0.dll/10。导出数：44（全部逐项见evidence-4.json）。

版本资源：`{"CompanyName": "2dust", "FileDescription": "v2rayN", "FileVersion": "7.22.5.0", "InternalName": "v2rayN.dll", "LegalCopyright": "Copyright © 2017-2026 2dust", "OriginalFilename": "v2rayN.dll", "ProductName": "v2rayN", "ProductVersion": "7.22.5+fcf6c1e3aefa6b0c96c2804a91661b26c39dd5ad", "Assembly Version": "7.22.5.0"}`。

## 360zip.sfx

- 路径：`F:\sliverfox-file\safe\360zip.sfx`
- SHA256：`179b874362fdd6d4461e6e5704f7f273e4cc0d4936d4a9787eaa52f7753c3a99`
- 大小：441344 字节；Machine=0x014c；EntryRVA=0x271ca；Subsystem=2。
- OOF=0.852033262，家族=Extortion，fold=1；最终训练分数=0.052314738。
- 签名：NotSigned / None；主体：无。
- Overlay：起点441344，总长0；证书偏移0、长0、结构有效=False；非证书尾部0、熵0.0000。
- 白标签：中。无签名/版本；静态RTTI含NSevenZ/NCrypto、CAesCbcDecoder、ICryptoGetTextPassword，与7z自解压/密码压缩功能一致。白标签获得功能结构支持。
- 相似特征：VirtualAlloc、文件创建/删除和大量压缩加密类型名称，和Extortion文件操作/加密功能存在表面特征重叠。无RWX、无overlay，无证据显示实际勒索流程。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|253440|252962|6.6014|RX|
|.rdata|55808|55646|4.6593|R|
|.data|9216|22024|4.4940|RW|
|.rsrc|121856|121424|7.0008|R|

导入DLL/函数数：KERNEL32.dll/151, USER32.dll/51, GDI32.dll/1, SHELL32.dll/7, ole32.dll/2, OLEAUT32.dll/5, SHLWAPI.dll/1。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{}`。

## 通用密码登录管理向导.exe

- 路径：`F:\sliverfox-file\safe\通用密码登录管理向导.exe`
- SHA256：`02fa6e1abef1d31caea41eeb3bd10996ceb7f30932eaf5d7f696daf0cb53869e`
- 大小：983552 字节；Machine=0x014c；EntryRVA=0x1000；Subsystem=2。
- OOF=0.763077530，家族=Extortion，fold=5；最终训练分数=0.040108850。
- 签名：NotSigned / None；主体：无。
- Overlay：起点983552，总长0；证书偏移0、长0、结构有效=False；非证书尾部0、熵0.0000。
- 白标签：低。无签名/版本资源，现有静态证据仅支持小型启动stub和较大嵌入数据；白标签来源信息不足，优先核对原始软件来源。
- 相似特征：977920字节 .data 同时RWX，占99.4%，.text仅1024字节；11个导入包含LoadLibraryA/GetProcAddress、注册表读取。类似封装/运行时解包结构，原OOF家族Extortion只是模型近邻，不说明有勒索行为。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|1024|556|3.5620|RX|
|.rdata|512|404|3.6407|R|
|.data|977920|977920|6.8499|RWX|
|.rsrc|3072|2984|3.0419|R|

导入DLL/函数数：USER32.dll/1, KERNEL32.dll/7, ADVAPI32.dll/3。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{}`。

## VMProtect.exe

- 路径：`F:\sliverfox-file\safe\VMProtect.exe`
- SHA256：`951f9bc353fb7e6b20d4ea6395ac000a22c264dda86ff09872225b8e062c5ac2`
- 大小：31358888 字节；Machine=0x8664；EntryRVA=0x3f1e39d；Subsystem=2。
- OOF=0.714442851，家族=SilverFox.W，fold=4；最终训练分数=0.084540697。
- 签名：Valid / Authenticode；主体：E=info@vmpsoft.com, CN=Permyakov Ivan Yurievich IP, O=Permyakov Ivan Yurievich IP, L=Ekaterinburg, S=Sverdlovskaya oblast, C=RU。
- Overlay：起点31347200，总长11688；证书偏移31347200、长11688、结构有效=True；非证书尾部0、熵0.0000。
- 白标签：高。有效签名主体 Permyakov Ivan Yurievich IP，版本资源 VMProtect Software / VMProtect 3.8.4一致；白标签支持充分。
- 相似特征：13节、9节raw为空、6个非标准节名，.l33高熵7.932达30,992,384字节，入口位于封装节，19个导入跨14个descriptor。保护软件自身封装模式与恶意壳程序结构接近，原OOF SilverFox.W。全部尾部11688字节是证书。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|0|19599090|0.0000|RX|
|.rdata|0|16400114|0.0000|R|
|.data|0|271728|0.0000|RW|
|.pdata|0|1159188|0.0000|R|
|.tls|0|13|0.0000|RW|
|.qtmetad|0|272|0.0000|R|
|.gfids|0|2272|0.0000|R|
|_RDATA|0|272|0.0000|R|
|.egE|0|12524033|0.0000|RX|
|.ov=|6144|5900|0.1548|RW|
|.l33|30992384|30992352|7.9323|RX|
|.reloc|512|272|2.6125|R|
|.rsrc|347136|346885|5.0471|R|

导入DLL/函数数：WINMM.dll/1, IMM32.dll/1, OPENGL32.dll/1, WS2_32.dll/1, KERNEL32.dll/1, USER32.dll/1, GDI32.dll/1, ADVAPI32.dll/1, SHELL32.dll/1, ole32.dll/1, OLEAUT32.dll/1, PSAPI.DLL/1, KERNEL32.dll/1, KERNEL32.dll/6。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{"Comments": "", "CompanyName": "VMProtect Software", "FileDescription": "", "FileVersion": "3.8.4.1754", "InternalName": "", "LegalCopyright": "Copyright 2003-2023 VMProtect Software", "OriginalFilename": "", "ProductName": "VMProtect", "ProductVersion": "3.8.4"}`。

## akshhl.sys

- 路径：`F:\sliverfox-file\safe\akshhl.sys`
- SHA256：`4a80438e8c8aa89b9e356fb9320b57d7c01c9b1ff66e7b8fdf69d4022024750c`
- 大小：68536 字节；Machine=0x8664；EntryRVA=0x11000；Subsystem=1。
- OOF=0.688809534，家族=Generic，fold=3；最终训练分数=0.046818470。
- 签名：Valid / Catalog；主体：CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US。
- Overlay：起点54272，总长14264；证书偏移54272、长14264、结构有效=True；非证书尾部0、熵0.0000。
- 白标签：高。Get-AuthenticodeSignature=Valid、SignatureType=Catalog、Microsoft Windows Hardware Compatibility Publisher；版本为SafeNet Sentinel HL Function Device Driver 1.27，内核导入ntoskrnl.exe一致。
- 相似特征：INIT节正常驱动初始化结构同时RWX，PAGE/INIT被特征标为非标准节；35个内核导入和14,264字节证书尾部占20.81%，与用户态PE混训容易使驱动结构成为异常点。数字签名结果提供硬件驱动来源支持。

|节|Raw大小|虚拟大小|熵|权限|
|---|---:|---:|---:|---|
|.text|24064|23710|6.3641|RX|
|.rdata|20992|20704|7.0794|R|
|.data|512|5488|0.4342|RW|
|.pdata|1536|1128|3.5377|R|
|PAGE|3072|2837|5.6986|RX|
|INIT|1536|1376|5.0966|RWX|
|.rsrc|1024|936|3.1339|RW|
|.reloc|512|168|0.5028|R|

导入DLL/函数数：ntoskrnl.exe/35。导出数：0（全部逐项见evidence-4.json）。

版本资源：`{"CompanyName": "SafeNet, Inc.", "FileDescription": "Sentinel HL Device Driver", "FileVersion": "1.27", "InternalName": "akshhl.sys for WIN AMD64", "LegalCopyright": "(c) 2018 SafeNet, Inc. All rights reserved.", "OriginalFilename": "akshhl.sys", "ProductName": "Sentinel HL Function Device Driver", "ProductVersion": "1.27"}`。


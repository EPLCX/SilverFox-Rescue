# 误报样本分析：第1组（8个）

静态读取PE、导入、资源、有限字符串与现有模型特征；未执行任何样本。签名证据来自本机 Get-AuthenticodeSignature。分数为保存的5折OOF校准概率；原OOF模型未保存，下面的结构解释为候选原因，未声称是逐树因果解释。

阈值：可疑0.6770026820，恶意0.9003467306。前4个超过恶意阈值，后4个落在可疑区间。本组5个签名Valid、3个NotSigned；压缩安装/卸载框架集中出现。

## 汇总

|样本|OOF分数|家族|签名|判断|
|---|---:|---|---|---|
|SliverFoxKiller.exe|0.995916|Generic|NotSigned|安全工具结构导致泛化误报候选|
|Firefox Setup 155.0.1.exe|0.976620|SilverFox|Valid|签名支持的安装包误报|
|Uninstall (5).exe|0.930576|SilverFox|NotSigned|无签名搜狗卸载安装框架，优先确认来源|
|inartboard.exe|0.909872|SilverFox|Valid|签名支持的RAR自解压包误报|
|day.exe|0.876199|Extortion|NotSigned|易语言程序壳，白标签来源最值得复核|
|AMDBugReportTool.exe|0.842472|Generic|Valid|签名支持的NSIS工具包误报|
|QQLiveUninstaller.exe|0.734966|Generic|Valid|签名支持的NSIS卸载器误报|
|uninst (4).exe|0.704874|Generic|Valid|签名支持的NSIS卸载器，附节重叠特征|

## SliverFoxKiller.exe

路径：`F:\sliverfox-file\safe\SliverFoxKiller.exe`  
SHA256：`79506e02a602c484c33a67bb5a0735ec5704de5c856d1118cae98102850dc1d1`  
大小：6,282,240字节；架构：x64；入口：0x1bd544（.text）；OOF第4折，概率0.9959156882，预测Generic。

签名：NotSigned；签名者：无；证书指纹：无。

版本资源：无。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/1,969,152|6.3666|0x60000020|
|.rdata|0x1e2000|1,970,176/4,271,104|6.2785|0x40000040|
|.data|0x5f5000|6,241,280/1,024|1.2841|0xc0000040|
|.pdata|0x5f6000|6,242,304/30,208|6.0882|0x40000040|
|.rsrc|0x5fe000|6,272,512/2,048|5.2506|0x40000040|
|.reloc|0x5ff000|6,274,560/7,680|5.3970|0x42000040|

Overlay：0字节，占0.0000%，熵0.0000；证书表0字节包含在overlay统计内。导入：272函数/23DLL。完整导入、头部字段及特征值见evidence-1.json。

不是UPX/SFX结构：6个标准节、无overlay、全文件熵6.4875；高熵64KiB块最高7.9974，.rdata达4,271,104字节。导入进程枚举/TerminateProcess、DeviceIoControl、AdjustTokenPrivileges、CreateProcessAsUserW，以及7条命令类字符串，安全工具与恶意加载/提权程序共享这些底层能力。

无签名/版本信息，但内容明确包含 silverfox-rescue、SilverFoxProtect.sys、隔离区、自更新及自提升参数，与安全救援工具定位一致。白标签有内部文本支持，建议对照项目发布构建SHA256确认来源。

## Firefox Setup 155.0.1.exe

路径：`F:\sliverfox-file\safe\Firefox Setup 155.0.1.exe`  
SHA256：`1dccc5db26b8246c5edf872da2898a981dac5e7fc7bad41a862e37e233b36495`  
大小：91,740,704字节；架构：x86；入口：0x34fa0（UPX1）；OOF第3折，概率0.9766201276，预测SilverFox。

签名：Valid；签名者：CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US；证书指纹：6663D5C4FDAF9EFD5F823A26C9C410DC9928C44A。

版本资源：{"CompanyName": "Mozilla", "FileDescription": "Firefox", "FileVersion": "18.05", "InternalName": "7zS.sfx", "LegalCopyright": "Mozilla", "OriginalFilename": "7zS.sfx.exe", "ProductName": "Firefox", "ProductVersion": "18.05"}。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|UPX0|0x1000|1,024/0|0.0000|0xe0000080|
|UPX1|0x25000|1,024/66,048|7.8779|0xe0000040|
|.rsrc|0x36000|67,072/64,512|7.5273|0xc0000040|

Overlay：91,609,120字节，占99.8566%，熵7.9998；证书表13,712字节包含在overlay统计内。导入：5函数/2DLL。完整导入、头部字段及特征值见evidence-1.json。

UPX0/UPX1 两个RWX节，UPX0无磁盘数据，UPX1熵7.8779；5个导入，含VirtualProtect/LoadLibraryA/GetProcAddress。overlay占99.8566%，熵7.9998，起始为7-Zip安装配置。这是正常压缩安装包与壳/载荷型恶意程序的直接结构重叠。

Authenticode Valid，签名者Mozilla Corporation，与Mozilla/Firefox/7zS.sfx资源一致，白标签可信度高。资源版本18.05是7-Zip SFX stub版本，文件名155.0.1本身未验证为Firefox载荷版本。

## Uninstall (5).exe

路径：`F:\sliverfox-file\safe\Uninstall (5).exe`  
SHA256：`5b4b53ca345a032470fe04c631d0ed77e4f79dd3eff249acb01ad56b8c3893b0`  
大小：4,571,461字节；架构：x86；入口：0x2c2910（UPX1）；OOF第5折，概率0.9305755998，预测SilverFox。

签名：NotSigned；签名者：无；证书指纹：无。

版本资源：{"Comments": "", "CompanyName": "Sogou.com", "FileDescription": "搜狗输入法 安装程序", "FileVersion": "16.8.0.4914", "LegalCopyright": "© 2026 Sogou.com. All rights reserved.", "ProductName": "搜狗输入法", "ProductVersion": "16.8.0.4914"}。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|UPX0|0x1000|1,024/0|0.0000|0xe0000080|
|UPX1|0x2bd000|1,024/23,552|7.8339|0xe0000040|
|.rsrc|0x2c3000|24,576/136,704|6.1333|0xc0000040|

Overlay：4,410,181字节，占96.4720%，熵7.9998；证书表10,624字节包含在overlay统计内。导入：13函数/8DLL。完整导入、头部字段及特征值见evidence-1.json。

UPX0/UPX1两个RWX节、UPX0无raw数据，UPX1熵7.8339，overlay4,410,181字节占96.4720%、熵7.9998。13个导入/8个DLL，仅保留VirtualAlloc/VirtualProtect/LoadLibrary/GetProcAddress等壳入口。压缩stub与SilverFox壳型载荷相似。

资源自称Sogou.com/搜狗输入法16.8.0.4914，overlay有NullsoftInst魔数；无Authenticode签名。框架和资源支持卸载程序解释，但来源验证强度低于厂商签名样本。

## inartboard.exe

路径：`F:\sliverfox-file\safe\inartboard.exe`  
SHA256：`353d1843afa850234367d4aba3970d3aa25b529400f552e98d067ae17f78606b`  
大小：97,541,488字节；架构：x86；入口：0x265c0（.text）；OOF第3折，概率0.9098723598，预测SilverFox。

签名：Valid；签名者：CN="Suzhou Xingcheng Interactive Technology Co., Ltd.", O="Suzhou Xingcheng Interactive Technology Co., Ltd.", L=苏州, S=江苏, C=CN；证书指纹：A2408D0CBB25E36081C7A77EB1338F1B1B4A63D2。

版本资源：无。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/238,592|6.6842|0x60000020|
|.rdata|0x3c000|239,616/52,224|5.1689|0x40000040|
|.data|0x49000|291,840/4,608|4.0290|0xc0000040|
|.didat|0x57000|296,448/512|3.5344|0xc0000040|
|.rsrc|0x58000|296,960/54,784|6.8360|0x40000040|
|.reloc|0x66000|351,744/11,264|6.6081|0x42000040|

Overlay：97,178,480字节，占99.6278%，熵7.9993；证书表10,632字节包含在overlay统计内。导入：157函数/3DLL。完整导入、头部字段及特征值见evidence-1.json。

97,178,480字节overlay占99.6278%、熵7.9993，版本资源缺失；常规6节没有RWX，却全文件熵7.9981。模型可能把几乎全文件的压缩载荷及缺失版本信息视为恶意包特征。

Authenticode Valid，苏州星橙互动技术签名者；overlay以RAR5头526172211a070100起始，含Setup=inArtBoard\inArt_PC.exe及成套Data/Images文件名，符合应用自解压安装包。白标签可信度较高。

## day.exe

路径：`F:\sliverfox-file\safe\day.exe`  
SHA256：`0aa7ddd7ae75d3e3b7cbfd08f5cea7d01ead752d07a3174a6c2bc331d3fb7c6a`  
大小：892,416字节；架构：x86；入口：0x1000（.text）；OOF第2折，概率0.8761988797，预测Extortion。

签名：NotSigned；签名者：无；证书指纹：无。

版本资源：无。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/1,024|3.5620|0x60000020|
|.rdata|0x2000|2,048/512|3.6407|0x40000040|
|.data|0x3000|2,560/886,784|7.8797|0xe0000040|
|.rsrc|0xdc000|889,344/3,072|3.0419|0x40000040|

Overlay：0字节，占0.0000%，熵0.0000；证书表0字节包含在overlay统计内。导入：11函数/3DLL。完整导入、头部字段及特征值见evidence-1.json。

入口0x1000；.text仅1,024字节，.data为RWX、886,784字节占文件99.37%、熵7.8797；仅11个导入，含LoadLibraryA/GetProcAddress及注册表查询。易语言stub+大块高熵可执行数据与多类壳型恶意样本相似，预测Extortion没有静态加密/勒索身份佐证。

入口内嵌krnln.fnr、krnln.fne、GetNewSock及Software\FlySky\E\Install注册表路径，直接支持易语言运行库stub。没有签名/版本/应用身份字符串，白标签只有数据集归档依据，建议先确认采集来源及原始用途。

入口字符串：["krnln.fnr", "krnln.fne", "GetNewSock", "Software\\FlySky\\E\\Install", "Not found the kernel library or the kernel library is invalid!", "Error"]

## AMDBugReportTool.exe

路径：`F:\sliverfox-file\safe\AMDBugReportTool.exe`  
SHA256：`05de24a09c46a0a19ba78ce69b42934972a11c687935f179f77fab9c39c06d48`  
大小：2,976,880字节；架构：x86；入口：0x338f（.text）；OOF第5折，概率0.8424723668，预测Generic。

签名：Valid；签名者：CN=Advanced Micro Devices, O=Advanced Micro Devices, S=California, C=US；证书指纹：33D35682079E201671B738B7209B4586103BC271。

版本资源：{"Comments": "AMD Bug Report Tool", "CompanyName": "Advanced Micro Devices, Inc.", "FileDescription": "AMD Bug Report Tool", "FileVersion": "1.7.0.0", "LegalCopyright": "Copyright (C) 2024 Advanced Micro Devices, Inc.", "LegalTrademarks": "Advanced Micro Devices, Inc.", "ProductName": "AMD Bug Report Tool", "ProductVersion": "23.19"}。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/26,624|6.4522|0x60000020|
|.rdata|0x8000|27,648/5,632|5.0071|0x40000040|
|.data|0xa000|33,280/1,536|4.0353|0xc0000040|
|.ndata|0x35000|0/0|0.0000|0xc0000080|
|.rsrc|0x45000|34,816/566,272|1.0875|0x40000040|

Overlay：2,375,792字节，占79.8081%，熵7.9981；证书表11,528字节包含在overlay统计内。导入：165函数/7DLL。完整导入、头部字段及特征值见evidence-1.json。

overlay2,375,792字节占79.8081%、熵7.9981，.ndata为空raw节。165个导入含CreateProcessW、RegSetValueExW、DeleteFileW、AdjustTokenPrivileges；安装框架的写盘/注册表/提权行为与恶意加载器重叠。

Authenticode Valid，Advanced Micro Devices签名与AMD Bug Report Tool资源一致（FileVersion1.7.0.0/ProductVersion23.19）。NullsoftInst头说明该文件是安装框架包装，白标签可信度高。

## QQLiveUninstaller.exe

路径：`F:\sliverfox-file\safe\QQLiveUninstaller.exe`  
SHA256：`2d2e739696685a22e04a74fad3e9ed5f998619fd184eee5c42e680e6749c7e97`  
大小：3,246,888字节；架构：x86；入口：0x350d（.text）；OOF第1折，概率0.7349664355，预测Generic。

签名：Valid；签名者：CN=Tencent Technology (Shenzhen) Company Limited, O=Tencent Technology (Shenzhen) Company Limited, L=Shenzhen, S=Guangdong Province, C=CN, SERIALNUMBER=9144030071526726XG, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.1=Shenzhen, OID.1.3.6.1.4.1.311.60.2.1.2=Guangdong Province, OID.1.3.6.1.4.1.311.60.2.1.3=CN；证书指纹：E1B5824EE85186B91E65DB3E75867F59E35CF4AB。

版本资源：{"Comments": "F1D829AB-7BA7-4EDB-8984-047500E6F696", "CompanyName": "Tencent Corporation", "FileDescription": "TencentVideo Installer Application", "FileVersion": "11.184.2229.0", "LegalCopyright": "Copyright (C) 1998-2026 Tencent. All Rights Reserved.", "OriginalFilename": "QQLiveSetup_{C0DC-697A-6A57-4d4f-8529-0D79-BF0F-8980-C0DC-697A-6A57-4d4f-8529-0D79-BF0F-8980-7075-F6C0-61C2-4e31-AFD4-281B-A03D-081C}.exe", "ProductName": "TencentVideo"}。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/26,112|6.4265|0x60000020|
|.rdata|0x8000|27,136/5,120|5.1363|0x40000040|
|.data|0xa000|32,256/1,536|4.0058|0xc0000040|
|.ndata|0x2b000|0/0|0.0000|0xc0000080|
|.rsrc|0x6e000|33,792/293,888|5.9457|0x40000040|

Overlay：2,919,208字节，占89.9079%，熵7.9998；证书表10,792字节包含在overlay统计内。导入：164函数/7DLL。完整导入、头部字段及特征值见evidence-1.json。

overlay2,919,208字节占89.9079%、熵7.9998，.ndata无raw数据。164个导入含CreateProcessW、RegSetValueExW、RegDeleteKeyW及AdjustTokenPrivileges。卸载框架的进程/注册表能力和压缩内容提供恶意结构相似性。

Authenticode Valid，腾讯签名；TencentVideo Installer Application、Tencent Corporation资源与NSIS魔数匹配，白标签可信度高。

## uninst (4).exe

路径：`F:\sliverfox-file\safe\uninst (4).exe`  
SHA256：`b7e4b01cf0bf9908c62d9ff631479156f4e73488f28229e628c7fe86484f284f`  
大小：6,017,688字节；架构：x86；入口：0x38af（.text）；OOF第4折，概率0.7048739149，预测Generic。

签名：Valid；签名者：CN=Tencent Technology (Shenzhen) Company Limited, O=Tencent Technology (Shenzhen) Company Limited, L=Shenzhen, S=Guangdong Province, C=CN, SERIALNUMBER=9144030071526726XG, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.1=Shenzhen, OID.1.3.6.1.4.1.311.60.2.1.2=Guangdong Province, OID.1.3.6.1.4.1.311.60.2.1.3=CN；证书指纹：E1B5824EE85186B91E65DB3E75867F59E35CF4AB。

版本资源：无。

|节|RVA|raw偏移/大小|熵|权限字段|
|---|---|---|---:|---|
|.text|0x1000|1,024/29,696|6.4997|0x60000020|
|.rdata|0x9000|30,720/11,264|4.4979|0x40000040|
|.data|0xc000|41,984/512|1.8049|0xc0000040|
|.ndata|0x7f000|0/0|0.0000|0xc0000080|
|.rsrc|0x128000|42,496/15,872|7.6534|0x40000040|
|.reloc|0x12c000|47,104/4,096|7.9239|0x42000040|

Overlay：5,959,320字节，占99.0301%，熵7.9972；证书表10,520字节包含在overlay统计内。导入：172函数/8DLL。完整导入、头部字段及特征值见evidence-1.json。

.rsrc raw范围42,496–58,368与.reloc47,104–51,200重叠，当前提取器overlapping_raw_sections=1；.rsrc熵7.6534、.reloc7.9239。overlay5,959,320字节占99.0301%、熵7.9972；.ndata为空raw数据，版本信息缺失。这些非常规布局/压缩内容均是候选误报因素。

Authenticode Valid，腾讯签名，与button/btn-uninstall资源及NullsoftInst文本互相支持，白标签可信度较高；缺少版本资源，具体腾讯产品身份未从该文件确认。

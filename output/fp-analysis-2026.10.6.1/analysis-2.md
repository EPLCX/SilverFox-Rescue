# 第2组：8个OOF误报样本静态分析

样本来自 assignment-2.json；恶意阈值0.9003467305902508，可疑阈值0.6770026820360666。4例达到恶意阈值（含ws.exe恰好等于阈值），4例为可疑。全程读取PE和Windows签名验证，未运行样本。分数为原5折OOF分数；下面结构相似性是静态解释，未使用未保存的OOF模型计算贡献。

本组4例Windows签名Valid；adig有明确DNS工具指纹；OpenGL为易语言runtime加载器形态；ws与Qzone优先核对来源和完整性。Google、ToDesk、aksusb、UU四者overlay全部等于证书表范围，现有overlay统计包含签名尾部。

## OpenGL应用程序向导.exe

- 路径：`F:\sliverfox-file\safe\OpenGL应用程序向导.exe`
- SHA256：`4724057d84bd4943901a8f426d992e21f6308301b8719469bdac2366eec04fa8`
- 大小：3918336 字节；架构：0x14c（x86）；入口RVA：0x1000；子系统：2。
- OOF：校准分数 0.983253851，原始恶意概率 0.992886264；预测家族 Loader；第5折；group=`safe-filename:opengl应用程序向导.exe`。
- 签名：NotSigned / None；主体：无。
- 节：.text raw=1024 entropy=3.562 flags=0x60000020 EP; .rdata raw=512 entropy=3.641 flags=0x40000040; .data raw=3912704 entropy=4.980 flags=0xe0000040; .rsrc raw=3072 entropy=3.042 flags=0x40000040。
- overlay：0字节；证书目录：offset=0, size=0, 文件范围内=True。
- 白标签判断：中：易语言运行时结构证据；发行来源仍缺少签名或版本锚点。
入口机器码后直接有 krnln.fnr、krnln.fne、GetNewSock、Software\FlySky\E\Install、Path 字符串，符合易语言运行时加载器形态。11个导入中有 LoadLibraryA/GetProcAddress；.text 仅1024字节，而可读写执行的 .data 为3912704字节（99.86%文件体积），无版本资源和签名。此种小stub+大RWX数据布局与Loader有统计相似性；这属于结构解释。

建议：核对原始发布者/易语言工程输出来源；增加合法易语言编译程序覆盖。

## adig.exe

- 路径：`F:\sliverfox-file\safe\adig.exe`
- SHA256：`da169efdf43f4f2e87937efaaaf328dd659e28740411d1904a5bd0908ea5e061`
- 大小：74364 字节；架构：0x8664（x64）；入口RVA：0x1400；子系统：3。
- OOF：校准分数 0.971919746，原始恶意概率 0.984602376；预测家族 Generic；第4折；group=`safe-filename:adig.exe`。
- 签名：NotSigned / None；主体：无。
- 节：.text raw=43008 entropy=6.120 flags=0x60000020 EP; .data raw=512 entropy=1.118 flags=0xc0000040; .rdata raw=12800 entropy=4.971 flags=0x40000040; .pdata raw=1536 entropy=4.250 flags=0x40000040; .xdata raw=1536 entropy=3.779 flags=0x40000040; .bss raw=0 entropy=0.000 flags=0xc0000080; .idata raw=5632 entropy=4.269 flags=0x40000040; .tls raw=512 entropy=0.000 flags=0xc0000040; .rsrc raw=1536 entropy=4.778 flags=0x40000040; .reloc raw=512 entropy=4.710 flags=0x42000040。
- overlay：5756字节；证书目录：offset=0, size=0, 文件范围内=True。
- 白标签判断：中高：DNS工具功能证据明确，未签名。
实际导入 libcares-2.dll 的70个 ares_* 函数及 WS2_32.dll，内嵌 c-ares、; <<>> c-ares DiG %s <<>> 字符串。10节布局包括 .pdata/.xdata/.bss/.idata/.tls，133导入，无RWX节，checksum匹配；更符合MinGW构建DNS工具。没有版本资源且有5756字节低熵overlay（4.24），容易与无版本的小型工具类恶意PE混淆。网络特征部分已被模型排除，DNS导入用于识别功能。

建议：优先补充同工具链/同组件的正常样本；通过原始c-ares发行包核对哈希。

## GoogleEarthProSetup_7.3.2.5776.exe

- 路径：`F:\sliverfox-file\safe\GoogleEarthProSetup_7.3.2.5776.exe`
- SHA256：`2746289c58b2c703b78ee0a203ad3eb264c2db5f7eae5484c9e84b261fb6d062`
- 大小：1214008 字节；架构：0x14c（x86）；入口RVA：0x4e56；子系统：2。
- OOF：校准分数 0.929480443，原始恶意概率 0.938892102；预测家族 Loader；第2折；group=`safe-component:["google llc", "google update", "googleupdatesetup.exe"]`。
- 签名：Valid / Authenticode；主体：CN=Google Inc, O=Google Inc, L=Mountain View, S=California, C=US。
- 节：.text raw=84480 entropy=6.641 flags=0x60000020 EP; .rdata raw=27648 entropy=5.300 flags=0x40000040; .data raw=2048 entropy=2.401 flags=0xc0000040; .gfids raw=512 entropy=1.701 flags=0x40000040; .rsrc raw=1070592 entropy=7.985 flags=0x40000040; .reloc raw=4608 entropy=6.347 flags=0x42000040。
- overlay：23096字节；证书目录：offset=1190912, size=23096, 文件范围内=True。
- 白标签判断：高：有效Google Authenticode与元数据一致。
Google Inc签名Valid并有DigiCert时间戳；版本是Google LLC / Google Update / GoogleUpdateSetup.exe / 1.3.34.7，实际是Google更新安装stub。.rsrc为1070592字节、熵7.985，占主体高熵；.gfids为CFG节；无RWX，99导入。尾部23096字节全部是证书表。打包资源高熵及checksum_mismatch=1与Loader结构相似。

建议：补充同类已签名高熵安装stub；overlay计算宜识别证书表范围。

## ws.exe

- 路径：`F:\sliverfox-file\safe\ws.exe`
- SHA256：`c30fba54c1852b3cb371477d69fc5fccef0a5abff2493e59103a0c9fdbfb3663`
- 大小：109056 字节；架构：0x8664（x64）；入口RVA：0x51cb0；子系统：3。
- OOF：校准分数 0.900346731，原始恶意概率 0.897915986；预测家族 CoinMiner；第3折；group=`safe-filename:ws.exe`。
- 签名：NotSigned / None；主体：无。
- 节：UPX0 raw=0 entropy=0.000 flags=0xe0000080; UPX1 raw=102400 entropy=7.918 flags=0xe0000040 EP; .rsrc raw=5632 entropy=3.188 flags=0xc0000040。
- overlay：0字节；证书目录：offset=0, size=0, 文件范围内=True。
- 白标签判断：低：UPX包装已明确，内部产品身份缺少证据。
UPX0 raw_size=0、virtual_size=229376；UPX1 raw_size=102400、熵7.918，入口0x51cb0落在UPX1；两个节均RWX。仅12导入，包括LoadLibraryA/GetProcAddress/VirtualProtect/OpenThreadToken，无版本和签名。manifest要求highestAvailable。压缩stub和动态导入结构与恶意PE相似性强，CoinMiner标签是分类器输出而非矿工行为证据。

建议：优先核对来源与原始未压缩文件；静态解包后再认定白标签。

## QzoneMusicUninst.exe

- 路径：`F:\sliverfox-file\safe\QzoneMusicUninst.exe`
- SHA256：`d88306fe84102af8b65cda0c9cb740dffd1fec34c61968e8b6ed24f4c62e65af`
- 大小：104684 字节；架构：0x14c（x86）；入口RVA：0x354b；子系统：2。
- OOF：校准分数 0.861454042，原始恶意概率 0.835124898；预测家族 Extortion；第3折；group=`safe-filename:qzonemusicuninst.exe`。
- 签名：NotSigned / None；主体：无。
- 节：.text raw=25600 entropy=6.480 flags=0x60000020 EP; .rdata raw=6656 entropy=4.888 flags=0x40000040; .data raw=512 entropy=1.430 flags=0xc0000040; .ndata raw=0 entropy=0.000 flags=0xc0000080; .rsrc raw=25600 entropy=4.807 flags=0x40000040。
- overlay：45292字节；证书目录：offset=4614472, size=14696, 文件范围内=False。
- 白标签判断：中低：NSIS形态明确，Qzone产品归属证据弱。
manifest内含Nullsoft.NSIS.exehead，.ndata空raw，导入删除文件、注册表修改、CreateProcess/OpenProcess等NSIS通用卸载逻辑。45292字节overlay占43.27%，熵7.996。PE证书目录offset=4614472、size=14696，超出仅104684字节文件边界；Windows签名结果NotSigned，无版本资源。当前文件像截取/重建的NSIS卸载器，Qzone名称之外的产品证据有限。Extortion输出可由高熵卸载负载及文件/注册表API混淆解释。

建议：优先核对原安装包生成的卸载器和文件完整性，避免将损坏/来源不明文件自动认作强可信白样本。

## ToDeskAudio.sys

- 路径：`F:\sliverfox-file\safe\ToDeskAudio.sys`
- SHA256：`d834c5d6c9232717fe2b2271b0c215e7148aaf5a5df30eab2521caf85444bdd5`
- 大小：104984 字节；架构：0x8664（x64）；入口RVA：0x4850；子系统：1。
- OOF：校准分数 0.806744891，原始恶意概率 0.737678359；预测家族 Generic；第3折；group=`safe-filename:todeskaudio.sys`。
- 签名：Valid / Authenticode；主体：CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US。
- 节：.text raw=17920 entropy=6.182 flags=0x68000020 EP; .rdata raw=58880 entropy=7.320 flags=0x48000040; .data raw=3072 entropy=2.742 flags=0xc8000040; .pdata raw=1536 entropy=4.191 flags=0x48000040; PAGE raw=9728 entropy=6.250 flags=0x60000020; INIT raw=2048 entropy=4.468 flags=0x62000020; .reloc raw=512 entropy=4.310 flags=0x42000040。
- overlay：10264字节；证书目录：offset=94720, size=10264, 文件范围内=True。
- 白标签判断：高：有效Microsoft硬件发布者签名、音频驱动功能明确。
Microsoft Windows Hardware Compatibility Publisher Authenticode签名Valid，有时间戳；导入portcls.sys的PcInitializeAdapterDriver/PcNewMiniport/PcNewPort/PcRegisterSubdevice，WDFLDR.SYS及内核API，符合音频驱动。字符串D:\gitlab\VirtualMicrophone\x64\Release\ToDeskAudio.pdb、\BaseNamedObjects\ToDeskVirtualAudio提供功能锚点。Native子系统1，PAGE/INIT为驱动常规节，无版本资源，.rdata熵7.320。10264字节overlay全部为证书表。

建议：补充带签名的音频/WDF驱动覆盖；根据驱动语义理解非标准PAGE/INIT节及内核API。

## aksusb.sys

- 路径：`F:\sliverfox-file\safe\aksusb.sys`
- SHA256：`63ac9315688dc5c67b79dbbd0205f69e3dafec1c4cb104b9f806809472819142`
- 大小：313784 字节；架构：0x8664（x64）；入口RVA：0x3b70；子系统：1。
- OOF：校准分数 0.722455715，原始恶意概率 0.583300226；预测家族 Generic；第1折；group=`safe-component:["safenet, inc.", "sentinel wdm device driver for usb protection devices", "aksusb.sys"]`。
- 签名：Valid / Catalog；主体：CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US。
- 节：.text raw=29184 entropy=6.385 flags=0x68000020 EP; .rdata raw=263680 entropy=7.999 flags=0x48000040; .data raw=1024 entropy=2.347 flags=0xc8000040; .pdata raw=1024 entropy=2.719 flags=0x48000040; PAGE raw=512 entropy=0.831 flags=0x60000020; INIT raw=1536 entropy=4.550 flags=0xe2000020; .rsrc raw=1024 entropy=3.250 flags=0xc2000040; .reloc raw=512 entropy=0.102 flags=0x42000040。
- overlay：14264字节；证书目录：offset=299520, size=14264, 文件范围内=True。
- 白标签判断：高：有效Microsoft Catalog签名及SafeNet版本一致。
Windows返回Valid/Catalog，签名主体Microsoft Windows Hardware Compatibility Publisher。元数据SafeNet, Inc. / Sentinel USB Key Driver / 3.44；导入AKSCLASS.SYS、USBD.SYS的USB描述符和配置请求函数，符合USB授权key驱动。Native子系统1；.rdata 263680字节熵7.999，INIT为RWX（0xe2000020），因此具有高熵+RWX统计信号。14264字节overlay全部为证书表；另有内嵌证书表，但本次Windows成功验证的是Catalog路径。

建议：补充合法加密狗/保护驱动，保留Catalog与嵌入签名区别；高熵数据和INIT节RWX不直接替代功能证据。

## UU-6.16.1-overseas.exe

- 路径：`F:\sliverfox-file\safe\UU-6.16.1-overseas.exe`
- SHA256：`d65eca2d89032b52107c062893bb7a766f02710c76255297022ad2baa351c186`
- 大小：41858040 字节；架构：0x14c（x86）；入口RVA：0x1b1783；子系统：2。
- OOF：校准分数 0.698386204，原始恶意概率 0.540773347；预测家族 Generic；第1折；group=`safe-component:["网易(杭州)网络有限公司", "uu加速器", "install.exe"]`。
- 签名：Valid / Authenticode；主体：CN="NetEase (Hangzhou) Network Co., Ltd", O="NetEase (Hangzhou) Network Co., Ltd", L=杭州市, S=浙江省, C=CN, SERIALNUMBER=91330000788831167A, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=浙江省, OID.1.3.6.1.4.1.311.60.2.1.3=CN。
- 节：.text raw=1929216 entropy=6.905 flags=0x60000020 EP; .rdata raw=523264 entropy=6.075 flags=0x40000040; .data raw=24064 entropy=3.664 flags=0xc0000040; .rsrc raw=39167488 entropy=7.996 flags=0x40000040; .reloc raw=202240 entropy=3.789 flags=0x42000040。
- overlay：10744字节；证书目录：offset=41847296, size=10744, 文件范围内=True。
- 白标签判断：高：有效网易Authenticode与UU元数据一致。
网易NetEase (Hangzhou) Network Co., Ltd签名Valid，有DigiCert时间戳；元数据UU加速器6.16.1.693、OriginalFilename install.exe。.rsrc为39167488字节、熵7.996，占文件93.57%；整文件熵7.971。456导入包含OpenProcess/CreateProcessW/WinExec和19个crypto API，同时可见libcurl/7.65.1、OpenSSL、D:\source\uuclient\src\tun2proxy\third_party\openssl...等真实工具库字符串。10744字节overlay全部为证书表。安装器大压缩资源与进程/加密API形成统计混淆。

建议：补充大资源已签名网络客户端安装器；库功能证据应与恶意能力区分。

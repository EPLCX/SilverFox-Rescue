# 2026.10.6.1 误报样本分析汇总

5个子agent各分析8个文件，共40个OOF误报、39个不同SHA256；17个达到恶意阈值，23个处于可疑区间。全部仅静态读取。逐文件证据包括SHA256、PE节/入口/熵、导入导出、版本资源和本机Windows签名状态。

## 主要发现

1. **内容相同却标签相反：2个SHA256，影响3个白样本误报。** POraKs.exe与V9YWjN.exe和SilverFox.W目录中5个文件完全一致，SHA256为676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7。有效腾讯签名、UxEnhanceHost.pdb、Enable/DisableUxEnhance及外部UxEnhance64.dll导入支持腾讯UX宿主身份；应统一文件级标签，另记录侧载利用上下文。adig.exe与others-virus同hash文件相同，SHA256为da169efdf43f4f2e87937efaaaf328dd659e28740411d1904a5bd0908ea5e061；70个ares_*接口及c-ares DiG字符串支持DNS工具身份。当前remove_conflicting_duplicates按group检查，因此此前conflicts=[]漏掉了跨文件名、跨目录的内容冲突。POraKs/V9同内容也分别落在第5/4折。

2. **签名证书表混入overlay特征。** 40例中18例Windows签名状态Valid、22例NotSigned。dotFix.exe文件27416字节，raw节结束6144，剩余21272字节（77.59%）全部为证书表；Google安装器、ToDeskAudio.sys、aksusb.sys、UU安装器及腾讯宿主等也出现全部尾部为证书表的情况。Python pe_features及C++ pe_metadata目前按节raw结束后全部字节统计overlay大小/熵，混合了证书与真正追加载荷。建议分开记录证书区域和非证书尾部，并保持两端算法一致。

3. **合法压缩安装/卸载包与恶意载荷共享统计结构。** Firefox为UPX+7-Zip SFX，inartboard为RAR5 SFX，AMD/腾讯/ToDesk/网易/Dokan/EasiUpdate等呈NSIS/Inno压缩框架，高熵、大尾部、小加载stub普遍出现。PerfectCalc为UPX保护；v2rayN有.NET单文件bundle；samplerate的大高熵.rdata带音频库导出/PDB；e_sqlite3导出及字符串符合SQLite；VMProtect、驱动RWX INIT节、安全救援工具的权限/驱动操作亦形成恶意相似结构。

4. **优先补充来源证据的白标签。** day.exe、ws.exe、TestApp.exe、EasiUpdateSetup.exe和若干易语言向导没有足够发行来源锚点；QzoneMusicUninst.exe为104684字节文件却声明证书表offset4614472/size14696，目录越过EOF，应检查原始采集完整性。

## 处理优先级

先按SHA256统一重复内容的文件级标签及分组，再区分证书表与其他overlay，随后补充来源明确的合法安装/卸载器、易语言程序、加壳程序、驱动和单文件.NET样本。分类证据弱的样本先核对原始来源。

本次分析未修改语料标签、模型或代码。OOF误报由未见该折样本的模型产生；下面的最终模型概率来自使用全部样本训练的模型，用于观察当前产物对这些已训练样本的表现。40例中38例低于可疑阈值，剩余两例均是上述腾讯宿主同hash标签冲突。

## 逐文件索引

|样本|Agent|OOF概率|最终模型概率（训练样本）|签名状态|同内容标签冲突|
|---|---:|---:|---:|---|---|
|SliverFoxKiller.exe|1|0.995916|0.098789|NotSigned||
|OpenGL应用程序向导.exe|2|0.983254|0.081113|NotSigned||
|samplerate.dll|3|0.982392|0.086778|NotSigned||
|Updater.dll|4|0.980157|0.092321|NotSigned||
|POraKs.exe|5|0.976823|0.963375|Valid|是|
|Firefox Setup 155.0.1.exe|1|0.976620|0.115222|Valid||
|adig.exe|2|0.971920|0.671998|NotSigned|是|
|PerfectCalc.exe|3|0.969614|0.079434|NotSigned||
|V9YWjN.exe|4|0.967577|0.963375|Valid|是|
|uninstall_3.exe|5|0.964364|0.107853|Valid||
|Uninstall (5).exe|1|0.930576|0.105023|NotSigned||
|GoogleEarthProSetup_7.3.2.5776.exe|2|0.929480|0.095961|Valid||
|ieinstal (2).exe|3|0.924415|0.063090|NotSigned||
|kaspersky4win202121.23.6.614zh-Hans_46411.exe|4|0.922943|0.065195|Valid||
|wininst-14.0.exe|5|0.914675|0.054964|NotSigned||
|inartboard.exe|1|0.909872|0.083769|Valid||
|ws.exe|2|0.900347|0.070168|NotSigned||
|dotFix.exe|3|0.892178|0.087648|Valid||
|v2rayN.exe|4|0.891782|0.073279|NotSigned||
|NsisHelper.dll|5|0.886326|0.086681|NotSigned||
|day.exe|1|0.876199|0.065926|NotSigned||
|QzoneMusicUninst.exe|2|0.861454|0.081851|NotSigned||
|Dokan.exe|3|0.853918|0.071271|Valid||
|360zip.sfx|4|0.852033|0.052315|NotSigned||
|应用程序向导.exe|5|0.850238|0.060642|NotSigned||
|AMDBugReportTool.exe|1|0.842472|0.088097|Valid||
|ToDeskAudio.sys|2|0.806745|0.066979|Valid||
|TestApp.exe|3|0.797251|0.041858|NotSigned||
|通用密码登录管理向导.exe|4|0.763078|0.040109|NotSigned||
|1531-2026-05-28100058-1779933658632.exe|5|0.753733|0.066373|Valid||
|QQLiveUninstaller.exe|1|0.734966|0.067498|Valid||
|aksusb.sys|2|0.722456|0.071167|Valid||
|e_sqlite3.dll|3|0.720140|0.054611|NotSigned||
|VMProtect.exe|4|0.714443|0.084541|Valid||
|SOCKS5网络代理向导.exe|5|0.708700|0.035615|NotSigned||
|uninst (4).exe|1|0.704874|0.071458|Valid||
|UU-6.16.1-overseas.exe|2|0.698386|0.077733|Valid||
|EasiUpdateSetup.exe|3|0.696769|0.085176|NotSigned||
|akshhl.sys|4|0.688810|0.046818|Valid||
|phoenix_core.dll|5|0.677003|0.058748|NotSigned||

## 分组报告

- [第1组：8个文件](analysis-1.md)；[完整静态证据](evidence-1.json)
- [第2组：8个文件](analysis-2.md)；[完整静态证据](evidence-2.json)
- [第3组：8个文件](analysis-3.md)；[完整静态证据](evidence-3.json)
- [第4组：8个文件](analysis-4.md)；[完整静态证据](evidence-4.json)
- [第5组：8个文件](analysis-5.md)；[完整静态证据](evidence-5.json)

[内容哈希及跨标签核对](fp-content-audit.json)

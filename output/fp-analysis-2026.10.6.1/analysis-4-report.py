import json
from pathlib import Path
out=Path('output/fp-analysis-2026.10.6.1');doc=json.loads((out/'evidence-4.json').read_text(encoding='utf-8'))
findings={
'Updater.dll':('中','版本资源完整，自述广州视睿 Updater 6.6.2.0；导入仅 mscoree.dll!_CorExeMain，资源中有 WPF XAML 结构。白标签有产品一致性支持，文件无数字签名。','接近全文件的 .text（3828224 字节）熵7.973，全文件熵7.961，托管程序仅1个导入且文件DLL扩展名对应的PE并未设置DLL特征位。密集托管内容/嵌入资源可能与封装载荷分布相似，具体是否混淆需进一步解析CLI结构。'),
'V9YWjN.exe':('标签冲突','腾讯有效签名、UxEnhance64.dll 的 Enable/DisableUxEnhance 导入、明文“UX enhancement was enabled successfully”、调试路径 UxEnhanceHost.pdb 共同支持其为腾讯UX增强宿主组件。','0.963375 的最终训练分数持续偏高，与两个safe、五个SilverFox.W标签的同内容混用一致。此例先归入标签冲突而非普通误报；普通8节结构、无RWX、无额外非证书载荷，不支持仅凭文件结构把它归为病毒。'),
'kaspersky4win202121.23.6.614zh-Hans_46411.exe':('高','有效 AO Kaspersky Lab 签名，版本/公司/产品/原文件名 Setup.exe 一致，白标签支持充分。','安装器 .rsrc 达5398016字节（熵7.906）、整体熵7.874，占文件约94%。CreateProcessW/VirtualAlloc/VirtualProtect等是安装器正常机制也常见于Loader。证书表16096字节全部被模型计入overlay特征。'),
'v2rayN.exe':('中偏高','版本资源自述2dust/v2rayN 7.22.5，有 .NET 单文件bundle签名及 v2rayN.dll、deps/runtimeconfig名称；NotSigned，身份一致性支持白标签。','95,378,783字节非证书overlay占90.48%，但识别到.NET单文件bundle结构，含托管依赖。模型只见overlay长度/熵/嵌入PE等粗特征，容易与携带载荷的Loader/SilverFox相似；原OOF家族SilverFox。'),
'360zip.sfx':('中','无签名/版本；静态RTTI含NSevenZ/NCrypto、CAesCbcDecoder、ICryptoGetTextPassword，与7z自解压/密码压缩功能一致。白标签获得功能结构支持。','VirtualAlloc、文件创建/删除和大量压缩加密类型名称，和Extortion文件操作/加密功能存在表面特征重叠。无RWX、无overlay，无证据显示实际勒索流程。'),
'通用密码登录管理向导.exe':('低','无签名/版本资源，现有静态证据仅支持小型启动stub和较大嵌入数据；白标签来源信息不足，优先核对原始软件来源。','977920字节 .data 同时RWX，占99.4%，.text仅1024字节；11个导入包含LoadLibraryA/GetProcAddress、注册表读取。类似封装/运行时解包结构，原OOF家族Extortion只是模型近邻，不说明有勒索行为。'),
'VMProtect.exe':('高','有效签名主体 Permyakov Ivan Yurievich IP，版本资源 VMProtect Software / VMProtect 3.8.4一致；白标签支持充分。','13节、9节raw为空、6个非标准节名，.l33高熵7.932达30,992,384字节，入口位于封装节，19个导入跨14个descriptor。保护软件自身封装模式与恶意壳程序结构接近，原OOF SilverFox.W。全部尾部11688字节是证书。'),
'akshhl.sys':('高','Get-AuthenticodeSignature=Valid、SignatureType=Catalog、Microsoft Windows Hardware Compatibility Publisher；版本为SafeNet Sentinel HL Function Device Driver 1.27，内核导入ntoskrnl.exe一致。','INIT节正常驱动初始化结构同时RWX，PAGE/INIT被特征标为非标准节；35个内核导入和14,264字节证书尾部占20.81%，与用户态PE混训容易使驱动结构成为异常点。数字签名结果提供硬件驱动来源支持。')
}
text=['# 第4组误报样本静态分析','', '样本8例：3例OOF达到恶意阈值，5例达到可疑阈值。可疑阈值0.6770026820，恶意阈值0.9003467306。最终模型分数来自已参与训练的样本，用于定位持续冲突；误报计数采用OOF。读取文件、PE结构、版本和Windows签名，未运行样本。结构相似解释是静态推断；原OOF模型未保存，未做SHAP。','', '|文件|OOF|OOF家族|最终训练分数|签名|白标签证据|','|---|---:|---|---:|---|---|']
for r in doc['samples']:
 name=Path(r['path']).name;rating,label,why=findings[name]
 r['analysis']=dict(white_label_evidence=rating,label_reason=label,similarity_reason=why)
 text.append(f'|{name}|{r["probability"]:.6f}|{r["predicted_family"]}|{r["final_model_probability"]:.6f}|{r["signature"]["status"]}/{r["signature"]["signatureType"]}|{rating}|')
text+=['','## 主要发现','','1. V9YWjN.exe 的同SHA内容跨白/病毒标签，同时跨fold：safe/V9YWjN.exe（fold4）、safe/POraKs.exe（fold5）与 virus/SilverFox.W/{AU0V5T,PpR0B1,Qs14Ad,V9YWjN,xMVah6}.exe 同SHA、139088字节。主体是腾讯签名UxEnhanceHost组件，优先统一内容标签与按SHA分组。主agent提供duplicate-audit.json，报告记录该证据。','2. 四例的尾部全部是合法范围且结构有效的WIN_CERTIFICATE：V9YWjN、Kaspersky、VMProtect、akshhl。额外非证书尾部均0。现有PE模型overlay_entropy/overlay_ratio仍包含证书字节，会把签名数据误当高熵尾部。','3. v2rayN巨大overlay有.NET单文件bundle签名（偏移8346472）和依赖名称支持；VMProtect是有效签名的保护软件。封装/压缩结构应增加相应白样本覆盖，而非单凭节名或高熵给恶意标签。','4. 通用密码登录管理向导.exe 只有目录白标签与封装结构，身份依据最弱，建议核对原始来源。7例最终训练分数均低于0.10，V9YWjN仍0.963375，与标签冲突吻合。','']
for r in doc['samples']:
 name=Path(r['path']).name;rating,label,why=findings[name];ov=r['overlay']
 text += [f'## {name}','',f'- 路径：`{r["path"]}`',f'- SHA256：`{r["sha256"]}`',f'- 大小：{r["size"]} 字节；Machine=0x{r["machine"]:04x}；EntryRVA=0x{r["entrypoint"]:x}；Subsystem={r["subsystem"]}。',f'- OOF={r["probability"]:.9f}，家族={r["predicted_family"]}，fold={r["fold"]}；最终训练分数={r["final_model_probability"]:.9f}。',f'- 签名：{r["signature"]["status"]} / {r["signature"]["signatureType"]}；主体：{r["signature"]["subject"] or "无"}。',f'- Overlay：起点{ov["start"]}，总长{ov["total_bytes"]}；证书偏移{ov["certificate_table_offset"]}、长{ov["certificate_table_size"]}、结构有效={ov["certificate_structure_valid"]}；非证书尾部{ov["noncertificate_bytes"]}、熵{ov["noncertificate_entropy"]:.4f}。',f'- 白标签：{rating}。{label}',f'- 相似特征：{why}','', '|节|Raw大小|虚拟大小|熵|权限|','|---|---:|---:|---:|---|']
 for z in r['sections']:text.append(f'|{z["name"]}|{z["raw_size"]}|{z["virtual_size"]}|{z["entropy"]:.4f}|'+''.join(k.upper() for k in ['r','w','x'] if z[k])+'|')
 text+=['','导入DLL/函数数：'+', '.join(z['dll']+'/'+str(len(z['functions'])) for z in r['imports'])+f'。导出数：{len(r["exports"])}（全部逐项见evidence-4.json）。','', '版本资源：`'+json.dumps(r['version'],ensure_ascii=False)+'`。','']
doc['duplicate_label_conflict']=dict(sha256='676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7',safe=['V9YWjN.exe','POraKs.exe'],virus_silverfox_w=['AU0V5T.exe','PpR0B1.exe','Qs14Ad.exe','V9YWjN.exe','xMVah6.exe'],evidence_source='duplicate-audit.json from parent agent')
doc['v2rayN_bundle']=dict(signature_offset=8346472,v2rayN_dll_string_offset=8346512,deps_json_string_offset=105412431,runtimeconfig_json_string_offset=105398953)
(out/'evidence-4.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding='utf-8')
(out/'analysis-4.md').write_text('\n'.join(text)+'\n',encoding='utf-8')


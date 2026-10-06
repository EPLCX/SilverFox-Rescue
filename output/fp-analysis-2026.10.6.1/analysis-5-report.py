import json
from pathlib import Path
out=Path('output/fp-analysis-2026.10.6.1')
d=json.loads((out/'evidence-5.json').read_text(encoding='utf-8'))
notes={
'POraKs.exe':('高：有效腾讯签名、UxEnhanceHost调试身份、无RWX；同时存在数据集标签冲突。','导入 UxEnhance64.dll 的 EnableUxEnhance/DisableUxEnhance，PDB为 D:\\qci_workspace\\root-workspaces\\__qci-pipeline-237585-1\\output\\platforms_output\\Windows\\bin\\Release\\UxEnhanceHost.pdb。身份为腾讯签名UxEnhanceHost宿主，依赖外部UxEnhance64.dll。可能在侧载语料中作为宿主出现，文件字节身份应与恶意依赖DLL上下文分开记录。模型特征缺少签名主体，且把完整证书表计入高熵overlay。','此样本同SHA在safe和SilverFox.W两种标签中出现，文件级标签冲突是持续高分的重要解释候选。证书表10064字节占文件7.24%，模型overlay_entropy=7.6436，实际其他尾部0字节。'),
'uninstall_3.exe':('高：有效网易签名，资源明确标识网易发烧游戏与Inno Setup。','Inno Setup卸载器：版本Comments及大量Uninstall/Compression.LZMA1SmallDecompressor字符串一致。CreateProcessW、VirtualAlloc/VirtualProtect和文件注册表API符合安装卸载功能。','非证书overlay1504768字节约占60.09%，模型overlay_entropy=7.9998；压缩安装数据和加载/分配API形成恶意打包器相似结构。11节但无RWX。'),
'wininst-14.0.exe':('较高：CPython distutils安装器身份有PDB、PythonCore注册表路径和一致安装器文本互相支持；无签名。','PDB E:\\CPython\\cpython35\\lib\\distutils\\command\\wininst-14.0.pdb；加载python%d%d.dll并执行安装前后脚本。含Python安装目录查找、卸载注册表项。','173项导入、执行安装脚本/进程与注册表写入、无版本/签名，容易落入功能相近恶意类；6节无RWX、无overlay，不像高熵压缩壳。'),
'NsisHelper.dll':('中高：EasiNote5/广州视睿版本资源与.NET卸载UI字符串一致；无签名。','仅导入mscoree.dll的_CorDllMain，典型托管.NET模块。NsisHelper、StartUninstall、BtnUninstall_OnClick等字符串与产品卸载辅助界面一致。','text熵7.45、rsrc熵7.55，高熵节2个，托管资源和数据形成壳/恶意载荷统计相似性。无RWX、无overlay、无本机导出。'),
'应用程序向导.exe':('中低：缺签名、版本和明确厂商；“向导”身份主要由文件名和结构支持。','导入只有USER32/KERNEL32/ADVAPI32，11项API；包含LoadLibraryA/GetProcAddress和注册表读取API，与同组SOCKS5向导共享简小启动器结构。','text与data均RWX；text熵7.07，data熵6.92；没有版本资源，稀疏导入/动态API解析/可写可执行节容易与壳或加载器混淆。'),
'1531-2026-05-28100058-1779933658632.exe':('高：有效Hainan YouQu签名、ToDesk资源和NSIS manifest互相一致。','ToDesk 4.8.9.0安装器，OriginalFilename ToDesk_Setup_4.8.9.0_2082.exe，NSIS v3.05 manifest。','文件122733088字节，非证书尾部122261536字节，占99.62%；overlay_entropy=7.9986，安装包压缩数据是主要相似特征。5节无RWX；文件中偶然upx子串只记录为字节匹配，未用于认定UPX壳。'),
'SOCKS5网络代理向导.exe':('中低：代理向导文本/FlySky易语言注册表路径支持用途，缺签名和版本资源。','Software\\FlySky\\E\\Install；大量SOCKS5功能文本和http://www.proxycn.com/socks5/page1.htm。仅11个导入，以LoadLibraryA/GetProcAddress动态解析为主。','data为RWX、导入稀疏、无版本、动态加载，形成壳/加载器相似结构。总熵6.368，无overlay。网络字符串对应向导功能；网络/URL相关元数据已从模型特征中排除。'),
'phoenix_core.dll':('中高：导出接口和配置/HTTPDNS字符串一致指向Phoenix SDK，但无签名或产品资源。','81导出含UNIFFI_META_NAMESPACE_PHOENIX、init/report_metrics/resolve/shutdown以及Rust未来对象接口。PhoenixConfig、HTTPDNS配置、vigil-gateway.cvtapi.com与httpdns-bootstrap.cvtapi.com字符串互相吻合。','Rust运行时带315条路径字符串、加密API BCryptGenRandom/SystemFunction036、无版本，可能贡献Generic统计相似性。5节正常无RWX、无overlay、无高熵节；网络字符串本身不参与当前模型。')}
lines=['# 第5组：8例误报静态分析','', '判定阈值：可疑0.6770026820，恶意0.9003467306。OOF分数来自该文件所在折的模型；最终模型分数来自训练样本，仅用于观察拟合差异。全程读取文件与签名，不执行样本，不修改模型或样本。','', '8例中3例具有效企业签名；2例具明确CPython或EasiNote组件身份；2例无签名/版本且带RWX节的向导；1例是接口完整的Phoenix Rust SDK。除POraKs.exe外，其余7例最终训练模型分数均低于可疑阈值。','', '**关键发现：POraKs.exe与V9YWjN.exe完全同内容，但落在fold5和fold4。** SHA256为676a2a7b94ca2f8ec76352ee656e4d075bb342bd7ad6efbc7c19c060001eace7，大小139088，327/327个模型特征完全一致，最大差0。主agent重复审计还发现相同SHA存在于SilverFox.W目录的AU0V5T.exe、PpR0B1.exe、Qs14Ad.exe、V9YWjN.exe、xMVah6.exe。这是同内容跨折及白黑标签冲突。','', '该文件腾讯Authenticode签名Valid，PDB指向UxEnhanceHost、导入UxEnhance64.dll UI增强接口，其他尾部0字节。身份为腾讯签名UxEnhanceHost宿主，依赖外部UxEnhance64.dll。SilverFox.W目录是语料标签，侧载场景可借用合法宿主；应统一宿主字节的文件级标签，并另外保留恶意DLL和侧载上下文。持续高恶意分数与冲突训练标签相符。','', '|文件|OOF恶意概率|OOF家族|最终训练模型概率|白标签可信度|','|---|---:|---|---:|---|']
for r in d['samples'][:8]:
 name=Path(r['sample']['path']).name;note=notes[name]
 lines.append(f"|{name}|{r['sample']['probability']:.6f}|{r['sample']['predicted_family']}|{r['sample']['final_model_probability']:.6f}|{note[0]}|")
lines+=['','以下相似特征是静态解释候选。原OOF模型没有保存，未把候选描述为特定树的已证实贡献。']
for r in d['samples'][:8]:
 name=Path(r['sample']['path']).name;n=notes[name];o=r['overlay'];s=r['signature'];m=r['model_scalars']
 lines+=['',f'## {name}','',f"路径：`{r['sample']['path']}`；SHA256：`{r['sha256']}`；大小：{r['size']}字节。",'',f"OOF fold{r['sample']['fold']}，分组`{r['sample']['group']}`。OOF概率{r['sample']['probability']:.10f}，预测家族{r['sample']['predicted_family']}；最终训练模型概率{r['sample']['final_model_probability']:.10f}。",'',n[1],'',f"签名状态：{s['status']}；签名主体：{s['subject'] or '无'}。版本资源：{json.dumps(r['version'],ensure_ascii=False)}。",'',f"导入：{int(m['import_function_count'])}项，DLL为{', '.join(r['imports'])}；导出{len(r['exports'])}项。完整API/导出/字符串在evidence-5.json。",'', '节结构（节名 / 原始大小 / 熵 / 权限）：','']
 for sec in r['sections']:
  flags=('R' if sec['r'] else '-')+('W' if sec['w'] else '-')+('X' if sec['x'] else '-')
  lines.append(f"- {sec['name']} / {sec['size']} / {sec['entropy']:.4f} / {flags}")
 lines+=['',f"overlay从{o['start']}开始，共{o['total_bytes']}字节；证书表offset={o['certificate_offset']}、size={o['certificate_size']}、结构有效={o['certificate_table_structurally_valid']}；扣除结构有效证书表后的其他尾部{o['non_certificate_tail_bytes']}字节。",'', '相似特征：'+n[2],'','白标签可信度：'+n[0]]
lines+=['','## 建议','', '优先按SHA256解决同内容白黑标签冲突并归入同一折，同时保留侧载宿主与恶意DLL的场景关联；把合法证书表从overlay统计中区分出来。安装/卸载器、托管高熵资源、疑似易语言启动器与Rust SDK是本组主要误报类型。对无签名向导样本补充来源记录，保持标签有依据。']
(out/'analysis-5.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')

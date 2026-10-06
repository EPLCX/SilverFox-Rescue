import json,re
from pathlib import Path
import pefile
base=Path('output/fp-analysis-2026.10.6.1')
e=json.loads((base/'evidence-1.json').read_text(encoding='utf-8'))
notes={
'SliverFoxKiller.exe':('安全工具结构导致泛化误报候选','无签名/版本信息，但内容明确包含 silverfox-rescue、SilverFoxProtect.sys、隔离区、自更新及自提升参数，与安全救援工具定位一致。白标签有内部文本支持，建议对照项目发布构建SHA256确认来源。','不是UPX/SFX结构：6个标准节、无overlay、全文件熵6.4875；高熵64KiB块最高7.9974，.rdata达4,271,104字节。导入进程枚举/TerminateProcess、DeviceIoControl、AdjustTokenPrivileges、CreateProcessAsUserW，以及7条命令类字符串，安全工具与恶意加载/提权程序共享这些底层能力。'),
'Firefox Setup 155.0.1.exe':('签名支持的安装包误报','Authenticode Valid，签名者Mozilla Corporation，与Mozilla/Firefox/7zS.sfx资源一致，白标签可信度高。资源版本18.05是7-Zip SFX stub版本，文件名155.0.1本身未验证为Firefox载荷版本。','UPX0/UPX1 两个RWX节，UPX0无磁盘数据，UPX1熵7.8779；5个导入，含VirtualProtect/LoadLibraryA/GetProcAddress。overlay占99.8566%，熵7.9998，起始为7-Zip安装配置。这是正常压缩安装包与壳/载荷型恶意程序的直接结构重叠。'),
'Uninstall (5).exe':('无签名搜狗卸载安装框架，优先确认来源','资源自称Sogou.com/搜狗输入法16.8.0.4914，overlay有NullsoftInst魔数；无Authenticode签名。框架和资源支持卸载程序解释，但来源验证强度低于厂商签名样本。','UPX0/UPX1两个RWX节、UPX0无raw数据，UPX1熵7.8339，overlay4,410,181字节占96.4720%、熵7.9998。13个导入/8个DLL，仅保留VirtualAlloc/VirtualProtect/LoadLibrary/GetProcAddress等壳入口。压缩stub与SilverFox壳型载荷相似。'),
'inartboard.exe':('签名支持的RAR自解压包误报','Authenticode Valid，苏州星橙互动技术签名者；overlay以RAR5头526172211a070100起始，含Setup=inArtBoard\\inArt_PC.exe及成套Data/Images文件名，符合应用自解压安装包。白标签可信度较高。','97,178,480字节overlay占99.6278%、熵7.9993，版本资源缺失；常规6节没有RWX，却全文件熵7.9981。模型可能把几乎全文件的压缩载荷及缺失版本信息视为恶意包特征。'),
'day.exe':('易语言程序壳，白标签来源最值得复核','入口内嵌krnln.fnr、krnln.fne、GetNewSock及Software\\FlySky\\E\\Install注册表路径，直接支持易语言运行库stub。没有签名/版本/应用身份字符串，白标签只有数据集归档依据，建议先确认采集来源及原始用途。','入口0x1000；.text仅1,024字节，.data为RWX、886,784字节占文件99.37%、熵7.8797；仅11个导入，含LoadLibraryA/GetProcAddress及注册表查询。易语言stub+大块高熵可执行数据与多类壳型恶意样本相似，预测Extortion没有静态加密/勒索身份佐证。'),
'AMDBugReportTool.exe':('签名支持的NSIS工具包误报','Authenticode Valid，Advanced Micro Devices签名与AMD Bug Report Tool资源一致（FileVersion1.7.0.0/ProductVersion23.19）。NullsoftInst头说明该文件是安装框架包装，白标签可信度高。','overlay2,375,792字节占79.8081%、熵7.9981，.ndata为空raw节。165个导入含CreateProcessW、RegSetValueExW、DeleteFileW、AdjustTokenPrivileges；安装框架的写盘/注册表/提权行为与恶意加载器重叠。'),
'QQLiveUninstaller.exe':('签名支持的NSIS卸载器误报','Authenticode Valid，腾讯签名；TencentVideo Installer Application、Tencent Corporation资源与NSIS魔数匹配，白标签可信度高。','overlay2,919,208字节占89.9079%、熵7.9998，.ndata无raw数据。164个导入含CreateProcessW、RegSetValueExW、RegDeleteKeyW及AdjustTokenPrivileges。卸载框架的进程/注册表能力和压缩内容提供恶意结构相似性。'),
'uninst (4).exe':('签名支持的NSIS卸载器，附节重叠特征','Authenticode Valid，腾讯签名，与button/btn-uninstall资源及NullsoftInst文本互相支持，白标签可信度较高；缺少版本资源，具体腾讯产品身份未从该文件确认。','.rsrc raw范围42,496–58,368与.reloc47,104–51,200重叠，当前提取器overlapping_raw_sections=1；.rsrc熵7.6534、.reloc7.9239。overlay5,959,320字节占99.0301%、熵7.9972；.ndata为空raw数据，版本信息缺失。这些非常规布局/压缩内容均是候选误报因素。')}
lines=['# 误报样本分析：第1组（8个）','','静态读取PE、导入、资源、有限字符串与现有模型特征；未执行任何样本。签名证据来自本机 Get-AuthenticodeSignature。分数为保存的5折OOF校准概率；原OOF模型未保存，下面的结构解释为候选原因，未声称是逐树因果解释。','','阈值：可疑0.6770026820，恶意0.9003467306。前4个超过恶意阈值，后4个落在可疑区间。本组5个签名Valid、3个NotSigned；压缩安装/卸载框架集中出现。','','## 汇总','','|样本|OOF分数|家族|签名|判断|','|---|---:|---|---|---|']
for s in e['samples']:
 n=Path(s['path']).name;s['assessment'],s['label_evidence'],s['structural_hypothesis']=notes[n]
 data=Path(s['path']).read_bytes();p=pefile.PE(data=data)
 for d,sec in zip(s['sections'],p.sections):d['raw_offset']=sec.PointerToRawData
 if n=='day.exe':s['entry_strings']= [v.decode('ascii','replace') for v in re.findall(rb'[ -~]{5,}',p.get_data(p.OPTIONAL_HEADER.AddressOfEntryPoint,556))];s['entry_hex_first128']=p.get_data(p.OPTIONAL_HEADER.AddressOfEntryPoint,128).hex()
 lines.append(f"|{n}|{s['probability']:.6f}|{s['predicted_family']}|{s['signature']['status']}|{s['assessment']}|")
for s in e['samples']:
 n=Path(s['path']).name;f=s['selected_features'];sig=s['signature']
 lines+=['',f'## {n}','',f"路径：`{s['path']}`  ",f"SHA256：`{s['sha256']}`  ",f"大小：{s['size']:,}字节；架构：{'x64' if s['machine']=='0x8664' else 'x86'}；入口：{s['entry_rva']}（{s['entry_section']}）；OOF第{s['fold']}折，概率{s['probability']:.10f}，预测{s['predicted_family']}。",'',f"签名：{sig['status']}；签名者：{sig['subject'] or '无'}；证书指纹：{sig['thumbprint'] or '无'}。",'',f"版本资源：{json.dumps(s['versions'],ensure_ascii=False) if s['versions'] else '无'}。",'', '|节|RVA|raw偏移/大小|熵|权限字段|','|---|---|---|---:|---|']
 for sec in s['sections']:lines.append(f"|{sec['name']}|{sec['rva']}|{sec['raw_offset']:,}/{sec['raw_size']:,}|{sec['entropy']:.4f}|{sec['characteristics']}|")
 lines+=['',f"Overlay：{s['overlay_size']:,}字节，占{100*f['pe_overlay_ratio']:.4f}%，熵{f['overlay_entropy']:.4f}；证书表{s['certificate_table_size']:,}字节包含在overlay统计内。导入：{int(f['import_function_count'])}函数/{int(f['import_dll_count'])}DLL。完整导入、头部字段及特征值见evidence-1.json。",'',s['structural_hypothesis'],'',s['label_evidence']]
 if n=='day.exe':lines+=['', '入口字符串：'+json.dumps(s['entry_strings'],ensure_ascii=False)]
(base/'evidence-1.json').write_text(json.dumps(e,ensure_ascii=False,indent=2),encoding='utf-8')
(base/'analysis-1.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('written analysis-1.md and evidence-1.json')

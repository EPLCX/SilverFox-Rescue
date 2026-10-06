import sys,json,hashlib,re,datetime
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
import pefile,numpy as np
from tools.train_static_ml import extract_features,FEATURE_NAMES
out=Path('output/fp-analysis-2026.10.6.1')
a=json.loads((out/'assignment-2.json').read_text(encoding='utf-8-sig'))
result={'scope':'static-only, OOF probabilities from assignment, no sample execution','thresholds':{k:v for k,v in a.items() if k!='samples'},'samples':[]}
for row in a['samples']:
 p=Path(row['path']); data=p.read_bytes(); pe=pefile.PE(data=data)
 s=dict(row); s.update(sha256=hashlib.sha256(data).hexdigest(),size=len(data),machine=hex(pe.FILE_HEADER.Machine),subsystem=pe.OPTIONAL_HEADER.Subsystem,entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),timestamp=pe.FILE_HEADER.TimeDateStamp)
 s['sections']=[{'name':sec.Name.rstrip(b'\0').decode('ascii','replace'),'rva':hex(sec.VirtualAddress),'raw_offset':sec.PointerToRawData,'raw_size':sec.SizeOfRawData,'virtual_size':sec.Misc_VirtualSize,'characteristics':hex(sec.Characteristics),'entropy':sec.get_entropy(),'entry_contains':sec.contains_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)} for sec in pe.sections]
 ov=pe.get_overlay_data_start_offset(); s['overlay_offset']=ov;s['overlay_size']=len(data)-ov if ov is not None else 0
 s['imports']={ent.dll.decode('ascii','replace'):[imp.name.decode('ascii','replace') if imp.name else 'ordinal:'+str(imp.ordinal) for imp in ent.imports] for ent in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}
 version={}
 for block in getattr(pe,'FileInfo',[]):
  for item in block:
   if hasattr(item,'StringTable'):
    for table in item.StringTable:
     version.update({k.decode('utf-8','replace'):v.decode('utf-8','replace') for k,v in table.entries.items()})
 s['version']=version
 secdir=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4];s['certificate_table']={'offset':secdir.VirtualAddress,'size':secdir.Size}
 strings=[m.group().decode('ascii','replace') for m in re.finditer(rb'[\x20-\x7e]{6,}',data)]
 strings+= [m.group().decode('utf-16le','replace') for m in re.finditer(rb'(?:[\x20-\x7e]\x00){6,}',data)]
 terms=re.compile(r'(?i)(http|openssl|ares|curl|socket|UPX|NSIS|Nullsoft|Inno|NetEase|ToDesk|Safenet|Aladdin|Qzone|Tencent|QQ|winpcap|nmap|wires|OpenGL|Google|CreateRemoteThread|VirtualAlloc|WriteProcessMemory|cmd\.exe|powershell|uninstall|winsock|WebSocket|webshell)')
 s['selected_strings']=list(dict.fromkeys(st[:220] for st in strings if terms.search(st)))[:90]
 feats=extract_features(data,len(data),p,[]);s['model_features']={n:float(v) for n,v in zip(FEATURE_NAMES,feats) if not n.startswith('byte_frequency_')}
 result['samples'].append(s)
 print(json.dumps({'name':p.name,'size':len(data),'sections':s['sections'],'version':version,'imports':s['imports'],'strings':s['selected_strings'],'features':s['model_features']},ensure_ascii=False))
(out/'evidence-2.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')

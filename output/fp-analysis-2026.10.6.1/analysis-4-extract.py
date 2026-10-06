import sys,json,hashlib,re,math
from pathlib import Path
import numpy as np,pefile
sys.path.insert(0,str(Path.cwd()))
from tools.train_static_ml import extract_features,FEATURE_NAMES
out=Path('output/fp-analysis-2026.10.6.1')
assignment=json.loads((out/'assignment-4.json').read_text(encoding='utf-8-sig'))
inventory=json.loads((out/'inventory.json').read_text(encoding='utf-8-sig'))
sig={s['path']:s for s in json.loads((out/'analysis-4-signatures.json').read_text(encoding='utf-8-sig'))}
inv={s['path']:s for s in inventory['samples']}
def entropy(data):
 if not data:return 0.
 p=np.bincount(np.frombuffer(data,dtype=np.uint8),minlength=256)/len(data);p=p[p>0]
 return float(-(p*np.log2(p)).sum())
rows=[]
for s in assignment['samples']:
 path=Path(s['path']);data=path.read_bytes();p=pefile.PE(data=data)
 sections=[dict(name=z.Name.rstrip(b'\0').decode('ascii','replace'),raw_offset=z.PointerToRawData,raw_size=z.SizeOfRawData,virtual_size=z.Misc_VirtualSize,entropy=entropy(z.get_data()),r=bool(z.Characteristics&0x40000000),w=bool(z.Characteristics&0x80000000),x=bool(z.Characteristics&0x20000000)) for z in p.sections]
 end=max([p.OPTIONAL_HEADER.SizeOfHeaders]+[z.PointerToRawData+z.SizeOfRawData for z in p.sections]);end=min(end,len(data))
 cert=p.OPTIONAL_HEADER.DATA_DIRECTORY[4];cert_ok=bool(cert.VirtualAddress>=end and cert.Size>=8 and cert.VirtualAddress+cert.Size<=len(data));entries=[]
 if cert_ok:
  at=cert.VirtualAddress;stop=at+cert.Size
  while at+8<=stop:
   length=int.from_bytes(data[at:at+4],'little');rev=int.from_bytes(data[at+4:at+6],'little');typ=int.from_bytes(data[at+6:at+8],'little')
   if length<8 or at+length>stop:cert_ok=False;break
   entries.append(dict(offset=at,length=length,revision=rev,type=typ));at+=(length+7)&~7
  cert_ok=cert_ok and at==stop
 other=data[end:cert.VirtualAddress]+data[cert.VirtualAddress+cert.Size:] if cert_ok else data[end:]
 versions={}
 for a in getattr(p,'FileInfo',[]):
  for b in a:
   for t in getattr(b,'StringTable',[]):versions.update({k.decode('utf-8','replace'):v.decode('utf-8','replace') for k,v in t.entries.items()})
 imports=[dict(dll=d.dll.decode('ascii','replace'),functions=[i.name.decode('ascii','replace') if i.name else '#'+str(i.ordinal) for i in d.imports]) for d in getattr(p,'DIRECTORY_ENTRY_IMPORT',[])]
 exports=[e.name.decode('ascii','replace') if e.name else '#'+str(e.ordinal) for e in getattr(getattr(p,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
 features=extract_features(data,len(data),path)
 strings=re.findall(rb'[\x20-\x7e]{7,}',data)
 indicators=[z.decode('ascii','replace')[:250] for z in strings if re.search(rb'(VMProtect|Themida|UPX|\.vmp|https?://|powershell|cmd\.exe|WinHttp|Crypt|Socket|VirtualAlloc|CreateRemoteThread|WriteProcessMemory|\.NET|Sentinel)',z,re.I)]
 r=dict(inv[s['path']],sha256=hashlib.sha256(data).hexdigest(),size=len(data),machine=p.FILE_HEADER.Machine,timestamp=p.FILE_HEADER.TimeDateStamp,entrypoint=p.OPTIONAL_HEADER.AddressOfEntryPoint,subsystem=p.OPTIONAL_HEADER.Subsystem,sections=sections,overlay=dict(start=end,total_bytes=len(data)-end,certificate_table_offset=cert.VirtualAddress,certificate_table_size=cert.Size,certificate_structure_valid=cert_ok,certificate_entries=entries,noncertificate_bytes=len(other),noncertificate_entropy=entropy(other)),imports=imports,exports=exports,version=versions,signature=sig[s['path']],features=dict(zip(FEATURE_NAMES,map(float,features))),feature_sha256=hashlib.sha256(features.tobytes()).hexdigest(),interesting_strings=indicators[:100])
 rows.append(r)
 print(path.name,json.dumps({k:r[k] for k in ['sha256','size','final_model_probability','version','overlay']},ensure_ascii=False),r['signature']['status'])
(out/'evidence-4.json').write_text(json.dumps(dict(thresholds={k:v for k,v in assignment.items() if k!='samples'},samples=rows),ensure_ascii=False,indent=2),encoding='utf-8')

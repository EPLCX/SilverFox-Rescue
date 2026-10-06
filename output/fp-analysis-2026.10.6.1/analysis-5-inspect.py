import sys,json,hashlib,re,math
from pathlib import Path
import pefile,numpy as np
root=Path.cwd();sys.path.insert(0,str(root/'tools'))
import train_static_ml as sm
out=root/'output/fp-analysis-2026.10.6.1'
a=json.loads((out/'assignment-5.json').read_text(encoding='utf-8'))
inv={s['path']:s for s in json.loads((out/'inventory.json').read_text(encoding='utf-8'))['samples']}
sigs={s['path']:s for s in json.loads((out/'analysis-5-signatures.json').read_text(encoding='utf-8-sig'))}
records=[];features={}
for sample in a['samples']+[{'path':r'F:\sliverfox-file\safe\V9YWjN.exe'}]:
 p=Path(sample['path']);data=p.read_bytes();pe=pefile.PE(data=data)
 sections=[dict(name=s.Name.rstrip(b'\0').decode(errors='replace'),size=s.SizeOfRawData,entropy=s.get_entropy(),r=bool(s.Characteristics&0x40000000),w=bool(s.Characteristics&0x80000000),x=bool(s.Characteristics&0x20000000)) for s in pe.sections]
 end=max([pe.OPTIONAL_HEADER.SizeOfHeaders]+[s.PointerToRawData+s.SizeOfRawData for s in pe.sections]);cert=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
 valid_range=bool(cert.VirtualAddress>=end and cert.Size>=8 and cert.VirtualAddress+cert.Size<=len(data))
 cert_records=[]
 if valid_range:
  pos=cert.VirtualAddress
  while pos+8<=cert.VirtualAddress+cert.Size:
   size=int.from_bytes(data[pos:pos+4],'little');rev=int.from_bytes(data[pos+4:pos+6],'little');typ=int.from_bytes(data[pos+6:pos+8],'little')
   if size<8 or pos+size>cert.VirtualAddress+cert.Size:valid_range=False;break
   cert_records.append(dict(offset=pos,size=size,revision=rev,type=typ));pos+=(size+7)//8*8
  if pos!=cert.VirtualAddress+cert.Size:valid_range=False
 imports={i.dll.decode(errors='replace'):[f.name.decode(errors='replace') if f.name else '#'+str(f.ordinal) for f in i.imports] for i in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}
 exports=[e.name.decode(errors='replace') if e.name else '#'+str(e.ordinal) for e in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])]
 version={}
 for block in getattr(pe,'FileInfo',[]):
  for fi in block:
   for table in getattr(fi,'StringTable',[]):
    version.update({k.decode(errors='replace'):v.decode(errors='replace') for k,v in table.entries.items()})
 strings=[m.decode(errors='replace') for m in re.findall(rb'[\x20-\x7e]{6,}',data)]
 interesting=[s[:500] for s in strings if re.search(r'(?i)https?://|\.pdb|powershell|cmd\.exe|taskkill|schtasks|rundll32|silverfox|todesk|nsis|python|proxy|socks|phoenix|upx|aspack|mpress|themida|install|uninstall',s)]
 feat=sm.extract_features(data[:sm.READ_LIMIT],len(data),p,[]);features[str(p)]=feat
 record=dict(sample=inv[str(p)],sha256=hashlib.sha256(data).hexdigest(),size=len(data),machine=pe.FILE_HEADER.Machine,timestamp=pe.FILE_HEADER.TimeDateStamp,entrypoint=pe.OPTIONAL_HEADER.AddressOfEntryPoint,sections=sections,overlay=dict(start=end,total_bytes=max(0,len(data)-end),certificate_offset=cert.VirtualAddress,certificate_size=cert.Size,certificate_table_structurally_valid=valid_range,certificate_records=cert_records,non_certificate_tail_bytes=max(0,len(data)-end)-(cert.Size if valid_range else 0)),imports=imports,exports=exports,version=version,signature=sigs.get(str(p)),interesting_strings=interesting[:250],model_scalars={k:float(v) for k,v in zip(sm.FEATURE_NAMES[256:],feat[256:])})
 records.append(record)
 print(p.name,record['sha256'],len(data),'sections',[(s['name'],round(s['entropy'],2)) for s in sections],'overlay',record['overlay'],'version',version,'signature',record['signature'],flush=True)
pair=features[r'F:\sliverfox-file\safe\POraKs.exe']-features[r'F:\sliverfox-file\safe\V9YWjN.exe']
compare=dict(feature_count=len(pair),equal_feature_count=int((pair==0).sum()),max_absolute_feature_difference=float(abs(pair).max()),different_features=[dict(name=n,delta=float(d)) for n,d in zip(sm.FEATURE_NAMES,pair) if d!=0])
(out/'evidence-5.json').write_text(json.dumps(dict(samples=records,poraks_v9ywjn_comparison=compare),ensure_ascii=False,indent=2),encoding='utf-8')
print('COMPARE',json.dumps(compare,ensure_ascii=False))

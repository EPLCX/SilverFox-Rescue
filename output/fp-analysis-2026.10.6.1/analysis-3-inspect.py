import sys,json,hashlib,re
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
import numpy as np,pefile
from tools.train_static_ml import extract_features,FEATURE_NAMES
d=Path('output/fp-analysis-2026.10.6.1')
a=json.loads((d/'assignment-3.json').read_text(encoding='utf-8-sig'))
sigs={s['path']:s for s in json.loads((d/'analysis-3-signatures.json').read_text(encoding='utf-8-sig'))}
out=[]
for sample in a['samples']:
 p=Path(sample['path']); data=p.read_bytes(); pe=pefile.PE(data=data)
 sections=[dict(name=s.Name.rstrip(b'\0').decode(errors='replace'),rva=hex(s.VirtualAddress),raw_offset=s.PointerToRawData,raw_size=s.SizeOfRawData,virtual_size=s.Misc_VirtualSize,characteristics=hex(s.Characteristics),entropy=s.get_entropy()) for s in pe.sections]
 imports={i.dll.decode(errors='replace'):[f.name.decode(errors='replace') if f.name else '#'+str(f.ordinal) for f in i.imports] for i in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}
 versions={}
 for block in getattr(pe,'FileInfo',[]):
  for info in block:
   for table in getattr(info,'StringTable',[]):
    versions.update({k.decode(errors='replace'):v.decode(errors='replace') for k,v in table.entries.items()})
 strings=[x.decode(errors='replace') for x in re.findall(rb'[\x20-\x7e]{8,}',data)]
 strings += [x.decode('utf-16le',errors='replace') for x in re.findall(rb'(?:[\x20-\x7e]\x00){8,}',data)]
 pattern=re.compile(r'https?://|sqlite|dokan|samplerate|resampl|libsamplerate|inno setup|nsis|7-zip|upx|aspack|perfectcalc|dotfix|testapp|easiupdate|microsoft|copyright|installer|pdb|\.cs\b|aes|encrypt|decrypt',re.I)
 selected=list(dict.fromkeys(s[:300] for s in strings if pattern.search(s)))[:70]
 features=extract_features(data,len(data),p,[])
 overlay=pe.get_overlay_data_start_offset(); security=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
 out.append(dict(sample=sample,sha256=hashlib.sha256(data).hexdigest(),size=len(data),machine=hex(pe.FILE_HEADER.Machine),timestamp=pe.FILE_HEADER.TimeDateStamp,entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),subsystem=pe.OPTIONAL_HEADER.Subsystem,clr_directory=pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size,sections=sections,overlay_offset=overlay,overlay_size=len(data)-overlay if overlay is not None else 0,security_directory_offset=security.VirtualAddress,security_directory_size=security.Size,imports=imports,export_count=len(getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[])),versions=versions,signature=sigs[str(p)],selected_strings=selected,model_features={n:float(v) for n,v in zip(FEATURE_NAMES,features) if not n.startswith('byte_frequency_')}))
(d/'evidence-3.json').write_text(json.dumps(dict(analysis_mode='static only; sample files never executed',thresholds={k:a[k] for k in a if k!='samples'},samples=out),ensure_ascii=False,indent=2),encoding='utf-8')
for e in out:
 print(json.dumps({k:v for k,v in e.items() if k not in ('imports','model_features')},ensure_ascii=False))
 print('IMPORTS',json.dumps(e['imports'],ensure_ascii=False))
 print('FEATURES',json.dumps(e['model_features'],ensure_ascii=False))

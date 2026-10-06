import sys,json,hashlib,re,subprocess
from pathlib import Path
import pefile
sys.path.insert(0,str(Path.cwd()))
from tools.train_static_ml import extract_features,FEATURE_NAMES
base=Path('output/fp-analysis-2026.10.6.1')
a=json.loads((base/'assignment-1.json').read_text(encoding='utf-8-sig'))
ps="""$a=Get-Content output/fp-analysis-2026.10.6.1/assignment-1.json -Raw|ConvertFrom-Json; $a.samples|ForEach-Object {$s=Get-AuthenticodeSignature -LiteralPath $_.path; [pscustomobject]@{path=$_.path;status=$s.Status.ToString();subject=$s.SignerCertificate.Subject;issuer=$s.SignerCertificate.Issuer;thumbprint=$s.SignerCertificate.Thumbprint;signature_type=$s.SignatureType.ToString()}}|ConvertTo-Json -Depth 4 -Compress"""
sig=json.loads(subprocess.check_output([r'C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe','-NoProfile','-Command',ps],encoding='utf-8',errors='replace'))
signatures={s['path']:s for s in sig}
out=[]
for sample in a['samples']:
 p=Path(sample['path']); data=p.read_bytes(); pe=pefile.PE(data=data)
 sections=[dict(name=s.Name.rstrip(b'\0').decode('ascii','replace'),rva=hex(s.VirtualAddress),raw_size=s.SizeOfRawData,virtual_size=s.Misc_VirtualSize,entropy=round(s.get_entropy(),6),characteristics=hex(s.Characteristics)) for s in pe.sections]
 imports={x.dll.decode('ascii','replace'):[(i.name.decode('ascii','replace') if i.name else '#'+str(i.ordinal)) for i in x.imports] for x in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])}
 versions={}
 for b in getattr(pe,'FileInfo',[]):
  for i in b:
   for t in getattr(i,'StringTable',[]):
    versions.update({k.decode('utf-8','replace'):v.decode('utf-8','replace') for k,v in t.entries.items()})
 offset=pe.get_overlay_data_start_offset(); overlay=data[offset:] if offset else b''
 strings=re.findall(rb'[\x20-\x7e]{6,}',data)
 interesting=[]
 patterns=(b'nsis',b'nullsoft',b'7-zip',b'7zs',b'upx',b'inno setup',b'pyinstaller',b'pyi-',b'python',b'autoit',b'ahk',b'silverfox',b'sliverfox',b'bugreport',b'uninstall',b'tencent',b'inartboard',b'mozilla',b'http')
 for s in strings:
  if any(v in s.lower() for v in patterns) and len(s)<250:
   decoded=s.decode('ascii','replace')
   if decoded not in interesting:interesting.append(decoded)
  if len(interesting)>=25:break
 feats=extract_features(data,len(data),p,[])
 selected={n:round(float(v),7) for n,v in zip(FEATURE_NAMES,feats) if not n.startswith('byte_frequency_')}
 out.append(dict(**sample,sha256=hashlib.sha256(data).hexdigest(),size=len(data),machine=hex(pe.FILE_HEADER.Machine),subsystem=pe.OPTIONAL_HEADER.Subsystem,timestamp=pe.FILE_HEADER.TimeDateStamp,entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),entry_section=next((s['name'] for s,ps in zip(sections,pe.sections) if ps.contains_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),None),sections=sections,overlay_offset=offset,overlay_size=len(overlay),overlay_prefix=overlay[:24].hex(),certificate_table_size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size,imports=imports,versions=versions,signature=signatures[sample['path']],selected_features=selected,limited_strings=interesting))
(base/'evidence-1.json').write_text(json.dumps(dict(method='Static PE parsing and existing native feature extraction; Get-AuthenticodeSignature; samples never executed. OOF model per-fold not retained; structural explanation is hypothesis.',samples=out),ensure_ascii=False,indent=2),encoding='utf-8')
for e in out:
 print(json.dumps({k:e[k] for k in ('path','size','sha256','entry_rva','sections','overlay_size','versions','signature','limited_strings','selected_features')},ensure_ascii=False))

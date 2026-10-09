#!/usr/bin/env python3
"""Train one native LightGBM model for Safe, Generic, and virus families."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .tool_paths import ENGINE_DLL, ROOT, MODEL_DIR, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir
    from . import train_static_ml as static_ml
else:
    from tool_paths import ENGINE_DLL, ROOT, MODEL_DIR, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir
    import train_static_ml as static_ml

prepare_temp_dir()

import lightgbm as lgb
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

if __package__:
    from .train_static_ml import c_float, load_extra_safe, load_samples, remove_conflicting_duplicates
else:
    from train_static_ml import c_float, load_extra_safe, load_samples, remove_conflicting_duplicates

SCHEMA_VERSION = 2
REMOVED_LEGACY = {"pe_timestamp", "pe_characteristics", "pe_dll_characteristics", "pe_entry_rva", "pe_image_size"}
PADDING_NAMES = [
    "max_byte_ratio", "max_byte_value", "top_run_byte_ratio", "nz_count_log1p",
    "zero_run_max_ratio", "zero_in_long_runs_ratio", "zero_chunk_ratio",
    "zero_ratio_overlay", "zero_ratio_sections", "nz_entropy",
    "nz_chunk_entropy_mean", "nz_chunk_entropy_std", "nz_chunk_entropy_min", "nz_chunk_entropy_max",
    "nz_printable_ratio", "nz_high_bit_ratio", "nz_unique_byte_ratio",
    "chunk_count", "chunk_entropy_p10", "chunk_entropy_p50", "chunk_entropy_p90",
]
PE_EXTRA_NAMES = [
    "resource_total_size_ratio", "resource_max_entropy", "resource_embedded_pe_header",
    "resource_icon_count", "resource_language_id_count", "overlay_magic_zip",
    "overlay_magic_7z", "overlay_magic_rar", "overlay_magic_nsis", "overlay_magic_inno",
    "overlay_embedded_pe_count", "resource_embedded_pe_count", "embedded_pe_count",
    "packer_upx_section", "packer_upx_magic", "packer_vmprotect_section", "packer_themida",
    "packer_mpress", "packer_aspack", "e_language_krnln_import", "e_language_eapi_string",
    "rich_header_present", "linker_major", "linker_minor", "os_major", "os_minor",
    "subsystem_major", "subsystem_minor", "code_size_ratio", "initialized_data_size_ratio",
    "uninitialized_data_size_ratio", "headers_size_anomalous", "tls_present", "tls_callback_count",
    "debug_directory_present", "pdb_path_present", "relocations_present", "load_config_present",
    "entry_section_entropy", "entry_section_is_last", "entry_section_name_standard",
    "section_raw_virtual_ratio_max", "section_raw_virtual_ratio_min",
    "section_entropy_max", "section_entropy_min", "section_entropy_weighted_mean",
    "entry_pre256_entropy", "entry_rva_image_ratio", "image_file_ratio",
    "entry_section_relative_offset", "timestamp_before_1995", "import_minimal_flag",
    "delay_import_count", "bound_import_count", "import_ordinal_ratio",
]
API_GROUPS = {
    "injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"],
    "keyboard": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetRawInputData"],
    "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW"],
    "network": ["InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "InternetReadFile", "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "connect", "send", "recv"],
    "service": ["OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "ControlService"],
    "registry": ["RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW", "RegDeleteValueA", "RegDeleteValueW"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt"],
}
DLL_BITS = {"high_entropy_va": 0x20, "aslr": 0x40, "force_integrity": 0x80, "nx_compat": 0x100,
            "no_seh": 0x400, "appcontainer": 0x1000, "cfg": 0x4000, "terminal_server_aware": 0x8000}
COFF_BITS = {"relocs_stripped": 1, "executable_image": 2, "line_nums_stripped": 4, "local_syms_stripped": 8,
             "large_address_aware": 0x20, "machine_32bit": 0x100, "debug_stripped": 0x200,
             "removable_run_from_swap": 0x400, "net_run_from_swap": 0x800, "system": 0x1000, "dll": 0x2000}
EXTRA_NAMES = (PADDING_NAMES + PE_EXTRA_NAMES
               + [f"api_{group}_{api.lower()}" for group, names in API_GROUPS.items() for api in names]
               + [f"dll_flag_{name}" for name in DLL_BITS]
               + [f"coff_flag_{name}" for name in COFF_BITS]
               + [f"rich_hash_{i:02d}" for i in range(16)]
               + [f"import_api_hash_{i:03d}" for i in range(128)]
               + [f"import_dll_hash_{i:02d}" for i in range(32)]
               + [f"byte_entropy_{e:02d}_{b:02d}" for e in range(16) for b in range(16)])

def model_names(legacy_names):
    return ([f"byte_bucket_{i:02d}" for i in range(16)]
            + [n for n in legacy_names[256:] if n not in REMOVED_LEGACY] + EXTRA_NAMES)

LEGACY_FEATURE_NAMES = static_ml.FEATURE_NAMES
FEATURE_NAMES = model_names(LEGACY_FEATURE_NAMES)

ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
STANDARD_SECTIONS = {'.text', '.data', '.rdata', '.rsrc', '.reloc', '.bss', '.idata', '.edata', '.tls', '.pdata', '.xdata', '.debug'}

def fnv1a(value):
    result = 2166136261
    for b in value:
        result = ((result ^ b) * 16777619) & 0xffffffff
    return result

def entropy(counts, length):
    if not length:
        return 0.0
    p = counts[counts > 0].astype(np.float64) / length
    return float(-(p * np.log2(p)).sum())

def block_entropy(data):
    counts = np.zeros(256, dtype=np.int64)
    for at in range(0, len(data), 1024*1024):
        a = np.frombuffer(data, dtype=np.uint8, count=min(1024*1024,len(data)-at), offset=at)
        counts += np.bincount(a, minlength=256)
    return entropy(counts, len(data))

def pe_headers(data):
    def read(at, size=4):
        return int.from_bytes(data[at:at+size], 'little') if 0 <= at <= len(data)-size else 0
    p = read(60)
    if len(data) < 64 or data[:2] != b'MZ' or p > len(data)-24 or data[p:p+4] != b'PE\0\0':
        return None
    optional = read(p+20, 2)
    if optional > len(data)-p-24:
        return None
    o = p+24; magic = read(o, 2); sections=[]
    for i in range(min(read(p+6, 2), 64)):
        at=o+optional+i*40
        if at > len(data)-40:
            break
        sections.append((data[at:at+8].split(b'\0')[0].decode('latin1').translate(ASCII_LOWER), read(at+20), read(at+16), read(at+12), read(at+8)))
    def map_rva(rva):
        for _, offset, raw, va, virtual in sections:
            if va <= rva < va+max(raw, virtual) and rva-va < raw and offset+rva-va < len(data):
                return offset+rva-va
        return rva if rva < read(o+60) and rva < len(data) else None
    def directory(index):
        relative=112 if magic==0x20b else 96
        at=o+relative+index*8
        return (read(at),read(at+4)) if magic in (0x10b,0x20b) and relative+index*8+8<=optional and index<read(o+relative-4) else (0,0)
    return read,p,o,magic,sections,map_rva,directory

def embedded_pe_count(data):
    count=0; at=data.find(b'MZ')
    while at>=0:
        if at+64<=len(data):
            offset=int.from_bytes(data[at+60:at+64],'little')
            if 64<=offset<1048576 and at+offset+24<=len(data) and data[at+offset:at+offset+4]==b'PE\0\0':
                count+=1
        at=data.find(b'MZ',at+2)
    return count

def byte_extras(data, total_size, out):
    a=np.frombuffer(data,dtype=np.uint8); n=len(a); denominator=max(total_size,1)
    counts=np.zeros(256,dtype=np.int64)
    long_total=zero_max=zero_long=0; carry_value=None; carry_length=0
    for at in range(0,n,1024*1024):
        block=a[at:at+1024*1024];counts+=np.bincount(block,minlength=256)
        boundary=np.r_[0,np.flatnonzero(block[1:]!=block[:-1])+1,len(block)]
        lengths=np.diff(boundary); values=block[boundary[:-1]]
        if carry_value is not None:
            if int(values[0])==carry_value:lengths[0]+=carry_length
            else:
                if carry_length>=256:long_total+=carry_length;zero_long+=carry_length if carry_value==0 else 0
                if carry_value==0:zero_max=max(zero_max,carry_length)
        carry_value=int(values[-1]);carry_length=int(lengths[-1]);lengths=lengths[:-1];values=values[:-1]
        long=lengths>=256;zero=values==0
        long_total+=int(lengths[long].sum());zero_long+=int(lengths[zero & long].sum());zero_max=max(zero_max,int(lengths[zero].max(initial=0)))
    if carry_value is not None:
        if carry_length>=256:long_total+=carry_length;zero_long+=carry_length if carry_value==0 else 0
        if carry_value==0:zero_max=max(zero_max,carry_length)
    dominant=int(counts.argmax()); out['max_byte_value']=dominant; out['max_byte_ratio']=counts[dominant]/max(n,1)
    out['nz_count_log1p']=math.log1p(n-int(counts[0]))
    out['top_run_byte_ratio']=long_total/denominator;out['zero_run_max_ratio']=zero_max/denominator
    out['zero_in_long_runs_ratio']=zero_long/max(int(counts[0]),1)
    chunk_ent=[]; nz_ent=[]; zero_chunks=0
    nz_counts=counts.copy(); nz_counts[0]=0; nz_n=int(n-counts[0])
    for at in range(0,n,65536):
        chunk=a[at:at+65536]; c=np.bincount(chunk,minlength=256)
        chunk_ent.append(entropy(c,len(chunk))); zero_chunks+=bool(len(chunk)==65536 and c[0]==65536)
        retained=int(len(chunk)-c[0]); c[0]=0
        if retained:
            nz_ent.append(entropy(c,retained))
    out['chunk_count']=len(chunk_ent); out['zero_chunk_ratio']=zero_chunks/max(n//65536,1)
    for label,value in zip(('p10','p50','p90'),np.quantile(chunk_ent or [0.], [.1,.5,.9])):
        out['chunk_entropy_'+label]=float(value)
    nz=np.asarray(nz_ent or [0.]); out['nz_entropy']=entropy(nz_counts,nz_n)
    for label,value in zip(('mean','std','min','max'),(nz.mean(),nz.std(),nz.min(),nz.max())):
        out['nz_chunk_entropy_'+label]=float(value)
    out['nz_printable_ratio']=(counts[9]+counts[10]+counts[13]+counts[32:127].sum())/max(nz_n,1)
    out['nz_high_bit_ratio']=counts[128:].sum()/max(nz_n,1)
    out['nz_unique_byte_ratio']=np.count_nonzero(nz_counts)/256.
    histogram=np.zeros((16,16),dtype=np.float64)
    # EMBER window/stride and high-nibble entropy bins. Use float64 in both runtimes.
    starts=range(0,n-2048+1,1024) if n>=2048 else ([0] if n else [])
    for at in starts:
        c=np.bincount(a[at:at+2048]>>4,minlength=16)
        e=min(15,int(entropy(c,2048)*4)); histogram[e]+=c
    if histogram.sum():
        histogram/=histogram.sum()
    for e in range(16):
        for b in range(16):
            out[f'byte_entropy_{e:02d}_{b:02d}']=histogram[e,b]
    return counts

def pe_extras(data,total_size,overlay_parts,out):
    h=pe_headers(data)
    if h is None:
        return
    read,p,o,magic,sections,map_rva,directory=h; denominator=max(total_size,1)
    def cstring(at,limit=256):
        if at is None:
            return b''
        return data[at:at+limit].split(b'\0')[0]
    overlay_length=sum(len(part) for part in overlay_parts)
    out['zero_ratio_overlay']=sum(part.count(0) for part in overlay_parts)/max(overlay_length,1)
    section_parts=[data[offset:offset+min(raw,max(len(data)-offset,0))] for _,offset,raw,_,_ in sections]
    out['zero_ratio_sections']=sum(part.count(0) for part in section_parts)/max(sum(map(len,section_parts)),1)
    out['overlay_embedded_pe_count']=sum(embedded_pe_count(part) for part in overlay_parts)
    out['embedded_pe_count']=max(0,embedded_pe_count(data)-1)
    signatures={'zip':[b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08'],'7z':[b'7z\xbc\xaf\x27\x1c'],
                'rar':[b'Rar!\x1a\x07\x00',b'Rar!\x1a\x07\x01\x00'],'nsis':[b'NullsoftInst'],
                'inno':[b'Inno Setup Setup Data',b'Inno Setup Messages']}
    for name,markers in signatures.items():
        out['overlay_magic_'+name]=int(any(marker in part for marker in markers for part in overlay_parts))
    names={s[0] for s in sections}
    out['packer_upx_section']=int(any(name.startswith('upx') for name in names)); out['packer_upx_magic']=int(b'UPX!' in data)
    out['packer_vmprotect_section']=int(bool(names & {'.vmp0','.vmp1','.vmp2'}))
    out['packer_themida']=int('.themida' in names or b'Themida' in data or b'THEMIDA' in data)
    out['packer_mpress']=int(any(name.startswith('.mpress') for name in names) or b'MPRESS' in data)
    out['packer_aspack']=int(bool(names & {'.aspack','.adata'}) or b'ASPack' in data)
    out['e_language_eapi_string']=int(b'eAPI' in data or b'EAPI' in data)
    for name,at,size in [('linker_major',o+2,1),('linker_minor',o+3,1),('os_major',o+40,2),('os_minor',o+42,2),('subsystem_major',o+48,2),('subsystem_minor',o+50,2)]:
        out[name]=read(at,size)
    for name,at in [('code_size_ratio',o+4),('initialized_data_size_ratio',o+8),('uninitialized_data_size_ratio',o+12)]:
        out[name]=read(at)/denominator
    headers=read(o+60); alignment=read(o+36)
    out['headers_size_anomalous']=int(headers<o+read(p+20,2)+read(p+6,2)*40 or headers>total_size or not alignment or headers%alignment!=0)
    entry=read(o+16); image=read(o+56)
    out['entry_rva_image_ratio']=entry/max(image,1); out['image_file_ratio']=image/denominator
    out['timestamp_before_1995']=int(0<read(p+8)<788918400)
    for name,bit in DLL_BITS.items():out['dll_flag_'+name]=int(bool(read(o+70,2)&bit))
    for name,bit in COFF_BITS.items():out['coff_flag_'+name]=int(bool(read(p+22,2)&bit))
    ents=[block_entropy(part) for part in section_parts]; ratios=[raw/max(virtual,1) for _,_,raw,_,virtual in sections]
    if sections:
        out['section_entropy_max']=max(ents); out['section_entropy_min']=min(ents)
        out['section_entropy_weighted_mean']=sum(e*len(part) for e,part in zip(ents,section_parts))/max(sum(map(len,section_parts)),1)
        out['section_raw_virtual_ratio_max']=max(ratios); out['section_raw_virtual_ratio_min']=min(ratios)
    for i,(_,offset,raw,va,virtual) in enumerate(sections):
        if va<=entry<va+max(raw,virtual):
            out['entry_section_entropy']=ents[i]; out['entry_section_is_last']=int(i==len(sections)-1)
            out['entry_section_name_standard']=int(sections[i][0] in STANDARD_SECTIONS)
            out['entry_section_relative_offset']=(entry-va)/max(raw,virtual,1)
            at=map_rva(entry)
            if at is not None:out['entry_pre256_entropy']=block_entropy(data[max(offset,at-256):at])
            break
    imagebase=read(o+24,8) if magic==0x20b else read(o+28)
    for name,index in [('tls_present',9),('debug_directory_present',6),('relocations_present',5),('load_config_present',10)]:
        rva,size=directory(index);out[name]=int(bool(rva and size))
    tls=map_rva(directory(9)[0]) if directory(9)[0] else None
    if tls is not None:
        address=read(tls+(24 if magic==0x20b else 12),8 if magic==0x20b else 4)
        at=map_rva(address-imagebase) if address>=imagebase else None; step=8 if magic==0x20b else 4
        if at is not None:
            for i in range(min(4096,max((len(data)-at)//step,0))):
                if not read(at+i*step,step):break
                out['tls_callback_count']+=1
    rva,size=directory(6); at=map_rva(rva) if rva else None
    if at is not None:
        for i in range(min(size//28,4096)):
            d=at+i*28
            if d+28>len(data):break
            if read(d+12)==2:
                q=read(d+24); length=read(d+16); sig=data[q:q+4]; skip=24 if sig==b'RSDS' else 16 if sig==b'NB10' else 0
                if skip and length>skip and q+length<=len(data) and cstring(q+skip,min(length-skip,4096)):out['pdb_path_present']=1
    rich=data.rfind(b'Rich',0,min(p,len(data)))
    if rich>=0 and rich+8<=p:
        key=read(rich+4); start=rich-4
        while start>=64 and (read(start)^key)!=0x536e6144:start-=4
        if start>=64 and start+16<=rich:
            out['rich_header_present']=1
            for at in range(start+16,rich-7,8):out[f'rich_hash_{fnv1a(struct.pack("<I",read(at)^key))%16:02d}']=1
    apis=set(); dlls=set(); ordinal=0; total=0; delay_count=0
    for index,step,limit in [(1,20,512),(13,32,512)]:
        rva,size=directory(index); at=map_rva(rva) if rva else None
        if at is None:continue
        for i in range(min(limit,size//step if size else limit)):
            d=at+i*step
            if d+step>len(data) or not any(data[d:d+step]):break
            attr=read(d); name=read(d+(12 if index==1 else 4)); thunk=read(d) or read(d+16) if index==1 else read(d+16) or read(d+12)
            if index==13 and not attr&1:
                name=name-imagebase if name>=imagebase else -1; thunk=thunk-imagebase if thunk>=imagebase else -1
            dll=cstring(map_rva(name),260).decode('latin1').translate(ASCII_LOWER); dlls.add(dll)
            q=map_rva(thunk); width=8 if magic==0x20b else 4
            if q is None:continue
            for j in range(1024):
                if q+j*width+width>len(data):break
                value=read(q+j*width,width)
                if not value:break
                total+=1; delay_count+=int(index==13)
                if value&(1<<(width*8-1)):ordinal+=1;continue
                name_at=map_rva(value&0xffffffff)
                if name_at is not None:apis.add(cstring(name_at+2,254).decode('latin1').translate(ASCII_LOWER))
    out['delay_import_count']=delay_count;out['import_ordinal_ratio']=ordinal/max(total,1)
    out['import_minimal_flag']=int(bool(apis) and not ordinal and 'getprocaddress' in apis and bool(apis&{'loadlibrarya','loadlibraryw','loadlibraryexa','loadlibraryexw'}) and apis<={'getprocaddress','loadlibrarya','loadlibraryw','loadlibraryexa','loadlibraryexw'})
    out['e_language_krnln_import']=int(any('krnln' in name for name in dlls))
    for group,names in API_GROUPS.items():
        for name in names:out[f'api_{group}_{name.lower()}']=int(name.lower() in apis)
    for name in apis:out[f'import_api_hash_{fnv1a(name.encode("latin1"))%128:03d}']=1
    for name in dlls:
        if name:out[f'import_dll_hash_{fnv1a(name.encode("latin1"))%32:02d}']=1
    rva,size=directory(11); at=map_rva(rva) if rva else None; end=min(len(data),at+size) if at is not None else 0
    while at is not None and at+8<=end and any(data[at:at+8]):
        out['bound_import_count']+=1;at+=8*(1+read(at+6,2))
    resource_rva,resource_size=directory(2); base=map_rva(resource_rva) if resource_rva else None
    resources=set(); icons=set(); languages=set(); visited=set()
    def walk(relative,depth,kind=0,ident=0):
        if base is None or depth>2 or (relative,depth) in visited or len(visited)>=4096:return
        visited.add((relative,depth));at=base+relative
        if relative<0 or relative+16>resource_size or at+16>len(data):return
        count=min(read(at+12,2)+read(at+14,2),4096)
        for i in range(count):
            q=at+16+i*8
            if q+8>len(data) or q+8>base+resource_size:break
            name=read(q); child=read(q+4); k=name if depth==0 else kind; identity=name if depth==1 else ident
            if child&0x80000000:walk(child&0x7fffffff,depth+1,k,identity);continue
            leaf=base+child
            if child+16>resource_size or leaf+16>len(data):continue
            offset=map_rva(read(leaf)); length=read(leaf+4)
            if offset is None or not length:continue
            resources.add((offset,min(length,len(data)-offset)))
            if k==3:icons.add(identity)
            if depth==2 and not name&0x80000000:languages.add(name)
    walk(0,0)
    for offset,length in resources:
        block=data[offset:offset+length];out['resource_total_size_ratio']+=length/denominator
        out['resource_max_entropy']=max(out['resource_max_entropy'],block_entropy(block));out['resource_embedded_pe_count']+=embedded_pe_count(block)
    out['resource_embedded_pe_header']=int(out['resource_embedded_pe_count']>0)
    out['resource_icon_count']=len(icons);out['resource_language_id_count']=len(languages)

def extend_features(data,total_size,legacy,legacy_names,overlay_parts):
    extra=dict.fromkeys(EXTRA_NAMES,0.)
    counts=byte_extras(data,total_size,extra);pe_extras(data,total_size,overlay_parts,extra)
    buckets=counts.reshape(16,16).sum(axis=1)/max(len(data),1)
    selected=[legacy[i] for i,n in enumerate(legacy_names) if i>=256 and n not in REMOVED_LEGACY]
    result=np.asarray([*buckets,*selected,*(extra[n] for n in EXTRA_NAMES)],dtype=np.float64)
    if not np.isfinite(result).all():raise ValueError('non-finite v2 feature')
    return result


def extract_feature_vector(data, total_size, path=None, siblings=None):
    legacy = static_ml.extract_features(data, total_size, path, siblings)
    parts = []
    if legacy[267] > 0.5:
        start, _, certificate, certificate_size = static_ml.overlay_info(data, total_size)
        parts = ([data[start:certificate], data[certificate+certificate_size:]]
                 if certificate_size else [data[start:]])
    return extend_features(data, total_size, legacy, LEGACY_FEATURE_NAMES, parts)


CONFIGS = {
    "specified": dict(n_estimators=700, learning_rate=0.03, num_leaves=23, max_depth=-1,
                       min_child_samples=15, subsample=1.0, subsample_freq=1,
                       colsample_bytree=0.7, reg_lambda=6.0, min_split_gain=0.0,
                       random_state=42, n_jobs=-1, deterministic=True, force_row_wise=True),
}


def model(config: dict):
    return lgb.LGBMClassifier(**config, objective="multiclass", verbosity=-1)


def report_iteration(env):
    if (env.iteration + 1) % 500 == 0:
        print(f"iteration {env.iteration + 1}/{env.end_iteration}", flush=True)


def probabilities(fitted, x, class_count):
    values = np.zeros((len(x), class_count), np.float64)
    predicted = fitted.predict_proba(x)
    for column, label in enumerate(fitted.classes_):
        values[:, int(label)] = predicted[:, column]
    return values


def grouped_oof(x, y, weights, config, class_count, splits):
    values = np.zeros((len(y), class_count), np.float64)
    for fold, (train, valid) in enumerate(splits, 1):
        fitted = model(config)
        fitted.fit(x[train], y[train], sample_weight=weights[train], callbacks=[report_iteration])
        values[valid] = probabilities(fitted, x[valid], class_count)
        print(f"fold {fold}/5: {len(valid)} validated", flush=True)
    return values


SAFE_STRATA = ("UPX加壳", "VMProtect相关", "易语言", "NET单文件程序", "驱动",
               "安装器或卸载器", "NET托管程序", "大型高熵数据节", "含RWX节", "大型非证书尾部")


def load_safe_catalog(path):
    if not path.is_file():
        print(f"safe classification: {path} absent; classify loaded safe bytes", flush=True)
        return {}
    rows = json.loads(path.read_text(encoding="utf-8"))["samples"]
    return {str(Path(row["path"]).resolve()).casefold(): row for row in rows}


def stratification_labels(samples, y, groups, class_count):
    # Keep the model's Safe class, while distributing its structural cohorts across folds.
    primary = [next((name for name in SAFE_STRATA if name in s.safe_categories), "其他白样本")
               if s.label == 0 else "" for s in samples]
    strata = y.copy()
    retained = {}
    for name in SAFE_STRATA:
        indices = np.asarray([i for i, category in enumerate(primary) if category == name], dtype=np.int64)
        group_count = len(np.unique(groups[indices]))
        if group_count >= 5:
            strata[indices] = class_count + len(retained)
            retained[name] = {"samples": len(indices), "groups": group_count}
    return strata, retained


def safe_category_metrics(samples, groups, probability, suspicious, malicious):
    categories = sorted({category for sample in samples if sample.label == 0 for category in sample.safe_categories})
    result = {}
    for category in categories:
        indices = np.asarray([i for i, s in enumerate(samples) if s.label == 0 and category in s.safe_categories], dtype=np.int64)
        p = probability[indices]
        result[category] = {"sample_count": len(indices), "group_count": len(np.unique(groups[indices])),
                            "suspicious_or_malicious_count": int((p >= suspicious).sum()),
                            "malicious_count": int((p >= malicious).sum()),
                            "false_positive_rate": float((p >= suspicious).mean()),
                            "malicious_false_positive_rate": float((p >= malicious).mean())}
    return result


def point(y, p, threshold):
    tn, fp, fn, tp = confusion_matrix(y, p >= threshold, labels=[0, 1]).ravel()
    return {"threshold": float(threshold), "safe": int(tn+fp), "malicious": int(tp+fn),
            "false_positive": int(fp), "true_positive": int(tp),
            "false_positive_rate": float(fp/max(tn+fp, 1)), "recall": float(tp/max(tp+fn, 1)),
            "precision": float(tp/max(tp+fp, 1))}


def threshold_for(y, p, max_fpr, floor):
    allowance = int((y == 0).sum() * max_fpr)
    candidates = np.unique(p[p >= floor])
    for threshold in candidates:
        if np.count_nonzero((y == 0) & (p >= threshold)) <= allowance:
            return float(threshold)
    return 1.0


def calibrate(probabilities, slope, intercept):
    raw = np.clip(probabilities, 1e-7, 1-1e-7)
    margin = np.log(raw / (1-raw))
    values = np.clip(slope * margin + intercept, -40, 40)
    return 1 / (1 + np.exp(-values))


def flatten(booster):
    offsets, left, right, features, thresholds, values = [], [], [], [], [], []
    def visit(node):
        at = len(features)
        features.append(-1); left.append(-1); right.append(-1); thresholds.append(0.0); values.append(0.0)
        if "leaf_value" in node:
            values[at] = float(node["leaf_value"])
        else:
            assert node["decision_type"] == "<=", node["decision_type"]
            assert node["missing_type"] == "None", node["missing_type"]
            features[at] = int(node["split_feature"])
            thresholds[at] = float(node["threshold"])
            left[at] = visit(node["left_child"])
            right[at] = visit(node["right_child"])
        return at
    for info in booster.dump_model()["tree_info"]:
        offsets.append(len(features))
        visit(info["tree_structure"])
        base = offsets[-1]
        for at in range(base, len(features)):
            if features[at] >= 0:
                left[at] -= base; right[at] -= base
    return offsets, left, right, features, thresholds, values


def flat_raw(tree, x, k):
    offsets, left, right, feat, thr, val = map(np.asarray, tree)
    out = np.zeros((len(x), k), dtype=np.float64)
    rows = np.arange(len(x))
    for t, base in enumerate(offsets):
        nodes = np.full(len(x), base, dtype=np.int64)
        active = feat[nodes] >= 0
        while active.any():
            r = rows[active]
            n = nodes[active]
            nodes[active] = base + np.where(x[r, feat[n]] <= thr[n], left[n], right[n])
            active = feat[nodes] >= 0
        out[:, t % k] += val[nodes]
    return out


FPR_POINTS = (0.001, 0.0035, 0.005, 0.01)


def low_fpr(y, p):
    # nextafter excludes a tied negative score rather than exceeding the FPR budget.
    safe = np.sort(p[y == 0])[::-1]
    result = {}
    for fpr in FPR_POINTS:
        allowance = int(len(safe) * fpr)
        threshold = float(np.nextafter(safe[allowance], np.inf))
        result[str(fpr)] = point(y, p, threshold)
    return result


def bootstrap_fpr(y, p, groups, seed, iterations=500):
    unique, inverse = np.unique(groups, return_inverse=True)
    members = [np.flatnonzero(inverse == i) for i in range(len(unique))]
    rng = np.random.default_rng(seed)
    recalls = {str(fpr): [] for fpr in FPR_POINTS}
    for _ in range(iterations):
        selected = np.concatenate([members[i] for i in rng.integers(len(unique), size=len(unique))])
        if len(np.unique(y[selected])) != 2:
            continue
        for fpr, metrics in low_fpr(y[selected], p[selected]).items():
            recalls[fpr].append(metrics["recall"])
    return {fpr: {"recall_95_ci": np.quantile(values, [0.025, 0.975]).tolist(),
                  "bootstrap_iterations": len(values), "resampling_unit": "group"}
            for fpr, values in recalls.items()}


def fitted_calibration(binary, raw):
    raw = np.clip(raw, 1e-7, 1-1e-7)
    margin = np.log(raw / (1-raw)).reshape(-1, 1)
    fitted = LogisticRegression(C=1e6, max_iter=500).fit(margin, binary)
    slope, intercept = float(fitted.coef_[0, 0]), float(fitted.intercept_[0])
    if slope <= 0:
        raise RuntimeError("calibration reversed model ranking")
    p = calibrate(raw, slope, intercept)
    suspicious = threshold_for(binary, p, 0.005, 0.01)
    malicious = threshold_for(binary, p, 0.0035, max(suspicious, 0.9))
    return slope, intercept, p, suspicious, malicious


def lines(values, format_value=str, width=10):
    return ["    " + ", ".join(format_value(value) for value in values[i:i+width]) + ","
            for i in range(0, len(values), width)]


def write_header(path, tree, classes, suspicious, malicious, slope, intercept, timestamp):
    offsets, left, right, features, thresholds, values = tree
    declarations = [
        ("std::uint32_t", "TREE_OFFSETS", offsets, str),
        ("std::int32_t", "LEFT", left, str), ("std::int32_t", "RIGHT", right, str),
        ("std::int16_t", "FEATURES", features, str),
        ("double", "THRESHOLDS", thresholds, lambda v: c_float(float(v))),
        ("double", "LEAF_VALUES", values, lambda v: c_float(float(v))),
    ]
    body = ["// Generated by tools/train_lightgbm.py. Do not edit by hand.", "#pragma once",
            "#include <array>", "#include <cstddef>", "#include <cstdint>",
            "namespace silverfox_ml_model {",
            f"inline constexpr std::size_t FEATURE_COUNT = {len(FEATURE_NAMES)};",
            f"inline constexpr unsigned FEATURE_SCHEMA_VERSION = {SCHEMA_VERSION};",
            f"inline constexpr std::size_t CLASS_COUNT = {len(classes)};",
            f"inline constexpr std::size_t TREE_COUNT = {len(offsets)};",
            f"inline constexpr std::size_t NODE_COUNT = {len(features)};",
            "inline constexpr std::uint64_t MIN_FILE_BYTES = 2048;",
            f"inline constexpr double SUSPICIOUS_THRESHOLD = {c_float(suspicious)};",
            f"inline constexpr double MALICIOUS_THRESHOLD = {c_float(malicious)};",
            f"inline constexpr double CALIBRATION_SLOPE = {c_float(slope)};",
            f"inline constexpr double CALIBRATION_INTERCEPT = {c_float(intercept)};",
            f'inline constexpr const char *TRAINED_AT_UTC = "{timestamp}";',
            "inline constexpr std::array<const char *, CLASS_COUNT> CLASS_NAMES = {",
            *lines(classes, lambda value: f'"{value}"', 6), "};"]
    for datatype, name, data, formatter in declarations:
        body += [f"inline constexpr std::array<{datatype}, {'TREE_COUNT' if name=='TREE_OFFSETS' else 'NODE_COUNT'}> {name} = {{",
                 *lines(data, formatter, 6 if datatype == "double" else 12), "};"]
    body += ["} // namespace silverfox_ml_model", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8", newline="\n")


def existing_calibration(path):
    header = path.read_text(encoding="utf-8")
    values = []
    for name in ("CALIBRATION_SLOPE", "CALIBRATION_INTERCEPT", "SUSPICIOUS_THRESHOLD", "MALICIOUS_THRESHOLD"):
        match = re.search(rf"\b{name} = ([^;]+);", header)
        if not match:
            raise RuntimeError(f"missing existing {name} in {path}")
        values.append(float(match.group(1)))
    if not np.isfinite(values).all() or values[0] <= 0 or not 0 <= values[2] <= values[3] <= 1:
        raise RuntimeError("invalid existing calibration or thresholds")
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=os.environ.get("SILVERFOX_DATASET_DIR"),
                        required=not bool(os.environ.get("SILVERFOX_DATASET_DIR")))
    parser.add_argument("--exclude-others-virus", action="store_true",
                        help="exclude the others-virus directory before reading samples")
    parser.add_argument("--extraction-workers", type=int, choices=range(1, 17), default=2,
                        help="feature extraction threads; use 1 to reduce peak memory")
    parser.add_argument("--header", type=Path, default=MODEL_HEADER)
    parser.add_argument("--report", type=Path, default=MODEL_REPORT)
    parser.add_argument("--booster-out", type=Path, default=MODEL_DIR / "static_ml_booster.txt")
    parser.add_argument("--extra-safe", type=Path, action="append", default=[],
                        help="confirmed safe PE regression sample; may be repeated")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--evaluate", action="store_true",
                        help="run grouped 5-fold evaluation, calibration and weight ablations before final fit")
    parser.add_argument("--engine", type=Path, default=ENGINE_DLL,
                        help="DLL containing the corrected certificate/overlay extractor")
    parser.add_argument("--safe-classification", type=Path,
                        default=ROOT / "output/safe-classification-2026.10.7/samples.json",
                        help="content classification inventory; new/changed files are classified from loaded bytes")
    args = parser.parse_args()
    static_ml.ENGINE_DLL = args.engine.resolve()
    static_ml.metadata_function(static_ml.ENGINE_DLL)
    if not hasattr(static_ml._metadata_function[0], "sf_pe_overlay_info"):
        raise RuntimeError("DLL lacks corrected overlay extractor; run engine/build-engine.bat or specify --engine")
    safe_catalog = load_safe_catalog(args.safe_classification)
    samples, skipped = load_samples(args.dataset, safe_catalog, feature_extractor=extract_feature_vector,
                                    valid_pe_index=FEATURE_NAMES.index("valid_pe"),
                                    exclude_others_virus=args.exclude_others_virus,
                                    extraction_workers=args.extraction_workers)
    samples.extend(load_extra_safe(args.extra_safe, safe_catalog, feature_extractor=extract_feature_vector,
                                   valid_pe_index=FEATURE_NAMES.index("valid_pe")))
    samples, conflicts = remove_conflicting_duplicates(samples)
    if not samples:
        raise RuntimeError("no eligible PE samples")
    families = sorted({sample.family.split("/", 1)[1] for sample in samples
                       if sample.family.startswith("virus/") and sample.family != "virus/Generic"})
    if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", name) for name in families):
        raise RuntimeError("family directory names must be safe ASCII identifiers")
    generic_present = any(sample.label != 0 and (not sample.family.startswith("virus/") or sample.family == "virus/Generic") for sample in samples)
    classes = ["Safe", *(["Generic"] if generic_present else []), *families]
    class_index = {name: index for index, name in enumerate(classes)}
    labels = ["Safe" if sample.label == 0 else
              sample.family.split("/", 1)[1] if sample.family.startswith("virus/") else "Generic"
              for sample in samples]
    x = np.stack([sample.features for sample in samples]).astype(np.float64)
    y = np.asarray([class_index[label] for label in labels], np.int32)
    binary = (y != 0).astype(np.int32)
    groups = np.asarray([sample.group for sample in samples])
    focus = np.asarray([sample.family.startswith("virus/") for sample in samples])
    counts = np.bincount(y, minlength=len(classes))
    generic_count = counts[class_index["Generic"]] if generic_present else 0
    weights = np.asarray([1.0 if label == 0 else min(12.0, max(1.0, math.sqrt(generic_count/max(counts[label], 1))))
                          for label in y], np.float64)
    weights[focus] *= 2.0
    print(json.dumps({"sample_count": len(y), "classes": dict(zip(classes, map(int, counts))),
                      "virus_pe_samples": int(focus.sum())}, ensure_ascii=False), flush=True)
    if not np.isfinite(x).all():
        raise RuntimeError("training features contain NaN or infinity")
    safe_groups, safe_group_sizes = np.unique(groups[binary == 0], return_counts=True)
    group_audit = {"safe_samples": int((binary == 0).sum()), "safe_groups": len(safe_groups),
                   "safe_multi_sample_groups": int((safe_group_sizes > 1).sum()),
                   "safe_samples_in_multi_sample_groups": int(safe_group_sizes[safe_group_sizes > 1].sum()),
                   "largest_safe_group": int(safe_group_sizes.max()),
                   "class_group_counts": {name: len(np.unique(groups[y == i])) for i, name in enumerate(classes)}}
    print(json.dumps({"group_audit": group_audit}, ensure_ascii=False), flush=True)
    best_name, best_config = next(iter(CONFIGS.items()))
    if len(CONFIGS) != 1:
        raise RuntimeError("compare configurations using mean recall over FPR_POINTS before selecting one")
    if args.evaluate:
        outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
        strata, safe_strata = stratification_labels(samples, y, groups, len(classes))
        splits = list(outer.split(x, strata, groups))
        for train, valid in splits:
            if set(groups[train]) & set(groups[valid]):
                raise RuntimeError("group leaked between train and validation")
        print("outer evaluation: full grouped 5-fold OOF", flush=True)
        outer_classes = grouped_oof(x, y, weights, best_config, len(classes), splits)
        fold_ids = np.zeros(len(y), dtype=np.int32)
        fold_reports = []
        for fold, (train, valid) in enumerate(splits, 1):
            if set(groups[train]) & set(groups[valid]):
                raise RuntimeError("group leaked between train and validation")
            raw = 1-outer_classes[valid, 0]
            fold_ids[valid] = fold
            metrics = {"fold": fold, "train_count": len(train), "valid_count": len(valid),
                       "train_class_counts": dict(zip(classes, map(int, np.bincount(y[train], minlength=len(classes))))),
                       "valid_class_counts": dict(zip(classes, map(int, np.bincount(y[valid], minlength=len(classes))))),
                       "valid_safe_category_counts": {category: sum(category in samples[i].safe_categories for i in valid if binary[i] == 0)
                                                      for category in sorted({c for s in samples if s.label == 0 for c in s.safe_categories})},
                       "roc_auc": float(roc_auc_score(binary[valid], raw)),
                       "average_precision": float(average_precision_score(binary[valid], raw)),
                       "low_fpr": low_fpr(binary[valid], raw)}
            fold_reports.append(metrics)
            print(json.dumps(metrics, ensure_ascii=False), flush=True)
        full_oof_raw = 1-outer_classes[:, 0]
        slope, intercept, dev_probability, suspicious, malicious = fitted_calibration(binary, full_oof_raw)
        pooled_low_fpr = low_fpr(binary, full_oof_raw)
        intervals = bootstrap_fpr(binary, full_oof_raw, groups, args.seed)
        for fpr in pooled_low_fpr:
            pooled_low_fpr[fpr].update(intervals[fpr])
        ablations = {"original": {"pooled_low_fpr": pooled_low_fpr,
                                  "mean_fold_recall": {str(fpr): float(np.mean([v["low_fpr"][str(fpr)]["recall"] for v in fold_reports]))
                                                       for fpr in FPR_POINTS}}}
        class_weights = weights.copy()
        class_weights[focus] /= 2.0
        no_class_weights = np.ones(len(y), dtype=np.float64)
        no_class_weights[focus] *= 2.0
        for name, ablation_weights in (("without_virus_x2", class_weights), ("without_class_weights", no_class_weights)):
            scores = np.zeros(len(y), dtype=np.float64)
            fold_scores = []
            for fold, (train, valid) in enumerate(splits, 1):
                print(f"ablation {name} fold {fold}/5", flush=True)
                fitted = model(best_config)
                fitted.fit(x[train], y[train], sample_weight=ablation_weights[train], callbacks=[report_iteration])
                scores[valid] = 1-probabilities(fitted, x[valid], len(classes))[:, 0]
                fold_scores.append(low_fpr(binary[valid], scores[valid]))
                del fitted
            ablations[name] = {"pooled_low_fpr": low_fpr(binary, scores),
                               "mean_fold_recall": {str(fpr): float(np.mean([v[str(fpr)]["recall"] for v in fold_scores]))
                                                    for fpr in FPR_POINTS}}
            print(json.dumps({"ablation": name, "metrics": ablations[name]}, ensure_ascii=False), flush=True)
    else:
        slope, intercept, suspicious, malicious = existing_calibration(args.header)
        print("direct full-data fit: using existing calibration and thresholds", flush=True)
    print("final fit: all eligible samples", flush=True)
    final = model(best_config)
    final.fit(x, y, sample_weight=weights, callbacks=[report_iteration])
    tree = flatten(final.booster_)
    parity_x = x[:500].copy()
    reference = final.booster_.predict(parity_x, raw_score=True)
    parity_error = float(np.abs(flat_raw(tree, parity_x, len(classes))-reference).max())
    if not np.isfinite(parity_error) or parity_error >= 1e-6:
        raise RuntimeError(f"flattened tree raw-score mismatch: {parity_error}")
    args.booster_out.parent.mkdir(parents=True, exist_ok=True)
    final.booster_.save_model(str(args.booster_out))
    parity_path = args.report.parent / "static_ml_parity_vectors.npz"
    parity_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(parity_path, x=parity_x, raw_score=reference,
                        paths=np.asarray([str(sample.path) for sample in samples[:500]]))
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    write_header(args.header, tree, classes, suspicious, malicious, slope, intercept, timestamp)
    report = {
        "model": "LightGBM single multiclass GBDT", "trained_at_utc": timestamp,
        "dataset": str(args.dataset), "feature_count": len(FEATURE_NAMES), "feature_names": FEATURE_NAMES,
        "feature_importance_gain": dict(zip(FEATURE_NAMES, map(float, final.booster_.feature_importance(importance_type="gain")))),
        "extra_safe_paths": [str(path) for path in args.extra_safe],
        "excluded_dataset_categories": ["others-virus"] if args.exclude_others_virus else [],
        "class_names": classes, "class_counts": dict(zip(classes, map(int, counts))),
        "sample_count": len(y), "final_fit_count": len(y), "virus_pe_samples": int(focus.sum()),
        "tree_count": len(tree[0]), "node_count": len(tree[3]), "supported_input": "valid_pe_only",
        "evaluation": "grouped_5_fold" if args.evaluate else "not_performed",
        "selected_config": best_name, "candidate_configs": CONFIGS, "split_seed": args.seed,
        "group_audit": group_audit,
        "feature_extractor": {"engine": str(static_ml.ENGINE_DLL),
                              "schema_version": SCHEMA_VERSION,
                              "workers": args.extraction_workers,
                              "byte_statistics": "original bytes; 16 byte buckets, 256 EMBER entropy bins, separate padding/nonzero statistics",
                              "pe_metadata": "original bytes and original total size",
                              "overlay": "exclude structurally validated WIN_CERTIFICATE regions"},
        "safe_classification": {"inventory": str(args.safe_classification),
                                "category_counts": {category: sum(category in sample.safe_categories for sample in samples if sample.label == 0)
                                                    for category in sorted({c for sample in samples if sample.label == 0 for c in sample.safe_categories})}},
        "calibration": {"method": "sigmoid_on_full_5_fold_oof" if args.evaluate else "retained_existing",
                        "slope": slope, "intercept": intercept},
        "thresholds": {"suspicious": suspicious, "malicious": malicious},
        "flatten_parity": {"checked": len(parity_x), "max_raw_score_error": parity_error, "vectors": str(parity_path)},
        "skipped": skipped, "conflicting_duplicate_groups_removed": conflicts,
    }
    sample_rows = [{"path": str(s.path), "label": int(s.label), "family": s.family,
                    "group": s.group, "safe_categories": list(s.safe_categories)} for s in samples]
    if args.evaluate:
        predicted_family = outer_classes[:, 1:].argmax(axis=1) + 1
        named = np.asarray([classes[int(label)] not in ("Safe", "Generic") for label in y])
        report["safe_classification"].update(safe_strata=safe_strata,
            category_metrics=safe_category_metrics(samples, groups, dev_probability, suspicious, malicious))
        report["calibration"].update(C=1e6, raw_brier=float(brier_score_loss(binary, full_oof_raw)),
                                    calibrated_brier=float(brier_score_loss(binary, dev_probability)))
        report.update(
            development_suspicious_operating_point=point(binary, dev_probability, suspicious),
            development_malicious_operating_point=point(binary, dev_probability, malicious),
            outer_cv={"folds": fold_reports, "roc_auc": float(roc_auc_score(binary, full_oof_raw)),
                      "average_precision": float(average_precision_score(binary, full_oof_raw)),
                      "virus_recall_at_fpr_0_005": float((full_oof_raw[focus] >= pooled_low_fpr["0.005"]["threshold"]).mean()),
                      "named_family_accuracy": float((predicted_family[named] == y[named]).mean()), "low_fpr": pooled_low_fpr},
            weight_ablation=ablations,
            out_of_fold_samples=[{**row, "probability": float(dev_probability[i]), "raw_probability": float(full_oof_raw[i]),
                                  "final_calibration_oof_probability": float(dev_probability[i]),
                                  "predicted_family": classes[int(predicted_family[i])], "fold": int(fold_ids[i]), "split": "outer_cv"}
                                 for i, row in enumerate(sample_rows)])
    else:
        report["calibration"]["source_header"] = str(args.header)
        report["training_samples"] = sample_rows
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("sample_count", "selected_config", "evaluation", "group_audit", "flatten_parity")},
                     ensure_ascii=False, indent=2), flush=True)



if __name__ == "__main__":
    main()

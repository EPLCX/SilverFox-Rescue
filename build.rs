use std::{env,path::PathBuf};
use sha2::{Digest,Sha256};

fn verify_embedded_engine_section(engine:&[u8],version:&str,key:&[u8]){
    assert!(engine.len()>=0x40 && &engine[..2]==b"MZ","embedded engine DOS header invalid");
    let pe=u32::from_le_bytes(engine[0x3c..0x40].try_into().unwrap())as usize;
    assert!(pe+24<=engine.len() && &engine[pe..pe+4]==b"PE\0\0","embedded engine PE header invalid");
    let count=u16::from_le_bytes(engine[pe+6..pe+8].try_into().unwrap())as usize;
    let optional=u16::from_le_bytes(engine[pe+20..pe+22].try_into().unwrap())as usize;
    let table=pe+24+optional;assert!(count>0&&count<=96&&table+count*40<=engine.len(),"embedded engine section table invalid");
    let mut offset=None;
    for index in 0..count{let h=table+index*40;if &engine[h..h+8]!=b".sfsig\0\0"{continue;}
        assert!(offset.is_none(),"duplicate embedded engine signature section");
        let size=u32::from_le_bytes(engine[h+16..h+20].try_into().unwrap())as usize;
        let raw=u32::from_le_bytes(engine[h+20..h+24].try_into().unwrap())as usize;
        let flags=u32::from_le_bytes(engine[h+36..h+40].try_into().unwrap());
        assert!(size>=128&&raw>=table+count*40&&raw.checked_add(size).is_some_and(|end|end<=engine.len()),"embedded engine signature section invalid");
        assert!(flags&0x4000_0000!=0&&flags&(0x2000_0000|0x8000_0000)==0,"embedded engine signature section permissions invalid");
        offset=Some(raw);
    }
    let offset=offset.expect("embedded engine signature section missing");let slot=&engine[offset..offset+128];
    assert_eq!(&slot[..8],b"SFXSIG01","embedded engine signature magic invalid");
    assert_eq!(&slot[8..12],&[2,0,0,0],"embedded engine signature schema invalid");
    let version_len=slot[108]as usize;
    assert!(version_len>0&&version_len<=19,"embedded engine signature version length invalid");
    assert_eq!(&slot[109..109+version_len],version.as_bytes(),"embedded engine signature version mismatch");
    assert!(slot[109+version_len..].iter().all(|byte|*byte==0),"embedded engine signature padding invalid");
    let mut hash=Sha256::new();hash.update(&engine[..offset]);hash.update([0u8;128]);hash.update(&engine[offset+128..]);let digest=hash.finalize();
    assert_eq!(&slot[12..44],digest.as_slice(),"embedded engine digest mismatch");
    let mut message=b"SilverFoxRescue/PE-engine-sign/v1\0".to_vec();message.extend_from_slice(version.as_bytes());message.push(0);message.extend_from_slice(&(engine.len()as u64).to_le_bytes());message.extend_from_slice(&digest);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,key).verify(&message,&slot[44..108]).expect("embedded engine signature invalid");
}
fn main(){
    for name in ["SILVERFOX_RULE_PUBLIC_KEY_HEX","SILVERFOX_PROGRAM_PUBLIC_KEY_HEX","SILVERFOX_BENCHMARK_BUILD","SILVERFOX_CLOUD_URL"]{println!("cargo:rerun-if-env-changed={name}");}
    let cloud_url=env::var("SILVERFOX_CLOUD_URL").unwrap_or_else(|_|"https://***.sf-rescue.top".into());
    let cloud_url=cloud_url.trim().trim_end_matches('/');
    let cloud_url=if cloud_url.contains("://"){cloud_url.to_owned()}else{format!("https://{cloud_url}")};
    assert!(cloud_url.starts_with("https://")&&!cloud_url.contains(['\r','\n']),"update site must use HTTPS");
    println!("cargo:rustc-env=SILVERFOX_CLOUD_URL={cloud_url}");
    println!("cargo:rerun-if-changed=engine/algorithms.dll");println!("cargo:rerun-if-changed=rules/seed/rules.manifest.json");println!("cargo:rerun-if-changed=rules/seed/rules.package.zip");
    for(name,label)in[("SILVERFOX_RULE_PUBLIC_KEY_HEX","rule"),("SILVERFOX_PROGRAM_PUBLIC_KEY_HEX","program")]{if let Ok(value)=env::var(name){let value=value.trim();assert!(value.len()==64&&value.bytes().all(|c|c.is_ascii_hexdigit()),"{label} public key must be 32 bytes of hex");println!("cargo:rustc-env={name}={value}");}}
    let root=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());let manifest=root.join("app.manifest");for shader in ["patterns.cso","entropy.cso"]{println!("cargo:rerun-if-changed={}",root.join("shaders").join(shader).display());}println!("cargo:rerun-if-changed={}",manifest.display());
    if env::var("PROFILE").as_deref()==Ok("release"){
        let rule_key=env::var("SILVERFOX_RULE_PUBLIC_KEY_HEX").unwrap_or_else(|_|std::fs::read_to_string(root.join("rules/seed/rules-public.hex")).expect("embedded rule public key missing"));let rule_key=rule_key.trim();assert!(rule_key.len()==64&&rule_key.bytes().all(|c|c.is_ascii_hexdigit()),"rule public key must be 32 bytes of hex");
        let engine=std::fs::read(root.join("engine/algorithms.dll")).expect("signed algorithms.dll is required for release");let engine_manifest:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("rules/seed/rules.manifest.json")).expect("signed embedded engine manifest is required")).expect("embedded engine manifest is malformed");let version=engine_manifest["version"].as_str().expect("embedded engine version missing");verify_embedded_engine_section(&engine,version,&hex::decode(rule_key).expect("rule public key encoding invalid"));
        println!("cargo:rustc-link-arg-bin=silverfox-rescue=/SECTION:.sfsig,R");
        if env::var("SILVERFOX_BENCHMARK_BUILD").as_deref()!=Ok("1"){println!("cargo:rustc-link-arg-bin=silverfox-rescue=/MANIFEST:EMBED");println!("cargo:rustc-link-arg-bin=silverfox-rescue=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");println!("cargo:rustc-link-arg-bin=silverfox-rescue=/MANIFESTINPUT:{}",manifest.display());}
    }
}

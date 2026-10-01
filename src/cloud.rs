//! Read-only client for the update website.
use anyhow::{Context,Result};
use serde::{Deserialize,Serialize};
use sha2::Digest;
use std::{fs,io::Read,sync::OnceLock,time::Duration};

pub fn https_agent()->anyhow::Result<&'static ureq::Agent>{
    static AGENT:OnceLock<ureq::Agent>=OnceLock::new();
    Ok(AGENT.get_or_init(||ureq::AgentBuilder::new().user_agent("SilverFoxRescue/2026.09").try_proxy_from_env(false).timeout_connect(Duration::from_secs(3)).timeout_read(Duration::from_secs(8)).timeout_write(Duration::from_secs(8)).build()))
}

#[derive(Clone)]
pub struct CloudClient{pub base_url:String}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProgramManifest{
    pub product:String,pub channel:String,
    #[serde(default)]pub available:bool,
    pub latest_version:Option<String>,pub minimum_version:Option<String>,pub policy:Option<String>,
    pub package_url:Option<String>,pub sha256:Option<String>,pub signature:Option<String>,
    pub executable_sha256:Option<String>,
    pub algorithm:Option<String>,pub platform:Option<String>,
}

impl CloudClient{
    pub fn configured()->Self{
        let base_url=std::env::var("SILVERFOX_CLOUD_URL").unwrap_or_else(|_|option_env!("SILVERFOX_CLOUD_URL").unwrap_or("https://ysmj4k.bond").to_owned()).trim().trim_end_matches('/').to_owned();
        Self{base_url}
    }

    pub fn program_manifest(&self)->Result<ProgramManifest>{
        if self.base_url.trim().is_empty(){anyhow::bail!("未配置更新站点地址");}
        if !crate::program_update::is_configured(){anyhow::bail!("当前构建未配置程序更新公钥");}
        self.program_manifest_for_channel(crate::settings::selected_update_channel())
    }

    fn program_manifest_for_channel(&self,preferred:&str)->Result<ProgramManifest>{
        let fetch=|channel:&str|->Result<ProgramManifest>{
            let url=format!("{}/public/program/{}/manifest.json",self.base_url.trim_end_matches('/'),channel);
            let response=https_agent()?.get(&url).call().with_context(||format!("无法获取 {} 程序更新清单",channel))?;
            let manifest:ProgramManifest=response.into_json().with_context(||format!("{} 程序更新清单无效",channel))?;
            if manifest.channel!=channel{anyhow::bail!("程序更新清单通道不匹配");}
            Ok(manifest)
        };
        if preferred!="beta"{return fetch("stable");}
        match fetch("beta"){
            Ok(manifest) if manifest.available=>Ok(manifest),
            Ok(_)=>fetch("stable"),
            Err(beta_error)=>fetch("stable").with_context(||format!("beta 通道不可用（{beta_error:#}），stable 通道也无法获取")),
        }
    }

    pub fn download_program_package(&self,manifest:&ProgramManifest,destination:&std::path::Path)->Result<()> {
        let url=manifest.package_url.as_deref().context("程序更新清单缺少下载地址")?;
        if !url.starts_with("https://")&&!url.starts_with("http://127.0.0.1"){anyhow::bail!("程序更新下载必须使用 HTTPS");}
        let reader=https_agent()?.get(url).call().context("程序更新包下载失败")?.into_reader();
        let mut bytes=Vec::new();reader.take(256*1024*1024).read_to_end(&mut bytes).context("读取程序更新包失败")?;
        if bytes.len()==256*1024*1024{anyhow::bail!("程序更新包超过 256 MiB");}
        let expected=manifest.sha256.as_deref().context("程序更新清单缺少哈希")?;
        if hex::encode(sha2::Sha256::digest(&bytes))!=expected.to_ascii_lowercase(){anyhow::bail!("程序更新包哈希不匹配");}
        if let Some(parent)=destination.parent(){fs::create_dir_all(parent)?;}
        let pending=destination.with_extension("pending");fs::write(&pending,&bytes)?;
        if destination.exists(){fs::remove_file(destination).ok();}fs::rename(&pending,destination)?;Ok(())
    }
}

#[cfg(test)]
mod network_diagnostics {
    #[test]
    #[ignore = "需要联网，用于检查更新连接"]
    fn fetch_program_manifest() {
        let client=super::CloudClient::configured();
        let result = client.program_manifest();
        if let Err(error) = &result { eprintln!("程序更新清单获取失败：{error:#}"); }
        let manifest=result.unwrap();
        let package=std::env::temp_dir().join(format!("silverfox-update-network-test-{}.zip",std::process::id()));
        let download=client.download_program_package(&manifest,&package);
        if let Err(error)=&download{eprintln!("程序更新包下载失败：{error:#}");}
        assert!(download.is_ok());
        std::fs::remove_file(package).unwrap();
    }
}

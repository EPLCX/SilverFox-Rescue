//! Read-only client for the update website.
use anyhow::{Context,Result};
use serde::{Deserialize,Serialize};
use sha2::Digest;
use ring::rand::{SecureRandom,SystemRandom};
use std::{fs,io::Read,sync::OnceLock,time::Duration};

pub fn https_agent()->anyhow::Result<&'static ureq::Agent>{
    static AGENT:OnceLock<ureq::Agent>=OnceLock::new();
    // The default rustls verifier checks public-root trust, hostname and validity.
    // HTTPS-only also rejects redirect downgrades before sending an HTTP request.
    Ok(AGENT.get_or_init(||ureq::AgentBuilder::new().https_only(true).user_agent("SilverFoxRescue/2026.09").try_proxy_from_env(false).timeout_connect(Duration::from_secs(3)).timeout_read(Duration::from_secs(8)).timeout_write(Duration::from_secs(8)).build()))
}

pub fn startup_connection_failure(error:&anyhow::Error,probe:impl FnOnce()->bool)->bool{
    // A bad clock can invalidate both the update server and the HTTPS probe.
    // Match the TLS error type directly, including rustls errors wrapped in IO.
    let certificate_failed=error.chain().any(|cause|{
        let tls=cause.downcast_ref::<ureq::rustls::Error>().or_else(||
            cause.downcast_ref::<std::io::Error>()
                .and_then(|error|error.get_ref())
                .and_then(|inner|inner.downcast_ref::<ureq::rustls::Error>()));
        matches!(tls,Some(ureq::rustls::Error::InvalidCertificate(_)))
    });
    if certificate_failed{return true;}
    let connection_failed=error.chain().any(|cause|cause.downcast_ref::<ureq::Error>().is_some_and(|error|
        matches!(error.kind(),ureq::ErrorKind::Dns|ureq::ErrorKind::ConnectionFailed|ureq::ErrorKind::Io)));
    connection_failed&&probe()
}

pub fn internet_reachable()->bool{
    let result=ureq::AgentBuilder::new().https_only(true).try_proxy_from_env(false)
        .timeout(Duration::from_secs(3)).redirects(0).build().get("https://1.1.1.1/").call();
    // An HTTP error response still proves that the HTTPS connection succeeded.
    matches!(result,Ok(_)|Err(ureq::Error::Status(_, _)))
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

const DEFAULT_UPDATE_URL:&str="https://***.sf-rescue.top";
const RANDOM_ALPHABET:&[u8;62]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static RUN_UPDATE_URL:OnceLock<String>=OnceLock::new();

fn random_character(random:&SystemRandom)->char{
    let mut byte=[0u8;1];
    loop{
        random.fill(&mut byte).expect("更新域名随机数生成失败");
        // Reject the uneven tail so all 62 characters have the same probability.
        if byte[0]<248{return RANDOM_ALPHABET[(byte[0]as usize)%62]as char;}
    }
}
fn expand_update_url(template:&str)->String{
    let template=template.trim().trim_end_matches('/');
    if template.is_empty(){return String::new();}
    let random=SystemRandom::new();
    let expanded:String=template.chars().map(|character|if character=='*'{random_character(&random)}else{character}).collect();
    if expanded.contains("://"){expanded}else{format!("https://{expanded}")}
}

// Update artifacts under /public share the manifest service's runtime origin.
// The signed manifest remains intact; only the HTTP request address changes.
pub fn download_url(base_url:&str,url:&str)->String{
    if base_url.starts_with("https://"){
        if let Some(rest)=url.strip_prefix("https://"){
            if let Some(at)=rest.find('/'){
                let path=&rest[at..];
                if path.starts_with("/public/rules/")||path.starts_with("/public/program/"){
                    return format!("{}{}",base_url.trim_end_matches('/'),path);
                }
            }
        }
    }
    url.to_owned()
}

impl CloudClient{
    pub fn configured()->Self{
        let base_url=RUN_UPDATE_URL.get_or_init(||{
            // The build selects the template; inherited workstation variables must
            // not override the address embedded in a distributed executable.
            expand_update_url(option_env!("SILVERFOX_CLOUD_URL").unwrap_or(DEFAULT_UPDATE_URL))
        }).clone();
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
        let url=download_url(&self.base_url,url);
        if !url.starts_with("https://"){anyhow::bail!("程序更新下载必须使用 HTTPS");}
        let reader=https_agent()?.get(&url).call().context("程序更新包下载失败")?.into_reader();
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

#[cfg(test)]mod domain_tests{
    use super::*;
    #[test]fn templates_expand_each_star_and_preserve_the_fixed_parts(){
        for template in ["***.sf-rescue.top","https://***.sf-rescue.top"]{
            let url=expand_update_url(template);let label=url.strip_prefix("https://").unwrap().strip_suffix(".sf-rescue.top").unwrap();
            assert_eq!(label.len(),3);assert!(label.bytes().all(|byte|RANDOM_ALPHABET.contains(&byte)));
        }
        let url=expand_update_url(" https://api-**.example.com/service/ ");
        assert!(url.starts_with("https://api-"));assert!(url.ends_with(".example.com/service"));assert!(!url.contains('*'));
        assert_eq!(expand_update_url("https://fixed.example.com/"),"https://fixed.example.com");
        assert_eq!(expand_update_url("http://127.0.0.1:18081"),"http://127.0.0.1:18081");
    }
    #[test]fn random_choices_cover_the_alphabet_and_clients_share_one_run_url(){
        let random=SystemRandom::new();for _ in 0..64{assert!(RANDOM_ALPHABET.contains(&(random_character(&random)as u8)));}
        assert_eq!(CloudClient::configured().base_url,CloudClient::configured().base_url);
    }
    #[test]fn inherited_environment_does_not_override_the_built_template(){
        const CHILD:&str="SILVERFOX_TEST_INHERITED_UPDATE_URL";
        if std::env::var_os(CHILD).is_some(){
            assert_eq!(std::env::var("SILVERFOX_CLOUD_URL").unwrap(),"https://obsolete.example.invalid");
            let template=option_env!("SILVERFOX_CLOUD_URL").unwrap_or(DEFAULT_UPDATE_URL).trim().trim_end_matches('/');
            let template=if template.contains("://"){template.to_owned()}else{format!("https://{template}")};
            let actual=CloudClient::configured().base_url;
            assert_eq!(actual.len(),template.len());
            for (expected,actual) in template.chars().zip(actual.chars()){
                if expected=='*'{assert!(actual.is_ascii_alphanumeric());}else{assert_eq!(actual,expected);}
            }
            return;
        }
        let status=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","cloud::domain_tests::inherited_environment_does_not_override_the_built_template"])
            .env(CHILD,"1").env("SILVERFOX_CLOUD_URL","https://obsolete.example.invalid")
            .status().unwrap();
        assert!(status.success());
    }
    #[test]fn downloads_use_the_runtime_host_and_keep_the_path_and_query(){
        let base="https://Ab9.sf-rescue.top";
        assert_eq!(download_url(base,"https://previous.example.com/public/rules/stable/a.zip?v=1"),format!("{base}/public/rules/stable/a.zip?v=1"));
        assert_eq!(download_url(base,"https://previous.example.com/public/program/beta/a.zip"),format!("{base}/public/program/beta/a.zip"));
        assert_eq!(download_url(base,"https://cdn.example.com/a.zip"),"https://cdn.example.com/a.zip");
        assert_eq!(download_url(base,"http://previous.example.com/public/rules/a.zip"),"http://previous.example.com/public/rules/a.zip");
    }
}

#[cfg(test)]mod startup_connection_tests{
    use super::*;
    #[test]fn certificate_validity_failures_block_without_connectivity_probe(){
        for reason in [ureq::rustls::CertificateError::NotValidYet,ureq::rustls::CertificateError::Expired]{
            let tls=ureq::rustls::Error::InvalidCertificate(reason);
            let transport:ureq::Error=std::io::Error::new(std::io::ErrorKind::InvalidData,tls).into();
            let error=anyhow::Error::new(transport).context("update manifest failed");
            assert!(startup_connection_failure(&error,||panic!("certificate failures must block without probing")));
        }
    }
    #[test]fn online_connection_failure_blocks_and_offline_failure_continues(){
        let transport:ureq::Error=std::io::Error::new(std::io::ErrorKind::TimedOut,"update connection timed out").into();
        let error=anyhow::Error::new(transport).context("update manifest failed");
        assert!(startup_connection_failure(&error,||true));
        assert!(!startup_connection_failure(&error,||false));
        let validation=anyhow::anyhow!("invalid manifest signature");
        assert!(!startup_connection_failure(&validation,||panic!("validation failure must not probe connectivity")));
    }
}

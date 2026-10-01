use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict { Malicious, Suspicious, Clean, Incomplete, Unknown }

impl Verdict {
    pub fn zh(&self) -> &'static str {
        match self {
            Self::Malicious => "恶意",
            Self::Suspicious => "可疑",
            Self::Clean => "未发现威胁",
            Self::Incomplete => "未完成检测",
            Self::Unknown => "云端未知",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: PathBuf,
    pub sha256: Option<String>,
    pub verdict: Verdict,
    pub score: u16,
    pub evidence: Vec<String>,
    pub source: String,
}

impl Finding {
    pub fn unsupported_non_pe(&self) -> bool {
        unsupported_file_decision(&self.verdict,&self.evidence)
    }

    pub fn in_report(&self) -> bool {
        matches!(self.verdict,Verdict::Malicious|Verdict::Suspicious|Verdict::Incomplete)
            && !self.unsupported_non_pe()
    }
}

pub fn unsupported_file_decision(verdict:&Verdict,evidence:&[String])->bool{
    *verdict==Verdict::Incomplete
        &&evidence.iter().any(|item|item.starts_with("非 PE 文件未命中受支持的专项检测")||item=="扫描的文件至少需要 2KB")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_excludes_only_clean_findings() {
        let mut finding=Finding{path:"test.exe".into(),sha256:None,verdict:Verdict::Clean,score:0,evidence:vec![],source:"test".into()};
        assert!(!finding.in_report());
        for verdict in [Verdict::Malicious,Verdict::Suspicious,Verdict::Incomplete] {
            finding.verdict=verdict;
            assert!(finding.in_report());
        }
        finding.verdict=Verdict::Unknown;
        assert!(!finding.in_report());
    }

    #[test]
    fn report_omits_unsupported_non_pe_but_keeps_png_alerts_and_errors() {
        let mut finding=Finding{path:"C:\\config.ini".into(),sha256:None,verdict:Verdict::Incomplete,score:0,
            evidence:vec!["非 PE 文件未命中受支持的专项检测；没有通用非 PE 机器学习模型".into()],source:"local-ml".into()};
        assert!(finding.unsupported_non_pe());
        assert!(!finding.in_report());
        finding.evidence=vec!["无法读取文件".into()];
        assert!(finding.in_report());
        finding.verdict=Verdict::Suspicious;
        finding.evidence=vec!["Stego.PNG.Overlay".into()];
        assert!(finding.in_report());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFinding {
    pub pid: u32,
    pub parent_pid: u32,
    pub image: String,
    pub cpu_percent: f32,
    pub file: Option<Finding>,
    pub coverage: String,
}

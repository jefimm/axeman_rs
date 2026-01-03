use chrono::{DateTime, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use base64_serde::base64_serde_type;
use crate::download_json_from_url;

base64_serde_type!(Base64Standard, base64::engine::general_purpose::STANDARD);

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CtLog {
    pub version: String,
    #[serde(rename = "log_list_timestamp")]
    pub log_list_timestamp: String,
    pub operators: Vec<Operator>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Log {
    pub description: String,
    #[serde(rename = "log_id")]
    pub log_id: String,
    pub key: String,
    pub url: String,
    pub mmd: i64,
    pub state: State,
    #[serde(rename = "temporal_interval")]
    pub temporal_interval: Option<TemporalInterval>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    pub usable: Option<Usable>,
    pub retired: Option<Retired>,
    pub qualified: Option<Qualified>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Usable {
    pub timestamp: DateTime<Utc>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Retired {
    pub timestamp: DateTime<Utc>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Qualified {
    pub timestamp: DateTime<Utc>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemporalInterval {
    #[serde(rename = "start_inclusive")]
    pub start_inclusive: DateTime<Utc>,
    #[serde(rename = "end_exclusive")]
    pub end_exclusive: DateTime<Utc>,
}

pub(crate) trait IsRateLimited {
    fn is_rate_limited(&self) -> bool;
}

// ===========================================

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CtLogInfo {
    #[serde(rename = "tree_size")]
    pub tree_size: u64,
    pub timestamp: u64,
    #[serde(rename = "sha256_root_hash")]
    pub sha256_root_hash: String,
    #[serde(rename = "tree_head_signature")]
    pub tree_head_signature: String,
    pub error_code: Option<String>,
}

impl IsRateLimited for CtLogInfo {
    fn is_rate_limited(&self) -> bool {
        if let Some(err_code) = &self.error_code {
            return err_code == "rate_limited";
        }
        false
    }
}
// ===========================================


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CtLogChunk {
    pub entries: Vec<CtLogEntry>,
    pub error_code: Option<String>,
}

impl IsRateLimited for CtLogChunk {
    fn is_rate_limited(&self) -> bool {
        if let Some(err_code) = &self.error_code {
            return err_code == "rate_limited";
        }
        false
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CtLogEntry {
    #[serde(with = "Base64Standard", rename = "leaf_input")]
    pub leaf_input: Vec<u8>,
    #[serde(with = "Base64Standard", rename = "extra_data")]
    pub extra_data: Vec<u8>,
}

const CTL_LISTS: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

pub(crate) fn get_ctl_logs() -> reqwest::Result<CtLog> {
    reqwest::blocking::get(CTL_LISTS)?
        .error_for_status()?
        .json()
}

pub(crate) fn retrieve_log_info(
    base_url: &str,
    client: &reqwest::blocking::Client,
) -> anyhow::Result<CtLogInfo> {
    let url = format!("{}ct/v1/get-sth", base_url);
    download_json_from_url(&url, client)
}

pub(crate) fn find_exactly_one_ct_log<'a>(
    ct_log: &'a CtLog,
    filter: &str,
) -> anyhow::Result<&'a Log> {
    let filter_with_https = format!("https://{}", filter);
    ct_log
        .operators
        .iter()
        .flat_map(|op| &op.logs)
        .filter(|log|
            (log.state.usable.is_some() || log.state.retired.is_some() || log.state.qualified.is_some()) &&
                (log.url.starts_with(filter) || log.url.starts_with(&filter_with_https)))
        .exactly_one()
        .map_err(|e| {
            // either 0 or 2+
            let logs = e.collect_vec();
            if logs.is_empty() {
                anyhow::anyhow!("No log found for {filter}")
            } else {
                match serde_json::to_string_pretty(&logs) {
                    Ok(pretty_logs) => {
                        anyhow::anyhow!("Multiple logs found for {filter} - {pretty_logs}")
                    }
                    Err(e) => anyhow::anyhow!("Multiple logs found for {filter} - {e}"),
                }
            }
        })
}

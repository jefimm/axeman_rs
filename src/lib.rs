mod ct_log;
mod merkle_tree;
mod mgr;
mod utils;

use crate::ct_log::{CtLogChunk, CtLogEntry, IsRateLimited, Log};
use crate::mgr::{ChannelWorker, WorkManager};
use crate::utils::write_strings_2_file;
use anyhow::bail;
use base64::Engine;
use chrono::DateTime;
use clap::Parser;
use crossbeam_channel::Receiver;
use openssl::asn1::Asn1TimeRef;
use openssl::x509::X509;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::cmp::min;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Write;
use std::{fs, thread, time};

/// This docstring will appear when you run the cli
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// This docstring will appear as the help message for -l
    #[arg(short = 'l', long)]
    pub list_mode: bool,
    #[arg(short = 'u', long)]
    pub ctl_url: Option<String>,
    #[arg(short = 'z', long, default_value_t = 0)]
    pub ctl_offset: u64,
    #[arg(short = 'o', long, default_value = "/tmp")]
    pub output_dir: String,
    #[arg(short = 'c', long = "concurency", default_value_t = 1)]
    pub concurrency_count: u8,
    #[arg(short = 'f', long = "filter", value_delimiter = ',')]
    pub filter_domains: Option<Vec<String>>,
    #[arg(short = 's', long)]
    pub save_max_idx_file: Option<String>,
}

pub fn handle_download(args: &Cli) -> anyhow::Result<()> {
    let ct_logs = ct_log::get_ctl_logs()?;
    if args.list_mode {
        println!("{}", serde_json::to_string_pretty(&ct_logs)?);
        return Ok(());
    }
    let Some(filter) = &args.ctl_url else {
        bail!("No log filter provided ")
    };
    let to_retrieve = ct_log::find_exactly_one_ct_log(&ct_logs, filter)?;
    download_log(to_retrieve, args)
}

fn download_log(to_retrieve: &Log, args: &Cli) -> anyhow::Result<()> {
    let client = create_http_client();
    let log_info = ct_log::retrieve_log_info(&to_retrieve.url, &client);
    let tree_size = log_info?.tree_size;

    if args.ctl_offset > tree_size {
        log::info!("Offset {} bigger than log size {}", args.ctl_offset , tree_size);
        return Ok(());
    }
    download_log_until(&to_retrieve.url, tree_size, args, &client)?;
    if let Some(save_max_idx_file) = &args.save_max_idx_file {
        write_strings_2_file(&tree_size.to_string(), save_max_idx_file);
    }
    Ok(())
}

#[derive(Default, Debug, Clone)]
pub(crate) struct HandleBlockData {
    pub log_url: String,
    pub start: u64,
    pub end: u64,
    pub output_dir: String,
    pub filter_domains: Vec<String>,
}

impl HandleBlockData {
    pub(crate) fn new(log_url: &str, start: u64, end: u64, out_dir: &str, args: &Cli) -> Self {
        Self {
            log_url: log_url.to_string(),
            start,
            end,
            output_dir: out_dir.to_string(),
            filter_domains: args.filter_domains.clone().unwrap_or_default(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct DownloadWorker {}

impl ChannelWorker<HandleBlockData> for DownloadWorker {
    fn run(&self, chan: &Receiver<HandleBlockData>) {
        let client = &create_http_client();

        while let Ok(work) = chan.recv() {
            if work.end == work.start && work.end == 0 {
                return;
            }
            handle_block(client, &work);
        }
    }
}

fn download_log_until(
    log_url: &str,
    log_size: u64,
    args: &Cli,
    client: &Client,
) -> anyhow::Result<()> {
    let block_size = get_max_block_size(log_url, client)? as u64;
    let mut start: u64 = (args.ctl_offset / block_size) * block_size;
    let mut dir_index = log_size + 1;
    let mut output_dir = String::new();
    // Instead of having a DownlodWorker struct with no members,
    // I would probably pass the run function to WorkManager
    // It can have the type `impl Fn(&Receiver<HandleBlockData>) -> ()`
    let worker = DownloadWorker {};
    let mut work_mgr = WorkManager::new(args.concurrency_count.into(), worker);

    log::info!(
        "Downloading log {log_url} from {ctl_offset} to {log_size} \
        block size {block_size} to directory {output_dir} with concurrency {concurrency_count}",
        ctl_offset = args.ctl_offset,
        output_dir = args.output_dir,
        concurrency_count = args.concurrency_count
    );
    while start < log_size {
        let current_dir_index = start / 1000000;
        if dir_index != current_dir_index {
            dir_index = current_dir_index;
            output_dir = verify_output_directory(dir_index, &args.output_dir, log_url)?;
        }
        let end = start + block_size;
        let hbd = HandleBlockData::new(log_url, start, end, &output_dir, args);
        work_mgr.submit(hbd)?;
        start = end;
    }

    for _ in 0..args.concurrency_count.into(){
        let hbd = HandleBlockData::new(log_url, 0, 0, &output_dir, args);
        work_mgr.submit(hbd)?;
    }
    log::info!("Waiting for the work to be completed");
    Ok(())
}

fn handle_block(client: &Client, hbd: &HandleBlockData) {
    let block = download_ctlog_json(&hbd.log_url, hbd.start, hbd.end, client);
    process_block(
        &hbd.log_url,
        hbd.start,
        hbd.end,
        &hbd.output_dir,
        &block.unwrap(),
        &hbd.filter_domains,
    );
}

fn process_block(
    log_url: &str,
    start: u64,
    end: u64,
    output_dir: &str,
    chunk: &CtLogChunk,
    filter_domains: &[String],
) {
    if chunk.entries.is_empty() {
        panic!("{} {}-{} returned empty data", log_url, start, end);
    }
    let mut idx = start;
    // collect on an iterator of strings joins them to a single string
    let file_content: String = chunk
        .entries
        .iter()
        .filter_map(|entry| {
            let s = to_csv_string(log_url, idx, entry, filter_domains);
            idx += 1;
            s
        })
        .collect();
    if file_content.is_empty() {
        return;
    }
    let csv_file = format!("{}/{}-{}.csv", output_dir, start, idx - 1);

    write_strings_2_file(&file_content, &csv_file);
}

fn to_csv_string(
    log_url: &str,
    idx: u64,
    entry: &CtLogEntry,
    filter_domains: &[String],
) -> Option<String> {
    let leaf_cert = merkle_tree::get_leaf_from_merkle_tree(&entry.leaf_input, &entry.extra_data);
    let domains = get_cert_domains(&leaf_cert);
    if is_filtered(&domains, filter_domains) {
        return None;
    }

    // let sha256 = chain_sha2456(entry.leaf_input.len() + entry.extra_data.len(), &chain[1..]);
    let not_before = get_cert_not_before(&leaf_cert);
    let not_after = get_cert_not_after(&leaf_cert);
    let as_der = base64::engine::general_purpose::STANDARD.encode(leaf_cert.to_der().unwrap());
    let log_with_last_char = log_url.trim_end_matches('/');
    Some(format!(
        "{},{},hash,{},{},{}.0,{}.0\n",
        log_with_last_char,
        idx,
        as_der,
        domains.join(" "),
        not_before,
        not_after
    ))
}

fn get_cert_domains(cert: &X509) -> Vec<String> {
    let mut ret: HashSet<String> = HashSet::new();
    let sn = cert.subject_name();

    for cn in sn.entries() {
        let nid = &cn.object().nid();
        if nid.as_raw() == openssl::nid::Nid::COMMONNAME.as_raw() {
            let os = cn.data().as_utf8().unwrap();
            let s: &str = os.as_ref();
            ret.insert(s.to_string());
        }
    }
    if let Some(sanr) = &cert.subject_alt_names() {
        for san in sanr {
            if let Some(dns_name) = san.dnsname() {
                ret.insert(String::from(dns_name));
            }
        }
    }
    Vec::from_iter(ret)
}

fn get_cert_not_before(cert: &X509) -> i64 {
    let not_before = &cert.not_before();
    asn_time_ref2ts(not_before)
}

fn get_cert_not_after(cert: &X509) -> i64 {
    let not_after = &cert.not_after();
    asn_time_ref2ts(not_after)
}

fn asn_time_ref2ts(not_before: &&Asn1TimeRef) -> i64 {
    let mut date_str = String::with_capacity(25);
    write!(date_str, "{}", not_before).unwrap();
    date_str = String::from(&date_str[..date_str.len() - 3]) + "+00:00";
    let datetime = DateTime::parse_from_str(&date_str, "%b %d %T %Y %z").unwrap();
    datetime.timestamp()
}

fn create_http_client() -> Client {
    let mut headers = HeaderMap::new();
    headers.append("accept-encoding", HeaderValue::from_static("gzip"));

    reqwest::blocking::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

fn is_filtered(domains: &[String], filters: &[String]) -> bool {
    if filters.is_empty() {
        return false;
    }
    for d in domains {
        for f in filters {
            if d.ends_with(f) {
                return true;
            }
        }
    }
    false
}

fn verify_output_directory(dir_index: u64, base_dir: &str, url: &str) -> anyhow::Result<String> {
    let url_dir = url
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .replace('/', "_");
    let dir_path = format!("{base_dir}/certificates/{url_dir}/{dir_index}");
    fs::create_dir_all(&dir_path)?;
    Ok(dir_path)
}

fn download_ctlog_json<T: DeserializeOwned + IsRateLimited>(
    base_url: &str,
    start: u64,
    end: u64,
    client: &Client,
) -> anyhow::Result<T> {
    let url = format!("{}ct/v1/get-entries?start={}&end={}", base_url, start, end);
    download_json_from_url(&url, client)
}

fn download_json_from_url<T: DeserializeOwned + IsRateLimited>(
    url: &str,
    client: &Client,
) -> anyhow::Result<T> {
    let minute = time::Duration::from_secs(60);
    let attempt_max = 30;

    for attempt in 1..=attempt_max {
        let result = client.get(url).send();
        match result {
            Ok(response) => match response.status() {
                StatusCode::OK => match response.json::<T>() {
                    Err(e) => {
                        log::warn!("Attempt {}: Url {} status 200 error {}", attempt, url, e);
                    }
                    Ok(json) => {
                        if !json.is_rate_limited() {
                            return Ok(json);
                        }
                        log::warn!(
                            "Attempt {}: Url {} status 200 got rate limited",
                            attempt,
                            url
                        );
                    }
                },
                StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::GATEWAY_TIMEOUT
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::BAD_GATEWAY => {
                    let status = response.status();
                    log::warn!(
                        "Attempt {}: Url {} got code {} with body {}",
                        attempt,
                        url,
                        status,
                        &response.text().unwrap()
                    );
                    if attempt == attempt_max {
                        bail!("max attempt reached {}", status);
                    }
                }
                code => {
                    log::warn!(
                        "Attempt {}: Url {} got code {} with body {}",
                        attempt,
                        url,
                        code,
                        &response.text().unwrap()
                    );
                    bail!("Http err {}", code);
                }
            },
            Err(ref e) => {
                log::warn!("Attempt {}: Url {} got error {:?}", attempt, url, e);
                if attempt == attempt_max {
                    bail!("max attempt reached {}", e);
                }
            }
        }
        thread::sleep(min(attempt, 10) * minute);
    }
    bail!("max attempt reached");
}

fn get_max_block_size(base_url: &str, client: &reqwest::blocking::Client) -> anyhow::Result<usize> {
    let chunk: CtLogChunk = download_ctlog_json(base_url, 0, 10000, client)?;
    Ok(chunk.entries.len())
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::fs::File;
    use std::io::BufReader;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_cert_parse() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/google.der");
        let mut my_buf = BufReader::new(File::open(&d).unwrap());
        let mut der_data = Vec::new();
        my_buf.read_to_end(&mut der_data).unwrap();
        let cert = &X509::from_der(&der_data).unwrap();
        let domains = get_cert_domains(cert);
        assert_eq!(domains.first().unwrap(), "www.google.com");
        let not_before = get_cert_not_before(cert);
        assert_eq!(not_before, 1682337676);
    }
}

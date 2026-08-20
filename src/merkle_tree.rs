use anyhow::{bail, Context};
use openssl::x509::X509;

#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct MerkleTreeHeader {
    /*    // "Version"         / Byte,
    pub version: u8,
    // "MerkleLeafType"  / Byte,
    pub leaf_type: u8,
    // "Timestamp"       / Int64ub,
    pub timestamp: u64,*/
    // "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    pub entry_type: u16,
    // "Entry"           / GreedyBytes
}

impl MerkleTreeHeader {
    fn parse(data: &[u8]) -> anyhow::Result<(MerkleTreeHeader, &[u8])> {
        if data.len() < 12 {
            bail!("merkle leaf too short: {} bytes", data.len());
        }
        Ok((
            MerkleTreeHeader {
                /*            version: data[0],
                leaf_type: data[1],
                timestamp: u64::from_be_bytes(data[2..10].try_into().unwrap()),*/
                entry_type: u16::from_be_bytes(data[10..12].try_into().unwrap()),
            },
            &data[12..],
        ))
    }
}

pub(crate) fn get_leaf_from_merkle_tree(leaf_input: &[u8], extra_data: &[u8]) -> anyhow::Result<X509> {
    let (mth, entry_data) = MerkleTreeHeader::parse(leaf_input)?;
    if mth.entry_type == 0 {
        parse_x509(entry_data).map(|(_, cert)| cert)
    } else {
        parse_x509(extra_data).map(|(_, cert)| cert)
    }
}

fn parse_x509(data: &[u8]) -> anyhow::Result<(&[u8], X509)> {
    if data.len() < 3 {
        bail!("certificate prefix too short");
    }
    let size = u32::from_be_bytes([0, data[0], data[1], data[2]]);
    let end = 3usize
        .checked_add(size as usize)
        .context("certificate size overflow")?;
    if data.len() < end {
        bail!("certificate truncated: need {end} bytes, have {}", data.len());
    }
    let cert = X509::from_der(&data[3..end]).context("X509 DER parse")?;
    Ok((&data[end..], cert))
}

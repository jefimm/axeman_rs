use openssl::error::ErrorStack;
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
    fn parse(data: &[u8]) -> (MerkleTreeHeader, &[u8]) {
        (MerkleTreeHeader {
            /*            version: data[0],
                        leaf_type: data[1],
                        timestamp: u64::from_be_bytes(data[2..10].try_into().unwrap()),*/
            entry_type: u16::from_be_bytes(data[10..12].try_into().unwrap()),
        }, &data[12..])
    }
}
/*
pub(crate) struct Certificate {
// "Length" / Int24ub,
// "CertData" / Bytes(this.Length)
}

pub(crate) struct CertificateChain {
// "ChainLength" / Int24ub,
// "Chain" / GreedyRange(Certificate),
}

pub(crate) struct PreCertEntry {
// "LeafCert" / Certificate,
// Embedded(CertificateChain),
// Terminated
}

*/
pub(crate) fn get_leaf_from_merkle_tree<'a>(leaf_input: &'a [u8], extra_data: &'a [u8]) -> X509 {
    let (mth, entry_data) = MerkleTreeHeader::parse(&leaf_input);
    /*    let mut extra_certs: Vec<X509>;
        let mut leaf_cert: X509;*/

    if mth.entry_type == 0 {
        return parse_x509(entry_data).unwrap().1;
        /*        leaf_cert = cert;
                extra_certs = parse_cert_list(&extra_data[3..]);*/
    } else {
        return parse_x509(extra_data).unwrap().1;
        /*        returnparse_result.1;
                extra_certs = parse_cert_list(&parse_result.0[3..]);*/
    }
    /*    let mut cert_chain: Vec<X509> = Vec::with_capacity(&extra_certs.len() + 1);
        cert_chain.push(leaf_cert);
        cert_chain.append(&mut extra_certs);
        cert_chain*/
}

fn parse_x509(data: &[u8]) -> Result<(&[u8], X509), ErrorStack> {
    let len = vec![0, data[0], data[1], data[2]];
    let size = u32::from_be_bytes(len.try_into().unwrap());
    let end: usize = (size + 3).try_into().unwrap();
    let cert_data = &data[3..end];
    let res = X509::from_der(cert_data);

    let cert = res.unwrap();
    let rest_of_data = &data[end..];
    return Ok((rest_of_data, cert));
}

/*fn parse_cert_list(data: &[u8]) -> Vec<X509> {
    let mut ret: Vec<X509> = Vec::new();
    let mut cursor = data;
    while cursor.len() > 5 {
        let (rest_data, cert) = parse_x509(cursor).unwrap();
        cursor = rest_data;
        ret.push(cert);
    }
    ret
}*/
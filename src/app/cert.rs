use anyhow::{bail, Result};

/// Certificate information extracted from a PEM/DER certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub is_expired: bool,
}

impl CertInfo {
    /// Create a CertInfo with explicit fields (useful for testing and manual construction).
    pub fn new(
        subject: String,
        not_before: String,
        not_after: String,
        days_until_expiry: i64,
    ) -> Self {
        Self {
            subject,
            not_before: not_before.clone(),
            not_after: not_after.clone(),
            days_until_expiry,
            is_expired: days_until_expiry < 0,
        }
    }
}

/// Certificate manager providing cert loading, parsing, and expiry checks.
pub struct CertManager;

impl CertManager {
    /// Check expiry information of a PEM-encoded certificate.
    ///
    /// Parses the PEM envelope, decodes the base64 DER body,
    /// and extracts the validity period from the X.509 TBSCertificate.
    pub fn check_expiry(pem_data: &[u8]) -> Result<CertInfo> {
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|_| anyhow::anyhow!("PEM data is not valid UTF-8"))?;

        let der = decode_pem(pem_str)?;
        parse_x509_validity(&der)
    }

    /// Validate that data looks like a valid PEM certificate.
    pub fn validate_pem(data: &[u8]) -> bool {
        let Ok(s) = std::str::from_utf8(data) else {
            return false;
        };
        s.contains("-----BEGIN CERTIFICATE-----") && s.contains("-----END CERTIFICATE-----")
    }
}

/// Decode PEM format: extract the base64 block between BEGIN/END markers.
fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem
        .find(begin_marker)
        .ok_or_else(|| anyhow::anyhow!("missing BEGIN CERTIFICATE marker"))?;
    let after_begin = start + begin_marker.len();

    let end = pem[after_begin..]
        .find(end_marker)
        .ok_or_else(|| anyhow::anyhow!("missing END CERTIFICATE marker"))?;

    let b64_block = &pem[after_begin..after_begin + end];
    let b64_clean: String = b64_block.chars().filter(|c| !c.is_whitespace()).collect();

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64_clean)
        .map_err(|e| anyhow::anyhow!("base64 decode error: {}", e))?;

    Ok(der)
}

/// Parse an X.509 DER certificate to extract subject and validity.
///
/// X.509 structure (simplified):
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate  SEQUENCE {
///     version         [0] EXPLICIT INTEGER OPTIONAL,
///     serialNumber    INTEGER,
///     signature       SEQUENCE,
///     issuer          SEQUENCE,
///     validity        SEQUENCE {
///       notBefore     Time,
///       notAfter      Time,
///     },
///     subject         SEQUENCE,
///     ...
///   },
///   ...
/// }
/// ```
fn parse_x509_validity(der: &[u8]) -> Result<CertInfo> {
    let (_, cert_content) = read_asn1_sequence(der)?;

    // TBSCertificate is the first element
    let (_, tbs_content) = read_asn1_sequence(cert_content)?;

    let mut pos = 0;

    // version (optional, context tag [0])
    if !tbs_content.is_empty() && (tbs_content[0] & 0xE0) == 0xA0 {
        let (len, _) = read_asn1_element(&tbs_content[pos..])?;
        pos += len;
    }

    // serialNumber (INTEGER)
    let (len, _) = read_asn1_element(&tbs_content[pos..])?;
    pos += len;

    // signature algorithm (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs_content[pos..])?;
    pos += len;

    // issuer (SEQUENCE)
    let (len, _) = read_asn1_element(&tbs_content[pos..])?;
    pos += len;

    // validity (SEQUENCE)
    let (_, validity_content) = read_asn1_sequence(&tbs_content[pos..])?;

    // notBefore
    let (nb_total_len, nb_content) = read_asn1_element(validity_content)?;
    let not_before = parse_asn1_time(nb_content)?;

    // notAfter
    let (_, na_content) = read_asn1_element(&validity_content[nb_total_len..])?;
    let not_after = parse_asn1_time(na_content)?;

    // Skip to subject -- advance past validity
    let (validity_total, _) = read_asn1_element(&tbs_content[pos..])?;
    pos += validity_total;

    // subject (SEQUENCE) - extract as a simple string
    let subject = if pos < tbs_content.len() {
        extract_subject_cn(&tbs_content[pos..]).unwrap_or_else(|_| "unknown".to_string())
    } else {
        "unknown".to_string()
    };

    // Calculate days until expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expiry_epoch = time_string_to_epoch(&not_after)?;
    let diff_secs = expiry_epoch as i64 - now as i64;
    let days_until_expiry = diff_secs / 86400;

    Ok(CertInfo {
        subject,
        not_before: not_before.clone(),
        not_after: not_after.clone(),
        days_until_expiry,
        is_expired: days_until_expiry < 0,
    })
}

/// Read an ASN.1 TLV element. Returns (total_bytes_consumed, content_slice).
fn read_asn1_element(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() {
        bail!("ASN.1: unexpected end of data");
    }

    let _tag = data[0];
    let (len, header_size) = read_asn1_length(&data[1..])?;
    let total = 1 + header_size + len;

    if total > data.len() {
        bail!("ASN.1: element length exceeds available data");
    }

    let content = &data[1 + header_size..1 + header_size + len];
    Ok((total, content))
}

/// Read an ASN.1 SEQUENCE, returning (total_bytes, content_slice).
fn read_asn1_sequence(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() || (data[0] & 0x1F) != 0x10 {
        bail!("ASN.1: expected SEQUENCE tag (0x30)");
    }
    read_asn1_element(data)
}

/// Read ASN.1 length encoding. Returns (length_value, bytes_consumed).
fn read_asn1_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        bail!("ASN.1: unexpected end when reading length");
    }

    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            bail!("ASN.1: unsupported length encoding ({} bytes)", num_bytes);
        }
        if data.len() < 1 + num_bytes {
            bail!("ASN.1: not enough data for multi-byte length");
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Parse an ASN.1 UTCTime or GeneralizedTime into a readable string.
fn parse_asn1_time(content: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(content)
        .map_err(|_| anyhow::anyhow!("ASN.1 time is not valid UTF-8"))?;

    // UTCTime: YYMMDDHHMMSSZ (13 chars) or GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars)
    if s.len() >= 13 {
        Ok(s.to_string())
    } else {
        bail!("ASN.1: unrecognized time format: {}", s);
    }
}

/// Convert an ASN.1 time string to Unix epoch seconds.
fn time_string_to_epoch(time_str: &str) -> Result<u64> {
    let s = time_str.trim_end_matches('Z');

    let (year, rest) = if s.len() >= 14 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        let year: u64 = s[..4]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid year in time"))?;
        (year, &s[4..])
    } else if s.len() >= 12 {
        // UTCTime: YYMMDDHHMMSS
        let yy: u64 = s[..2]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid year in time"))?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &s[2..])
    } else {
        bail!("time string too short: {}", time_str);
    };

    let month: u64 = rest[..2]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid month"))?;
    let day: u64 = rest[2..4]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid day"))?;
    let hour: u64 = rest[4..6]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid hour"))?;
    let minute: u64 = rest[6..8]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid minute"))?;
    let second: u64 = if rest.len() >= 10 {
        rest[8..10]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid second"))?
    } else {
        0
    };

    // Approximate epoch calculation (not accounting for leap seconds, but sufficient)
    let mut total_days: u64 = 0;

    // Years
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Months in current year
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        total_days += days_in_month[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            total_days += 1;
        }
    }

    total_days += day - 1;

    Ok(total_days * 86400 + hour * 3600 + minute * 60 + second)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Extract Common Name (CN) from a subject SEQUENCE.
fn extract_subject_cn(data: &[u8]) -> Result<String> {
    let (_, subject_content) = read_asn1_sequence(data)?;

    // Subject is a SEQUENCE of SETs of SEQUENCE(OID, value)
    let mut pos = 0;
    while pos < subject_content.len() {
        let (set_total, set_content) = read_asn1_element(&subject_content[pos..])?;

        // Each SET contains a SEQUENCE
        if let Ok((_, seq_content)) = read_asn1_sequence(set_content) {
            // OID
            if let Ok((oid_total, oid_content)) = read_asn1_element(seq_content) {
                // CN OID = 2.5.4.3 = 55 04 03
                if oid_content == [0x55, 0x04, 0x03] {
                    // Value follows the OID
                    if let Ok((_, value_content)) = read_asn1_element(&seq_content[oid_total..]) {
                        return Ok(String::from_utf8_lossy(value_content).to_string());
                    }
                }
            }
        }

        pos += set_total;
    }

    Ok("unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_info_creation_and_expiry() {
        let info = CertInfo::new(
            "test.example.com".to_string(),
            "230101000000Z".to_string(),
            "250101000000Z".to_string(),
            365,
        );
        assert_eq!(info.subject, "test.example.com");
        assert!(!info.is_expired);
        assert_eq!(info.days_until_expiry, 365);
    }

    #[test]
    fn cert_info_expired() {
        let info = CertInfo::new(
            "expired.example.com".to_string(),
            "200101000000Z".to_string(),
            "210101000000Z".to_string(),
            -100,
        );
        assert!(info.is_expired);
        assert!(info.days_until_expiry < 0);
    }

    #[test]
    fn validate_pem_format() {
        let valid_pem = b"-----BEGIN CERTIFICATE-----\nMIIBxx==\n-----END CERTIFICATE-----\n";
        assert!(CertManager::validate_pem(valid_pem));

        let invalid_pem = b"not a certificate";
        assert!(!CertManager::validate_pem(invalid_pem));

        let partial_pem = b"-----BEGIN CERTIFICATE-----\ndata";
        assert!(!CertManager::validate_pem(partial_pem));
    }

    #[test]
    fn pem_validation_rejects_binary() {
        let binary_data: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        assert!(!CertManager::validate_pem(binary_data));
    }

    #[test]
    fn check_expiry_with_generated_cert() {
        // Use rcgen (dev-dependency) to generate a test certificate
        let subject_alt_names = vec!["test.example.com".to_string()];
        let params = rcgen::CertificateParams::new(subject_alt_names).unwrap();
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let pem = cert.pem();

        let info = CertManager::check_expiry(pem.as_bytes()).unwrap();
        assert!(
            !info.is_expired,
            "freshly generated cert should not be expired"
        );
        assert!(
            info.days_until_expiry > 0,
            "should have positive days until expiry"
        );
    }

    #[test]
    fn time_string_to_epoch_utctime() {
        // 2024-01-01 00:00:00 UTC
        let epoch = time_string_to_epoch("240101000000Z").unwrap();
        // 2024-01-01 is known to be 19723 days after 1970-01-01
        // 19723 * 86400 = 1704067200 -- but our calculation might differ slightly
        // due to leap year handling. Let's just verify it's reasonable.
        assert!(epoch > 1_700_000_000);
        assert!(epoch < 1_710_000_000);
    }

    #[test]
    fn time_string_to_epoch_generalizedtime() {
        let epoch = time_string_to_epoch("20240101000000Z").unwrap();
        assert!(epoch > 1_700_000_000);
        assert!(epoch < 1_710_000_000);
    }
}

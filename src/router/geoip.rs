use std::net::IpAddr;

use anyhow::Result;

/// GeoIP 数据库（MaxMind mmdb 格式）
pub struct GeoIpDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpDb {
    /// 从 mmdb 文件加载
    pub fn load(path: &str) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| anyhow::anyhow!("failed to load GeoIP database '{}': {}", path, e))?;
        Ok(Self { reader })
    }

    /// 查询 IP 对应的国家 ISO 代码（如 "CN", "US"）
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct Country {
            country: Option<CountryInfo>,
        }
        #[derive(serde::Deserialize)]
        struct CountryInfo {
            iso_code: Option<String>,
        }

        let result: Country = self.reader.lookup(ip).ok()?;
        result.country?.iso_code
    }
}

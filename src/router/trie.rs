use std::collections::HashMap;
use std::net::IpAddr;

/// Trie node for efficient domain suffix matching.
///
/// Domains are inserted in reverse-label order, e.g. "www.example.com"
/// is stored as ["com", "example", "www"].
pub struct DomainTrie {
    root: TrieNode,
}

struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// If Some, this node is a terminal and holds the associated value (outbound tag index).
    value: Option<usize>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            value: None,
        }
    }
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    /// Insert a domain suffix with an associated value.
    /// The domain is split by '.' and inserted in reverse order.
    pub fn insert(&mut self, domain: &str, value: usize) {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &mut self.root;
        for label in labels {
            node = node
                .children
                .entry(label.to_lowercase())
                .or_insert_with(TrieNode::new);
        }
        if node.value.is_none() {
            node.value = Some(value);
        }
    }

    /// Find the longest matching suffix for the given domain.
    /// Returns the value associated with the best match, or None.
    pub fn find(&self, domain: &str) -> Option<usize> {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &self.root;
        let mut best_match = None;

        for label in labels {
            let lower = label.to_lowercase();
            if let Some(child) = node.children.get(&lower) {
                if child.value.is_some() {
                    best_match = child.value;
                }
                node = child;
            } else {
                break;
            }
        }

        best_match
    }

    pub fn find_first_match(&self, domain: &str) -> Option<usize> {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &self.root;
        let mut first_match: Option<usize> = None;

        for label in labels {
            let lower = label.to_lowercase();
            if let Some(child) = node.children.get(&lower) {
                if let Some(v) = child.value {
                    first_match = Some(first_match.map(|cur| cur.min(v)).unwrap_or(v));
                }
                node = child;
            } else {
                break;
            }
        }

        first_match
    }

    /// Check if the domain matches any entry (exact or suffix match).
    pub fn matches(&self, domain: &str) -> bool {
        self.find(domain).is_some()
    }

    pub fn len(&self) -> usize {
        self.count_nodes(&self.root)
    }

    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }

    fn count_nodes(&self, node: &TrieNode) -> usize {
        let mut count = if node.value.is_some() { 1 } else { 0 };
        for child in node.children.values() {
            count += self.count_nodes(child);
        }
        count
    }
}

/// LRU cache for route matching results
pub struct RouteLruCache {
    capacity: usize,
    entries: Vec<(String, String)>, // (key, outbound_tag)
}

impl RouteLruCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<&str> {
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == key) {
            let entry = self.entries.remove(pos);
            self.entries.push(entry);
            self.entries.last().map(|(_, v)| v.as_str())
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: String, value: String) {
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == &key) {
            self.entries.remove(pos);
        }
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push((key, value));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Binary trie for IP CIDR longest-prefix matching.
/// Supports both IPv4 (32-bit) and IPv6 (128-bit).
pub struct IpPrefixTrie {
    root_v4: IpTrieNode,
    root_v6: IpTrieNode,
}

struct IpTrieNode {
    children: [Option<Box<IpTrieNode>>; 2],
    value: Option<usize>,
}

impl IpTrieNode {
    fn new() -> Self {
        Self {
            children: [None, None],
            value: None,
        }
    }
}

impl IpPrefixTrie {
    pub fn new() -> Self {
        Self {
            root_v4: IpTrieNode::new(),
            root_v6: IpTrieNode::new(),
        }
    }

    /// Insert a CIDR prefix with an associated value.
    pub fn insert(&mut self, cidr: &ipnet::IpNet, value: usize) {
        let (bits, prefix_len, root) = match cidr {
            ipnet::IpNet::V4(v4) => {
                let octets = v4.addr().octets();
                let mut bits = [0u8; 4];
                bits.copy_from_slice(&octets);
                (
                    Self::octets_to_bits_v4(&bits),
                    v4.prefix_len(),
                    &mut self.root_v4,
                )
            }
            ipnet::IpNet::V6(v6) => {
                let octets = v6.addr().octets();
                let mut bits = [0u8; 16];
                bits.copy_from_slice(&octets);
                (
                    Self::octets_to_bits_v6(&bits),
                    v6.prefix_len(),
                    &mut self.root_v6,
                )
            }
        };

        let mut node = root;
        for i in 0..prefix_len as usize {
            let bit = if i < bits.len() { bits[i] } else { 0 };
            let idx = bit as usize;
            if node.children[idx].is_none() {
                node.children[idx] = Some(Box::new(IpTrieNode::new()));
            }
            node = node.children[idx].as_mut().unwrap();
        }
        if node.value.is_none() {
            node.value = Some(value);
        }
    }

    /// Find the longest prefix match for an IP address.
    pub fn longest_prefix_match(&self, addr: IpAddr) -> Option<usize> {
        let (bits, root) = match addr {
            IpAddr::V4(v4) => (Self::octets_to_bits_v4(&v4.octets()), &self.root_v4),
            IpAddr::V6(v6) => (Self::octets_to_bits_v6(&v6.octets()), &self.root_v6),
        };

        let mut node = root;
        let mut best = node.value;

        for &bit in &bits {
            let idx = bit as usize;
            match &node.children[idx] {
                Some(child) => {
                    node = child;
                    if node.value.is_some() {
                        best = node.value;
                    }
                }
                None => break,
            }
        }

        best
    }

    pub fn first_prefix_match(&self, addr: IpAddr) -> Option<usize> {
        let (bits, root) = match addr {
            IpAddr::V4(v4) => (Self::octets_to_bits_v4(&v4.octets()), &self.root_v4),
            IpAddr::V6(v6) => (Self::octets_to_bits_v6(&v6.octets()), &self.root_v6),
        };

        let mut node = root;
        let mut first = node.value;

        for &bit in &bits {
            let idx = bit as usize;
            match &node.children[idx] {
                Some(child) => {
                    node = child;
                    if let Some(v) = node.value {
                        first = Some(first.map(|cur| cur.min(v)).unwrap_or(v));
                    }
                }
                None => break,
            }
        }

        first
    }

    /// Check if an IP matches any prefix.
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.longest_prefix_match(addr).is_some()
    }

    // Convert IPv4 octets to bit array (32 bits)
    fn octets_to_bits_v4(octets: &[u8; 4]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(32);
        for &byte in octets {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        bits
    }

    // Convert IPv6 octets to bit array (128 bits)
    fn octets_to_bits_v6(octets: &[u8; 16]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(128);
        for &byte in octets {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trie_insert_and_find() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);
        trie.insert("google.com", 2);

        assert_eq!(trie.find("example.com"), Some(1));
        assert_eq!(trie.find("www.example.com"), Some(1));
        assert_eq!(trie.find("sub.www.example.com"), Some(1));
        assert_eq!(trie.find("google.com"), Some(2));
        assert_eq!(trie.find("notexample.com"), None);
    }

    #[test]
    fn trie_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("Example.COM", 1);

        assert_eq!(trie.find("example.com"), Some(1));
        assert_eq!(trie.find("EXAMPLE.COM"), Some(1));
        assert_eq!(trie.find("www.Example.Com"), Some(1));
    }

    #[test]
    fn trie_longest_match() {
        let mut trie = DomainTrie::new();
        trie.insert("com", 1);
        trie.insert("example.com", 2);
        trie.insert("www.example.com", 3);

        assert_eq!(trie.find("www.example.com"), Some(3));
        assert_eq!(trie.find("sub.example.com"), Some(2));
        assert_eq!(trie.find("other.com"), Some(1));
    }

    #[test]
    fn trie_no_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com", 1);

        assert_eq!(trie.find("example.org"), None);
        assert!(!trie.matches("example.org"));
    }

    #[test]
    fn trie_cn_suffix() {
        let mut trie = DomainTrie::new();
        trie.insert("cn", 1);

        assert!(trie.matches("baidu.cn"));
        assert!(trie.matches("www.gov.cn"));
        assert!(!trie.matches("cnn.com"));
    }

    #[test]
    fn trie_len() {
        let mut trie = DomainTrie::new();
        assert!(trie.is_empty());
        trie.insert("example.com", 1);
        trie.insert("google.com", 2);
        assert_eq!(trie.len(), 2);
    }

    #[test]
    fn lru_cache_basic() {
        let mut cache = RouteLruCache::new(3);
        cache.insert("a".to_string(), "direct".to_string());
        cache.insert("b".to_string(), "proxy".to_string());

        assert_eq!(cache.get("a"), Some("direct"));
        assert_eq!(cache.get("b"), Some("proxy"));
        assert_eq!(cache.get("c"), None);
    }

    #[test]
    fn lru_cache_eviction() {
        let mut cache = RouteLruCache::new(2);
        cache.insert("a".to_string(), "1".to_string());
        cache.insert("b".to_string(), "2".to_string());
        cache.insert("c".to_string(), "3".to_string());

        assert_eq!(cache.get("a"), None); // evicted
        assert_eq!(cache.get("b"), Some("2"));
        assert_eq!(cache.get("c"), Some("3"));
    }

    #[test]
    fn lru_cache_update_moves_to_front() {
        let mut cache = RouteLruCache::new(2);
        cache.insert("a".to_string(), "1".to_string());
        cache.insert("b".to_string(), "2".to_string());
        cache.get("a"); // access 'a' to move to most recent
        cache.insert("c".to_string(), "3".to_string());

        assert_eq!(cache.get("a"), Some("1")); // still present (most recently used)
        assert_eq!(cache.get("b"), None); // evicted
        assert_eq!(cache.get("c"), Some("3"));
    }

    #[test]
    fn lru_cache_overwrite() {
        let mut cache = RouteLruCache::new(3);
        cache.insert("a".to_string(), "1".to_string());
        cache.insert("a".to_string(), "2".to_string());
        assert_eq!(cache.get("a"), Some("2"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn lru_cache_clear() {
        let mut cache = RouteLruCache::new(3);
        cache.insert("a".to_string(), "1".to_string());
        cache.clear();
        assert!(cache.is_empty());
    }

    // IpPrefixTrie tests
    #[test]
    fn ip_trie_insert_and_match_v4() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"10.0.0.0/8".parse().unwrap(), 1);
        trie.insert(&"192.168.0.0/16".parse().unwrap(), 2);

        assert_eq!(
            trie.longest_prefix_match("10.1.2.3".parse().unwrap()),
            Some(1)
        );
        assert_eq!(
            trie.longest_prefix_match("192.168.1.1".parse().unwrap()),
            Some(2)
        );
        assert_eq!(trie.longest_prefix_match("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn ip_trie_longest_prefix_v4() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"10.0.0.0/8".parse().unwrap(), 1);
        trie.insert(&"10.0.0.0/16".parse().unwrap(), 2);
        trie.insert(&"10.0.0.0/24".parse().unwrap(), 3);

        // /24 is the longest match
        assert_eq!(
            trie.longest_prefix_match("10.0.0.5".parse().unwrap()),
            Some(3)
        );
        // /16 match
        assert_eq!(
            trie.longest_prefix_match("10.0.1.5".parse().unwrap()),
            Some(2)
        );
        // /8 match
        assert_eq!(
            trie.longest_prefix_match("10.1.0.5".parse().unwrap()),
            Some(1)
        );
    }

    #[test]
    fn ip_trie_v6() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"2001:db8::/32".parse().unwrap(), 1);
        trie.insert(&"fe80::/10".parse().unwrap(), 2);

        assert_eq!(
            trie.longest_prefix_match("2001:db8::1".parse().unwrap()),
            Some(1)
        );
        assert_eq!(
            trie.longest_prefix_match("fe80::1".parse().unwrap()),
            Some(2)
        );
        assert_eq!(trie.longest_prefix_match("::1".parse().unwrap()), None);
    }

    #[test]
    fn ip_trie_mixed_v4_v6() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"10.0.0.0/8".parse().unwrap(), 1);
        trie.insert(&"2001:db8::/32".parse().unwrap(), 2);

        assert_eq!(
            trie.longest_prefix_match("10.1.2.3".parse().unwrap()),
            Some(1)
        );
        assert_eq!(
            trie.longest_prefix_match("2001:db8::1".parse().unwrap()),
            Some(2)
        );
        // v4 addr shouldn't match v6 prefix
        assert_eq!(trie.longest_prefix_match("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn ip_trie_contains() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"172.16.0.0/12".parse().unwrap(), 1);

        assert!(trie.contains("172.16.0.1".parse().unwrap()));
        assert!(trie.contains("172.31.255.255".parse().unwrap()));
        assert!(!trie.contains("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn ip_trie_single_host_v4() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"1.2.3.4/32".parse().unwrap(), 1);

        assert_eq!(
            trie.longest_prefix_match("1.2.3.4".parse().unwrap()),
            Some(1)
        );
        assert_eq!(trie.longest_prefix_match("1.2.3.5".parse().unwrap()), None);
    }

    #[test]
    fn ip_trie_default_route() {
        let mut trie = IpPrefixTrie::new();
        trie.insert(&"0.0.0.0/0".parse().unwrap(), 0);
        trie.insert(&"10.0.0.0/8".parse().unwrap(), 1);

        // 10.x.x.x matches /8 (longer prefix)
        assert_eq!(
            trie.longest_prefix_match("10.1.2.3".parse().unwrap()),
            Some(1)
        );
        // Everything else matches /0
        assert_eq!(
            trie.longest_prefix_match("8.8.8.8".parse().unwrap()),
            Some(0)
        );
    }
}

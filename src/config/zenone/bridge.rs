use std::collections::HashMap;

use super::error::Diagnostics;
use super::types::*;
use crate::config::types as cfg;

/// ZenOneDoc -> Config（用于内核加载）
pub fn zenone_to_config(doc: &ZenOneDoc, diags: &mut Diagnostics) -> cfg::Config {
    let log_level = doc
        .settings
        .as_ref()
        .and_then(|s| s.log_level.clone())
        .unwrap_or_else(|| "info".to_string());

    let max_connections = doc
        .settings
        .as_ref()
        .and_then(|s| s.max_connections)
        .unwrap_or(10000);

    let outbounds = convert_nodes_to_outbounds(&doc.nodes, diags);
    let proxy_groups = convert_groups(&doc.groups);
    let router = convert_router(doc.router.as_ref());
    let dns = doc.dns.as_ref().map(convert_dns);
    let inbounds = convert_inbounds(&doc.inbounds);
    let api = doc.settings.as_ref().and_then(|s| {
        s.api.as_ref().map(|a| cfg::ApiConfig {
            listen: a.listen.clone(),
            port: a.port,
            secret: a.secret.clone(),
            external_ui: a.external_ui.clone(),
        })
    });
    let derp = doc.settings.as_ref().and_then(|s| {
        s.derp.as_ref().map(|d| cfg::DerpConfig {
            enabled: d.enabled,
            port: d.port.unwrap_or(3340),
            private_key: None,
            region_id: 900,
            region_name: "OpenWorld-DERP".to_string(),
        })
    });

    // metadata -> subscription
    let subscriptions = doc
        .metadata
        .as_ref()
        .and_then(|m| {
            m.source_url.as_ref().map(|url| {
                vec![cfg::SubscriptionConfig {
                    name: m.name.clone().unwrap_or_else(|| "zenone-sub".to_string()),
                    url: url.clone(),
                    interval_secs: m.update_interval.unwrap_or(3600),
                    enabled: true,
                }]
            })
        })
        .unwrap_or_default();

    cfg::Config {
        log: cfg::LogConfig { level: log_level },
        profile: None,
        inbounds,
        outbounds,
        proxy_groups,
        router,
        subscriptions,
        api,
        dns,
        derp,
        max_connections,
    }
}

/// ZenOneDoc -> OutboundConfig 列表（用于订阅解析）
pub fn zenone_to_outbounds(doc: &ZenOneDoc, diags: &mut Diagnostics) -> Vec<cfg::OutboundConfig> {
    convert_nodes_to_outbounds(&doc.nodes, diags)
}

fn convert_nodes_to_outbounds(
    nodes: &[ZenNode],
    diags: &mut Diagnostics,
) -> Vec<cfg::OutboundConfig> {
    nodes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| convert_node_to_outbound(n, i, diags))
        .collect()
}

fn convert_node_to_outbound(
    node: &ZenNode,
    _idx: usize,
    _diags: &mut Diagnostics,
) -> Option<cfg::OutboundConfig> {
    let protocol = node.node_type.clone();

    // TLS -> cfg::TlsConfig
    let tls = node.tls.as_ref().map(|t| {
        let is_reality = t.reality.is_some();
        cfg::TlsConfig {
            enabled: t.enabled.unwrap_or(false),
            security: if is_reality {
                "reality".to_string()
            } else {
                "tls".to_string()
            },
            sni: t.sni.clone(),
            allow_insecure: t.insecure.unwrap_or(false),
            alpn: t.alpn.clone(),
            fingerprint: t.fingerprint.clone(),
            public_key: t.reality.as_ref().map(|r| r.public_key.clone()),
            short_id: t.reality.as_ref().and_then(|r| r.short_id.clone()),
            server_name: t.sni.clone(),
            ech_config: t.ech.as_ref().and_then(|e| e.config.clone()),
            ech_grease: t.ech.as_ref().map(|e| e.grease).unwrap_or(false),
            ech_outer_sni: None,
            ech_auto: t.ech.as_ref().map(|e| e.auto).unwrap_or(false),
            fragment: t.fragment.as_ref().map(|f| cfg::TlsFragmentConfig {
                min_length: f.min_length,
                max_length: f.max_length,
                min_delay_ms: f.min_delay_ms,
                max_delay_ms: f.max_delay_ms,
            }),
        }
    });

    // Transport
    let transport = node.transport.as_ref().map(|t| cfg::TransportConfig {
        transport_type: t.transport_type.clone(),
        path: t.path.clone(),
        host: t.host.clone(),
        headers: t.headers.clone(),
        service_name: t.service_name.clone(),
        shadow_tls_password: t.shadow_tls_password.clone(),
        shadow_tls_sni: t.shadow_tls_sni.clone(),
    });

    // Mux
    let mux = node.mux.as_ref().map(|m| cfg::MuxConfig {
        protocol: m.protocol.clone(),
        max_connections: m.max_connections,
        max_streams_per_connection: m.max_streams,
        padding: m.padding,
    });

    // Security 字段
    let security = tls.as_ref().map(|t| t.security.clone());
    let sni = tls.as_ref().and_then(|t| t.sni.clone());

    // WireGuard peers
    let peers = node.peers.as_ref().map(|ps| {
        ps.iter()
            .map(|p| cfg::WireGuardPeerConfig {
                public_key: p.public_key.clone(),
                endpoint: p.endpoint.clone(),
                allowed_ips: p.allowed_ips.clone(),
                keepalive: node.keepalive,
                preshared_key: node.preshared_key.clone(),
            })
            .collect()
    });

    Some(cfg::OutboundConfig {
        tag: node.name.clone(),
        protocol,
        settings: cfg::OutboundSettings {
            address: node.address.clone(),
            port: node.port,
            uuid: node.uuid.clone(),
            password: node.password.clone(),
            method: node.method.clone(),
            security,
            sni,
            allow_insecure: tls.as_ref().map(|t| t.allow_insecure).unwrap_or(false),
            flow: node.flow.clone(),
            public_key: tls.as_ref().and_then(|t| t.public_key.clone()),
            short_id: tls.as_ref().and_then(|t| t.short_id.clone()),
            server_name: tls.as_ref().and_then(|t| t.server_name.clone()),
            fingerprint: tls.as_ref().and_then(|t| t.fingerprint.clone()),
            plugin: node.plugin.clone(),
            plugin_opts: node.plugin_opts.clone(),
            identity_key: node.identity_key.clone(),
            private_key: node.private_key.clone(),
            peer_public_key: node.peer_public_key.clone(),
            preshared_key: node.preshared_key.clone(),
            local_address: node.local_address.clone(),
            mtu: node.mtu,
            keepalive: node.keepalive,
            username: node.username.clone(),
            private_key_passphrase: node.private_key_passphrase.clone(),
            congestion_control: node.congestion_control.clone(),
            up_mbps: node.up_mbps,
            down_mbps: node.down_mbps,
            alter_id: node.alter_id,
            peers,
            socks_port: None,
            transport,
            tls,
            mux,
            obfs: node.obfs.clone(),
            obfs_password: node.obfs_password.clone(),
            chain: node.chain.clone(),
            dialer: None,
            domain_resolver: node.dialer.as_ref().and_then(|d| d.domain_resolver.clone()),
        },
    })
}

fn convert_groups(groups: &[ZenGroup]) -> Vec<cfg::ProxyGroupConfig> {
    groups
        .iter()
        .map(|g| cfg::ProxyGroupConfig {
            name: g.name.clone(),
            group_type: g.group_type.clone(),
            proxies: g.nodes.clone(),
            url: g.url.clone(),
            interval: g.interval.unwrap_or(300),
            tolerance: g.tolerance.unwrap_or(150),
            strategy: g.strategy.clone(),
        })
        .collect()
}

fn convert_router(router: Option<&ZenRouter>) -> cfg::RouterConfig {
    let router = match router {
        Some(r) => r,
        None => {
            return cfg::RouterConfig::default();
        }
    };

    let rules: Vec<cfg::RuleConfig> = router
        .rules
        .iter()
        .map(|r| cfg::RuleConfig {
            rule_type: r.rule_type.clone(),
            values: r.values.clone(),
            outbound: r.outbound.clone().unwrap_or_default(),
            action: r.action.clone().unwrap_or_else(|| "route".to_string()),
            override_address: r.override_address.clone(),
            override_port: r.override_port,
            sniff: r.sniff.unwrap_or(false),
            resolve_strategy: None,
        })
        .collect();

    let rule_providers: HashMap<String, cfg::RuleProviderConfig> = router
        .rule_providers
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                cfg::RuleProviderConfig {
                    provider_type: v.provider_type.clone(),
                    behavior: v.behavior.clone(),
                    path: v.path.clone().unwrap_or_default(),
                    url: v.url.clone(),
                    interval: v.interval.unwrap_or(86400),
                    lazy: v.lazy,
                },
            )
        })
        .collect();

    cfg::RouterConfig {
        rules,
        default: router.default.clone(),
        geoip_db: router.geoip_db.clone(),
        geosite_db: router.geosite_db.clone(),
        rule_providers,
        geoip_url: router.geoip_url.clone(),
        geosite_url: router.geosite_url.clone(),
        geo_update_interval: 7 * 24 * 3600,
        geo_auto_update: router.geo_auto_update,
    }
}

fn convert_dns(dns: &ZenDns) -> cfg::DnsConfig {
    let servers: Vec<cfg::DnsServerConfig> = dns
        .servers
        .iter()
        .map(|s| cfg::DnsServerConfig {
            address: s.address.clone(),
            domains: s.domains.clone(),
        })
        .collect();

    let fallback: Vec<cfg::DnsServerConfig> = dns
        .fallback
        .iter()
        .map(|s| cfg::DnsServerConfig {
            address: s.address.clone(),
            domains: s.domains.clone(),
        })
        .collect();

    let fallback_filter = dns
        .fallback_filter
        .as_ref()
        .map(|f| cfg::FallbackFilterConfig {
            ip_cidr: f.ip_cidr.clone(),
            domain: f.domain.clone(),
        });

    let fake_ip = dns.fake_ip.as_ref().map(|f| cfg::FakeIpConfig {
        ipv4_range: f.ipv4_range.clone(),
        ipv6_range: f.ipv6_range.clone(),
        exclude: f.exclude.clone(),
    });

    cfg::DnsConfig {
        servers,
        cache_size: dns.cache_size.unwrap_or(1024),
        cache_ttl: dns.cache_ttl.unwrap_or(300),
        negative_cache_ttl: dns.negative_cache_ttl.unwrap_or(30),
        hosts: dns.hosts.clone(),
        fake_ip,
        mode: dns.mode.clone(),
        fallback,
        fallback_filter,
        edns_client_subnet: dns.edns_client_subnet.clone(),
        prefer_ip: dns.prefer_ip.clone(),
    }
}

fn convert_inbounds(inbounds: &[ZenInbound]) -> Vec<cfg::InboundConfig> {
    inbounds
        .iter()
        .map(|ib| cfg::InboundConfig {
            tag: ib.tag.clone(),
            protocol: ib.inbound_type.clone(),
            listen: ib.listen.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
            port: ib.port.unwrap_or(7890),
            sniffing: cfg::SniffingConfig {
                enabled: ib.sniffing.as_ref().map(|s| s.enabled).unwrap_or(false),
            },
            settings: cfg::InboundSettings {
                set_system_proxy: ib.set_system_proxy,
                system_proxy_bypass: ib.system_proxy_bypass.clone(),
                ..Default::default()
            },
            max_connections: ib.max_connections,
        })
        .collect()
}

/// Config -> ZenOneDoc（用于导出）
pub fn config_to_zenone(config: &cfg::Config) -> ZenOneDoc {
    let mut diags = Diagnostics::new();
    let nodes = super::converter::from_outbound_configs(&config.outbounds, &mut diags);

    let groups: Vec<ZenGroup> = config
        .proxy_groups
        .iter()
        .map(|g| ZenGroup {
            name: g.name.clone(),
            group_type: g.group_type.clone(),
            nodes: g.proxies.clone(),
            url: g.url.clone(),
            interval: Some(g.interval),
            tolerance: Some(g.tolerance),
            strategy: g.strategy.clone(),
        })
        .collect();

    let router = Some(ZenRouter {
        default: config.router.default.clone(),
        geoip_db: config.router.geoip_db.clone(),
        geosite_db: config.router.geosite_db.clone(),
        geo_auto_update: config.router.geo_auto_update,
        geoip_url: config.router.geoip_url.clone(),
        geosite_url: config.router.geosite_url.clone(),
        rule_providers: config
            .router
            .rule_providers
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    ZenRuleProvider {
                        provider_type: v.provider_type.clone(),
                        behavior: v.behavior.clone(),
                        url: v.url.clone(),
                        path: Some(v.path.clone()),
                        interval: Some(v.interval),
                        lazy: v.lazy,
                    },
                )
            })
            .collect(),
        rules: config
            .router
            .rules
            .iter()
            .map(|r| ZenRule {
                rule_type: r.rule_type.clone(),
                values: r.values.clone(),
                outbound: if r.outbound.is_empty() {
                    None
                } else {
                    Some(r.outbound.clone())
                },
                action: if r.action == "route" {
                    None
                } else {
                    Some(r.action.clone())
                },
                sniff: if r.sniff { Some(true) } else { None },
                override_address: r.override_address.clone(),
                override_port: r.override_port,
                sub_rules: None,
            })
            .collect(),
    });

    let dns = config.dns.as_ref().map(|d| ZenDns {
        mode: d.mode.clone(),
        cache_size: Some(d.cache_size),
        cache_ttl: Some(d.cache_ttl),
        negative_cache_ttl: Some(d.negative_cache_ttl),
        prefer_ip: d.prefer_ip.clone(),
        edns_client_subnet: d.edns_client_subnet.clone(),
        servers: d
            .servers
            .iter()
            .map(|s| ZenDnsServer {
                address: s.address.clone(),
                domains: s.domains.clone(),
            })
            .collect(),
        fallback: d
            .fallback
            .iter()
            .map(|s| ZenDnsServer {
                address: s.address.clone(),
                domains: s.domains.clone(),
            })
            .collect(),
        fallback_filter: d.fallback_filter.as_ref().map(|f| ZenFallbackFilter {
            ip_cidr: f.ip_cidr.clone(),
            domain: f.domain.clone(),
        }),
        fake_ip: d.fake_ip.as_ref().map(|f| ZenFakeIp {
            ipv4_range: f.ipv4_range.clone(),
            ipv6_range: f.ipv6_range.clone(),
            exclude: f.exclude.clone(),
        }),
        hosts: d.hosts.clone(),
    });

    let metadata = if !config.subscriptions.is_empty() {
        let sub = &config.subscriptions[0];
        Some(ZenMetadata {
            name: Some(sub.name.clone()),
            source_url: Some(sub.url.clone()),
            update_interval: Some(sub.interval_secs),
            ..Default::default()
        })
    } else {
        None
    };

    let settings = Some(ZenSettings {
        log_level: Some(config.log.level.clone()),
        max_connections: Some(config.max_connections),
        validation_mode: None,
        api: config.api.as_ref().map(|a| ZenApi {
            listen: a.listen.clone(),
            port: a.port,
            secret: a.secret.clone(),
            external_ui: a.external_ui.clone(),
        }),
        derp: config.derp.as_ref().map(|d| ZenDerp {
            enabled: d.enabled,
            port: Some(d.port),
        }),
        secrets: None,
        performance: None,
        extensions: None,
    });

    let inbounds: Vec<ZenInbound> = config
        .inbounds
        .iter()
        .map(|ib| ZenInbound {
            tag: ib.tag.clone(),
            inbound_type: ib.protocol.clone(),
            listen: Some(ib.listen.clone()),
            port: Some(ib.port),
            max_connections: ib.max_connections,
            sniffing: Some(ZenSniffing {
                enabled: ib.sniffing.enabled,
            }),
            auth: None,
            set_system_proxy: ib.settings.set_system_proxy,
            system_proxy_bypass: ib.settings.system_proxy_bypass.clone(),
        })
        .collect();

    ZenOneDoc {
        zen_version: 1,
        metadata,
        nodes,
        groups,
        router,
        dns,
        inbounds,
        settings,
        signature: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_config_zenone() {
        let config = cfg::Config {
            log: cfg::LogConfig {
                level: "debug".to_string(),
            },
            profile: None,
            inbounds: vec![cfg::InboundConfig {
                tag: "mixed-in".to_string(),
                protocol: "mixed".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 7890,
                sniffing: cfg::SniffingConfig::default(),
                settings: cfg::InboundSettings::default(),
                max_connections: None,
            }],
            outbounds: vec![cfg::OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: cfg::OutboundSettings::default(),
            }],
            proxy_groups: vec![],
            router: cfg::RouterConfig {
                rules: vec![],
                default: "direct".to_string(),
                geoip_db: None,
                geosite_db: None,
                rule_providers: Default::default(),
                geoip_url: None,
                geosite_url: None,
                geo_update_interval: 7 * 24 * 3600,
                geo_auto_update: false,
            },
            subscriptions: vec![],
            api: None,
            dns: None,
            derp: None,
            max_connections: 10000,
        };

        let doc = config_to_zenone(&config);
        assert_eq!(doc.zen_version, 1);
        assert_eq!(doc.nodes.len(), 1);
        assert_eq!(doc.nodes[0].name, "direct");

        let mut diags = Diagnostics::new();
        let back = zenone_to_config(&doc, &mut diags);
        assert_eq!(back.outbounds.len(), 1);
        assert_eq!(back.outbounds[0].tag, "direct");
        assert_eq!(back.log.level, "debug");
    }
}

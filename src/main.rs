use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[command(
    name = "openworld",
    version,
    about = "OpenWorld - High-performance proxy kernel"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Config file path
    #[arg(short, long, global = true, default_value = "config.yaml")]
    config: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy server (default when no subcommand given)
    Run,

    /// Validate config file syntax and semantics
    Check,

    /// Format and normalize config file (YAML)
    Format {
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Encrypt config file with AES-256-GCM
    EncryptConfig {
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Encryption password
        #[arg(short, long)]
        password: String,
    },

    /// Decrypt an encrypted config file
    DecryptConfig {
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Decryption password
        #[arg(short, long)]
        password: String,
    },

    /// Generate sample configurations
    Generate {
        #[command(subcommand)]
        target: GenerateTarget,
    },

    /// Convert config from Clash format and show compatibility report
    Convert {
        /// Input Clash config file path
        input: String,
    },
}

#[derive(Subcommand)]
enum GenerateTarget {
    /// Generate sample config file
    Config {
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Generate systemd service unit file
    Systemd {
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Check) => cmd_check(&cli.config),
        Some(Commands::Format { output }) => cmd_format(&cli.config, output.as_deref()),
        Some(Commands::EncryptConfig { output, password }) => {
            cmd_encrypt(&cli.config, &output, &password)
        }
        Some(Commands::DecryptConfig { output, password }) => {
            cmd_decrypt(&cli.config, &output, &password)
        }
        Some(Commands::Generate { target }) => cmd_generate(target),
        Some(Commands::Convert { input }) => cmd_convert(&input),
        Some(Commands::Run) | None => cmd_run(&cli.config).await,
    }
}

async fn cmd_run(config_path: &str) -> Result<()> {
    let log_broadcaster = openworld::api::log_broadcast::LogBroadcaster::new(256);

    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    );

    let log_layer = openworld::api::log_broadcast::LogLayer::new(log_broadcaster.clone());

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(log_layer)
        .init();

    info!("OpenWorld starting...");

    let config = openworld::config::load_config(config_path)?;
    info!("config loaded");

    let app =
        openworld::app::App::new(config, Some(config_path.to_string()), Some(log_broadcaster))
            .await?;
    app.run().await?;

    Ok(())
}

fn cmd_check(config_path: &str) -> Result<()> {
    match openworld::config::load_config(config_path) {
        Ok(config) => {
            println!("config '{}' is valid", config_path);
            println!("  inbounds:     {}", config.inbounds.len());
            println!("  outbounds:    {}", config.outbounds.len());
            println!("  proxy-groups: {}", config.proxy_groups.len());
            println!("  router rules: {}", config.router.rules.len());
            Ok(())
        }
        Err(e) => {
            eprintln!("config '{}' has errors:", config_path);
            eprintln!("  {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_format(config_path: &str, output: Option<&str>) -> Result<()> {
    let content = openworld::config::load_config_content(config_path)?;
    let value: serde_yml::Value = serde_yml::from_str(&content)?;
    let formatted = serde_yml::to_string(&value)?;

    match output {
        Some(path) => {
            std::fs::write(path, &formatted)?;
            println!("formatted config written to '{}'", path);
        }
        None => {
            print!("{}", formatted);
        }
    }
    Ok(())
}

fn cmd_encrypt(input: &str, output: &str, password: &str) -> Result<()> {
    let plaintext = std::fs::read(input)?;
    let encrypted = openworld::config::encryption::encrypt_config(&plaintext, password)?;
    std::fs::write(output, &encrypted)?;
    println!(
        "encrypted config written to '{}' ({} bytes)",
        output,
        encrypted.len()
    );
    Ok(())
}

fn cmd_decrypt(input: &str, output: &str, password: &str) -> Result<()> {
    let encrypted = std::fs::read(input)?;
    let decrypted = openworld::config::encryption::decrypt_config(&encrypted, password)?;
    std::fs::write(output, &decrypted)?;
    println!(
        "decrypted config written to '{}' ({} bytes)",
        output,
        decrypted.len()
    );
    Ok(())
}

fn cmd_generate(target: GenerateTarget) -> Result<()> {
    let content = match &target {
        GenerateTarget::Config { .. } => SAMPLE_CONFIG,
        GenerateTarget::Systemd { .. } => SYSTEMD_UNIT,
    };

    let output = match target {
        GenerateTarget::Config { output } => output,
        GenerateTarget::Systemd { output } => output,
    };

    match output.as_deref() {
        Some(path) => {
            std::fs::write(path, content)?;
            println!("written to '{}'", path);
        }
        None => {
            print!("{}", content);
        }
    }
    Ok(())
}

fn cmd_convert(input: &str) -> Result<()> {
    let content = std::fs::read_to_string(input)?;
    let result = openworld::config::compat::parse_clash_config(&content)?;

    println!("Conversion result for '{}':", input);

    match &result.level {
        openworld::config::compat::CompatLevel::Full => {
            println!("  Level: Full compatibility");
        }
        openworld::config::compat::CompatLevel::Degraded(issues) => {
            println!("  Level: Degraded compatibility");
            for issue in issues {
                println!("    - {}", issue);
            }
        }
        openworld::config::compat::CompatLevel::Incompatible(issues) => {
            println!("  Level: Incompatible");
            for issue in issues {
                println!("    - {}", issue);
            }
        }
    }

    if !result.warnings.is_empty() {
        println!("\nWarnings:");
        for w in &result.warnings {
            println!("  - {}", w);
        }
    }

    match result.config.validate() {
        Ok(_) => println!("\nConverted config validation: OK"),
        Err(e) => println!("\nConverted config validation failed: {}", e),
    }

    println!("\nSummary:");
    println!("  Inbounds:     {}", result.config.inbounds.len());
    println!("  Outbounds:    {}", result.config.outbounds.len());
    println!("  Proxy groups: {}", result.config.proxy_groups.len());
    println!("  Router rules: {}", result.config.router.rules.len());

    Ok(())
}

const SAMPLE_CONFIG: &str = r#"# OpenWorld sample configuration
log:
  level: info

inbounds:
  - tag: mixed-in
    protocol: mixed
    listen: "127.0.0.1"
    port: 7890
    sniffing:
      enabled: true
    # Optional authentication:
    # settings:
    #   auth:
    #     - username: user1
    #       password: pass1

outbounds:
  - tag: direct
    protocol: direct

  - tag: reject
    protocol: reject

  # Example VLESS outbound:
  # - tag: my-vless
  #   protocol: vless
  #   settings:
  #     address: "example.com"
  #     port: 443
  #     uuid: "your-uuid-here"
  #     tls:
  #       enabled: true
  #       sni: "example.com"

router:
  rules:
    - type: domain-keyword
      values: [ads, tracker, adservice]
      outbound: reject
  default: direct

# Optional API server (compatible with Clash dashboard):
# api:
#   listen: "127.0.0.1"
#   port: 9090
#   secret: "your-secret"

# Optional DNS configuration:
# dns:
#   servers:
#     - address: "https://dns.google/dns-query"
#     - address: "tls://8.8.8.8"
#   cache_size: 1024
#   cache_ttl: 300
"#;

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=OpenWorld Proxy Kernel
Documentation=https://github.com/openworld-proxy/openworld
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/openworld run -c /etc/openworld/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/openworld /var/lib/openworld

[Install]
WantedBy=multi-user.target
"#;

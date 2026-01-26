mod auth;
mod config;
mod net_engine;
mod ninep;
mod wireguard;

use anyhow::Result;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug)]
struct Args {
    config_path: PathBuf,
    verbose: u8,
    quiet: bool,
    check_only: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut config_path = PathBuf::from("/etc/crabbit.toml");
        let mut verbose = 0u8;
        let mut quiet = false;
        let mut check_only = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    config_path = PathBuf::from(
                        args.next()
                            .ok_or_else(|| anyhow::anyhow!("Missing config file path"))?,
                    );
                }
                "-v" | "--verbose" => verbose += 1,
                "-q" | "--quiet" => quiet = true,
                "--check" => check_only = true,
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {
                    anyhow::bail!("Unknown argument: {}", arg);
                }
            }
        }

        // Check environment variable
        if let Ok(env_config) = std::env::var("CRABBIT_CONFIG") {
            if config_path == PathBuf::from("/etc/crabbit.toml") {
                config_path = PathBuf::from(env_config);
            }
        }

        Ok(Args {
            config_path,
            verbose,
            quiet,
            check_only,
        })
    }
}

fn print_help() {
    println!(
        r#"Crabbit - A grumpy wee guardian that bridges WireGuard and Plan 9

USAGE:
    crabbit [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Config file path (default: /etc/crabbit.toml)
    -v, --verbose          Increase log level (can be used multiple times)
    -q, --quiet            Decrease log level
    --check                Validate config and exit
    -h, --help             Show this help message

ENVIRONMENT:
    CRABBIT_CONFIG         Config file path (overridden by -c)
    CRABBIT_LOG            Log level (overridden by config/flags)
    CRABBIT_PRIVATE_KEY    WireGuard private key (avoids putting in file)
"#
    );
}

fn init_logging(verbose: u8, quiet: bool) -> Result<()> {
    let log_level = if quiet {
        "error".to_string()
    } else {
        match verbose {
            0 => std::env::var("CRABBIT_LOG").unwrap_or_else(|_| "info".to_string()),
            1 => "debug".to_string(),
            _ => "trace".to_string(),
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(&log_level))?;

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse()?;

    // Initialize logging
    init_logging(args.verbose, args.quiet)?;

    info!("Crabbit starting");
    info!("Loading configuration from: {}", args.config_path.display());

    // Load configuration
    let config = config::Config::load(&args.config_path)?;
    info!("Configuration loaded successfully");

    // Validate configuration
    config.validate()?;
    info!("Configuration validated");

    if args.check_only {
        info!("Configuration check passed");
        return Ok(());
    }

    // Initialize components
    info!("Initializing WireGuard module");
    let wg = wireguard::WireGuard::new(&config.wireguard).await?;

    info!("Initializing /net engine");
    let net_engine = net_engine::NetEngine::new(wg, &config).await?;

    info!("Initializing authentication module");
    let auth = auth::AuthModule::new(&config.auth)?;

    info!("Starting 9P server on {}", config.listen.address);
    let server = ninep::Server::new(config.listen.address.clone(), auth, net_engine).await?;

    // Run server
    info!("Crabbit is ready");
    server.run().await?;

    info!("Crabbit shutting down");
    Ok(())
}

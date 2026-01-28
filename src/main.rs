use crabbit::{auth, config, keys, net_engine, ninep, wireguard};
use anyhow::{bail, Result};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug)]
enum Command {
    Run,
    AddUser { name: String, keys_file: Option<PathBuf> },
    DelUser { name: String, keys_file: Option<PathBuf> },
    ListUsers { keys_file: Option<PathBuf> },
}

#[derive(Debug)]
struct Args {
    config_path: PathBuf,
    verbose: u8,
    quiet: bool,
    check_only: bool,
    command: Command,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut config_path = PathBuf::from("/etc/crabbit.toml");
        let mut verbose = 0u8;
        let mut quiet = false;
        let mut check_only = false;
        let mut command = Command::Run;
        let mut keys_file: Option<PathBuf> = None;

        let mut args = std::env::args().skip(1).peekable();

        // Check for subcommand first
        if let Some(first) = args.peek() {
            match first.as_str() {
                "adduser" => {
                    args.next(); // consume "adduser"
                    let name = args.next()
                        .ok_or_else(|| anyhow::anyhow!("adduser requires username"))?;

                    // Parse remaining flags for adduser
                    while let Some(arg) = args.next() {
                        match arg.as_str() {
                            "-k" | "--keys" => {
                                keys_file = Some(PathBuf::from(
                                    args.next()
                                        .ok_or_else(|| anyhow::anyhow!("Missing keys file path"))?,
                                ));
                            }
                            "-h" | "--help" => {
                                print_adduser_help();
                                std::process::exit(0);
                            }
                            _ => bail!("Unknown option for adduser: {}", arg),
                        }
                    }

                    command = Command::AddUser { name, keys_file };
                    return Ok(Args { config_path, verbose, quiet, check_only, command });
                }
                "deluser" => {
                    args.next(); // consume "deluser"
                    let name = args.next()
                        .ok_or_else(|| anyhow::anyhow!("deluser requires username"))?;

                    while let Some(arg) = args.next() {
                        match arg.as_str() {
                            "-k" | "--keys" => {
                                keys_file = Some(PathBuf::from(
                                    args.next()
                                        .ok_or_else(|| anyhow::anyhow!("Missing keys file path"))?,
                                ));
                            }
                            _ => bail!("Unknown option for deluser: {}", arg),
                        }
                    }

                    command = Command::DelUser { name, keys_file };
                    return Ok(Args { config_path, verbose, quiet, check_only, command });
                }
                "listusers" | "users" => {
                    args.next(); // consume command

                    while let Some(arg) = args.next() {
                        match arg.as_str() {
                            "-k" | "--keys" => {
                                keys_file = Some(PathBuf::from(
                                    args.next()
                                        .ok_or_else(|| anyhow::anyhow!("Missing keys file path"))?,
                                ));
                            }
                            _ => bail!("Unknown option for listusers: {}", arg),
                        }
                    }

                    command = Command::ListUsers { keys_file };
                    return Ok(Args { config_path, verbose, quiet, check_only, command });
                }
                _ => {} // Not a subcommand, continue with normal parsing
            }
        }

        // Normal argument parsing for run mode
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
                    bail!("Unknown argument: {}", arg);
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
            command,
        })
    }
}

fn print_help() {
    println!(
        r#"Crabbit - A grumpy wee guardian that bridges WireGuard and Plan 9

USAGE:
    crabbit [OPTIONS]
    crabbit adduser <NAME> [--keys FILE]
    crabbit deluser <NAME> [--keys FILE]
    crabbit listusers [--keys FILE]

COMMANDS:
    adduser <NAME>    Add a user (prompts for password)
    deluser <NAME>    Remove a user
    listusers         List all users

OPTIONS:
    -c, --config <FILE>    Config file path (default: /etc/crabbit.toml)
    -v, --verbose          Increase log level (can be used multiple times)
    -q, --quiet            Decrease log level
    --check                Validate config and exit
    -h, --help             Show this help message

COMMAND OPTIONS:
    -k, --keys <FILE>      Keys file path (default: ~/.crabbit/keys)

ENVIRONMENT:
    CRABBIT_CONFIG         Config file path (overridden by -c)
    CRABBIT_KEYS           Keys file path (overridden by -k)
    CRABBIT_LOG            Log level (overridden by config/flags)
    CRABBIT_PRIVATE_KEY    WireGuard private key (avoids putting in file)
"#
    );
}

fn print_adduser_help() {
    println!(
        r#"Add a user to the Crabbit keys file

USAGE:
    crabbit adduser <NAME> [OPTIONS]

ARGUMENTS:
    <NAME>    Username to add

OPTIONS:
    -k, --keys <FILE>    Keys file path (default: ~/.crabbit/keys)
    -h, --help           Show this help message

The password will be prompted interactively. Only derived keys are stored,
never the plaintext password.
"#
    );
}

fn get_keys_path(override_path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = override_path {
        return path;
    }
    if let Ok(env_path) = std::env::var("CRABBIT_KEYS") {
        return PathBuf::from(env_path);
    }
    keys::default_keys_path()
}

fn cmd_adduser(name: &str, keys_file: Option<PathBuf>) -> Result<()> {
    let keys_path = get_keys_path(keys_file);

    // Prompt for password
    eprint!("Password for {}: ", name);
    std::io::Write::flush(&mut std::io::stderr())?;
    let password = rpassword::read_password()?;

    eprint!("Confirm password: ");
    std::io::Write::flush(&mut std::io::stderr())?;
    let confirm = rpassword::read_password()?;

    if password != confirm {
        bail!("Passwords do not match");
    }

    if password.is_empty() {
        bail!("Password cannot be empty");
    }

    // Load keys file
    let mut keys = keys::KeysFile::load(&keys_path)?;

    let action = if keys.has_user(name) {
        "updated"
    } else {
        "added"
    };

    // Add/update user
    keys.add_user(name, &password);
    keys.save()?;

    eprintln!("User '{}' {} in {}", name, action, keys_path.display());
    Ok(())
}

fn cmd_deluser(name: &str, keys_file: Option<PathBuf>) -> Result<()> {
    let keys_path = get_keys_path(keys_file);

    let mut keys = keys::KeysFile::load(&keys_path)?;

    if keys.remove_user(name) {
        keys.save()?;
        eprintln!("User '{}' removed from {}", name, keys_path.display());
    } else {
        bail!("User '{}' not found", name);
    }

    Ok(())
}

fn cmd_listusers(keys_file: Option<PathBuf>) -> Result<()> {
    let keys_path = get_keys_path(keys_file);

    let keys = keys::KeysFile::load(&keys_path)?;

    if keys.is_empty() {
        eprintln!("No users in {}", keys_path.display());
    } else {
        eprintln!("Users in {}:", keys_path.display());
        for user in keys.list_users() {
            println!("{}", user);
        }
    }

    Ok(())
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

    // Handle subcommands that don't need full server setup
    match args.command {
        Command::AddUser { name, keys_file } => {
            return cmd_adduser(&name, keys_file);
        }
        Command::DelUser { name, keys_file } => {
            return cmd_deluser(&name, keys_file);
        }
        Command::ListUsers { keys_file } => {
            return cmd_listusers(keys_file);
        }
        Command::Run => {
            // Continue with server startup
        }
    }

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

    // Load keys file if it exists
    let keys_path = get_keys_path(None);
    let keys_file = keys::KeysFile::load(&keys_path)?;
    if !keys_file.is_empty() {
        info!("Loaded {} users from {}", keys_file.len(), keys_path.display());
    }

    // Initialize components
    info!("Initializing WireGuard module");
    let wg = wireguard::WireGuard::new(&config.wireguard).await?;

    info!("Initializing /net engine");
    let net_engine = net_engine::NetEngine::new(wg, &config).await?;

    // Create auth module, merging config users with keys file users
    info!("Initializing authentication module");
    let mut auth = auth::AuthModule::new(&config.auth)?;

    // Add users from keys file
    for (_, creds) in keys_file.users {
        auth.add_user(creds);
    }

    info!("Starting 9P server on {}", config.listen.address);
    let server = ninep::Server::new(config.listen.address.clone(), auth, net_engine).await?;

    // Run server
    info!("Crabbit is ready");
    server.run().await?;

    info!("Crabbit shutting down");
    Ok(())
}

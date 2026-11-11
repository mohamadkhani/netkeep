pub mod cmd;
mod daemon;
mod render;

use clap::Parser;
use thiserror::Error;

const DEFAULT_SOCKET_PATH: &str = "/run/netkeep/netkeep.sock";

#[derive(Error, Debug)]
enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Daemon(String),
    #[error("{0}")]
    Render(String),
    #[error("connection failed")]
    Connection,
}

#[derive(Parser)]
#[command(name = "netkeep")]
#[command(author, version, about, long_about = None)]
#[command(trailing_var_arg = true)]
#[command(help_expected = true)]
#[command(styles = help_styles())]
struct Cli {
    /// Unix socket path the daemon listens on.
    #[arg(short, long, env, default_value = DEFAULT_SOCKET_PATH, global = true)]
    socket: String,

    /// Output format: json | yaml | table | ps | flat | text | md.
    #[arg(
        short,
        long,
        env,
        value_name = "FMT",
        default_value = "ps",
        global = true
    )]
    format: Format,

    /// When to use colored output: auto | always | never.
    #[arg(
        long,
        env,
        value_name = "WHEN",
        value_enum,
        default_value_t = clap::ColorChoice::Auto,
        global = true
    )]
    color: clap::ColorChoice,

    #[command(subcommand)]
    command: cmd::args::Command,
}

#[derive(Debug, Clone, Copy, Default)]
enum Format {
    #[default]
    Table,
    Ps,
    Flat,
    Text,
    Json,
    Yaml,
    Md,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "json" | "j" => Ok(Format::Json),
            "yaml" | "yml" | "y" => Ok(Format::Yaml),
            "table" | "t" => Ok(Format::Table),
            "text" | "txt" | "plain" => Ok(Format::Text),
            "md" | "markdown" | "m" => Ok(Format::Md),
            "ps" | "docker" => Ok(Format::Ps),
            "flat" => Ok(Format::Flat),
            other => Err(format!(
                "invalid format '{other}'; use json, yaml, table, ps, flat, text, or md"
            )),
        }
    }
}

fn help_styles() -> clap::builder::Styles {
    use clap::builder::styling::{AnsiColor, Effects, Styles};

    Styles::styled()
        .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
        .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
        .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
        .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
        .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
}

/// Apply `--color` before clap parses so it also affects help and error output.
fn apply_color_choice() {
    let mut args = std::env::args_os();
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy();
        let value = if let Some(value) = arg.strip_prefix("--color=") {
            Some(value.to_string())
        } else if arg == "--color" {
            args.next()
                .map(|value| value.to_string_lossy().into_owned())
        } else {
            None
        };
        let Some(value) = value else { continue };
        match value.to_ascii_lowercase().as_str() {
            "always" => {
                std::env::set_var("CLICOLOR_FORCE", "1");
                std::env::remove_var("NO_COLOR");
            }
            "never" => {
                std::env::set_var("NO_COLOR", "1");
                std::env::remove_var("CLICOLOR_FORCE");
            }
            "auto" => {
                std::env::remove_var("CLICOLOR_FORCE");
                std::env::remove_var("NO_COLOR");
            }
            _ => {}
        }
        break;
    }
}

fn main() {
    apply_color_choice();
    let cli = Cli::parse();
    let exit = run(cli).unwrap_or_else(|err| {
        let msg = match &err {
            CliError::Usage(m) | CliError::Render(m) => m,
            CliError::Daemon(m) => m,
            CliError::Connection => "connection failed",
        };
        eprintln!("error: {msg}");
        match err {
            CliError::Usage(_) | CliError::Render(_) => 2,
            CliError::Daemon(_) | CliError::Connection => 1,
        }
    });
    std::process::exit(exit);
}

fn run(cli: Cli) -> Result<i32, CliError> {
    let socket = cli.socket.clone();
    let format = cli.format;
    let rule_filter = extract_rule_filter(&cli.command);

    match cli.command.execute(&socket, format) {
        Ok(response) => {
            let rendered = render::render(&response, format, rule_filter.as_ref())
                .map_err(CliError::Render)?;
            println!("{rendered}");
            Ok(0)
        }
        Err(err) => Err(err),
    }
}

/// Extract rule-list filters (search, id, process, action, duration) from the parsed command.
fn extract_rule_filter(cmd: &cmd::args::Command) -> Option<render::RuleFilter> {
    let cmd::args::Command::Rule { action } = cmd else {
        return None;
    };
    let cmd::args::RuleAction::List {
        process,
        id,
        search,
        action: rule_action,
        duration,
    } = action
    else {
        return None;
    };
    if process.is_some()
        || id.is_some()
        || search.is_some()
        || rule_action.is_some()
        || duration.is_some()
    {
        Some(render::RuleFilter {
            process: process.clone(),
            id: id.clone(),
            search: search.clone(),
            action: rule_action.clone(),
            duration: duration.clone(),
        })
    } else {
        None
    }
}

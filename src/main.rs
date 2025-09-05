use std::net::IpAddr;

use anyhow::Result;
use drill_cli::{client::Client, server::Server};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Local {
        #[clap(env = "BORE_LOCAL_PORT")]
        local_port: u16,

        #[clap(short, long, value_name = "HOST", default_value = "localhost")]
        local_host: String,

        #[clap(short, long, env = "BORE_SERVER")]
        to: String,

        #[clap(short, long, default_value_t = 0)]
        port: u16,

        #[clap(short, long, env = "BORE_SECRET", hide_env_values = true)]
        secret: Option<String>,
    },
    Server {
        #[clap(long, default_value_t = 1024, env = "BORE_MIN_PORT")]
        min_port: u16,

        #[clap(long, default_value_t = 65535, env = "BORE_MAX_PORT")]
        max_port: u16,

        #[clap(short, long, env = "BORE_SECRET", hide_env_values = true)]
        secret: Option<String>,

        #[clap(long, default_value = "0.0.0.0")]
        bind_addr: IpAddr,

        #[clap(long)]
        bind_tunnels: Option<IpAddr>,
    }
}

#[tokio::main]
async fn run(command: Command) -> Result<()> {
    match command {
        Command::Local {
            local_host,
            local_port,
            to,
            port,
            secret,
        } => {
            let client = Client::new(&local_host, local_port, &to, port, secret.as_deref()).await?;
            client.listen().await?;
        }
        Command::Server {
            min_port,
            max_port,
            secret,
            bind_addr,
            bind_tunnels,
        } => {
            let port_range = min_port..=max_port;
            if port_range.is_empty() {
                Args::command()
                    .error(ErrorKind::InvalidValue, "port range is empty")
                    .exit();
            }
            let mut server = Server::new(port_range, secret.as_deref());
            server.set_bind_addr(bind_addr);
            server.set_bind_tunnels(bind_tunnels.unwrap_or(bind_addr));
            server.listen().await?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run(Args::parse().command)
}

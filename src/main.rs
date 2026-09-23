use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Domain to check (e.g. example.com)
    domain: String,

    /// Port to connect to
    #[arg(short, long, default_value_t = 443)]
    port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = args
        .domain
        .as_str()
        .try_into()
        .context("Invalid domain name")?;

    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("Failed to create TLS connection")?;

    let addr = format!("{}:{}", args.domain, args.port);
    let mut sock = TcpStream::connect(&addr).context("Failed to connect to host")?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    // Trigger handshake
    let _ = tls.write_all(b"HEAD / HTTP/1.0\r\nHost: ");
    let _ = tls.write_all(args.domain.as_bytes());
    let _ = tls.write_all(b"\r\n\r\n");

    let certs = conn
        .peer_certificates()
        .context("No peer certificates found")?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates returned by the server"));
    }

    let cert_der = &certs[0].0;
    let (_, cert) =
        X509Certificate::from_der(cert_der).context("Failed to parse X509 certificate")?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    println!("{}: {}", "Subject".bold(), subject.cyan());
    println!("{}: {}", "Issuer".bold(), issuer.cyan());
    println!(
        "{}: {}",
        "Valid From".bold(),
        cert.validity()
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|_| "Unknown".into())
    );
    println!(
        "{}: {}",
        "Valid To".bold(),
        cert.validity()
            .not_after
            .to_rfc2822()
            .unwrap_or_else(|_| "Unknown".into())
    );

    let days_left = (not_after - now) / 86400;

    if now < not_before {
        println!(
            "{}",
            "Status: Certificate is not yet valid!"
                .to_string()
                .red()
                .bold()
        );
        std::process::exit(1);
    } else if now > not_after {
        println!(
            "{}",
            format!("Status: EXPIRED ({} days ago)", -days_left)
                .red()
                .bold()
        );
        std::process::exit(1);
    } else {
        let status = format!("Status: Valid ({} days remaining)", days_left);
        if days_left < 30 {
            println!("{}", status.yellow().bold());
        } else {
            println!("{}", status.green().bold());
        }
    }

    Ok(())
}

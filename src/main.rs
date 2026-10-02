use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!(
                "{{\"schema\":\"zixcel://topology/cli-error/v1\",\"error\":{}}}",
                serde_json::to_string(&message).unwrap_or_else(|_| "\"unknown\"".to_owned())
            );
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, database] if command == "import-source" => {
            let document = zixcel_topology_api::source_contract::read(std::io::stdin().lock())?;
            zixcel_topology_api::store::replace_file(Path::new(database), &document)
        }
        [command, database, node, code] if command == "disconnect" => {
            safe_error_code(code)?;
            let connection = zixcel_topology_api::store::open(Path::new(database))?;
            zixcel_topology_api::store::disconnect(&connection, node, code)
        }
        [command, database, node] if command == "connect" => {
            let connection = zixcel_topology_api::store::open(Path::new(database))?;
            zixcel_topology_api::store::connect(&connection, node)
        }
        [command, database] if command == "export" => {
            let connection = zixcel_topology_api::store::open_read_only(Path::new(database))?;
            let document = zixcel_topology_api::store::read(&connection)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        [command, database, address] if command == "serve" => zixcel_topology_api::http::serve(
            PathBuf::from(database),
            zixcel_topology_api::http::parse_loopback(address)?,
        ),
        [command, database, address, private] if command == "serve-authenticated" => {
            zixcel_topology_api::http::serve_authenticated(
                PathBuf::from(database),
                zixcel_topology_api::http::parse_loopback(address)?,
                Path::new(private),
            )
        }
        [command, private, trust, domain, deployment, audience]
            if command == "generate-identity" =>
        {
            zixcel_topology_api::authentication::generate_identity(
                Path::new(private),
                Path::new(trust),
                &zixcel_topology_api::authentication::IdentityPolicy {
                    audience: audience.clone(),
                    security_domain: domain.clone(),
                    deployment_id: deployment.clone(),
                },
            )
        }
        _ => Err(usage()),
    }
}

fn safe_error_code(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("error code must be a lowercase ASCII identifier".to_owned());
    }
    Ok(())
}

fn usage() -> String {
    "usage: zixcel-topology-api <import-source DB|export DB|connect DB NODE|\
     disconnect DB NODE CODE|\
     serve DB LOOPBACK:PORT|serve-authenticated DB 127.0.0.1:PORT PRIVATE_KEY|\
     generate-identity PRIVATE_KEY TRUST_BUNDLE SECURITY_DOMAIN DEPLOYMENT_ID AUDIENCE>"
        .to_owned()
}

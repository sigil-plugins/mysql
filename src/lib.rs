#![deny(unsafe_code)]

use std::cell::RefCell;

use sha2::{Digest, Sha256};

#[allow(unsafe_code, clippy::all, clippy::nursery, clippy::pedantic)]
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "mysql",
        generate_all,
    });
}

mod protocol;

use bindings::exports::sigil::sql::driver::{
    Cell, Column, CommandResult, ConnectOptions, Connection, Error, ErrorClass, Guest,
    GuestConnection, QueryResult, Row, RowSet,
};
use bindings::sigil::host::{net, secrets};
use protocol::{CodecError, RawQueryResult};

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const CLIENT_REQUIRED: u32 = CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION;
const CLIENT_OPTIONAL: u32 = CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF;
const MAX_PACKET_PAYLOAD: usize = 1_048_576;
const MAX_SQL_BYTES: usize = 1_048_575;

struct Mysql;

struct ConnectionState {
    stream: net::Stream,
    secrets: Vec<(String, Vec<u8>)>,
}

struct MysqlConnection {
    state: RefCell<Option<ConnectionState>>,
}

fn driver_error(class: ErrorClass, message: &str) -> Error {
    Error {
        class,
        vendor_code: None,
        sqlstate: None,
        message: message.to_owned(),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies the generated host error by value"
)]
fn map_net_error(error: net::Error) -> Error {
    match error {
        net::Error::Timeout(_) => driver_error(ErrorClass::Timeout, "network operation timed out"),
        net::Error::Limit(_) => driver_error(ErrorClass::Limit, "network limit exceeded"),
        net::Error::Denied(_)
        | net::Error::Unavailable(_)
        | net::Error::Tls(_)
        | net::Error::Io(_) => driver_error(ErrorClass::Transport, "network operation failed"),
    }
}

fn map_secret_error(_error: secrets::SecretError) -> Error {
    driver_error(ErrorClass::Transport, "credential access failed")
}

fn map_codec_error(error: CodecError) -> Error {
    match error {
        CodecError::Authentication(server) => Error {
            class: ErrorClass::Authentication,
            vendor_code: Some(u32::from(server.vendor_code)),
            sqlstate: server.sqlstate,
            message: server.message,
        },
        CodecError::Server(server) => Error {
            class: ErrorClass::Server,
            vendor_code: Some(u32::from(server.vendor_code)),
            sqlstate: server.sqlstate,
            message: server.message,
        },
        CodecError::Protocol => driver_error(ErrorClass::Protocol, "invalid MySQL protocol data"),
        CodecError::Encoding => driver_error(ErrorClass::Encoding, "invalid MySQL text data"),
        CodecError::Limit => driver_error(ErrorClass::Limit, "MySQL result limit exceeded"),
        CodecError::Unsupported => driver_error(
            ErrorClass::Unsupported,
            "unsupported MySQL protocol feature",
        ),
    }
}

fn read_packet(stream: &net::Stream, expected_sequence: u8) -> Result<Vec<u8>, Error> {
    let header = stream.read_exact(4).map_err(map_net_error)?;
    let (payload_len, sequence) =
        protocol::parse_packet_header(&header).map_err(map_codec_error)?;
    if sequence != expected_sequence {
        return Err(map_codec_error(CodecError::Protocol));
    }
    if payload_len > MAX_PACKET_PAYLOAD {
        return Err(map_codec_error(CodecError::Limit));
    }
    stream
        .read_exact(u32::try_from(payload_len).map_err(|_| map_codec_error(CodecError::Limit))?)
        .map_err(map_net_error)
}

fn write_packet(stream: &net::Stream, sequence: u8, payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(map_codec_error(CodecError::Limit));
    }
    let packet = protocol::frame_packet(payload, sequence).map_err(map_codec_error)?;
    stream.write_all(&packet).map_err(map_net_error)?;
    stream.flush().map_err(map_net_error)
}

fn caching_sha2_token(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = Sha256::digest(password);
    let stage2 = Sha256::digest(stage1);
    let mut challenge = Sha256::new();
    challenge.update(stage2);
    challenge.update(nonce);
    let stage3 = challenge.finalize();
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn connect_mysql(options: ConnectOptions) -> Result<MysqlConnection, Error> {
    let username = secrets::get(&options.username_secret).map_err(map_secret_error)?;
    let password = secrets::get(&options.password_secret).map_err(map_secret_error)?;
    if username.is_empty()
        || username.contains(&0)
        || options
            .database
            .as_ref()
            .is_some_and(|value| value.contains('\0'))
    {
        return Err(map_codec_error(CodecError::Encoding));
    }

    let stream = net::connect(&options.endpoint).map_err(map_net_error)?;
    let handshake_bytes = read_packet(&stream, 0)?;
    let handshake = protocol::parse_handshake(&handshake_bytes).map_err(map_codec_error)?;
    if handshake.server_capabilities & CLIENT_REQUIRED != CLIENT_REQUIRED
        || handshake.auth_plugin != "caching_sha2_password"
    {
        return Err(map_codec_error(CodecError::Unsupported));
    }

    let mut capabilities = CLIENT_REQUIRED | (handshake.server_capabilities & CLIENT_OPTIONAL);
    if options.database.is_some() {
        capabilities |= CLIENT_CONNECT_WITH_DB;
    }
    let ssl_request = protocol::ssl_request(capabilities, handshake.character_set);
    write_packet(&stream, 1, &ssl_request)?;
    stream.upgrade_tls().map_err(map_net_error)?;

    let token = caching_sha2_token(&password, &handshake.auth_data);
    let response = protocol::handshake_response(
        capabilities,
        handshake.character_set,
        &username,
        &token,
        options.database.as_deref(),
    )
    .map_err(map_codec_error)?;
    write_packet(&stream, 2, &response)?;

    let secret_refs = [
        (options.username_secret.as_str(), username.as_slice()),
        (options.password_secret.as_str(), password.as_slice()),
    ];
    let auth = read_packet(&stream, 3)?;
    match protocol::parse_auth_response(&auth, &secret_refs).map_err(map_codec_error)? {
        protocol::AuthResponse::Complete => {}
        protocol::AuthResponse::FastComplete => {
            let complete = read_packet(&stream, 4)?;
            protocol::parse_ok_or_error(&complete, &secret_refs, true).map_err(map_codec_error)?;
        }
        protocol::AuthResponse::FullAuthentication => {
            let mut cleartext = password.clone();
            cleartext.push(0);
            write_packet(&stream, 4, &cleartext)?;
            cleartext.fill(0);
            let complete = read_packet(&stream, 5)?;
            protocol::parse_ok_or_error(&complete, &secret_refs, true).map_err(map_codec_error)?;
        }
    }

    Ok(MysqlConnection {
        state: RefCell::new(Some(ConnectionState {
            stream,
            secrets: vec![
                (options.username_secret, username),
                (options.password_secret, password),
            ],
        })),
    })
}

impl Guest for Mysql {
    type Connection = MysqlConnection;

    fn connect(options: ConnectOptions) -> Result<Connection, Error> {
        connect_mysql(options).map(Connection::new)
    }
}

impl GuestConnection for MysqlConnection {
    fn query(&self, sql: String) -> Result<QueryResult, Error> {
        if sql.len() > MAX_SQL_BYTES {
            return Err(map_codec_error(CodecError::Limit));
        }
        let mut state = self.state.borrow_mut();
        let connection = state
            .as_mut()
            .ok_or_else(|| driver_error(ErrorClass::Closed, "connection is closed"))?;
        let mut command = Vec::with_capacity(sql.len().saturating_add(1));
        command.push(0x03);
        command.extend_from_slice(sql.as_bytes());
        write_packet(&connection.stream, 0, &command)?;
        let secret_refs: Vec<(&str, &[u8])> = connection
            .secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let result = protocol::read_query_result(
            |sequence| {
                read_packet(&connection.stream, sequence).map_err(|error| {
                    if error.class == ErrorClass::Timeout {
                        protocol::IoError::Timeout
                    } else if error.class == ErrorClass::Limit {
                        protocol::IoError::Limit
                    } else {
                        protocol::IoError::Transport
                    }
                })
            },
            &secret_refs,
        )
        .map_err(|error| match error {
            protocol::QueryError::Codec(error) => map_codec_error(error),
            protocol::QueryError::Io(protocol::IoError::Timeout) => {
                driver_error(ErrorClass::Timeout, "network operation timed out")
            }
            protocol::QueryError::Io(protocol::IoError::Limit) => {
                driver_error(ErrorClass::Limit, "network limit exceeded")
            }
            protocol::QueryError::Io(protocol::IoError::Transport) => {
                driver_error(ErrorClass::Transport, "network operation failed")
            }
        })?;
        Ok(match result {
            RawQueryResult::Command { affected_rows } => {
                QueryResult::Command(CommandResult { affected_rows })
            }
            RawQueryResult::Rows { columns, rows } => QueryResult::Rows(RowSet {
                columns: columns
                    .into_iter()
                    .map(|column| Column {
                        catalog: column.catalog,
                        schema: column.schema,
                        table: column.table,
                        original_table: column.original_table,
                        name: column.name,
                        original_name: column.original_name,
                        vendor_type: u32::from(column.vendor_type),
                        charset: u32::from(column.charset),
                        collation: u32::from(column.collation),
                        flags: u32::from(column.flags),
                    })
                    .collect(),
                rows: rows
                    .into_iter()
                    .map(|cells| Row {
                        cells: cells
                            .into_iter()
                            .map(|cell| match cell {
                                protocol::RawCell::Null => Cell::Null,
                                protocol::RawCell::Text(value) => Cell::Text(value),
                                protocol::RawCell::Bytes(value) => Cell::Bytes(value),
                            })
                            .collect(),
                    })
                    .collect(),
            }),
        })
    }

    fn close(&self) {
        if let Some(mut connection) = self.state.borrow_mut().take() {
            connection.stream.close();
            for (_name, secret) in &mut connection.secrets {
                secret.fill(0);
            }
        }
    }
}

impl Drop for MysqlConnection {
    fn drop(&mut self) {
        if let Some(mut connection) = self.state.get_mut().take() {
            connection.stream.close();
            for (_name, secret) in &mut connection.secrets {
                secret.fill(0);
            }
        }
    }
}

#[allow(unsafe_code, clippy::all, clippy::nursery, clippy::pedantic)]
#[cfg(target_arch = "wasm32")]
mod export {
    use super::Mysql;

    crate::bindings::export!(Mysql with_types_in crate::bindings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caching_sha2_token_is_deterministic_and_bounded() {
        let nonce = b"01234567890123456789";
        let first = caching_sha2_token(b"secret", nonce);
        let second = caching_sha2_token(b"secret", nonce);
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
        assert!(caching_sha2_token(b"", nonce).is_empty());
    }
}

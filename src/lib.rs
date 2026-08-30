#![deny(unsafe_code)]

use std::cell::RefCell;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[allow(unsafe_code, clippy::all, clippy::nursery, clippy::pedantic)]
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "mysql",
        generate_all,
    });
}

#[allow(
    dead_code,
    reason = "the reviewed SQL 0.2 codec is staged for the separate adapter integration bone"
)]
mod protocol;

use bindings::exports::sigil::sql::driver::{
    Cell, Column, CommandResult, ConnectOptions, Connection, Error, ErrorClass, Guest,
    GuestConnection, QueryResult, Row, RowSet,
};
use bindings::sigil::host::{net, net_policy, secrets};
use protocol::{AuthPlugin, CodecError, RawQueryResult};

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
const CLIENT_REQUIRED: u32 = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
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

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
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

trait MysqlIo {
    fn read_exact(&self, bytes: u32) -> Result<Vec<u8>, Error>;
    fn write_all(&self, bytes: &[u8]) -> Result<(), Error>;
    fn flush(&self) -> Result<(), Error>;
    fn upgrade_tls(&self) -> Result<(), Error>;
}

impl MysqlIo for net::Stream {
    fn read_exact(&self, bytes: u32) -> Result<Vec<u8>, Error> {
        self.read_exact(bytes).map_err(map_net_error)
    }

    fn write_all(&self, bytes: &[u8]) -> Result<(), Error> {
        self.write_all(bytes).map_err(map_net_error)
    }

    fn flush(&self) -> Result<(), Error> {
        self.flush().map_err(map_net_error)
    }

    fn upgrade_tls(&self) -> Result<(), Error> {
        self.upgrade_tls().map_err(map_net_error)
    }
}

fn read_packet(stream: &impl MysqlIo, expected_sequence: u8) -> Result<Vec<u8>, Error> {
    let header = stream.read_exact(4)?;
    let (payload_len, sequence) =
        protocol::parse_packet_header(&header).map_err(map_codec_error)?;
    if sequence != expected_sequence {
        return Err(map_codec_error(CodecError::Protocol));
    }
    if payload_len > MAX_PACKET_PAYLOAD {
        return Err(map_codec_error(CodecError::Limit));
    }
    stream.read_exact(u32::try_from(payload_len).map_err(|_| map_codec_error(CodecError::Limit))?)
}

fn write_packet(stream: &impl MysqlIo, sequence: u8, payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_PACKET_PAYLOAD {
        return Err(map_codec_error(CodecError::Limit));
    }
    // The host's inclusive per-call ceiling is exactly one MiB. Keep the
    // four-byte MySQL header in its own bounded call so a maximum-size payload
    // remains representable without an oversized write or a second full copy.
    let header = protocol::packet_header(payload.len(), sequence).map_err(map_codec_error)?;
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

#[allow(
    clippy::needless_borrows_for_generic_args,
    reason = "borrow sensitive intermediate digests instead of creating implicit copies"
)]
fn caching_sha2_token(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut stage1 = Sha256::digest(password);
    let mut stage2 = Sha256::digest(&stage1);
    let mut challenge = Sha256::new();
    challenge.update(&stage2);
    challenge.update(nonce);
    let mut stage3 = challenge.finalize();
    let token = stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect();
    stage1.as_mut_slice().zeroize();
    stage2.as_mut_slice().zeroize();
    stage3.as_mut_slice().zeroize();
    token
}

#[allow(
    clippy::needless_borrows_for_generic_args,
    reason = "borrow sensitive intermediate digests instead of creating implicit copies"
)]
fn mysql_native_password_token(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut stage1 = Sha1::digest(password);
    let mut stage2 = Sha1::digest(&stage1);
    let mut challenge = Sha1::new();
    challenge.update(nonce);
    challenge.update(&stage2);
    let mut stage3 = challenge.finalize();
    let token = stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect();
    stage1.as_mut_slice().zeroize();
    stage2.as_mut_slice().zeroize();
    stage3.as_mut_slice().zeroize();
    token
}

fn auth_token(auth_plugin: AuthPlugin, password: &[u8], nonce: &[u8]) -> Vec<u8> {
    match auth_plugin {
        AuthPlugin::CachingSha2Password => caching_sha2_token(password, nonce),
        AuthPlugin::MysqlNativePassword => mysql_native_password_token(password, nonce),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionTlsMode {
    Disabled,
    Upgrade,
}

fn authenticate_mysql(
    stream: &impl MysqlIo,
    tls_mode: ConnectionTlsMode,
    username: &[u8],
    password: &[u8],
    database: Option<&str>,
    secret_refs: &[(&str, &[u8])],
) -> Result<(), Error> {
    let handshake_bytes = read_packet(stream, 0)?;
    let handshake = protocol::parse_handshake(&handshake_bytes).map_err(map_codec_error)?;
    let transport_capability = match tls_mode {
        ConnectionTlsMode::Disabled => 0,
        ConnectionTlsMode::Upgrade => CLIENT_SSL,
    };
    let required = CLIENT_REQUIRED | transport_capability;
    if handshake.server_capabilities & required != required
        || !protocol::supported_utf8_collation(u16::from(handshake.character_set))
    {
        return Err(map_codec_error(CodecError::Unsupported));
    }

    let mut capabilities =
        CLIENT_REQUIRED | transport_capability | (handshake.server_capabilities & CLIENT_OPTIONAL);
    if database.is_some() {
        capabilities |= CLIENT_CONNECT_WITH_DB;
    }
    let (response_sequence, auth_sequence) = match tls_mode {
        ConnectionTlsMode::Disabled => (1, 2),
        ConnectionTlsMode::Upgrade => {
            let ssl_request = protocol::ssl_request(capabilities, handshake.character_set);
            write_packet(stream, 1, &ssl_request)?;
            stream.upgrade_tls()?;
            (2, 3)
        }
    };

    let token = SecretBytes(auth_token(
        handshake.auth_plugin,
        password,
        &handshake.auth_data,
    ));
    let response = SecretBytes(
        protocol::handshake_response(
            capabilities,
            handshake.character_set,
            username,
            &token.0,
            database,
            handshake.auth_plugin,
        )
        .map_err(map_codec_error)?,
    );
    write_packet(stream, response_sequence, &response.0)?;

    let auth = read_packet(stream, auth_sequence)?;
    match protocol::parse_auth_response(&auth, secret_refs, handshake.auth_plugin)
        .map_err(map_codec_error)?
    {
        protocol::AuthResponse::Complete => {}
        protocol::AuthResponse::FastComplete => {
            let complete = read_packet(stream, auth_sequence.wrapping_add(1))?;
            protocol::parse_ok_or_error(&complete, secret_refs, true).map_err(map_codec_error)?;
        }
        protocol::AuthResponse::FullAuthentication => {
            if handshake.auth_plugin != AuthPlugin::CachingSha2Password
                || tls_mode != ConnectionTlsMode::Upgrade
            {
                return Err(map_codec_error(CodecError::Unsupported));
            }
            let mut cleartext = SecretBytes(password.to_vec());
            cleartext.0.push(0);
            write_packet(stream, auth_sequence.wrapping_add(1), &cleartext.0)?;
            let complete = read_packet(stream, auth_sequence.wrapping_add(2))?;
            protocol::parse_ok_or_error(&complete, secret_refs, true).map_err(map_codec_error)?;
        }
    }
    Ok(())
}

fn connect_mysql(options: ConnectOptions) -> Result<MysqlConnection, Error> {
    let tls_mode = match net_policy::get_tls_mode(&options.endpoint).map_err(map_net_error)? {
        net_policy::TlsMode::Disabled => ConnectionTlsMode::Disabled,
        net_policy::TlsMode::Upgrade => ConnectionTlsMode::Upgrade,
        net_policy::TlsMode::Direct => return Err(map_codec_error(CodecError::Unsupported)),
    };
    let mut username =
        SecretBytes(secrets::get(&options.username_secret).map_err(map_secret_error)?);
    let mut password =
        SecretBytes(secrets::get(&options.password_secret).map_err(map_secret_error)?);
    if username.0.is_empty()
        || username.0.contains(&0)
        || options
            .database
            .as_ref()
            .is_some_and(|value| value.contains('\0'))
    {
        return Err(map_codec_error(CodecError::Encoding));
    }

    let stream = net::connect(&options.endpoint).map_err(map_net_error)?;
    let secret_refs = [
        (options.username_secret.as_str(), username.0.as_slice()),
        (options.password_secret.as_str(), password.0.as_slice()),
    ];
    authenticate_mysql(
        &stream,
        tls_mode,
        &username.0,
        &password.0,
        options.database.as_deref(),
        &secret_refs,
    )?;

    Ok(MysqlConnection {
        state: RefCell::new(Some(ConnectionState {
            stream,
            secrets: vec![
                (options.username_secret, username.take()),
                (options.password_secret, password.take()),
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
        if let Err(error) = write_packet(&connection.stream, 0, &command) {
            close_connection_state(&mut state);
            return Err(error);
        }
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
        );
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                let error = match error {
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
                };
                close_connection_state(&mut state);
                return Err(error);
            }
        };
        Ok(match result {
            RawQueryResult::Command { affected_rows, .. } => {
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
        close_connection_state(&mut self.state.borrow_mut());
    }
}

fn close_connection_state(state: &mut Option<ConnectionState>) {
    if let Some(mut connection) = state.take() {
        connection.stream.close();
        for (_name, secret) in &mut connection.secrets {
            secret.fill(0);
        }
    }
}

impl Drop for MysqlConnection {
    fn drop(&mut self) {
        close_connection_state(self.state.get_mut());
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
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    struct ScriptedIo {
        reads: RefCell<VecDeque<Vec<u8>>>,
        writes: RefCell<Vec<Vec<u8>>>,
        flushes: Cell<usize>,
        upgrades: Cell<usize>,
    }

    impl ScriptedIo {
        fn new(packets: &[(u8, &[u8])]) -> Self {
            let mut reads = VecDeque::new();
            for (sequence, payload) in packets {
                reads.push_back(
                    protocol::packet_header(payload.len(), *sequence)
                        .expect("scripted packet header")
                        .to_vec(),
                );
                reads.push_back(payload.to_vec());
            }
            Self {
                reads: RefCell::new(reads),
                writes: RefCell::new(Vec::new()),
                flushes: Cell::new(0),
                upgrades: Cell::new(0),
            }
        }
    }

    impl MysqlIo for ScriptedIo {
        fn read_exact(&self, bytes: u32) -> Result<Vec<u8>, Error> {
            let Some(value) = self.reads.borrow_mut().pop_front() else {
                return Err(driver_error(
                    ErrorClass::Protocol,
                    "scripted server exhausted",
                ));
            };
            if value.len() != usize::try_from(bytes).expect("scripted read size") {
                return Err(driver_error(
                    ErrorClass::Protocol,
                    "scripted server read size mismatch",
                ));
            }
            Ok(value)
        }

        fn write_all(&self, bytes: &[u8]) -> Result<(), Error> {
            self.writes.borrow_mut().push(bytes.to_vec());
            Ok(())
        }

        fn flush(&self) -> Result<(), Error> {
            self.flushes.set(self.flushes.get() + 1);
            Ok(())
        }

        fn upgrade_tls(&self) -> Result<(), Error> {
            self.upgrades.set(self.upgrades.get() + 1);
            Ok(())
        }
    }

    struct TcpIo(TcpStream);

    impl MysqlIo for TcpIo {
        fn read_exact(&self, bytes: u32) -> Result<Vec<u8>, Error> {
            let mut output = vec![0; usize::try_from(bytes).expect("bounded live read")];
            let mut stream = &self.0;
            Read::read_exact(&mut stream, &mut output)
                .map_err(|_| driver_error(ErrorClass::Transport, "live network read failed"))?;
            Ok(output)
        }

        fn write_all(&self, bytes: &[u8]) -> Result<(), Error> {
            let mut stream = &self.0;
            Write::write_all(&mut stream, bytes)
                .map_err(|_| driver_error(ErrorClass::Transport, "live network write failed"))
        }

        fn flush(&self) -> Result<(), Error> {
            let mut stream = &self.0;
            Write::flush(&mut stream)
                .map_err(|_| driver_error(ErrorClass::Transport, "live network flush failed"))
        }

        fn upgrade_tls(&self) -> Result<(), Error> {
            Err(driver_error(
                ErrorClass::Unsupported,
                "live plaintext fixture cannot upgrade TLS",
            ))
        }
    }

    fn greeting(version: &[u8], capabilities: u32, nonce: &[u8; 20], plugin: &[u8]) -> Vec<u8> {
        let mut packet = vec![10];
        packet.extend_from_slice(version);
        packet.push(0);
        packet.extend_from_slice(&11_u32.to_le_bytes());
        packet.extend_from_slice(&nonce[..8]);
        packet.push(0);
        packet.extend_from_slice(&(capabilities as u16).to_le_bytes());
        packet.push(33);
        packet.extend_from_slice(&2_u16.to_le_bytes());
        packet.extend_from_slice(
            &u16::try_from(capabilities >> 16)
                .expect("upper caps")
                .to_le_bytes(),
        );
        packet.push(21);
        packet.extend_from_slice(&[0; 10]);
        packet.extend_from_slice(&nonce[8..]);
        packet.push(0);
        packet.extend_from_slice(plugin);
        packet.push(0);
        packet
    }

    fn singlestore_greeting() -> Vec<u8> {
        greeting(
            b"5.7.32",
            0x801f_f7df,
            b"gve'V,rQ\"{v/;mYHB8.;",
            b"mysql_native_password",
        )
    }

    fn mysql_8_4_greeting() -> Vec<u8> {
        greeting(
            b"8.4.0",
            CLIENT_REQUIRED | CLIENT_SSL | CLIENT_PLUGIN_AUTH | CLIENT_DEPRECATE_EOF,
            b"0123456789abcdefghij",
            b"caching_sha2_password",
        )
    }

    const AUTH_OK: &[u8] = &[0x00, 0, 0, 0, 0, 0, 0];

    fn authenticate_script(stream: &ScriptedIo, tls_mode: ConnectionTlsMode) -> Result<(), Error> {
        authenticate_mysql(
            stream,
            tls_mode,
            b"root",
            b"secret",
            Some("app"),
            &[("username", b"root"), ("password", b"secret")],
        )
    }

    #[test]
    fn caching_sha2_token_is_deterministic_and_bounded() {
        let nonce = b"01234567890123456789";
        let first = caching_sha2_token(b"secret", nonce);
        let second = caching_sha2_token(b"secret", nonce);
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
        assert!(caching_sha2_token(b"", nonce).is_empty());
    }

    #[test]
    fn mysql_native_password_token_matches_singlestore_challenge() {
        let nonce = b"gve'V,rQ\"{v/;mYHB8.;";
        let token = mysql_native_password_token(b"secret", nonce);
        assert_eq!(
            token,
            [
                0xcc, 0x8c, 0x3b, 0xb2, 0x4b, 0x68, 0x84, 0x59, 0xe2, 0x00, 0x01, 0xbb, 0x43, 0xf2,
                0xc4, 0x88, 0x10, 0x71, 0x77, 0x2b,
            ]
        );
        assert_eq!(
            mysql_native_password_token(b"secret", nonce),
            token,
            "the challenge response must be deterministic"
        );
        assert!(mysql_native_password_token(b"", nonce).is_empty());
    }

    #[test]
    fn scripted_native_auth_has_exact_plaintext_and_upgrade_sequences() {
        let singlestore = singlestore_greeting();

        let plaintext = ScriptedIo::new(&[(0, &singlestore), (2, AUTH_OK)]);
        authenticate_script(&plaintext, ConnectionTlsMode::Disabled)
            .expect("explicit plaintext native auth");
        let plaintext_writes = plaintext.writes.borrow();
        assert_eq!(plaintext_writes.len(), 2);
        assert_eq!(plaintext_writes[0][3], 1, "HandshakeResponse sequence");
        assert_eq!(
            u32::from_le_bytes(
                plaintext_writes[1][..4]
                    .try_into()
                    .expect("client capabilities"),
            ) & CLIENT_SSL,
            0,
            "disabled policy must omit CLIENT_SSL"
        );
        assert!(plaintext_writes[1].ends_with(b"mysql_native_password\0"));
        assert_eq!(plaintext.flushes.get(), 1);
        assert_eq!(plaintext.upgrades.get(), 0);
        drop(plaintext_writes);

        let tls_native_greeting = greeting(
            b"5.7.32",
            0x801f_f7df | CLIENT_SSL,
            b"gve'V,rQ\"{v/;mYHB8.;",
            b"mysql_native_password",
        );
        let upgraded = ScriptedIo::new(&[(0, &tls_native_greeting), (3, AUTH_OK)]);
        authenticate_script(&upgraded, ConnectionTlsMode::Upgrade)
            .expect("TLS-upgraded native auth");
        let upgraded_writes = upgraded.writes.borrow();
        assert_eq!(upgraded_writes.len(), 4);
        assert_eq!(upgraded_writes[0][3], 1, "SSLRequest sequence");
        assert_eq!(upgraded_writes[1].len(), 32, "SSLRequest payload");
        assert_ne!(
            u32::from_le_bytes(
                upgraded_writes[1][..4]
                    .try_into()
                    .expect("SSL capabilities"),
            ) & CLIENT_SSL,
            0
        );
        assert_eq!(upgraded_writes[2][3], 2, "HandshakeResponse sequence");
        assert!(upgraded_writes[3].ends_with(b"mysql_native_password\0"));
        assert_eq!(upgraded.flushes.get(), 2);
        assert_eq!(upgraded.upgrades.get(), 1);
    }

    #[test]
    fn scripted_auth_rejects_sequence_drift_bad_credentials_and_switches() {
        let greeting = singlestore_greeting();
        let wrong_sequence = ScriptedIo::new(&[(0, &greeting), (3, AUTH_OK)]);
        let error = authenticate_script(&wrong_sequence, ConnectionTlsMode::Disabled)
            .expect_err("plaintext auth result must be sequence 2");
        assert_eq!(error.class, ErrorClass::Protocol);

        let mut denied = vec![0xff, 0x15, 0x04, b'#'];
        denied.extend_from_slice(b"28000Access denied for secret");
        let bad_credentials = ScriptedIo::new(&[(0, &greeting), (2, &denied)]);
        let error = authenticate_script(&bad_credentials, ConnectionTlsMode::Disabled)
            .expect_err("bad credentials remain typed authentication");
        assert_eq!(error.class, ErrorClass::Authentication);
        assert_eq!(error.vendor_code, Some(1045));
        assert_eq!(error.sqlstate.as_deref(), Some("28000"));
        assert_eq!(error.message, "Access denied for [REDACTED]");

        let auth_switch = b"\xfecaching_sha2_password\0hostile-challenge";
        let switched = ScriptedIo::new(&[(0, &greeting), (2, auth_switch)]);
        let error = authenticate_script(&switched, ConnectionTlsMode::Disabled)
            .expect_err("auth switches fail closed");
        assert_eq!(error.class, ErrorClass::Unsupported);
    }

    #[test]
    fn scripted_mysql_8_4_caching_auth_preserves_tls_continuations() {
        let greeting = mysql_8_4_greeting();
        let fast = ScriptedIo::new(&[(0, &greeting), (3, &[0x01, 0x03]), (4, AUTH_OK)]);
        authenticate_script(&fast, ConnectionTlsMode::Upgrade)
            .expect("MySQL 8.4 fast authentication");
        let writes = fast.writes.borrow();
        assert_eq!(writes.len(), 4);
        assert_eq!(writes[0][3], 1);
        assert_eq!(writes[2][3], 2);
        assert!(writes[3].ends_with(b"caching_sha2_password\0"));
        assert_eq!(fast.upgrades.get(), 1);
        drop(writes);

        let full_without_tls = ScriptedIo::new(&[(0, &greeting), (2, &[0x01, 0x04])]);
        let error = authenticate_script(&full_without_tls, ConnectionTlsMode::Disabled)
            .expect_err("cleartext password must never be sent without host TLS");
        assert_eq!(error.class, ErrorClass::Unsupported);
        assert_eq!(full_without_tls.writes.borrow().len(), 2);
        assert_eq!(full_without_tls.upgrades.get(), 0);
    }

    #[test]
    #[ignore = "requires a pinned SingleStoreDB Dev 0.2.35 endpoint"]
    fn live_singlestore_0_2_35_native_auth_and_query_smoke() {
        let address = std::env::var("SIGIL_MYSQL_SMOKE_ADDR")
            .expect("set SIGIL_MYSQL_SMOKE_ADDR for the pinned live smoke");
        let password = std::env::var("SIGIL_MYSQL_SMOKE_PASSWORD")
            .expect("set SIGIL_MYSQL_SMOKE_PASSWORD for the pinned live smoke");

        let connect = || {
            let stream = TcpStream::connect(&address).expect("connect pinned SingleStore");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound live read");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("bound live write");
            TcpIo(stream)
        };

        let stream = connect();
        authenticate_mysql(
            &stream,
            ConnectionTlsMode::Disabled,
            b"root",
            password.as_bytes(),
            None,
            &[("password", password.as_bytes())],
        )
        .expect("pinned SingleStore authentication reaches OK");
        write_packet(&stream, 0, b"\x03select 1").expect("send live query");
        let result = protocol::read_query_result(
            |sequence| {
                read_packet(&stream, sequence).map_err(|error| match error.class {
                    ErrorClass::Timeout => protocol::IoError::Timeout,
                    ErrorClass::Limit => protocol::IoError::Limit,
                    _ => protocol::IoError::Transport,
                })
            },
            &[("password", password.as_bytes())],
        )
        .expect("live query result");
        let protocol::RawQueryResult::Rows { rows, .. } = result else {
            panic!("select returned a command result");
        };
        assert_eq!(rows, [vec![protocol::RawCell::Bytes(vec![b'1'])]]);

        let denied = connect();
        let error = authenticate_mysql(
            &denied,
            ConnectionTlsMode::Disabled,
            b"root",
            b"definitely-wrong",
            None,
            &[("password", b"definitely-wrong")],
        )
        .expect_err("bad credentials remain a typed server rejection");
        assert_eq!(error.class, ErrorClass::Authentication);
        assert_eq!(error.vendor_code, Some(1045));
        assert_eq!(error.sqlstate.as_deref(), Some("28000"));
    }

    #[test]
    fn sql_limit_precedes_resource_state_and_closed_is_idempotent() {
        let connection = MysqlConnection {
            state: RefCell::new(None),
        };
        let accepted_boundary =
            <MysqlConnection as GuestConnection>::query(&connection, "x".repeat(MAX_SQL_BYTES))
                .expect_err("inclusive SQL maximum reaches the closed-resource check");
        assert_eq!(accepted_boundary.class, ErrorClass::Closed);

        let rejected =
            <MysqlConnection as GuestConnection>::query(&connection, "x".repeat(MAX_SQL_BYTES + 1))
                .expect_err("maximum plus one must be rejected before resource use");
        assert_eq!(rejected.class, ErrorClass::Limit);
        <MysqlConnection as GuestConnection>::close(&connection);
        <MysqlConnection as GuestConnection>::close(&connection);
    }

    #[test]
    fn host_result_mapping_is_closed_and_source_free() {
        use bindings::sigil::host::net::Error as NetError;

        for (source, expected) in [
            (
                NetError::Unavailable("target".to_owned()),
                ErrorClass::Transport,
            ),
            (NetError::Io("socket".to_owned()), ErrorClass::Transport),
            (
                NetError::Timeout("deadline".to_owned()),
                ErrorClass::Timeout,
            ),
            (NetError::Limit("quota".to_owned()), ErrorClass::Limit),
            (
                NetError::Denied("authority".to_owned()),
                ErrorClass::Transport,
            ),
            (
                NetError::Tls("certificate".to_owned()),
                ErrorClass::Transport,
            ),
        ] {
            let mapped = map_net_error(source);
            assert_eq!(mapped.class, expected);
            assert_eq!(mapped.vendor_code, None);
            assert_eq!(mapped.sqlstate, None);
            assert!(!mapped.message.contains("target"));
            assert!(!mapped.message.contains("socket"));
            assert!(!mapped.message.contains("authority"));
            assert!(!mapped.message.contains("certificate"));
        }
    }

    #[test]
    fn candidate_requires_a_sigil_release_with_net_policy() {
        let manifest = include_str!("../plugin.toml");

        assert!(manifest.contains("sigil = \">=0.33.1, <1.0.0\""));
        assert!(!manifest.contains("sigil = \">=0.33.0, <1.0.0\""));
    }
}

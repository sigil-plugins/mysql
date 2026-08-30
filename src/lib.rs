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

mod protocol;

use bindings::exports::sigil::sql::driver::{
    Cell, Column, ColumnType, CommandResult, ConnectOptions, Connection, Error, ErrorClass, Guest,
    GuestConnection, Row, RowSet, TemporalType,
};
use bindings::sigil::host::{net, net_policy, secrets};
use protocol::{
    AuthPlugin, CodecError, RawQueryResult, TypedCell, TypedColumnType, TypedQueryResult,
    TypedResultLimits, TypedRowSet, TypedTemporalType,
};

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

struct ConnectionState<S> {
    stream: S,
    secrets: Vec<(String, Vec<u8>)>,
}

struct ConnectionCore<S: MysqlIo> {
    state: RefCell<Option<ConnectionState<S>>>,
    limits: TypedResultLimits,
}

type MysqlConnection = ConnectionCore<net::Stream>;

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

fn invalid_argument(name: &str) -> Error {
    driver_error(ErrorClass::Invalid, &format!("invalid `{name}` argument"))
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
    fn close(&self);
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

    fn close(&self) {
        self.close();
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

fn validate_connect_options(options: &ConnectOptions) -> Result<(), Error> {
    if options.endpoint.is_empty() || options.endpoint.contains('\0') {
        return Err(invalid_argument("endpoint"));
    }
    if options.username_secret.is_empty() {
        return Err(invalid_argument("username-secret"));
    }
    if options.password_secret.is_empty() {
        return Err(invalid_argument("password-secret"));
    }
    if options
        .database
        .as_ref()
        .is_some_and(|database| database.contains('\0'))
    {
        return Err(invalid_argument("database"));
    }
    Ok(())
}

fn connect_mysql(options: ConnectOptions) -> Result<MysqlConnection, Error> {
    validate_connect_options(&options)?;
    let limits = TypedResultLimits {
        max_rows: options.max_rows,
        max_result_bytes: options.max_result_bytes,
    };
    let tls_mode = match net_policy::get_tls_mode(&options.endpoint).map_err(map_net_error)? {
        net_policy::TlsMode::Disabled => ConnectionTlsMode::Disabled,
        net_policy::TlsMode::Upgrade => ConnectionTlsMode::Upgrade,
        net_policy::TlsMode::Direct => return Err(map_codec_error(CodecError::Unsupported)),
    };
    let mut username =
        SecretBytes(secrets::get(&options.username_secret).map_err(map_secret_error)?);
    let mut password =
        SecretBytes(secrets::get(&options.password_secret).map_err(map_secret_error)?);
    if username.0.is_empty() || username.0.contains(&0) {
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

    Ok(ConnectionCore::new(
        stream,
        vec![
            (options.username_secret, username.take()),
            (options.password_secret, password.take()),
        ],
        limits,
    ))
}

impl Guest for Mysql {
    type Connection = MysqlConnection;

    fn connect(options: ConnectOptions) -> Result<Connection, Error> {
        connect_mysql(options).map(Connection::new)
    }
}

impl<S: MysqlIo> ConnectionCore<S> {
    const fn new(stream: S, secrets: Vec<(String, Vec<u8>)>, limits: TypedResultLimits) -> Self {
        Self {
            state: RefCell::new(Some(ConnectionState { stream, secrets })),
            limits,
        }
    }

    fn execute_raw(&self, sql: &str) -> Result<RawQueryResult, Error> {
        if sql.is_empty() {
            return Err(invalid_argument("sql"));
        }
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
        match result {
            Ok(result) => Ok(result),
            Err(error) => {
                let terminal =
                    !matches!(&error, protocol::QueryError::Codec(CodecError::Server(_)));
                let mapped = map_query_error(error);
                if terminal {
                    close_connection_state(&mut state);
                }
                Err(mapped)
            }
        }
    }

    fn decode_typed(&self, result: RawQueryResult) -> Result<TypedQueryResult, Error> {
        match protocol::decode_typed_result(result, self.limits) {
            Ok(result) => Ok(result),
            Err(error) => {
                let terminal = !matches!(error, CodecError::Unsupported | CodecError::Server(_));
                let mapped = map_codec_error(error);
                if terminal {
                    close_connection_state(&mut self.state.borrow_mut());
                }
                Err(mapped)
            }
        }
    }

    fn query_typed(&self, sql: &str) -> Result<RowSet, Error> {
        match self.decode_typed(self.execute_raw(sql)?)? {
            TypedQueryResult::Rows(rows) => Ok(bind_row_set(rows)),
            TypedQueryResult::Command(_) => Err(driver_error(
                ErrorClass::Unsupported,
                "query returned command metadata; use exec",
            )),
        }
    }

    fn exec_typed(&self, sql: &str) -> Result<CommandResult, Error> {
        match self.decode_typed(self.execute_raw(sql)?)? {
            TypedQueryResult::Command(command) => Ok(CommandResult {
                affected_rows: command.affected_rows,
                last_insert_id: command.last_insert_id,
                warnings: u32::from(command.warnings),
            }),
            TypedQueryResult::Rows(_) => Err(driver_error(
                ErrorClass::Unsupported,
                "exec returned rows; use query",
            )),
        }
    }

    fn close_state(&self) {
        close_connection_state(&mut self.state.borrow_mut());
    }
}

fn map_query_error(error: protocol::QueryError) -> Error {
    match error {
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
    }
}

const fn bind_column_type(column_type: TypedColumnType) -> ColumnType {
    match column_type {
        TypedColumnType::Null => ColumnType::Null,
        TypedColumnType::Signed => ColumnType::Signed,
        TypedColumnType::Unsigned => ColumnType::Unsigned,
        TypedColumnType::Floating => ColumnType::Floating,
        TypedColumnType::Decimal => ColumnType::Decimal,
        TypedColumnType::Text => ColumnType::Text,
        TypedColumnType::Bytes => ColumnType::Bytes,
        TypedColumnType::Temporal => ColumnType::Temporal,
    }
}

const fn bind_temporal_type(temporal_type: TypedTemporalType) -> TemporalType {
    match temporal_type {
        TypedTemporalType::Date => TemporalType::Date,
        TypedTemporalType::Time => TemporalType::Time,
        TypedTemporalType::Datetime => TemporalType::Datetime,
        TypedTemporalType::Timestamp => TemporalType::Timestamp,
        TypedTemporalType::Year => TemporalType::Year,
    }
}

fn bind_cell(cell: TypedCell) -> Cell {
    match cell {
        TypedCell::Null => Cell::Null,
        TypedCell::Signed(value) => Cell::Signed(value),
        TypedCell::Unsigned(value) => Cell::Unsigned(value),
        TypedCell::Floating(value) => Cell::Floating(value),
        TypedCell::Decimal(value) => Cell::Decimal(value),
        TypedCell::Text(value) => Cell::Text(value),
        TypedCell::Bytes(value) => Cell::Bytes(value),
        TypedCell::Temporal(value) => Cell::Temporal(value),
    }
}

fn bind_row_set(rows: TypedRowSet) -> RowSet {
    RowSet {
        columns: rows
            .columns
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
                type_: bind_column_type(column.column_type),
                temporal_type: column.temporal_type.map(bind_temporal_type),
            })
            .collect(),
        rows: rows
            .rows
            .into_iter()
            .map(|cells| Row {
                cells: cells.into_iter().map(bind_cell).collect(),
            })
            .collect(),
    }
}

impl GuestConnection for MysqlConnection {
    fn query(&self, sql: String) -> Result<RowSet, Error> {
        self.query_typed(&sql)
    }

    fn exec(&self, sql: String) -> Result<CommandResult, Error> {
        self.exec_typed(&sql)
    }

    fn close(&self) {
        self.close_state();
    }
}

fn close_connection_state<S: MysqlIo>(state: &mut Option<ConnectionState<S>>) {
    if let Some(mut connection) = state.take() {
        connection.stream.close();
        for (_name, secret) in &mut connection.secrets {
            secret.fill(0);
        }
    }
}

impl<S: MysqlIo> Drop for ConnectionCore<S> {
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
    use std::cell::Cell as CounterCell;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::rc::Rc;
    use std::time::Duration;

    struct ScriptedIo {
        reads: RefCell<VecDeque<Vec<u8>>>,
        writes: RefCell<Vec<Vec<u8>>>,
        flushes: CounterCell<usize>,
        upgrades: CounterCell<usize>,
        closes: Rc<CounterCell<usize>>,
    }

    impl ScriptedIo {
        fn new(packets: &[(u8, &[u8])]) -> Self {
            Self::from_owned(
                packets
                    .iter()
                    .map(|(sequence, payload)| (*sequence, payload.to_vec()))
                    .collect(),
            )
        }

        fn from_owned(packets: Vec<(u8, Vec<u8>)>) -> Self {
            let mut reads = VecDeque::new();
            for (sequence, payload) in packets {
                reads.push_back(
                    protocol::packet_header(payload.len(), sequence)
                        .expect("scripted packet header")
                        .to_vec(),
                );
                reads.push_back(payload);
            }
            Self {
                reads: RefCell::new(reads),
                writes: RefCell::new(Vec::new()),
                flushes: CounterCell::new(0),
                upgrades: CounterCell::new(0),
                closes: Rc::new(CounterCell::new(0)),
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

        fn close(&self) {
            self.closes.set(self.closes.get() + 1);
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

        fn close(&self) {
            let _result = self.0.shutdown(Shutdown::Both);
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

    fn lenenc_u64(value: u64) -> Vec<u8> {
        if value <= 0xfa {
            vec![u8::try_from(value).expect("single-byte length encoding")]
        } else if u16::try_from(value).is_ok() {
            let mut output = vec![0xfc];
            output.extend_from_slice(
                &u16::try_from(value)
                    .expect("two-byte length encoding")
                    .to_le_bytes(),
            );
            output
        } else if value <= 0x00ff_ffff {
            let bytes = u32::try_from(value)
                .expect("three-byte length encoding")
                .to_le_bytes();
            vec![0xfd, bytes[0], bytes[1], bytes[2]]
        } else {
            let mut output = vec![0xfe];
            output.extend_from_slice(&value.to_le_bytes());
            output
        }
    }

    fn ok_packet(affected_rows: u64, last_insert_id: u64, warnings: u16) -> Vec<u8> {
        let mut packet = vec![0x00];
        packet.extend(lenenc_u64(affected_rows));
        packet.extend(lenenc_u64(last_insert_id));
        packet.extend_from_slice(&2_u16.to_le_bytes());
        packet.extend_from_slice(&warnings.to_le_bytes());
        packet
    }

    fn column_packet(vendor_type: u8, flags: u16, collation: u16) -> Vec<u8> {
        let mut packet = vec![0; 6];
        packet.push(0x0c);
        packet.extend_from_slice(&collation.to_le_bytes());
        packet.extend_from_slice(&64_u32.to_le_bytes());
        packet.push(vendor_type);
        packet.extend_from_slice(&flags.to_le_bytes());
        packet.extend_from_slice(&[0; 3]);
        packet
    }

    fn row_packet(value: Option<&[u8]>) -> Vec<u8> {
        let Some(value) = value else {
            return vec![0xfb];
        };
        let mut packet = lenenc_u64(u64::try_from(value.len()).expect("fixture row length"));
        packet.extend_from_slice(value);
        packet
    }

    fn row_result_packets(
        vendor_type: u8,
        flags: u16,
        values: &[Option<&[u8]>],
    ) -> Vec<(u8, Vec<u8>)> {
        let mut packets = vec![
            (1, vec![1]),
            (2, column_packet(vendor_type, flags, 63)),
            (3, vec![0xfe, 0, 0, 0, 0]),
        ];
        for (index, value) in values.iter().enumerate() {
            packets.push((
                u8::try_from(index + 4).expect("fixture sequence"),
                row_packet(*value),
            ));
        }
        packets.push((
            u8::try_from(values.len() + 4).expect("fixture terminator sequence"),
            vec![0xfe, 0, 0, 0, 0],
        ));
        packets
    }

    fn scripted_connection(
        packets: Vec<(u8, Vec<u8>)>,
        limits: TypedResultLimits,
    ) -> (ConnectionCore<ScriptedIo>, Rc<CounterCell<usize>>) {
        let stream = ScriptedIo::from_owned(packets);
        let closes = Rc::clone(&stream.closes);
        (
            ConnectionCore::new(
                stream,
                vec![("password".to_owned(), b"secret".to_vec())],
                limits,
            ),
            closes,
        )
    }

    fn server_error_packet() -> Vec<u8> {
        let mut packet = vec![0xff, 0xb1, 0x04, b'#'];
        packet.extend_from_slice(b"HY000server rejected secret");
        packet
    }

    struct FailingIo {
        class: ErrorClass,
        closes: Rc<CounterCell<usize>>,
    }

    impl MysqlIo for FailingIo {
        fn read_exact(&self, _bytes: u32) -> Result<Vec<u8>, Error> {
            Err(driver_error(self.class, "scripted host failure"))
        }

        fn write_all(&self, _bytes: &[u8]) -> Result<(), Error> {
            Ok(())
        }

        fn flush(&self) -> Result<(), Error> {
            Ok(())
        }

        fn upgrade_tls(&self) -> Result<(), Error> {
            Ok(())
        }

        fn close(&self) {
            self.closes.set(self.closes.get() + 1);
        }
    }

    fn failing_connection(
        class: ErrorClass,
    ) -> (ConnectionCore<FailingIo>, Rc<CounterCell<usize>>) {
        let closes = Rc::new(CounterCell::new(0));
        (
            ConnectionCore::new(
                FailingIo {
                    class,
                    closes: Rc::clone(&closes),
                },
                Vec::new(),
                TypedResultLimits::default(),
            ),
            closes,
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
    fn stateful_adapter_alternates_exec_and_query_on_one_stream() {
        let mut packets = vec![(1, ok_packet(0, 0, 0)), (1, ok_packet(1, 0, 2))];
        packets.extend(row_result_packets(3, 0, &[Some(b"7")]));
        let (connection, closes) = scripted_connection(packets, TypedResultLimits::default());

        let created = connection
            .exec_typed("CREATE TEMPORARY TABLE conformance(value BIGINT)")
            .expect("create temporary table");
        assert_eq!(created.affected_rows, 0);
        assert_eq!(created.last_insert_id, Some(0));
        assert_eq!(created.warnings, 0);

        let inserted = connection
            .exec_typed("INSERT INTO conformance VALUES (7)")
            .expect("insert into the same session");
        assert_eq!(inserted.affected_rows, 1);
        assert_eq!(inserted.last_insert_id, Some(0));
        assert_eq!(inserted.warnings, 2);

        let selected = connection
            .query_typed("SELECT value FROM conformance")
            .expect("select from the same temporary table session");
        assert_eq!(selected.columns.len(), 1);
        assert_eq!(selected.columns[0].type_, ColumnType::Signed);
        assert_eq!(selected.columns[0].temporal_type, None);
        assert_eq!(selected.rows.len(), 1);
        assert!(matches!(
            selected.rows[0].cells.as_slice(),
            [Cell::Signed(7)]
        ));

        {
            let state = connection.state.borrow();
            let writes = &state.as_ref().expect("open session").stream.writes;
            let writes = writes.borrow();
            assert_eq!(writes.len(), 6, "one COM_QUERY packet per call");
            assert_eq!(
                &writes[1][1..],
                b"CREATE TEMPORARY TABLE conformance(value BIGINT)"
            );
            assert_eq!(&writes[3][1..], b"INSERT INTO conformance VALUES (7)");
            assert_eq!(&writes[5][1..], b"SELECT value FROM conformance");
        }
        assert_eq!(closes.get(), 0);
        connection.close_state();
        connection.close_state();
        assert_eq!(closes.get(), 1);
        drop(connection);
        assert_eq!(
            closes.get(),
            1,
            "drop cannot close an idempotently closed stream"
        );
    }

    #[test]
    fn wrong_result_arm_is_nonterminal_and_never_discards_success() {
        let mut packets = vec![(1, ok_packet(3, 0, 0))];
        packets.extend(row_result_packets(3, 0, &[Some(b"7")]));
        packets.extend(row_result_packets(3, 0, &[Some(b"8")]));
        packets.push((1, ok_packet(4, 0, 0)));
        let (connection, closes) = scripted_connection(packets, TypedResultLimits::default());

        let wrong_query = connection
            .query_typed("UPDATE fixture")
            .expect_err("query must not manufacture an empty row set");
        assert_eq!(wrong_query.class, ErrorClass::Unsupported);
        let rows = connection
            .query_typed("SELECT 7")
            .expect("wrong query arm leaves the synchronized session usable");
        assert!(matches!(rows.rows[0].cells.as_slice(), [Cell::Signed(7)]));

        let wrong_exec = connection
            .exec_typed("SELECT 8")
            .expect_err("exec must not discard returned rows");
        assert_eq!(wrong_exec.class, ErrorClass::Unsupported);
        let command = connection
            .exec_typed("UPDATE fixture AGAIN")
            .expect("wrong exec arm leaves the synchronized session usable");
        assert_eq!(command.affected_rows, 4);
        assert_eq!(closes.get(), 0);
    }

    #[test]
    fn caller_limits_precede_wrong_arm_classification() {
        let (command, command_closes) = scripted_connection(
            vec![(1, ok_packet(3, 0, 0))],
            TypedResultLimits {
                max_rows: None,
                max_result_bytes: Some(19),
            },
        );
        let command_limit = command
            .query_typed("UPDATE fixture")
            .expect_err("wrong-arm command still obeys its logical byte ceiling");
        assert_eq!(command_limit.class, ErrorClass::Limit);
        assert_eq!(command_closes.get(), 1);
        assert_eq!(
            command
                .query_typed("SELECT must_not_run")
                .expect_err("limit is terminal")
                .class,
            ErrorClass::Closed
        );

        let (rows, row_closes) = scripted_connection(
            row_result_packets(3, 0, &[Some(b"7")]),
            TypedResultLimits {
                max_rows: Some(0),
                max_result_bytes: None,
            },
        );
        let row_limit = rows
            .exec_typed("SELECT value FROM conformance")
            .expect_err("wrong-arm rows still obey their row ceiling");
        assert_eq!(row_limit.class, ErrorClass::Limit);
        assert_eq!(row_closes.get(), 1);
        assert_eq!(
            rows.exec_typed("UPDATE must_not_run")
                .expect_err("limit is terminal")
                .class,
            ErrorClass::Closed
        );
    }

    #[test]
    fn server_error_retains_fields_and_does_not_poison_the_session() {
        let mut packets = vec![(1, server_error_packet())];
        packets.extend(row_result_packets(3, 0, &[Some(b"9")]));
        let (connection, closes) = scripted_connection(packets, TypedResultLimits::default());

        let error = connection
            .query_typed("SELECT rejected")
            .expect_err("server rejection");
        assert_eq!(error.class, ErrorClass::Server);
        assert_eq!(error.vendor_code, Some(1201));
        assert_eq!(error.sqlstate.as_deref(), Some("HY000"));
        assert_eq!(error.message, "server rejected [REDACTED]");
        assert_eq!(closes.get(), 0);

        let rows = connection
            .query_typed("SELECT 9")
            .expect("a complete ERR packet leaves protocol synchronization intact");
        assert!(matches!(rows.rows[0].cells.as_slice(), [Cell::Signed(9)]));
    }

    #[test]
    fn host_io_failures_latch_closed_without_retry_or_replay() {
        for expected in [
            ErrorClass::Timeout,
            ErrorClass::Limit,
            ErrorClass::Transport,
        ] {
            let (connection, close_count) = failing_connection(expected);
            let error = connection
                .query_typed("SELECT host_failure")
                .expect_err("host failure");
            assert_eq!(error.class, expected);
            assert_eq!(close_count.get(), 1);
            let after_failure = connection
                .exec_typed("UPDATE must_not_run")
                .expect_err("terminal failure latches closed");
            assert_eq!(after_failure.class, ErrorClass::Closed);
            assert_eq!(close_count.get(), 1, "no reconnect or second close");
            drop(connection);
            assert_eq!(close_count.get(), 1, "drop remains idempotent");
        }
    }

    #[test]
    fn malformed_and_bounded_results_close_once_without_partial_output() {
        for (packets, limits, expected) in [
            (
                row_result_packets(3, 0, &[Some(b"server-secret")]),
                TypedResultLimits::default(),
                ErrorClass::Encoding,
            ),
            (
                row_result_packets(6, 0, &[Some(b"not-null")]),
                TypedResultLimits::default(),
                ErrorClass::Protocol,
            ),
            (
                row_result_packets(3, 0, &[Some(b"7")]),
                TypedResultLimits {
                    max_rows: Some(0),
                    max_result_bytes: None,
                },
                ErrorClass::Limit,
            ),
        ] {
            let (connection, closes) = scripted_connection(packets, limits);
            let error = connection
                .query_typed("SELECT malformed")
                .expect_err("typed result must fail as a whole");
            assert_eq!(error.class, expected);
            assert_eq!(error.vendor_code, None);
            assert_eq!(error.sqlstate, None);
            assert_eq!(closes.get(), 1);
            assert_eq!(
                connection
                    .query_typed("SELECT partial")
                    .expect_err("no partial result and no reuse")
                    .class,
                ErrorClass::Closed
            );
        }

        let (local_infile, closes) =
            scripted_connection(vec![(1, vec![0xfb])], TypedResultLimits::default());
        assert_eq!(
            local_infile
                .query_typed("LOAD DATA LOCAL INFILE")
                .expect_err("local infile is outside the contract")
                .class,
            ErrorClass::Unsupported
        );
        assert_eq!(closes.get(), 1, "unfinished exchange must close");
    }

    #[test]
    fn caller_result_limits_are_inclusive_lower_only_and_terminal_when_reached() {
        let exact_limits = TypedResultLimits {
            max_rows: Some(1),
            max_result_bytes: Some(8),
        };
        let (exact, _) = scripted_connection(row_result_packets(3, 0, &[Some(b"7")]), exact_limits);
        assert!(matches!(
            exact
                .query_typed("SELECT exact")
                .expect("exact boundary")
                .rows[0]
                .cells
                .as_slice(),
            [Cell::Signed(7)]
        ));

        let (command_exact, _) = scripted_connection(
            vec![(1, ok_packet(1, 0, 2))],
            TypedResultLimits {
                max_rows: None,
                max_result_bytes: Some(20),
            },
        );
        assert!(command_exact.exec_typed("UPDATE exact").is_ok());

        let (command_limited, closes) = scripted_connection(
            vec![(1, ok_packet(1, 0, 2))],
            TypedResultLimits {
                max_rows: None,
                max_result_bytes: Some(19),
            },
        );
        assert_eq!(
            command_limited
                .exec_typed("UPDATE limited")
                .expect_err("command maximum plus one")
                .class,
            ErrorClass::Limit
        );
        assert_eq!(closes.get(), 1);

        let large_caller = TypedResultLimits {
            max_rows: Some(u32::MAX),
            max_result_bytes: Some(u64::MAX),
        };
        let (large, _) = scripted_connection(row_result_packets(3, 0, &[Some(b"7")]), large_caller);
        assert!(large.query_typed("SELECT bounded").is_ok());
        assert_eq!(
            large.limits, large_caller,
            "caller input grants no new host authority"
        );
    }

    #[test]
    fn invalid_input_is_named_and_does_not_touch_an_open_session() {
        let options =
            |endpoint: &str, username_secret: &str, password_secret: &str| ConnectOptions {
                endpoint: endpoint.to_owned(),
                username_secret: username_secret.to_owned(),
                password_secret: password_secret.to_owned(),
                database: None,
                max_rows: None,
                max_result_bytes: None,
            };
        for (options, name) in [
            (options("", "user", "password"), "endpoint"),
            (options("database", "", "password"), "username-secret"),
            (options("database", "user", ""), "password-secret"),
        ] {
            let error = validate_connect_options(&options).expect_err("invalid required option");
            assert_eq!(error.class, ErrorClass::Invalid);
            assert!(error.message.contains(name));
        }

        let mut packets = row_result_packets(3, 0, &[Some(b"11")]);
        let (connection, closes) =
            scripted_connection(std::mem::take(&mut packets), TypedResultLimits::default());
        let empty = connection.query_typed("").expect_err("empty SQL");
        assert_eq!(empty.class, ErrorClass::Invalid);
        assert!(empty.message.contains("sql"));
        assert_eq!(closes.get(), 0);
        let oversized = connection
            .exec_typed(&"x".repeat(MAX_SQL_BYTES + 1))
            .expect_err("oversized SQL");
        assert_eq!(oversized.class, ErrorClass::Limit);
        assert_eq!(closes.get(), 0, "preflight limit preserves synchronization");
        assert!(matches!(
            connection
                .query_typed("SELECT 11")
                .expect("still open")
                .rows[0]
                .cells
                .as_slice(),
            [Cell::Signed(11)]
        ));
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
            limits: TypedResultLimits::default(),
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
    fn candidate_names_exact_sql_v02_and_requires_a_compatible_sigil() {
        let manifest = include_str!("../plugin.toml");

        assert!(manifest.contains("version = \"0.2.0\""));
        assert!(manifest.contains("entrypoint = \"sigil:sql/driver@0.2.0\""));
        assert!(!manifest.contains("entrypoint = \"sigil:sql/driver@0.1.0\""));
        assert!(manifest.contains("sigil = \">=0.33.1, <1.0.0\""));
        assert!(!manifest.contains("sigil = \">=0.33.0, <1.0.0\""));
    }
}

use std::cmp::Ordering;

pub const MAX_PACKET_PAYLOAD: usize = 1_048_576;
pub const MAX_COLUMNS: usize = 1_024;
pub const MAX_ROWS: usize = 10_000;
pub const MAX_CELLS: usize = 100_000;
pub const MAX_FIELD_BYTES: usize = 1_048_576;
pub const MAX_ROW_BYTES: usize = 1_048_576;
pub const MAX_METADATA_BYTES: usize = 1_048_576;
pub const MAX_CELL_PAYLOAD_BYTES: usize = 8_388_608;
pub const MAX_PACKETS: usize = 100_000;
const MAX_LABEL_BYTES: usize = 1_024;
const MAX_LABEL_SCALARS: usize = 256;
const MAX_ERROR_BYTES: usize = 4_096;
const MAX_ERROR_SCALARS: usize = 1_024;
const MAX_SANITIZED_ERROR_BYTES: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    Transport,
    Timeout,
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerError {
    pub vendor_code: u16,
    pub sqlstate: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Authentication(ServerError),
    Server(ServerError),
    Protocol,
    Encoding,
    Limit,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    Io(IoError),
    Codec(CodecError),
}

fn checked_accumulate(
    current: usize,
    increment: usize,
    maximum: usize,
) -> Result<usize, CodecError> {
    current
        .checked_add(increment)
        .filter(|value| *value <= maximum)
        .ok_or(CodecError::Limit)
}

impl From<CodecError> for QueryError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub server_capabilities: u32,
    pub character_set: u8,
    pub auth_data: Vec<u8>,
    pub auth_plugin: AuthPlugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlugin {
    CachingSha2Password,
    MysqlNativePassword,
}

impl AuthPlugin {
    pub const fn name(self) -> &'static str {
        match self {
            Self::CachingSha2Password => "caching_sha2_password",
            Self::MysqlNativePassword => "mysql_native_password",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResponse {
    Complete,
    FastComplete,
    FullAuthentication,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCell {
    Null,
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedColumnType {
    Null,
    Signed,
    Unsigned,
    Floating,
    Decimal,
    Text,
    Bytes,
    Temporal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedTemporalType {
    Date,
    Time,
    Datetime,
    Timestamp,
    Year,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypedCell {
    Null,
    Signed(i64),
    Unsigned(u64),
    Floating(f64),
    Decimal(String),
    Text(String),
    Bytes(Vec<u8>),
    Temporal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawColumn {
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub original_table: String,
    pub name: String,
    pub original_name: String,
    pub vendor_type: u8,
    pub charset: u16,
    pub collation: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedColumn {
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub original_table: String,
    pub name: String,
    pub original_name: String,
    pub vendor_type: u8,
    pub charset: u16,
    pub collation: u16,
    pub flags: u16,
    pub column_type: TypedColumnType,
    pub temporal_type: Option<TypedTemporalType>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypedRowSet {
    pub columns: Vec<TypedColumn>,
    pub rows: Vec<Vec<TypedCell>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandMetadata {
    pub affected_rows: u64,
    pub last_insert_id: Option<u64>,
    pub warnings: u16,
    pub status_flags: u16,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TypedResultLimits {
    pub max_rows: Option<u32>,
    pub max_result_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypedQueryResult {
    Rows(TypedRowSet),
    Command(CommandMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawQueryResult {
    Rows {
        columns: Vec<RawColumn>,
        rows: Vec<Vec<RawCell>>,
    },
    Command {
        affected_rows: u64,
        last_insert_id: Option<u64>,
        warnings: u16,
        status_flags: u16,
    },
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.offset..).unwrap_or_default()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(count).ok_or(CodecError::Protocol)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::Protocol)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        self.take(1)?.first().copied().ok_or(CodecError::Protocol)
    }

    fn u16_le(&mut self) -> Result<u16, CodecError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| CodecError::Protocol)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u24_le(&mut self) -> Result<usize, CodecError> {
        let bytes = self.take(3)?;
        Ok(usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16))
    }

    fn u32_le(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| CodecError::Protocol)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn nul_bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let relative = self
            .remaining()
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(CodecError::Protocol)?;
        let value = self.take(relative)?;
        self.take(1)?;
        Ok(value)
    }

    fn lenenc(&mut self) -> Result<Option<u64>, CodecError> {
        match self.u8()? {
            value @ 0..=0xfa => Ok(Some(u64::from(value))),
            0xfb => Ok(None),
            0xfc => Ok(Some(u64::from(self.u16_le()?))),
            0xfd => Ok(Some(
                u64::try_from(self.u24_le()?).map_err(|_| CodecError::Limit)?,
            )),
            0xfe => {
                let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| CodecError::Protocol)?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
            0xff => Err(CodecError::Protocol),
        }
    }

    fn lenenc_bytes(&mut self, maximum: usize) -> Result<Option<&'a [u8]>, CodecError> {
        let Some(length) = self.lenenc()? else {
            return Ok(None);
        };
        let length = usize::try_from(length).map_err(|_| CodecError::Limit)?;
        if length > maximum {
            return Err(CodecError::Limit);
        }
        self.take(length).map(Some)
    }
}

pub fn parse_packet_header(header: &[u8]) -> Result<(usize, u8), CodecError> {
    if header.len() != 4 {
        return Err(CodecError::Protocol);
    }
    let mut cursor = Cursor::new(header);
    let payload = cursor.u24_le()?;
    let sequence = cursor.u8()?;
    Ok((payload, sequence))
}

pub fn packet_header(payload_len: usize, sequence: u8) -> Result<[u8; 4], CodecError> {
    if payload_len > MAX_PACKET_PAYLOAD || payload_len > 0x00ff_ffff {
        return Err(CodecError::Limit);
    }
    let length = u32::try_from(payload_len).map_err(|_| CodecError::Limit)?;
    let bytes = length.to_le_bytes();
    Ok([bytes[0], bytes[1], bytes[2], sequence])
}

pub fn parse_handshake(payload: &[u8]) -> Result<Handshake, CodecError> {
    let mut cursor = Cursor::new(payload);
    if cursor.u8()? != 10 {
        return Err(CodecError::Unsupported);
    }
    let _server_version = cursor.nul_bytes()?;
    cursor.take(4)?;
    let first_nonce = cursor.take(8)?;
    if cursor.u8()? != 0 {
        return Err(CodecError::Protocol);
    }
    let lower = u32::from(cursor.u16_le()?);
    if cursor.remaining().is_empty() {
        return Err(CodecError::Unsupported);
    }
    let character_set = cursor.u8()?;
    cursor.take(2)?;
    let upper = u32::from(cursor.u16_le()?);
    let capabilities = lower | (upper << 16);
    let auth_length = usize::from(cursor.u8()?);
    cursor.take(10)?;
    let expected_tail = auth_length.saturating_sub(8).max(13);
    let available_tail = expected_tail.min(cursor.remaining().len());
    let second_nonce = cursor.take(available_tail)?;
    let plugin_bytes = if cursor.remaining().is_empty() {
        &[][..]
    } else {
        cursor.nul_bytes()?
    };
    let mut auth_data = Vec::with_capacity(20);
    auth_data.extend_from_slice(first_nonce);
    auth_data.extend(second_nonce.iter().copied().filter(|byte| *byte != 0));
    auth_data.truncate(20);
    if auth_data.len() != 20 {
        return Err(CodecError::Protocol);
    }
    let auth_plugin = match std::str::from_utf8(plugin_bytes).map_err(|_| CodecError::Encoding)? {
        "caching_sha2_password" => AuthPlugin::CachingSha2Password,
        "mysql_native_password" => AuthPlugin::MysqlNativePassword,
        _ => return Err(CodecError::Unsupported),
    };
    Ok(Handshake {
        server_capabilities: capabilities,
        character_set,
        auth_data,
        auth_plugin,
    })
}

pub fn ssl_request(capabilities: u32, character_set: u8) -> Vec<u8> {
    let mut output = Vec::with_capacity(32);
    output.extend_from_slice(&capabilities.to_le_bytes());
    output.extend_from_slice(&(MAX_PACKET_PAYLOAD as u32).to_le_bytes());
    output.push(character_set);
    output.extend_from_slice(&[0; 23]);
    output
}

pub fn handshake_response(
    capabilities: u32,
    character_set: u8,
    username: &[u8],
    token: &[u8],
    database: Option<&str>,
    auth_plugin: AuthPlugin,
) -> Result<Vec<u8>, CodecError> {
    if username.contains(&0)
        || database.is_some_and(|value| value.as_bytes().contains(&0))
        || token.len() > usize::from(u8::MAX)
    {
        return Err(CodecError::Encoding);
    }
    let capacity = 64_usize
        .checked_add(username.len())
        .and_then(|value| value.checked_add(token.len()))
        .and_then(|value| value.checked_add(database.map_or(0, str::len)))
        .ok_or(CodecError::Limit)?;
    if capacity > MAX_PACKET_PAYLOAD {
        return Err(CodecError::Limit);
    }
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&capabilities.to_le_bytes());
    output.extend_from_slice(&(MAX_PACKET_PAYLOAD as u32).to_le_bytes());
    output.push(character_set);
    output.extend_from_slice(&[0; 23]);
    output.extend_from_slice(username);
    output.push(0);
    output.push(u8::try_from(token.len()).map_err(|_| CodecError::Limit)?);
    output.extend_from_slice(token);
    if let Some(database) = database {
        output.extend_from_slice(database.as_bytes());
        output.push(0);
    }
    if capabilities & 0x0008_0000 != 0 {
        output.extend_from_slice(auth_plugin.name().as_bytes());
        output.push(0);
    }
    Ok(output)
}

const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

fn terminator_status(payload: &[u8]) -> Result<Option<u16>, CodecError> {
    if payload.first() != Some(&0xfe) {
        return Ok(None);
    }
    // In the text protocol, 0xfe begins a row's eight-byte length encoding
    // whenever the packet is at least nine bytes. Treating that row as EOF
    // would silently discard hostile oversized fields as successful output.
    if payload.len() >= 9 {
        return Ok(None);
    }
    if payload.len() == 5 {
        let mut cursor = Cursor::new(payload);
        cursor.take(3)?;
        return cursor.u16_le().map(Some);
    }
    let mut cursor = Cursor::new(payload);
    cursor.take(1)?;
    cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    let status = cursor.u16_le()?;
    cursor.u16_le()?;
    Ok(Some(status))
}

const fn reject_more_results(status: u16) -> Result<(), CodecError> {
    if status & SERVER_MORE_RESULTS_EXISTS != 0 {
        Err(CodecError::Unsupported)
    } else {
        Ok(())
    }
}

fn validate_sqlstate(bytes: &[u8]) -> Result<String, CodecError> {
    if bytes.len() != 5
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_uppercase() && !byte.is_ascii_digit())
    {
        return Err(CodecError::Protocol);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::Protocol)
}

const fn forbidden_scalar(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn safe_label(bytes: &[u8]) -> Result<String, CodecError> {
    if bytes.len() > MAX_LABEL_BYTES {
        return Err(CodecError::Limit);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| CodecError::Encoding)?;
    if value.chars().count() > MAX_LABEL_SCALARS || value.chars().any(forbidden_scalar) {
        return Err(CodecError::Encoding);
    }
    Ok(value.to_owned())
}

fn sanitize_error(bytes: &[u8], secrets: &[(&str, &[u8])]) -> Result<String, CodecError> {
    if bytes.len() > MAX_ERROR_BYTES {
        return Err(CodecError::Limit);
    }
    let mut output = Vec::with_capacity(MAX_SANITIZED_ERROR_BYTES);
    let mut index = 0;
    while index < bytes.len() {
        let matched = secrets
            .iter()
            .filter(|(_name, value)| {
                !value.is_empty()
                    && bytes
                        .get(index..)
                        .is_some_and(|rest| rest.starts_with(value))
            })
            .max_by(
                |(left_name, left), (right_name, right)| match left.len().cmp(&right.len()) {
                    Ordering::Equal => right_name.cmp(left_name),
                    ordering => ordering,
                },
            );
        if let Some((_name, value)) = matched {
            if output
                .len()
                .checked_add(10)
                .is_none_or(|length| length > MAX_SANITIZED_ERROR_BYTES)
            {
                return Err(CodecError::Limit);
            }
            output.extend_from_slice(b"[REDACTED]");
            index = index.checked_add(value.len()).ok_or(CodecError::Limit)?;
        } else {
            if output.len() == MAX_SANITIZED_ERROR_BYTES {
                return Err(CodecError::Limit);
            }
            output.push(bytes[index]);
            index = index.checked_add(1).ok_or(CodecError::Limit)?;
        }
    }
    let value = std::str::from_utf8(&output).map_err(|_| CodecError::Encoding)?;
    if value.chars().count() > MAX_ERROR_SCALARS {
        return Err(CodecError::Limit);
    }
    let mut sanitized = String::with_capacity(MAX_SANITIZED_ERROR_BYTES);
    for character in value.chars() {
        if forbidden_scalar(character) {
            use std::fmt::Write as _;
            if sanitized
                .len()
                .checked_add(8)
                .is_none_or(|length| length > MAX_SANITIZED_ERROR_BYTES)
            {
                return Err(CodecError::Limit);
            }
            write!(&mut sanitized, "\\u{{{:04X}}}", u32::from(character))
                .map_err(|_| CodecError::Limit)?;
        } else {
            if sanitized
                .len()
                .checked_add(character.len_utf8())
                .is_none_or(|length| length > MAX_SANITIZED_ERROR_BYTES)
            {
                return Err(CodecError::Limit);
            }
            sanitized.push(character);
        }
    }
    Ok(sanitized)
}

fn parse_server_error(
    payload: &[u8],
    secrets: &[(&str, &[u8])],
    authentication: bool,
) -> Result<CodecError, CodecError> {
    let mut cursor = Cursor::new(payload);
    if cursor.u8()? != 0xff {
        return Err(CodecError::Protocol);
    }
    let vendor_code = cursor.u16_le()?;
    let sqlstate = if cursor.remaining().first() == Some(&b'#') {
        cursor.take(1)?;
        Some(validate_sqlstate(cursor.take(5)?)?)
    } else {
        None
    };
    let message = sanitize_error(cursor.remaining(), secrets)?;
    let error = ServerError {
        vendor_code,
        sqlstate,
        message,
    };
    Ok(if authentication {
        CodecError::Authentication(error)
    } else {
        CodecError::Server(error)
    })
}

pub fn parse_ok_or_error(
    payload: &[u8],
    secrets: &[(&str, &[u8])],
    authentication: bool,
) -> Result<(), CodecError> {
    match payload.first().copied() {
        Some(0x00) => parse_ok_packet(payload).map(|_metadata| ()),
        Some(0xff) => Err(parse_server_error(payload, secrets, authentication)?),
        _ => Err(CodecError::Protocol),
    }
}

pub fn parse_auth_response(
    payload: &[u8],
    secrets: &[(&str, &[u8])],
    auth_plugin: AuthPlugin,
) -> Result<AuthResponse, CodecError> {
    match payload {
        [0x00, ..] => parse_ok_packet(payload).map(|_metadata| AuthResponse::Complete),
        [0xff, ..] => Err(parse_server_error(payload, secrets, true)?),
        [0x01, 0x03] if auth_plugin == AuthPlugin::CachingSha2Password => {
            Ok(AuthResponse::FastComplete)
        }
        [0x01, 0x04] if auth_plugin == AuthPlugin::CachingSha2Password => {
            Ok(AuthResponse::FullAuthentication)
        }
        [0x01 | 0xfe, ..] => Err(CodecError::Unsupported),
        _ => Err(CodecError::Protocol),
    }
}

pub fn parse_ok_packet(payload: &[u8]) -> Result<CommandMetadata, CodecError> {
    let mut cursor = Cursor::new(payload);
    if cursor.u8()? != 0x00 {
        return Err(CodecError::Protocol);
    }
    let affected_rows = cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    let last_insert_id = cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    let status_flags = cursor.u16_le()?;
    let warnings = cursor.u16_le()?;
    reject_more_results(status_flags)?;
    Ok(CommandMetadata {
        affected_rows,
        last_insert_id: Some(last_insert_id),
        warnings,
        status_flags,
    })
}

#[cfg(test)]
fn parse_ok_affected_rows(payload: &[u8]) -> Result<u64, CodecError> {
    parse_ok_packet(payload).map(|metadata| metadata.affected_rows)
}

fn parse_column(payload: &[u8]) -> Result<RawColumn, CodecError> {
    if payload.len() > MAX_METADATA_BYTES {
        return Err(CodecError::Limit);
    }
    let mut cursor = Cursor::new(payload);
    let catalog = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    let schema = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    let table = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    let original_table = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    let name = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    let original_name = safe_label(
        cursor
            .lenenc_bytes(MAX_LABEL_BYTES)?
            .ok_or(CodecError::Protocol)?,
    )?;
    if cursor.u8()? != 0x0c {
        return Err(CodecError::Protocol);
    }
    let collation = cursor.u16_le()?;
    cursor.u32_le()?;
    let vendor_type = cursor.u8()?;
    let flags = cursor.u16_le()?;
    cursor.take(3)?;
    if !cursor.remaining().is_empty() {
        return Err(CodecError::Protocol);
    }
    Ok(RawColumn {
        catalog,
        schema,
        table,
        original_table,
        name,
        original_name,
        vendor_type,
        charset: collation,
        collation,
        flags,
    })
}

pub const fn supported_utf8_collation(collation: u16) -> bool {
    matches!(collation, 33 | 45 | 46 | 76 | 83 | 192..=247 | 255..=323)
}

const BINARY_FLAG: u16 = 0x0080;
pub const UNSIGNED_FLAG: u16 = 0x0020;

const MYSQL_TYPE_DECIMAL: u8 = 0;
const MYSQL_TYPE_TINY: u8 = 1;
const MYSQL_TYPE_SHORT: u8 = 2;
const MYSQL_TYPE_LONG: u8 = 3;
const MYSQL_TYPE_FLOAT: u8 = 4;
const MYSQL_TYPE_DOUBLE: u8 = 5;
const MYSQL_TYPE_NULL: u8 = 6;
const MYSQL_TYPE_TIMESTAMP: u8 = 7;
const MYSQL_TYPE_LONGLONG: u8 = 8;
const MYSQL_TYPE_INT24: u8 = 9;
const MYSQL_TYPE_DATE: u8 = 10;
const MYSQL_TYPE_TIME: u8 = 11;
const MYSQL_TYPE_DATETIME: u8 = 12;
const MYSQL_TYPE_YEAR: u8 = 13;
const MYSQL_TYPE_VARCHAR: u8 = 15;
const MYSQL_TYPE_BIT: u8 = 16;
const MYSQL_TYPE_TIMESTAMP2: u8 = 17;
const MYSQL_TYPE_DATETIME2: u8 = 18;
const MYSQL_TYPE_TIME2: u8 = 19;
const MYSQL_TYPE_TYPED_ARRAY: u8 = 20;
const MYSQL_TYPE_VECTOR: u8 = 242;
const MYSQL_TYPE_INVALID: u8 = 243;
const MYSQL_TYPE_BOOL: u8 = 244;
const MYSQL_TYPE_JSON: u8 = 245;
const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
const MYSQL_TYPE_ENUM: u8 = 247;
const MYSQL_TYPE_SET: u8 = 248;
const MYSQL_TYPE_TINY_BLOB: u8 = 249;
const MYSQL_TYPE_MEDIUM_BLOB: u8 = 250;
const MYSQL_TYPE_LONG_BLOB: u8 = 251;
const MYSQL_TYPE_BLOB: u8 = 252;
const MYSQL_TYPE_VAR_STRING: u8 = 253;
const MYSQL_TYPE_STRING: u8 = 254;
const MYSQL_TYPE_GEOMETRY: u8 = 255;

const MAX_TYPED_RESULT_BYTES: u64 = (MAX_METADATA_BYTES as u64) + (MAX_CELL_PAYLOAD_BYTES as u64);

const fn column_is_text(column: &RawColumn) -> Result<bool, CodecError> {
    if column.charset != column.collation || column.collation == 0 || column.collation > 323 {
        return Err(CodecError::Protocol);
    }
    Ok(column.flags & BINARY_FLAG == 0
        && column.collation != 63
        && supported_utf8_collation(column.collation))
}

pub fn classify_typed_column(
    column: &RawColumn,
) -> Result<(TypedColumnType, Option<TypedTemporalType>), CodecError> {
    let integer = || {
        if column.flags & UNSIGNED_FLAG == 0 {
            TypedColumnType::Signed
        } else {
            TypedColumnType::Unsigned
        }
    };
    let string = || {
        column_is_text(column).map(|is_text| {
            if is_text {
                TypedColumnType::Text
            } else {
                TypedColumnType::Bytes
            }
        })
    };

    match column.vendor_type {
        MYSQL_TYPE_INVALID => Err(CodecError::Protocol),
        MYSQL_TYPE_TYPED_ARRAY | MYSQL_TYPE_VECTOR | MYSQL_TYPE_BOOL | 14 | 21..=241 => {
            Err(CodecError::Unsupported)
        }
        MYSQL_TYPE_DECIMAL | MYSQL_TYPE_NEWDECIMAL => {
            column_is_text(column)?;
            Ok((TypedColumnType::Decimal, None))
        }
        MYSQL_TYPE_TINY | MYSQL_TYPE_SHORT | MYSQL_TYPE_LONG | MYSQL_TYPE_LONGLONG
        | MYSQL_TYPE_INT24 => {
            column_is_text(column)?;
            Ok((integer(), None))
        }
        MYSQL_TYPE_FLOAT | MYSQL_TYPE_DOUBLE => {
            column_is_text(column)?;
            Ok((TypedColumnType::Floating, None))
        }
        MYSQL_TYPE_NULL => {
            column_is_text(column)?;
            Ok((TypedColumnType::Null, None))
        }
        MYSQL_TYPE_TIMESTAMP | MYSQL_TYPE_TIMESTAMP2 => {
            column_is_text(column)?;
            Ok((
                TypedColumnType::Temporal,
                Some(TypedTemporalType::Timestamp),
            ))
        }
        MYSQL_TYPE_DATE => {
            column_is_text(column)?;
            Ok((TypedColumnType::Temporal, Some(TypedTemporalType::Date)))
        }
        MYSQL_TYPE_TIME | MYSQL_TYPE_TIME2 => {
            column_is_text(column)?;
            Ok((TypedColumnType::Temporal, Some(TypedTemporalType::Time)))
        }
        MYSQL_TYPE_DATETIME | MYSQL_TYPE_DATETIME2 => {
            column_is_text(column)?;
            Ok((TypedColumnType::Temporal, Some(TypedTemporalType::Datetime)))
        }
        MYSQL_TYPE_YEAR => {
            column_is_text(column)?;
            Ok((TypedColumnType::Temporal, Some(TypedTemporalType::Year)))
        }
        MYSQL_TYPE_JSON => {
            column_is_text(column)?;
            Ok((TypedColumnType::Text, None))
        }
        MYSQL_TYPE_VARCHAR
        | MYSQL_TYPE_ENUM
        | MYSQL_TYPE_SET
        | MYSQL_TYPE_TINY_BLOB
        | MYSQL_TYPE_MEDIUM_BLOB
        | MYSQL_TYPE_LONG_BLOB
        | MYSQL_TYPE_BLOB
        | MYSQL_TYPE_VAR_STRING
        | MYSQL_TYPE_STRING => Ok((string()?, None)),
        MYSQL_TYPE_BIT | MYSQL_TYPE_GEOMETRY => {
            column_is_text(column)?;
            Ok((TypedColumnType::Bytes, None))
        }
    }
}

fn raw_cell_bytes(cell: &RawCell) -> Option<&[u8]> {
    match cell {
        RawCell::Null => None,
        RawCell::Text(value) => Some(value.as_bytes()),
        RawCell::Bytes(value) => Some(value),
    }
}

fn integer_grammar(bytes: &[u8], negative_allowed: bool) -> bool {
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    let digits = match first {
        b'+' => rest,
        b'-' if negative_allowed => rest,
        b'0'..=b'9' => bytes,
        _ => return false,
    };
    !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
}

fn finite_number_grammar(bytes: &[u8]) -> bool {
    let bytes = match bytes.first() {
        Some(b'+' | b'-') => &bytes[1..],
        _ => bytes,
    };
    if bytes.is_empty() {
        return false;
    }

    let exponent = bytes.iter().position(|byte| matches!(byte, b'e' | b'E'));
    let (mantissa, exponent) = exponent.map_or((bytes, None), |index| {
        (&bytes[..index], Some(&bytes[index + 1..]))
    });
    if let Some(exponent) = exponent {
        let digits = match exponent.first() {
            Some(b'+' | b'-') => &exponent[1..],
            _ => exponent,
        };
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return false;
        }
    }
    if mantissa.iter().any(|byte| matches!(byte, b'e' | b'E')) {
        return false;
    }

    let mut decimal_points = 0_u8;
    let mut digits = 0_usize;
    for byte in mantissa {
        match byte {
            b'0'..=b'9' => digits += 1,
            b'.' => decimal_points = decimal_points.saturating_add(1),
            _ => return false,
        }
    }
    digits != 0 && decimal_points <= 1
}

fn mantissa_has_nonzero_digit(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .take_while(|byte| !matches!(byte, b'e' | b'E'))
        .any(|byte| matches!(byte, b'1'..=b'9'))
}

fn parse_signed(column: &RawColumn, bytes: &[u8]) -> Result<i64, CodecError> {
    if !integer_grammar(bytes, true) {
        return Err(CodecError::Encoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::Encoding)?;
    let value = text.parse::<i64>().map_err(|_| CodecError::Unsupported)?;
    let (minimum, maximum) = match column.vendor_type {
        MYSQL_TYPE_TINY => (i64::from(i8::MIN), i64::from(i8::MAX)),
        MYSQL_TYPE_SHORT => (i64::from(i16::MIN), i64::from(i16::MAX)),
        MYSQL_TYPE_LONG => (i64::from(i32::MIN), i64::from(i32::MAX)),
        MYSQL_TYPE_INT24 => (-8_388_608, 8_388_607),
        MYSQL_TYPE_LONGLONG => (i64::MIN, i64::MAX),
        _ => return Err(CodecError::Protocol),
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(CodecError::Protocol);
    }
    Ok(value)
}

fn parse_unsigned(column: &RawColumn, bytes: &[u8]) -> Result<u64, CodecError> {
    if !integer_grammar(bytes, false) {
        return Err(CodecError::Encoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::Encoding)?;
    let value = text.parse::<u64>().map_err(|_| CodecError::Unsupported)?;
    let maximum = match column.vendor_type {
        MYSQL_TYPE_TINY => u64::from(u8::MAX),
        MYSQL_TYPE_SHORT => u64::from(u16::MAX),
        MYSQL_TYPE_LONG => u64::from(u32::MAX),
        MYSQL_TYPE_INT24 => 16_777_215,
        MYSQL_TYPE_LONGLONG => u64::MAX,
        _ => return Err(CodecError::Protocol),
    };
    if value > maximum {
        return Err(CodecError::Protocol);
    }
    Ok(value)
}

fn special_float(bytes: &[u8]) -> Option<f64> {
    if bytes.eq_ignore_ascii_case(b"nan") || bytes.eq_ignore_ascii_case(b"+nan") {
        Some(f64::NAN)
    } else if bytes.eq_ignore_ascii_case(b"-nan") {
        Some(-f64::NAN)
    } else if bytes.eq_ignore_ascii_case(b"inf")
        || bytes.eq_ignore_ascii_case(b"+inf")
        || bytes.eq_ignore_ascii_case(b"infinity")
        || bytes.eq_ignore_ascii_case(b"+infinity")
    {
        Some(f64::INFINITY)
    } else if bytes.eq_ignore_ascii_case(b"-inf") || bytes.eq_ignore_ascii_case(b"-infinity") {
        Some(f64::NEG_INFINITY)
    } else {
        None
    }
}

fn parse_floating(column: &RawColumn, bytes: &[u8]) -> Result<f64, CodecError> {
    if let Some(value) = special_float(bytes) {
        return Ok(value);
    }
    if !finite_number_grammar(bytes) {
        return Err(CodecError::Encoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::Encoding)?;
    let value = match column.vendor_type {
        MYSQL_TYPE_FLOAT => f64::from(text.parse::<f32>().map_err(|_| CodecError::Unsupported)?),
        MYSQL_TYPE_DOUBLE => text.parse::<f64>().map_err(|_| CodecError::Unsupported)?,
        _ => return Err(CodecError::Protocol),
    };
    if !value.is_finite() || (value == 0.0 && mantissa_has_nonzero_digit(bytes)) {
        return Err(CodecError::Unsupported);
    }
    Ok(value)
}

fn validate_typed_cell(
    column: &RawColumn,
    column_type: TypedColumnType,
    cell: &RawCell,
) -> Result<u64, CodecError> {
    let Some(bytes) = raw_cell_bytes(cell) else {
        return Ok(0);
    };
    match column_type {
        TypedColumnType::Null => Err(CodecError::Protocol),
        TypedColumnType::Signed => parse_signed(column, bytes).map(|_| 8),
        TypedColumnType::Unsigned => parse_unsigned(column, bytes).map(|_| 8),
        TypedColumnType::Floating => parse_floating(column, bytes).map(|_| 8),
        TypedColumnType::Decimal => {
            if !bytes.is_ascii() || !finite_number_grammar(bytes) {
                return Err(CodecError::Encoding);
            }
            Ok(bytes.len() as u64)
        }
        TypedColumnType::Text | TypedColumnType::Temporal => {
            let value = std::str::from_utf8(bytes).map_err(|_| CodecError::Encoding)?;
            if column_type == TypedColumnType::Temporal && value.is_empty() {
                return Err(CodecError::Encoding);
            }
            Ok(bytes.len() as u64)
        }
        TypedColumnType::Bytes => Ok(bytes.len() as u64),
    }
}

fn decode_typed_cell(
    column: &RawColumn,
    column_type: TypedColumnType,
    cell: RawCell,
) -> Result<TypedCell, CodecError> {
    validate_typed_cell(column, column_type, &cell)?;
    let bytes = match cell {
        RawCell::Null => return Ok(TypedCell::Null),
        RawCell::Text(value) => value.into_bytes(),
        RawCell::Bytes(value) => value,
    };
    match column_type {
        TypedColumnType::Null => Err(CodecError::Protocol),
        TypedColumnType::Signed => parse_signed(column, &bytes).map(TypedCell::Signed),
        TypedColumnType::Unsigned => parse_unsigned(column, &bytes).map(TypedCell::Unsigned),
        TypedColumnType::Floating => parse_floating(column, &bytes).map(TypedCell::Floating),
        TypedColumnType::Decimal => String::from_utf8(bytes)
            .map(TypedCell::Decimal)
            .map_err(|_| CodecError::Encoding),
        TypedColumnType::Text => String::from_utf8(bytes)
            .map(TypedCell::Text)
            .map_err(|_| CodecError::Encoding),
        TypedColumnType::Bytes => Ok(TypedCell::Bytes(bytes)),
        TypedColumnType::Temporal => String::from_utf8(bytes)
            .map(TypedCell::Temporal)
            .map_err(|_| CodecError::Encoding),
    }
}

fn metadata_logical_bytes(column: &RawColumn) -> Result<u64, CodecError> {
    [
        column.catalog.len(),
        column.schema.len(),
        column.table.len(),
        column.original_table.len(),
        column.name.len(),
        column.original_name.len(),
    ]
    .into_iter()
    .try_fold(0_u64, |total, length| {
        total.checked_add(length as u64).ok_or(CodecError::Limit)
    })
}

fn result_byte_ceiling(limits: TypedResultLimits) -> u64 {
    limits
        .max_result_bytes
        .map_or(MAX_TYPED_RESULT_BYTES, |value| {
            value.min(MAX_TYPED_RESULT_BYTES)
        })
}

pub fn decode_typed_result(
    result: RawQueryResult,
    limits: TypedResultLimits,
) -> Result<TypedQueryResult, CodecError> {
    match result {
        RawQueryResult::Command {
            affected_rows,
            last_insert_id,
            warnings,
            status_flags,
        } => {
            let logical_bytes = 12_u64
                .checked_add(if last_insert_id.is_some() { 8 } else { 0 })
                .ok_or(CodecError::Limit)?;
            if logical_bytes > result_byte_ceiling(limits) {
                return Err(CodecError::Limit);
            }
            Ok(TypedQueryResult::Command(CommandMetadata {
                affected_rows,
                last_insert_id,
                warnings,
                status_flags,
            }))
        }
        RawQueryResult::Rows { columns, rows } => {
            let row_ceiling = limits.max_rows.map_or(MAX_ROWS, |value| {
                usize::try_from(value).unwrap_or(usize::MAX).min(MAX_ROWS)
            });
            if rows.len() > row_ceiling {
                return Err(CodecError::Limit);
            }

            let classified: Vec<_> = columns
                .iter()
                .map(classify_typed_column)
                .collect::<Result<_, _>>()?;
            let mut logical_bytes = 0_u64;
            for column in &columns {
                logical_bytes = logical_bytes
                    .checked_add(metadata_logical_bytes(column)?)
                    .ok_or(CodecError::Limit)?;
            }
            for row in &rows {
                if row.len() != columns.len() {
                    return Err(CodecError::Protocol);
                }
                for ((column, cell), (column_type, _temporal_type)) in
                    columns.iter().zip(row).zip(&classified)
                {
                    logical_bytes = logical_bytes
                        .checked_add(validate_typed_cell(column, *column_type, cell)?)
                        .ok_or(CodecError::Limit)?;
                }
            }
            if logical_bytes > result_byte_ceiling(limits) {
                return Err(CodecError::Limit);
            }

            let typed_columns: Vec<_> = columns
                .iter()
                .zip(&classified)
                .map(|(column, (column_type, temporal_type))| TypedColumn {
                    catalog: column.catalog.clone(),
                    schema: column.schema.clone(),
                    table: column.table.clone(),
                    original_table: column.original_table.clone(),
                    name: column.name.clone(),
                    original_name: column.original_name.clone(),
                    vendor_type: column.vendor_type,
                    charset: column.charset,
                    collation: column.collation,
                    flags: column.flags,
                    column_type: *column_type,
                    temporal_type: *temporal_type,
                })
                .collect();
            let typed_rows = rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .zip(columns.iter().zip(&classified))
                        .map(|(cell, (column, (column_type, _temporal_type)))| {
                            decode_typed_cell(column, *column_type, cell)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TypedQueryResult::Rows(TypedRowSet {
                columns: typed_columns,
                rows: typed_rows,
            }))
        }
    }
}

fn parse_row(
    payload: &[u8],
    columns: &[RawColumn],
    maximum_cell_bytes: usize,
) -> Result<(Vec<RawCell>, usize), CodecError> {
    if payload.len() > MAX_ROW_BYTES {
        return Err(CodecError::Limit);
    }
    // Validate every field and the aggregate budget before allocating any
    // returned cell. The second pass performs the exact lossless conversion.
    let mut preflight = Cursor::new(payload);
    let mut cell_bytes = 0_usize;
    for column in columns {
        let Some(value) = preflight.lenenc_bytes(MAX_FIELD_BYTES)? else {
            continue;
        };
        cell_bytes = checked_accumulate(cell_bytes, value.len(), maximum_cell_bytes)?;
        if column_is_text(column)? {
            std::str::from_utf8(value).map_err(|_| CodecError::Encoding)?;
        }
    }
    if !preflight.remaining().is_empty() {
        return Err(CodecError::Protocol);
    }

    let mut cursor = Cursor::new(payload);
    let mut cells = Vec::with_capacity(columns.len());
    for column in columns {
        let Some(value) = cursor.lenenc_bytes(MAX_FIELD_BYTES)? else {
            cells.push(RawCell::Null);
            continue;
        };
        if column_is_text(column)? {
            let text = std::str::from_utf8(value).map_err(|_| CodecError::Encoding)?;
            cells.push(RawCell::Text(text.to_owned()));
        } else {
            cells.push(RawCell::Bytes(value.to_vec()));
        }
    }
    if !cursor.remaining().is_empty() {
        return Err(CodecError::Protocol);
    }
    Ok((cells, cell_bytes))
}

pub fn read_query_result(
    mut read: impl FnMut(u8) -> Result<Vec<u8>, IoError>,
    secrets: &[(&str, &[u8])],
) -> Result<RawQueryResult, QueryError> {
    let mut sequence = 1_u8;
    let mut packets = 1_usize;
    let first = read(sequence).map_err(QueryError::Io)?;
    match first.first().copied() {
        Some(0x00) => {
            let metadata = parse_ok_packet(&first)?;
            return Ok(RawQueryResult::Command {
                affected_rows: metadata.affected_rows,
                last_insert_id: metadata.last_insert_id,
                warnings: metadata.warnings,
                status_flags: metadata.status_flags,
            });
        }
        Some(0xff) => return Err(parse_server_error(&first, secrets, false)?.into()),
        Some(0xfb) => return Err(CodecError::Unsupported.into()),
        None => return Err(CodecError::Protocol.into()),
        _ => {}
    }
    let mut cursor = Cursor::new(&first);
    let column_count = cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    if !cursor.remaining().is_empty() {
        return Err(CodecError::Protocol.into());
    }
    let column_count = usize::try_from(column_count).map_err(|_| CodecError::Limit)?;
    if column_count == 0 || column_count > MAX_COLUMNS {
        return Err(CodecError::Limit.into());
    }
    let mut columns = Vec::with_capacity(column_count);
    let mut metadata_bytes = 0_usize;
    for _ in 0..column_count {
        sequence = sequence.wrapping_add(1);
        packets = checked_accumulate(packets, 1, MAX_PACKETS)?;
        let payload = read(sequence).map_err(QueryError::Io)?;
        metadata_bytes = checked_accumulate(metadata_bytes, payload.len(), MAX_METADATA_BYTES)?;
        columns.push(parse_column(&payload)?);
    }

    sequence = sequence.wrapping_add(1);
    packets = checked_accumulate(packets, 1, MAX_PACKETS)?;
    let mut payload = read(sequence).map_err(QueryError::Io)?;
    if let Some(status) = terminator_status(&payload)? {
        reject_more_results(status)?;
        sequence = sequence.wrapping_add(1);
        packets = checked_accumulate(packets, 1, MAX_PACKETS)?;
        payload = read(sequence).map_err(QueryError::Io)?;
    }

    let mut rows = Vec::new();
    let mut total_cells = 0_usize;
    let mut total_cell_bytes = 0_usize;
    loop {
        if packets > MAX_PACKETS {
            return Err(CodecError::Limit.into());
        }
        if payload.first() == Some(&0xff) {
            return Err(parse_server_error(&payload, secrets, false)?.into());
        }
        if let Some(status) = terminator_status(&payload)? {
            reject_more_results(status)?;
            break;
        }
        if rows.len() >= MAX_ROWS {
            return Err(CodecError::Limit.into());
        }
        let remaining_cell_bytes = MAX_CELL_PAYLOAD_BYTES
            .checked_sub(total_cell_bytes)
            .ok_or(CodecError::Limit)?;
        let (cells, row_cell_bytes) = parse_row(&payload, &columns, remaining_cell_bytes)?;
        total_cells = checked_accumulate(total_cells, cells.len(), MAX_CELLS)?;
        total_cell_bytes =
            checked_accumulate(total_cell_bytes, row_cell_bytes, MAX_CELL_PAYLOAD_BYTES)?;
        rows.push(cells);
        sequence = sequence.wrapping_add(1);
        packets = checked_accumulate(packets, 1, MAX_PACKETS)?;
        payload = read(sequence).map_err(QueryError::Io)?;
    }
    Ok(RawQueryResult::Rows { columns, rows })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn singlestore_0_2_35_greeting() -> Vec<u8> {
        let mut packet = vec![10];
        packet.extend_from_slice(b"5.7.32\0");
        packet.extend_from_slice(&11_u32.to_le_bytes());
        packet.extend_from_slice(b"gve'V,rQ\0");
        packet.extend_from_slice(&0xf7df_u16.to_le_bytes());
        packet.push(33);
        packet.extend_from_slice(&2_u16.to_le_bytes());
        packet.extend_from_slice(&0x801f_u16.to_le_bytes());
        packet.push(21);
        packet.extend_from_slice(&[0; 10]);
        packet.extend_from_slice(b"\"{v/;mYHB8.;\0mysql_native_password\0");
        packet
    }

    fn lenenc(value: &[u8]) -> Vec<u8> {
        let mut result = vec![u8::try_from(value.len()).expect("small fixture")];
        result.extend_from_slice(value);
        result
    }

    #[test]
    fn packet_header_enforces_inclusive_packet_cap() {
        let header = packet_header(MAX_PACKET_PAYLOAD, 9).expect("inclusive maximum");
        assert_eq!(parse_packet_header(&header), Ok((MAX_PACKET_PAYLOAD, 9)));
        assert_eq!(
            packet_header(MAX_PACKET_PAYLOAD + 1, 0),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn exact_singlestore_0_2_35_greeting_selects_native_password() {
        let packet = singlestore_0_2_35_greeting();
        assert_eq!(packet.len(), 74);
        assert_eq!(
            parse_handshake(&packet),
            Ok(Handshake {
                server_capabilities: 0x801f_f7df,
                character_set: 33,
                auth_data: b"gve'V,rQ\"{v/;mYHB8.;".to_vec(),
                auth_plugin: AuthPlugin::MysqlNativePassword,
            })
        );
    }

    #[test]
    fn handshake_response_names_the_selected_plugin_exactly() {
        let capabilities = 0x0008_8a08;
        let native = handshake_response(
            capabilities,
            33,
            b"root",
            &[0x5a; 20],
            Some("app"),
            AuthPlugin::MysqlNativePassword,
        )
        .expect("native response");
        assert!(native.ends_with(b"app\0mysql_native_password\0"));

        let caching = handshake_response(
            capabilities,
            255,
            b"root",
            &[0xa5; 32],
            Some("app"),
            AuthPlugin::CachingSha2Password,
        )
        .expect("caching response");
        assert!(caching.ends_with(b"app\0caching_sha2_password\0"));

        assert_eq!(
            handshake_response(
                capabilities,
                33,
                b"root",
                &[],
                Some("bad\0db"),
                AuthPlugin::MysqlNativePassword,
            ),
            Err(CodecError::Encoding)
        );
    }

    #[test]
    fn every_aggregate_counter_is_inclusive_checked_and_zero_stable() {
        for maximum in [
            MAX_METADATA_BYTES,
            MAX_CELLS,
            MAX_CELL_PAYLOAD_BYTES,
            MAX_PACKETS,
        ] {
            assert_eq!(checked_accumulate(0, 0, maximum), Ok(0));
            assert_eq!(checked_accumulate(0, maximum, maximum), Ok(maximum));
            assert_eq!(
                checked_accumulate(maximum, 1, maximum),
                Err(CodecError::Limit)
            );
            assert_eq!(
                checked_accumulate(usize::MAX, 1, maximum),
                Err(CodecError::Limit)
            );
        }
    }

    #[test]
    fn field_and_decoded_row_payload_bounds_are_independently_exact() {
        let mut maximum_field = vec![0xfd, 0x00, 0x00, 0x10];
        maximum_field.resize(maximum_field.len() + MAX_FIELD_BYTES, b'x');
        let mut cursor = Cursor::new(&maximum_field);
        assert_eq!(
            cursor
                .lenenc_bytes(MAX_FIELD_BYTES)
                .expect("inclusive field maximum")
                .map(<[u8]>::len),
            Some(MAX_FIELD_BYTES)
        );
        let mut oversized_field = Cursor::new(&[0xfd, 0x01, 0x00, 0x10]);
        assert_eq!(
            oversized_field.lenenc_bytes(MAX_FIELD_BYTES),
            Err(CodecError::Limit)
        );

        let row_field_bytes = MAX_ROW_BYTES - 4;
        let length = u32::try_from(row_field_bytes)
            .expect("row length")
            .to_le_bytes();
        let mut maximum_row = vec![0xfd, length[0], length[1], length[2]];
        maximum_row.resize(MAX_ROW_BYTES, b'x');
        let parsed = parse_row(&maximum_row, &[column(63)], MAX_CELL_PAYLOAD_BYTES)
            .expect("inclusive row maximum");
        assert_eq!(
            parsed,
            (
                vec![RawCell::Bytes(vec![b'x'; row_field_bytes])],
                row_field_bytes
            )
        );

        let mut oversized_row = maximum_row;
        oversized_row.push(0);
        assert_eq!(
            parse_row(&oversized_row, &[column(63)], MAX_CELL_PAYLOAD_BYTES),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn sanitizer_uses_longest_then_name_and_escapes_controls() {
        let secrets = [("b", b"abc".as_slice()), ("a", b"abcd".as_slice())];
        assert_eq!(
            sanitize_error(b"xabcdy\n", &secrets),
            Ok("x[REDACTED]y\\u{000A}".to_owned())
        );
        let maximum_controls = vec![b'\n'; MAX_ERROR_SCALARS];
        let sanitized = sanitize_error(&maximum_controls, &[]).expect("inclusive sanitized cap");
        assert_eq!(sanitized.len(), MAX_SANITIZED_ERROR_BYTES);
        assert!(sanitized.bytes().all(|byte| byte.is_ascii()));
        assert_eq!(
            sanitize_error(&vec![b'a'; MAX_ERROR_SCALARS], &[("one-byte", b"a")]),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn labels_sqlstate_and_errors_enforce_every_string_boundary() {
        assert_eq!(safe_label("☃".as_bytes()), Ok("☃".to_owned()));
        let maximum_label = "😀".repeat(MAX_LABEL_SCALARS);
        assert_eq!(maximum_label.len(), MAX_LABEL_BYTES);
        assert_eq!(safe_label(maximum_label.as_bytes()), Ok(maximum_label));
        assert_eq!(
            safe_label("😀".repeat(MAX_LABEL_SCALARS + 1).as_bytes()),
            Err(CodecError::Limit)
        );
        assert_eq!(safe_label(b"line\nfeed"), Err(CodecError::Encoding));
        assert_eq!(safe_label(&[0xff]), Err(CodecError::Encoding));
        assert_eq!(validate_sqlstate(b"HY000"), Ok("HY000".to_owned()));
        assert_eq!(validate_sqlstate(b"hy000"), Err(CodecError::Protocol));
        assert_eq!(validate_sqlstate(b"HY00"), Err(CodecError::Protocol));
        assert_eq!(
            sanitize_error(&vec![b'a'; MAX_ERROR_BYTES], &[]),
            Err(CodecError::Limit)
        );
        assert_eq!(
            sanitize_error(&vec![b'a'; MAX_ERROR_SCALARS], &[]),
            Ok("a".repeat(MAX_ERROR_SCALARS))
        );
        assert_eq!(sanitize_error(&[0xff], &[]), Err(CodecError::Encoding));
    }

    #[test]
    fn authentication_states_and_server_errors_are_closed_and_sanitized() {
        assert_eq!(
            parse_auth_response(
                &[0x00, 0, 0, 0, 0, 0, 0],
                &[],
                AuthPlugin::MysqlNativePassword,
            ),
            Ok(AuthResponse::Complete)
        );
        assert_eq!(
            parse_auth_response(&[0x00], &[], AuthPlugin::MysqlNativePassword),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x03], &[], AuthPlugin::CachingSha2Password),
            Ok(AuthResponse::FastComplete)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x04], &[], AuthPlugin::CachingSha2Password),
            Ok(AuthResponse::FullAuthentication)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x03], &[], AuthPlugin::MysqlNativePassword),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            parse_auth_response(
                b"\xfemysql_native_password\0hostile-switch",
                &[],
                AuthPlugin::MysqlNativePassword,
            ),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x05], &[], AuthPlugin::CachingSha2Password),
            Err(CodecError::Unsupported)
        );

        let mut packet = vec![0xff, 0x15, 0x04, b'#'];
        packet.extend_from_slice(b"28000");
        packet.extend_from_slice(b"bad secret\n");
        assert_eq!(
            parse_auth_response(
                &packet,
                &[("password", b"secret")],
                AuthPlugin::MysqlNativePassword,
            ),
            Err(CodecError::Authentication(ServerError {
                vendor_code: 1045,
                sqlstate: Some("28000".to_owned()),
                message: "bad [REDACTED]\\u{000A}".to_owned(),
            }))
        );
    }

    fn column(collation: u16) -> RawColumn {
        RawColumn {
            catalog: "def".to_owned(),
            schema: String::new(),
            table: String::new(),
            original_table: String::new(),
            name: "x".to_owned(),
            original_name: "x".to_owned(),
            vendor_type: 0xfd,
            charset: collation,
            collation,
            flags: 0,
        }
    }

    fn typed_column(vendor_type: u8, flags: u16, collation: u16) -> RawColumn {
        RawColumn {
            catalog: String::new(),
            schema: String::new(),
            table: String::new(),
            original_table: String::new(),
            name: String::new(),
            original_name: String::new(),
            vendor_type,
            charset: collation,
            collation,
            flags,
        }
    }

    fn typed_cell(
        column: RawColumn,
        cell: RawCell,
    ) -> Result<(TypedColumn, TypedCell), CodecError> {
        let result = decode_typed_result(
            RawQueryResult::Rows {
                columns: vec![column],
                rows: vec![vec![cell]],
            },
            TypedResultLimits::default(),
        )?;
        let TypedQueryResult::Rows(rows) = result else {
            panic!("row input returned command metadata");
        };
        let mut columns = rows.columns.into_iter();
        let mut rows = rows.rows.into_iter();
        let mut cells = rows.next().expect("one row").into_iter();
        Ok((
            columns.next().expect("one column"),
            cells.next().expect("one cell"),
        ))
    }

    fn decimal_lexemes() -> impl Strategy<Value = String> {
        use std::fmt::Write as _;

        (
            any::<bool>(),
            prop::collection::vec(b'0'..=b'9', 1..33),
            prop::option::of(prop::collection::vec(b'0'..=b'9', 0..17)),
            prop::option::of((any::<bool>(), -999_i16..=999)),
        )
            .prop_map(|(negative, integer, fraction, exponent)| {
                let mut value = String::new();
                if negative {
                    value.push('-');
                }
                value.extend(integer.into_iter().map(char::from));
                if let Some(fraction) = fraction {
                    value.push('.');
                    value.extend(fraction.into_iter().map(char::from));
                }
                if let Some((uppercase, exponent)) = exponent {
                    value.push(if uppercase { 'E' } else { 'e' });
                    write!(&mut value, "{exponent:+}").expect("string formatting cannot fail");
                }
                value
            })
    }

    #[test]
    fn typed_numeric_column_mapping_is_metadata_driven() {
        for vendor_type in [
            MYSQL_TYPE_TINY,
            MYSQL_TYPE_SHORT,
            MYSQL_TYPE_LONG,
            MYSQL_TYPE_LONGLONG,
            MYSQL_TYPE_INT24,
        ] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Signed, None))
            );
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, UNSIGNED_FLAG, 63)),
                Ok((TypedColumnType::Unsigned, None))
            );
        }
        for vendor_type in [MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Decimal, None))
            );
        }
        for vendor_type in [MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Floating, None))
            );
        }
        assert_eq!(
            classify_typed_column(&typed_column(MYSQL_TYPE_NULL, 0, 63)),
            Ok((TypedColumnType::Null, None))
        );
        let mut contradictory = typed_column(MYSQL_TYPE_LONG, 0, 63);
        contradictory.charset = 255;
        assert_eq!(
            classify_typed_column(&contradictory),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            classify_typed_column(&typed_column(MYSQL_TYPE_LONG, 0, 0)),
            Err(CodecError::Protocol)
        );
    }

    #[test]
    fn typed_text_temporal_and_unsupported_mapping_is_exhaustive() {
        for (vendor_type, temporal_type) in [
            (MYSQL_TYPE_DATE, TypedTemporalType::Date),
            (MYSQL_TYPE_TIME, TypedTemporalType::Time),
            (MYSQL_TYPE_TIME2, TypedTemporalType::Time),
            (MYSQL_TYPE_DATETIME, TypedTemporalType::Datetime),
            (MYSQL_TYPE_DATETIME2, TypedTemporalType::Datetime),
            (MYSQL_TYPE_TIMESTAMP, TypedTemporalType::Timestamp),
            (MYSQL_TYPE_TIMESTAMP2, TypedTemporalType::Timestamp),
            (MYSQL_TYPE_YEAR, TypedTemporalType::Year),
        ] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Temporal, Some(temporal_type)))
            );
        }
        for vendor_type in [
            MYSQL_TYPE_VARCHAR,
            MYSQL_TYPE_ENUM,
            MYSQL_TYPE_SET,
            MYSQL_TYPE_TINY_BLOB,
            MYSQL_TYPE_MEDIUM_BLOB,
            MYSQL_TYPE_LONG_BLOB,
            MYSQL_TYPE_BLOB,
            MYSQL_TYPE_VAR_STRING,
            MYSQL_TYPE_STRING,
        ] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 255)),
                Ok((TypedColumnType::Text, None))
            );
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, BINARY_FLAG, 255)),
                Ok((TypedColumnType::Bytes, None))
            );
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Bytes, None))
            );
        }
        assert_eq!(
            classify_typed_column(&typed_column(MYSQL_TYPE_JSON, BINARY_FLAG, 46)),
            Ok((TypedColumnType::Text, None))
        );
        for vendor_type in [MYSQL_TYPE_BIT, MYSQL_TYPE_GEOMETRY] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Ok((TypedColumnType::Bytes, None))
            );
        }

        for vendor_type in [14, 20, 21, 100, 241, 242, 244] {
            assert_eq!(
                classify_typed_column(&typed_column(vendor_type, 0, 63)),
                Err(CodecError::Unsupported),
                "vendor type {vendor_type}"
            );
        }
        assert_eq!(
            classify_typed_column(&typed_column(MYSQL_TYPE_INVALID, 0, 63)),
            Err(CodecError::Protocol)
        );
    }

    #[test]
    fn signed_integer_vendor_ranges_and_lexemes_are_exact() {
        for (vendor_type, minimum, maximum) in [
            (MYSQL_TYPE_TINY, i64::from(i8::MIN), i64::from(i8::MAX)),
            (MYSQL_TYPE_SHORT, i64::from(i16::MIN), i64::from(i16::MAX)),
            (MYSQL_TYPE_LONG, i64::from(i32::MIN), i64::from(i32::MAX)),
            (MYSQL_TYPE_INT24, -8_388_608, 8_388_607),
            (MYSQL_TYPE_LONGLONG, i64::MIN, i64::MAX),
        ] {
            for value in [minimum, 0, maximum] {
                let (_, cell) = typed_cell(
                    typed_column(vendor_type, 0, 63),
                    RawCell::Bytes(value.to_string().into_bytes()),
                )
                .expect("signed boundary");
                assert_eq!(cell, TypedCell::Signed(value));
            }
        }
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_TINY, 0, 63),
                RawCell::Bytes(b"128".to_vec()),
            ),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_LONGLONG, 0, 63),
                RawCell::Bytes(b"9223372036854775808".to_vec()),
            ),
            Err(CodecError::Unsupported)
        );
        for (lexeme, expected) in [(b"+0007".as_slice(), 7), (b"-0000", 0)] {
            assert_eq!(
                typed_cell(
                    typed_column(MYSQL_TYPE_LONG, 0, 63),
                    RawCell::Bytes(lexeme.to_vec()),
                )
                .map(|(_column, cell)| cell),
                Ok(TypedCell::Signed(expected))
            );
        }
        for malformed in [b"".as_slice(), b"+", b"--1", b"1 ", b"1.0"] {
            assert_eq!(
                typed_cell(
                    typed_column(MYSQL_TYPE_LONG, 0, 63),
                    RawCell::Bytes(malformed.to_vec()),
                ),
                Err(CodecError::Encoding),
                "lexeme {malformed:?}"
            );
        }
    }

    #[test]
    fn unsigned_integer_vendor_ranges_and_lexemes_are_exact() {
        for (vendor_type, maximum) in [
            (MYSQL_TYPE_TINY, u64::from(u8::MAX)),
            (MYSQL_TYPE_SHORT, u64::from(u16::MAX)),
            (MYSQL_TYPE_LONG, u64::from(u32::MAX)),
            (MYSQL_TYPE_INT24, 16_777_215),
            (MYSQL_TYPE_LONGLONG, u64::MAX),
        ] {
            for value in [0, maximum] {
                let (_, cell) = typed_cell(
                    typed_column(vendor_type, UNSIGNED_FLAG, 63),
                    RawCell::Bytes(value.to_string().into_bytes()),
                )
                .expect("unsigned boundary");
                assert_eq!(cell, TypedCell::Unsigned(value));
            }
        }
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_TINY, UNSIGNED_FLAG, 63),
                RawCell::Bytes(b"256".to_vec()),
            ),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_LONGLONG, UNSIGNED_FLAG, 63),
                RawCell::Bytes(b"18446744073709551616".to_vec()),
            ),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_LONG, UNSIGNED_FLAG, 63),
                RawCell::Bytes(b"+0007".to_vec()),
            )
            .map(|(_column, cell)| cell),
            Ok(TypedCell::Unsigned(7))
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_LONG, UNSIGNED_FLAG, 63),
                RawCell::Bytes(b"-1".to_vec()),
            ),
            Err(CodecError::Encoding)
        );
    }

    #[test]
    fn decimal_and_temporal_values_preserve_wire_lexemes() {
        for lexeme in ["0", "-0.00", "+001.2300", ".5", "1.", "1.20e+003"] {
            let (_, cell) = typed_cell(
                typed_column(MYSQL_TYPE_NEWDECIMAL, 0, 63),
                RawCell::Bytes(lexeme.as_bytes().to_vec()),
            )
            .expect("exact decimal");
            assert_eq!(cell, TypedCell::Decimal(lexeme.to_owned()));
        }
        for malformed in ["", ".", "1e", "NaN", "inf", " 1", "1_0"] {
            assert_eq!(
                typed_cell(
                    typed_column(MYSQL_TYPE_NEWDECIMAL, 0, 63),
                    RawCell::Bytes(malformed.as_bytes().to_vec()),
                ),
                Err(CodecError::Encoding),
                "decimal {malformed:?}"
            );
        }

        let exact = "0000-00-00 01:02:03.004000+99";
        let (column, cell) = typed_cell(
            typed_column(MYSQL_TYPE_TIMESTAMP2, 0, 63),
            RawCell::Bytes(exact.as_bytes().to_vec()),
        )
        .expect("temporal lexeme");
        assert_eq!(column.column_type, TypedColumnType::Temporal);
        assert_eq!(column.temporal_type, Some(TypedTemporalType::Timestamp));
        assert_eq!(cell, TypedCell::Temporal(exact.to_owned()));
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_DATE, 0, 63),
                RawCell::Bytes(Vec::new()),
            ),
            Err(CodecError::Encoding)
        );
    }

    #[test]
    fn floating_policy_accepts_explicit_specials_and_rejects_finite_range_loss() {
        for vendor_type in [MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE] {
            let (_, negative_zero) = typed_cell(
                typed_column(vendor_type, 0, 63),
                RawCell::Bytes(b"-0.0".to_vec()),
            )
            .expect("negative zero");
            let TypedCell::Floating(negative_zero) = negative_zero else {
                panic!("expected floating value");
            };
            assert!(negative_zero.is_sign_negative());

            let (_, infinity) = typed_cell(
                typed_column(vendor_type, 0, 63),
                RawCell::Bytes(b"+Infinity".to_vec()),
            )
            .expect("explicit infinity");
            assert_eq!(infinity, TypedCell::Floating(f64::INFINITY));

            let (_, nan) = typed_cell(
                typed_column(vendor_type, 0, 63),
                RawCell::Bytes(b"NaN".to_vec()),
            )
            .expect("explicit NaN");
            let TypedCell::Floating(nan) = nan else {
                panic!("expected NaN");
            };
            assert!(nan.is_nan());
        }
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_FLOAT, 0, 63),
                RawCell::Bytes(b"1e100".to_vec()),
            ),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_DOUBLE, 0, 63),
                RawCell::Bytes(b"1e9999".to_vec()),
            ),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_FLOAT, 0, 63),
                RawCell::Bytes(b"1e-100".to_vec()),
            ),
            Err(CodecError::Unsupported)
        );
        for malformed in [b"".as_slice(), b".", b"1e", b"1 2", b"nanx"] {
            assert_eq!(
                typed_cell(
                    typed_column(MYSQL_TYPE_DOUBLE, 0, 63),
                    RawCell::Bytes(malformed.to_vec()),
                ),
                Err(CodecError::Encoding)
            );
        }
    }

    #[test]
    fn null_text_and_bytes_are_tagged_without_guessing() {
        assert_eq!(
            typed_cell(typed_column(MYSQL_TYPE_LONG, 0, 63), RawCell::Null,)
                .map(|(_column, cell)| cell),
            Ok(TypedCell::Null)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_NULL, 0, 63),
                RawCell::Bytes(b"not-null".to_vec()),
            ),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_JSON, BINARY_FLAG, 46),
                RawCell::Bytes(br#"{"x":1}"#.to_vec()),
            )
            .map(|(_column, cell)| cell),
            Ok(TypedCell::Text(r#"{"x":1}"#.to_owned()))
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_JSON, BINARY_FLAG, 46),
                RawCell::Bytes(vec![0xff]),
            ),
            Err(CodecError::Encoding)
        );
        assert_eq!(
            typed_cell(
                typed_column(MYSQL_TYPE_VAR_STRING, BINARY_FLAG, 255),
                RawCell::Text("still bytes".to_owned()),
            )
            .map(|(_column, cell)| cell),
            Ok(TypedCell::Bytes(b"still bytes".to_vec()))
        );
    }

    #[test]
    fn typed_conversion_checks_whole_result_before_returning_any_rows() {
        let result = RawQueryResult::Rows {
            columns: vec![typed_column(MYSQL_TYPE_LONG, 0, 63)],
            rows: vec![
                vec![RawCell::Bytes(b"1".to_vec())],
                vec![RawCell::Bytes(b"server-secret".to_vec())],
            ],
        };
        assert_eq!(
            decode_typed_result(result, TypedResultLimits::default()),
            Err(CodecError::Encoding)
        );
        assert_eq!(
            decode_typed_result(
                RawQueryResult::Rows {
                    columns: vec![typed_column(MYSQL_TYPE_LONG, 0, 63)],
                    rows: vec![vec![]],
                },
                TypedResultLimits::default(),
            ),
            Err(CodecError::Protocol)
        );
    }

    #[test]
    fn typed_logical_bounds_are_inclusive_and_never_truncate() {
        let integer = || RawQueryResult::Rows {
            columns: vec![typed_column(MYSQL_TYPE_LONG, 0, 63)],
            rows: vec![vec![RawCell::Bytes(b"1".to_vec())]],
        };
        assert!(
            decode_typed_result(
                integer(),
                TypedResultLimits {
                    max_rows: Some(1),
                    max_result_bytes: Some(8),
                },
            )
            .is_ok()
        );
        for limits in [
            TypedResultLimits {
                max_rows: Some(0),
                max_result_bytes: Some(8),
            },
            TypedResultLimits {
                max_rows: Some(1),
                max_result_bytes: Some(7),
            },
        ] {
            assert_eq!(
                decode_typed_result(integer(), limits),
                Err(CodecError::Limit)
            );
        }

        let command = || RawQueryResult::Command {
            affected_rows: 3,
            last_insert_id: Some(0),
            warnings: 2,
            status_flags: 2,
        };
        assert!(
            decode_typed_result(
                command(),
                TypedResultLimits {
                    max_rows: None,
                    max_result_bytes: Some(20),
                },
            )
            .is_ok()
        );
        assert_eq!(
            decode_typed_result(
                command(),
                TypedResultLimits {
                    max_rows: None,
                    max_result_bytes: Some(19),
                },
            ),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn command_ok_retains_all_metadata_and_rejects_ambiguous_packets() {
        let packet = [0x00, 3, 7, 2, 0, 9, 0];
        assert_eq!(
            parse_ok_packet(&packet),
            Ok(CommandMetadata {
                affected_rows: 3,
                last_insert_id: Some(7),
                warnings: 9,
                status_flags: 2,
            })
        );
        assert_eq!(
            read_query_result(|_sequence| Ok(packet.to_vec()), &[]),
            Ok(RawQueryResult::Command {
                affected_rows: 3,
                last_insert_id: Some(7),
                warnings: 9,
                status_flags: 2,
            })
        );
        assert_eq!(
            parse_ok_packet(&[0xff, 0, 0, 0, 0, 0, 0]),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            parse_ok_packet(&[0x00, 0xfb, 0, 0, 0, 0, 0]),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            parse_ok_packet(&[0x00, 0, 0, 8, 0, 0, 0]),
            Err(CodecError::Unsupported)
        );
    }

    #[test]
    fn supported_invalid_utf8_is_encoding_and_binary_is_exact() {
        assert_eq!(
            parse_row(&[1, 0xff], &[column(255)], MAX_CELL_PAYLOAD_BYTES),
            Err(CodecError::Encoding)
        );
        assert_eq!(
            parse_row(&[1, 0xff], &[column(63)], MAX_CELL_PAYLOAD_BYTES),
            Ok((vec![RawCell::Bytes(vec![0xff])], 1))
        );
        let mut flagged = column(255);
        flagged.flags = BINARY_FLAG;
        assert_eq!(
            parse_row(&[1, 0xff], &[flagged], MAX_CELL_PAYLOAD_BYTES),
            Ok((vec![RawCell::Bytes(vec![0xff])], 1))
        );
        assert_eq!(
            parse_row(&[0], &[column(0)], MAX_CELL_PAYLOAD_BYTES),
            Err(CodecError::Protocol)
        );
        assert_eq!(
            parse_row(&[0], &[column(u16::MAX)], MAX_CELL_PAYLOAD_BYTES),
            Err(CodecError::Protocol)
        );
    }

    #[test]
    fn row_result_preserves_null_text_and_bytes() {
        let mut column_text = Vec::new();
        for value in [b"def".as_slice(), b"s", b"t", b"t", b"a", b"a"] {
            column_text.extend(lenenc(value));
        }
        column_text.extend([0x0c, 0xff, 0x00, 16, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
        let mut column_binary = Vec::new();
        for value in [b"def".as_slice(), b"s", b"t", b"t", b"b", b"b"] {
            column_binary.extend(lenenc(value));
        }
        column_binary.extend([0x0c, 63, 0, 16, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
        let packets = [
            vec![2],
            column_text,
            column_binary,
            vec![0xfe, 0, 0, 0, 0],
            vec![1, b'x', 0xfb],
            vec![0xfe, 0, 0, 0, 0],
        ];
        let mut index = 0;
        let result = read_query_result(
            |_sequence| {
                let value = packets.get(index).cloned().ok_or(IoError::Transport)?;
                index += 1;
                Ok(value)
            },
            &[],
        );
        let expected = RawQueryResult::Rows {
            columns: vec![
                parse_column(&packets[1]).expect("text"),
                parse_column(&packets[2]).expect("binary"),
            ],
            rows: vec![vec![RawCell::Text("x".to_owned()), RawCell::Null]],
        };
        assert_eq!(result, Ok(expected));
    }

    #[test]
    fn row_limit_is_inclusive_and_maximum_plus_one_has_no_partial_result() {
        fn run(row_count: usize) -> Result<RawQueryResult, QueryError> {
            let column = {
                let mut packet = Vec::new();
                for value in [b"def".as_slice(), b"", b"", b"", b"x", b"x"] {
                    packet.extend(lenenc(value));
                }
                packet.extend([0x0c, 0xff, 0x00, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0]);
                packet
            };
            let mut reads = 0_usize;
            read_query_result(
                |_sequence| {
                    let payload = match reads {
                        0 => vec![1],
                        1 => column.clone(),
                        2 => vec![0xfe, 0, 0, 0, 0],
                        index if index < row_count + 3 => vec![0],
                        _ => vec![0xfe, 0, 0, 0, 0],
                    };
                    reads += 1;
                    Ok(payload)
                },
                &[],
            )
        }

        let result = run(MAX_ROWS).expect("inclusive row maximum");
        let RawQueryResult::Rows { rows, .. } = result else {
            panic!("row fixture returned command result");
        };
        assert_eq!(rows.len(), MAX_ROWS);
        assert_eq!(run(MAX_ROWS + 1), Err(CodecError::Limit.into()));
    }

    #[test]
    fn local_infile_io_failures_and_server_errors_have_exact_classes() {
        assert_eq!(
            read_query_result(|_sequence| Ok(vec![0xfb]), &[]),
            Err(CodecError::Unsupported.into())
        );
        for (io, expected) in [
            (IoError::Transport, QueryError::Io(IoError::Transport)),
            (IoError::Timeout, QueryError::Io(IoError::Timeout)),
            (IoError::Limit, QueryError::Io(IoError::Limit)),
        ] {
            assert_eq!(read_query_result(|_sequence| Err(io), &[]), Err(expected));
        }
        let mut server = vec![0xff, 0xd2, 0x04, b'#'];
        server.extend_from_slice(b"HY000server refused");
        assert_eq!(
            read_query_result(|_sequence| Ok(server.clone()), &[]),
            Err(CodecError::Server(ServerError {
                vendor_code: 1234,
                sqlstate: Some("HY000".to_owned()),
                message: "server refused".to_owned(),
            })
            .into())
        );
    }

    #[test]
    fn command_and_row_terminators_reject_additional_results() {
        assert_eq!(parse_ok_affected_rows(&[0x00, 3, 0, 0, 0, 0, 0]), Ok(3));
        assert_eq!(
            parse_ok_affected_rows(&[0x00, 3, 0, 8, 0, 0, 0]),
            Err(CodecError::Unsupported)
        );
        assert_eq!(terminator_status(&[0xfe, 0, 0, 0, 0]), Ok(Some(0)));
        assert_eq!(
            terminator_status(&[0xfe, 0, 0, 8, 0]),
            Ok(Some(SERVER_MORE_RESULTS_EXISTS))
        );
        assert_eq!(terminator_status(&[0xfe, 0, 0, 0, 0, 0, 0]), Ok(Some(0)));
        let oversized_lenenc_row = [0xfe, 1, 0, 16, 0, 0, 0, 0, 0];
        assert_eq!(terminator_status(&oversized_lenenc_row), Ok(None));
        assert_eq!(
            parse_row(&oversized_lenenc_row, &[column(63)], MAX_CELL_PAYLOAD_BYTES),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn every_truncation_of_command_ok_fails_closed() {
        let packet = [0x00, 3, 0, 0, 0, 0, 0];
        for end in 0..packet.len() {
            assert_eq!(
                parse_ok_affected_rows(packet.get(..end).expect("prefix")),
                Err(CodecError::Protocol),
                "prefix length {end}"
            );
        }
    }

    #[test]
    fn inclusive_column_limit_fails_before_column_reads() {
        let within = vec![0xfc, 0x00, 0x04];
        let mut reads = 0;
        let result = read_query_result(
            |_sequence| {
                reads += 1;
                Ok(within.clone())
            },
            &[],
        );
        assert_ne!(result, Err(CodecError::Limit.into()));
        assert!(reads > 1, "the inclusive column count proceeds to metadata");

        let above = vec![0xfc, 0x01, 0x04];
        reads = 0;
        assert_eq!(
            read_query_result(
                |_sequence| {
                    reads += 1;
                    Ok(above.clone())
                },
                &[],
            ),
            Err(CodecError::Limit.into())
        );
        assert_eq!(reads, 1, "above-max columns fail before metadata reads");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn hostile_protocol_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let _ = parse_packet_header(&bytes);
            let _ = parse_handshake(&bytes);
            let _ = parse_ok_or_error(&bytes, &[], false);
            let _ = parse_auth_response(&bytes, &[], AuthPlugin::CachingSha2Password);
            let _ = parse_auth_response(&bytes, &[], AuthPlugin::MysqlNativePassword);
            let _ = parse_ok_affected_rows(&bytes);
            let _ = parse_ok_packet(&bytes);
            let _ = parse_column(&bytes);
            let _ = parse_row(&bytes, &[column(255)], MAX_CELL_PAYLOAD_BYTES);
            let _ = terminator_status(&bytes);
        }

        #[test]
        fn signed_longlong_roundtrips_every_i64(value in any::<i64>()) {
            let decoded = typed_cell(
                typed_column(MYSQL_TYPE_LONGLONG, 0, 63),
                RawCell::Bytes(value.to_string().into_bytes()),
            );
            prop_assert_eq!(
                decoded.map(|(_column, cell)| cell),
                Ok(TypedCell::Signed(value))
            );
        }

        #[test]
        fn unsigned_longlong_roundtrips_every_u64(value in any::<u64>()) {
            let decoded = typed_cell(
                typed_column(MYSQL_TYPE_LONGLONG, UNSIGNED_FLAG, 63),
                RawCell::Bytes(value.to_string().into_bytes()),
            );
            prop_assert_eq!(
                decoded.map(|(_column, cell)| cell),
                Ok(TypedCell::Unsigned(value))
            );
        }

        #[test]
        fn decimal_property_preserves_every_accepted_lexeme(lexeme in decimal_lexemes()) {
            let decoded = typed_cell(
                typed_column(MYSQL_TYPE_NEWDECIMAL, 0, 63),
                RawCell::Bytes(lexeme.as_bytes().to_vec()),
            );
            prop_assert_eq!(
                decoded.map(|(_column, cell)| cell),
                Ok(TypedCell::Decimal(lexeme))
            );
        }

        #[test]
        fn hostile_typed_metadata_and_values_never_panic(
            vendor_type in any::<u8>(),
            flags in any::<u16>(),
            charset in any::<u16>(),
            collation in any::<u16>(),
            bytes in prop::collection::vec(any::<u8>(), 0..256),
            use_null in any::<bool>(),
        ) {
            let mut column = typed_column(vendor_type, flags, collation);
            column.charset = charset;
            let cell = if use_null {
                RawCell::Null
            } else {
                RawCell::Bytes(bytes)
            };
            let _ = decode_typed_result(
                RawQueryResult::Rows {
                    columns: vec![column],
                    rows: vec![vec![cell]],
                },
                TypedResultLimits::default(),
            );
        }

        #[test]
        fn every_handshake_truncation_fails_closed(cut in 0usize..64) {
            let mut packet = vec![10];
            packet.extend_from_slice(b"8.4.0\0");
            packet.extend_from_slice(&1_u32.to_le_bytes());
            packet.extend_from_slice(b"12345678\0");
            packet.extend_from_slice(&0xffff_u16.to_le_bytes());
            packet.push(45);
            packet.extend_from_slice(&2_u16.to_le_bytes());
            packet.extend_from_slice(&0xffff_u16.to_le_bytes());
            packet.push(21);
            packet.extend_from_slice(&[0; 10]);
            packet.extend_from_slice(b"abcdefghijkl\0caching_sha2_password\0");
            let end = cut.min(packet.len().saturating_sub(1));
            prop_assert!(parse_handshake(packet.get(..end).expect("prefix")).is_err());
        }
    }
}

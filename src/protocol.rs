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
    pub auth_plugin: String,
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
pub enum RawQueryResult {
    Rows {
        columns: Vec<RawColumn>,
        rows: Vec<Vec<RawCell>>,
    },
    Command {
        affected_rows: u64,
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
    let auth_plugin = std::str::from_utf8(plugin_bytes)
        .map_err(|_| CodecError::Encoding)?
        .to_owned();
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
) -> Result<Vec<u8>, CodecError> {
    if username.contains(&0) || token.len() > usize::from(u8::MAX) {
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
        output.extend_from_slice(b"caching_sha2_password\0");
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
        Some(0x00) => parse_ok_affected_rows(payload).map(|_affected_rows| ()),
        Some(0xff) => Err(parse_server_error(payload, secrets, authentication)?),
        _ => Err(CodecError::Protocol),
    }
}

pub fn parse_auth_response(
    payload: &[u8],
    secrets: &[(&str, &[u8])],
) -> Result<AuthResponse, CodecError> {
    match payload {
        [0x00, ..] => parse_ok_affected_rows(payload).map(|_affected_rows| AuthResponse::Complete),
        [0xff, ..] => Err(parse_server_error(payload, secrets, true)?),
        [0x01, 0x03] => Ok(AuthResponse::FastComplete),
        [0x01, 0x04] => Ok(AuthResponse::FullAuthentication),
        [0xfe, ..] => Err(CodecError::Unsupported),
        _ => Err(CodecError::Protocol),
    }
}

fn parse_ok_affected_rows(payload: &[u8]) -> Result<u64, CodecError> {
    let mut cursor = Cursor::new(payload);
    if cursor.u8()? != 0x00 {
        return Err(CodecError::Protocol);
    }
    let affected_rows = cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    cursor.lenenc()?.ok_or(CodecError::Protocol)?;
    let status = cursor.u16_le()?;
    cursor.u16_le()?;
    reject_more_results(status)?;
    Ok(affected_rows)
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

const fn column_is_text(column: &RawColumn) -> Result<bool, CodecError> {
    if column.collation == 0 || column.collation > 323 {
        return Err(CodecError::Protocol);
    }
    Ok(column.flags & BINARY_FLAG == 0
        && column.collation != 63
        && supported_utf8_collation(column.collation))
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
            return Ok(RawQueryResult::Command {
                affected_rows: parse_ok_affected_rows(&first)?,
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
            parse_auth_response(&[0x00, 0, 0, 0, 0, 0, 0], &[]),
            Ok(AuthResponse::Complete)
        );
        assert_eq!(parse_auth_response(&[0x00], &[]), Err(CodecError::Protocol));
        assert_eq!(
            parse_auth_response(&[0x01, 0x03], &[]),
            Ok(AuthResponse::FastComplete)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x04], &[]),
            Ok(AuthResponse::FullAuthentication)
        );
        assert_eq!(
            parse_auth_response(&[0xfe, 0], &[]),
            Err(CodecError::Unsupported)
        );
        assert_eq!(
            parse_auth_response(&[0x01, 0x05], &[]),
            Err(CodecError::Protocol)
        );

        let mut packet = vec![0xff, 0x15, 0x04, b'#'];
        packet.extend_from_slice(b"28000");
        packet.extend_from_slice(b"bad secret\n");
        assert_eq!(
            parse_auth_response(&packet, &[("password", b"secret")]),
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
            let _ = parse_auth_response(&bytes, &[]);
            let _ = parse_ok_affected_rows(&bytes);
            let _ = parse_column(&bytes);
            let _ = parse_row(&bytes, &[column(255)], MAX_CELL_PAYLOAD_BYTES);
            let _ = terminator_status(&bytes);
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
            if let Ok(handshake) = parse_handshake(packet.get(..end).expect("prefix")) {
                prop_assert_ne!(handshake.auth_plugin, "caching_sha2_password");
            }
        }
    }
}

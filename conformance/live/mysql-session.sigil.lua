local function connect(mysql, password_secret, limits)
  limits = limits or {}
  local connection, err = mysql.connect({
    endpoint = "database",
    ["username-secret"] = "MYSQL_USER",
    ["password-secret"] = password_secret,
    database = "app",
    ["max-rows"] = limits.max_rows,
    ["max-result-bytes"] = limits.max_result_bytes,
  })
  return connection, err
end

local function expect_cell(cell, tag, value)
  expect(cell.tag == tag)
  if tag == "unsigned" and type(value) == "string" then
    expect(tostring(cell.value) == value)
  else
    expect(cell.value == value)
  end
end

return {
  title = "Live MySQL dialect is typed, stateful, bounded, and fail-closed",
  priority = "P0",
  budget = { max_seconds = 30 },
  policy = { capabilities = { "wasm.mysql" } },

  run = function()
    local mysql = require("wasm.mysql")
    local dialect = sigil.env("MYSQL_DIALECT")
    expect(dialect == "singlestore" or dialect == "mysql84")

    local rejected, auth_err = connect(mysql, "MYSQL_BAD_PASSWORD")
    expect(rejected == nil)
    if dialect == "mysql84" then
      -- The lane-less route is intentionally plaintext. A wrong
      -- caching_sha2_password token requests full authentication, which this
      -- driver must refuse rather than transmit a password without TLS.
      expect(auth_err.class == "unsupported")
      expect(auth_err["vendor-code"] == nil)
      expect(auth_err.sqlstate == nil)
    else
      expect(auth_err.class == "authentication")
      expect(auth_err["vendor-code"] == 1045)
      expect(auth_err.sqlstate == "28000")
    end

    local session, connect_err = connect(mysql, "MYSQL_PASSWORD")
    expect(session ~= nil, connect_err and connect_err.message)

    local selected_database, database_err = session:query("SELECT DATABASE()")
    expect(selected_database ~= nil, database_err and database_err.message)
    expect_cell(selected_database.rows[1].cells[1], "text", "app")

    local created, create_err = session:exec([[
      CREATE TEMPORARY TABLE sigil_acceptance (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        signed_value BIGINT,
        unsigned_value BIGINT UNSIGNED,
        decimal_value DECIMAL(30,6),
        float_value DOUBLE,
        null_value BIGINT NULL,
        text_value VARCHAR(64),
        bytes_value VARBINARY(3),
        ts_value DATETIME(6)
      )
    ]])
    expect(created ~= nil, create_err and create_err.message)
    expect(created["affected-rows"] == 0)
    expect(created["last-insert-id"] == 0)
    expect(created.warnings == 0)

    local inserted, insert_err = session:exec([[
      INSERT INTO sigil_acceptance
        (signed_value, unsigned_value, decimal_value, float_value,
         null_value, text_value, bytes_value, ts_value)
      VALUES
        (-9223372036854775808, 18446744073709551615,
         12345678901234567890.123400, 1.25,
         NULL, 'snowman ☃', _binary 0x00ff80,
         '2026-08-30 12:34:56.000001')
    ]])
    expect(inserted ~= nil, insert_err and insert_err.message)
    expect(inserted["affected-rows"] == 1)
    expect(inserted["last-insert-id"] == 1)
    expect(inserted.warnings == 0)

    local rows, rows_err = session:query([[
      SELECT signed_value, unsigned_value, decimal_value, float_value,
             null_value, text_value, bytes_value, ts_value,
             UNIX_TIMESTAMP('2026-08-30 12:34:56') AS epoch_seconds
      FROM sigil_acceptance
    ]])
    expect(rows ~= nil, rows_err and rows_err.message)
    expect(#rows.columns == 9)
    expect(#rows.rows == 1)
    expect(#rows.rows[1].cells == 9)
    expect_cell(rows.rows[1].cells[1], "signed", -9223372036854775807 - 1)
    expect_cell(rows.rows[1].cells[2], "unsigned", "18446744073709551615")
    expect_cell(rows.rows[1].cells[3], "decimal", "12345678901234567890.123400")
    expect_cell(rows.rows[1].cells[4], "floating", 1.25)
    expect_cell(rows.rows[1].cells[5], "null", nil)
    expect_cell(rows.rows[1].cells[6], "text", "snowman ☃")
    expect(rows.rows[1].cells[7].tag == "bytes")
    local b1, b2, b3 = string.byte(rows.rows[1].cells[7].value, 1, 3)
    expect(b1 == 0 and b2 == 255 and b3 == 128)
    expect_cell(rows.rows[1].cells[8], "temporal", "2026-08-30 12:34:56.000001")
    expect(rows.columns[8].type == "temporal")
    expect(rows.columns[8]["temporal-type"] == "datetime")
    expect(rows.rows[1].cells[9].value == 1788093296)
    expect(tostring(rows.rows[1].cells[9].value):match("^%d%d%d%d%d%d%d%d%d%d$") ~= nil)

    local warning_table, warning_table_err = session:exec(
      "CREATE TEMPORARY TABLE sigil_warning(value VARCHAR(3))"
    )
    expect(warning_table ~= nil, warning_table_err and warning_table_err.message)
    local warned, warned_err = session:exec(
      "INSERT IGNORE INTO sigil_warning(value) VALUES ('toolong')"
    )
    expect(warned ~= nil, warned_err and warned_err.message)
    expect(warned["affected-rows"] == 1)
    if dialect == "mysql84" then
      expect(warned.warnings == 1)
    else
      expect(warned.warnings == 0)
    end

    local duplicate, duplicate_err = session:exec([[
      INSERT INTO sigil_acceptance
        (id, signed_value, unsigned_value, decimal_value, float_value,
         null_value, text_value, bytes_value, ts_value)
      VALUES
        (1, 0, 0, 0, 0, NULL, 'duplicate', _binary 0x000000,
         '2026-08-30 12:34:56')
    ]])
    expect(duplicate == nil)
    expect(duplicate_err.class == "server")
    expect(duplicate_err["vendor-code"] == 1062)
    expect(duplicate_err.sqlstate == "23000")

    local after_server, after_server_err = session:query(
      "SELECT signed_value FROM sigil_acceptance"
    )
    expect(after_server ~= nil, after_server_err and after_server_err.message)
    expect(after_server.rows[1].cells[1].value == -9223372036854775807 - 1)

    local delayed, delayed_err = session:query("SELECT SLEEP(2), 7")
    expect(delayed ~= nil, delayed_err and delayed_err.message)
    expect(delayed.rows[1].cells[2].value == 7)

    session:close()
    session:close()

    local fresh, fresh_err = connect(mysql, "MYSQL_PASSWORD")
    expect(fresh ~= nil, fresh_err and fresh_err.message)
    local leaked, leaked_err = fresh:query("SELECT signed_value FROM sigil_acceptance")
    expect(leaked == nil)
    expect(leaked_err.class == "server")
    fresh:close()

    local row_limited, row_connect_err = connect(mysql, "MYSQL_PASSWORD", { max_rows = 1 })
    expect(row_limited ~= nil, row_connect_err and row_connect_err.message)
    local partial_rows, row_limit_err = row_limited:query("SELECT 1 UNION ALL SELECT 2")
    expect(partial_rows == nil)
    expect(row_limit_err.class == "limit")
    local row_after, row_closed = row_limited:query("SELECT 3")
    expect(row_after == nil)
    expect(row_closed.class == "closed")
    row_limited:close()

    local byte_limited, byte_connect_err = connect(
      mysql,
      "MYSQL_PASSWORD",
      { max_result_bytes = 7 }
    )
    expect(byte_limited ~= nil, byte_connect_err and byte_connect_err.message)
    local partial_bytes, byte_limit_err = byte_limited:query("SELECT 1")
    expect(partial_bytes == nil)
    expect(byte_limit_err.class == "limit")
    local byte_after, byte_closed = byte_limited:exec("DO 1")
    expect(byte_after == nil)
    expect(byte_closed.class == "closed")
    byte_limited:close()

    local fixed_limited, fixed_connect_err = connect(
      mysql,
      "MYSQL_PASSWORD",
      { max_rows = 4294967295, max_result_bytes = 33554432 }
    )
    expect(fixed_limited ~= nil, fixed_connect_err and fixed_connect_err.message)
    local oversized, fixed_limit_err = fixed_limited:query("SELECT LPAD('', 1048576, 'x')")
    expect(oversized == nil)
    expect(fixed_limit_err.class == "limit")
    local fixed_after, fixed_closed = fixed_limited:query("SELECT 4")
    expect(fixed_after == nil)
    expect(fixed_closed.class == "closed")
    fixed_limited:close()
  end,
}

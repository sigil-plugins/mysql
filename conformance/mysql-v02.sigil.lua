local function connect(mysql, max_rows, max_result_bytes)
  local connection, err = mysql.connect({
    endpoint = "database",
    ["username-secret"] = "MYSQL_USER",
    ["password-secret"] = "MYSQL_PASSWORD",
    database = "app",
    ["max-rows"] = max_rows,
    ["max-result-bytes"] = max_result_bytes,
  })
  expect(connection ~= nil, err and err.message)
  return connection
end

return {
  title = "MySQL 0.2 keeps one typed, fail-closed session",
  priority = "P0",
  policy = { capabilities = { "wasm.mysql" } },

  run = function()
    local mysql = require("wasm.mysql")
    local session = connect(mysql)

    local created, create_err = session:exec("CREATE TEMPORARY TABLE conformance(value BIGINT)")
    expect(created ~= nil, create_err and create_err.message)
    expect(created["affected-rows"] == 0)
    expect(created["last-insert-id"] == 0)
    expect(created.warnings == 0)

    local inserted, insert_err = session:exec("INSERT INTO conformance VALUES (7)")
    expect(inserted ~= nil, insert_err and insert_err.message)
    expect(inserted["affected-rows"] == 1)
    expect(inserted["last-insert-id"] == 0)
    expect(inserted.warnings == 2)

    local rows, rows_err = session:query("SELECT typed FROM conformance")
    expect(rows ~= nil, rows_err and rows_err.message)
    expect(#rows.columns == 8)
    expect(#rows.rows == 1)
    expect(#rows.rows[1].cells == #rows.columns)
    expect(rows.rows[1].cells[1].tag == "null")
    expect(rows.rows[1].cells[1].value == nil)
    expect(rows.rows[1].cells[2].value == -9223372036854775807 - 1)
    expect(type(rows.rows[1].cells[3].value) == "userdata")
    expect(tostring(rows.rows[1].cells[3].value) == "18446744073709551615")
    expect(1 / rows.rows[1].cells[4].value == -math.huge)
    expect(rows.rows[1].cells[5].value == "001.2300")
    expect(rows.rows[1].cells[6].value == "snowman ☃")
    local b1, b2, b3 = string.byte(rows.rows[1].cells[7].value, 1, 3)
    expect(b1 == 0 and b2 == 255 and b3 == 128)
    expect(rows.rows[1].cells[8].value == "2026-08-30 12:34:56.000001")
    expect(rows.columns[8].type == "temporal")
    expect(rows.columns[8]["temporal-type"] == "timestamp")

    local wrong_query, wrong_query_err = session:query("UPDATE fixture")
    expect(wrong_query == nil)
    expect(wrong_query_err.class == "unsupported")
    local wrong_exec, wrong_exec_err = session:exec("SELECT value FROM conformance")
    expect(wrong_exec == nil)
    expect(wrong_exec_err.class == "unsupported")

    local server_result, server_err = session:query("ERROR server")
    expect(server_result == nil)
    expect(server_err.class == "server")
    expect(server_err["vendor-code"] == 1201)
    expect(server_err.sqlstate == "HY000")
    local after_server, after_server_err = session:query("SELECT value FROM conformance")
    expect(after_server ~= nil, after_server_err and after_server_err.message)
    expect(after_server.rows[1].cells[1].value == 7)
    session:close()
    session:close()

    local limited = connect(mysql, 0)
    local limited_rows, limit_err = limited:query("SELECT value FROM conformance")
    expect(limited_rows == nil)
    expect(limit_err.class == "limit")
    local after_limit, closed_err = limited:query("SELECT value FROM conformance")
    expect(after_limit == nil)
    expect(closed_err.class == "closed")
    limited:close()
  end,
}

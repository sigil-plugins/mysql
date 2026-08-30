local function connect(mysql)
  local connection, err = mysql.connect({
    endpoint = "database",
    ["username-secret"] = "MYSQL_USER",
    ["password-secret"] = "MYSQL_PASSWORD",
    database = "app",
  })
  expect(connection ~= nil, err and err.message)
  return connection
end

local function expect_terminal(connection, statement, expected_class)
  local rows, err = connection:query(statement)
  expect(rows == nil)
  expect(err.class == expected_class)
  local after, closed = connection:query("SELECT must_not_replay")
  expect(after == nil)
  expect(closed.class == "closed")
  connection:close()
  connection:close()
end

return {
  title = "Malformed MySQL results fail closed without partial values",
  priority = "P0",
  policy = { capabilities = { "wasm.mysql" } },

  run = function()
    local mysql = require("wasm.mysql")
    expect_terminal(connect(mysql), "SELECT malformed_metadata", "protocol")
    expect_terminal(connect(mysql), "SELECT invalid_integer", "encoding")
    expect_terminal(connect(mysql), "SELECT integer_overflow", "protocol")
    expect_terminal(connect(mysql), "SELECT oversized_packet", "limit")
  end,
}

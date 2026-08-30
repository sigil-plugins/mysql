return {
  title = "Operator I/O deadline is timeout and closes the session",
  priority = "P0",
  budget = { max_seconds = 10 },
  policy = { capabilities = { "wasm.mysql" } },

  run = function()
    local mysql = require("wasm.mysql")
    local connection, connect_err = mysql.connect({
      endpoint = "database",
      ["username-secret"] = "MYSQL_USER",
      ["password-secret"] = "MYSQL_PASSWORD",
      database = "app",
    })
    expect(connection ~= nil, connect_err and connect_err.message)
    local rows, timeout_err = connection:query("SELECT SLEEP(2), 7")
    expect(rows == nil)
    expect(timeout_err.class == "timeout")
    local after, closed = connection:query("SELECT must_not_replay")
    expect(after == nil)
    expect(closed.class == "closed")
    connection:close()
    connection:close()
  end,
}

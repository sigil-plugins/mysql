return {
  title = "Socket loss is transport and never reconnects or replays",
  priority = "P0",
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
    local rows, transport_err = connection:query("SELECT socket_loss")
    expect(rows == nil)
    expect(transport_err.class == "transport")
    local after, closed = connection:query("SELECT must_not_replay")
    expect(after == nil)
    expect(closed.class == "closed")
    connection:close()
    connection:close()
  end,
}

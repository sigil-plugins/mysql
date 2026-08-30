return {
  title = "Operator wire ceiling cannot return a partial SQL result",
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
    local rows, limit_err = connection:query("SELECT LPAD('', 4096, 'x')")
    -- A host-owned max_bytes breach is deliberately latched by Sigil and
    -- cannot be caught or relabelled by guest code. The harness expects this
    -- scenario to abort with PLUGIN_RESOURCE_LIMIT before either assertion.
    expect(rows == nil)
    expect(limit_err.class == "limit")
  end,
}

# Security

Please report vulnerabilities privately through GitHub's security advisory
form for this repository. Do not include credentials, holdout scenarios, or
production query data in a public issue.

The driver deliberately has no raw network, DNS, filesystem, process, clock,
stdio, or WASI authority. Any change to imported WIT, authentication state,
packet bounds, secret handling, retry behavior, or release bytes requires a
security review.

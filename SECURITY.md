# Security policy

This is a release candidate and has not undergone an independent security review. The plugin runs inside Electrum and is not isolated from wallet data.

## Reporting

Use **Security → Advisories → Report a vulnerability** on this repository's
GitHub page.

Include the plugin version or commit, Electrum version, operating system, impact, and steps to reproduce using dummy data. Do not include real wallet secrets, passwords, or credentials.

Security fixes are made on the current development branch. There is no
guaranteed response time or bug bounty. Please avoid duplicate reports of
published upstream issues unless you have new information about how they
affect this plugin.

## Known limitations

- Vulnerable versions of Electrum's aiohttp dependency can use excessive CPU or
  memory when processing response cookies, before the plugin checks the headers.
  Response-size limits do not fully protect against this. See
  [GHSA-2g87-pp6c-29x5](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-2g87-pp6c-29x5).
- If saving Electrum's configuration fails, the file may be left partially
  written. Restoring the previous settings in memory cannot repair that file.
- SOCKS authentication is not encrypted on the connection to the proxy. Use a
  trusted connection; backend HTTPS does not protect that link.

See the [README](README.md#considerations) for what leak checks disclose and what the results mean.
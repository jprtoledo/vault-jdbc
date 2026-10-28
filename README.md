# vault-jdbc

[Português](README.pt-BR.md)

A JDBC driver that gets database usernames and passwords from [HashiCorp Vault](https://www.vaultproject.io/)
and passes the connection on to the real driver (PostgreSQL, MySQL, MariaDB, Aurora, …).

- **One jar.** The real driver is downloaded from Maven Central on first use and checked against a SHA-256
  pinned in the code. You can also bring your own jar.
- **Dynamic and static database roles, and KV v1/v2.**
- **Vault login.** Uses the token from `vault login` (`~/.vault-token`). When that token is missing or
  expired, it can run `vault login` for you; for OIDC/Okta this opens the browser.
- **Credential refresh.** Credentials are renewed before their lease ends. If the database rejects one, a
  new one is fetched and the connection retried.
- **Works in any JDBC client** that accepts a custom driver: DBX, DBeaver, DataGrip, IntelliJ, scripts, apps.
- **Requirements:** Java 17+. No runtime dependencies.

## Quick start

Download the jar from the [releases](../../releases) or [Maven Central](https://central.sonatype.com/artifact/br.com.juantoledo/vault-jdbc),
or build it with `mvn package` (`target/vault-jdbc-0.1.1.jar`). As a dependency:

```xml
<dependency>
    <groupId>br.com.juantoledo</groupId>
    <artifactId>vault-jdbc</artifactId>
    <version>0.1.1</version>
</dependency>
```

```kotlin
runtimeOnly("br.com.juantoledo:vault-jdbc:0.1.1")
```

Create a generic JDBC connection in your client:

| Setting | Value |
|---|---|
| Driver jar | `vault-jdbc-0.1.1.jar` |
| Driver class | `br.com.juantoledo.vaultjdbc.VaultDriver` |
| User / password | empty |
| URL | `jdbc:vault:` + your usual JDBC URL without `jdbc:`, plus `vault.*` parameters |

```text
jdbc:vault:postgresql://db.example.com:5432/app?sslmode=require&vault.addr=https://vault.example.com&vault.role=app-read

jdbc:vault:mysql://db.example.com:3306/app?sslMode=REQUIRED&vault.addr=https://vault.example.com&vault.role=app-read&vault.method=oidc&vault.authPath=okta_oidc
```

The second example reads `database/creds/app-read`. If there is no valid Vault token, it first runs
`vault login -method=oidc -path=okta_oidc`.

## Parameters

Each `vault.*` parameter can go in the URL query string or in the connection properties; the URL wins.
They are removed before the URL and properties reach the real driver.

### Vault server

| Parameter | Default | Description |
|---|---|---|
| `vault.addr` | `VAULT_ADDR` | Vault address. Must be `https` (`http` is accepted only for localhost). Desktop apps usually do **not** inherit `VAULT_ADDR` from your shell, so put it in the URL |
| `vault.namespace` | `VAULT_NAMESPACE` | Vault Enterprise namespace |
| `vault.cacert` | `VAULT_CACERT` | PEM/DER file with extra CAs to trust for Vault, in addition to the JDK's |

### Secret

| Parameter | Default | Description |
|---|---|---|
| `vault.role` | — | Role in the database secrets engine. Reads `<mount>/creds/<role>` |
| `vault.mount` | `database` | Mount path of the database secrets engine |
| `vault.static` | `false` | Set to `true` for a static role. Reads `<mount>/static-creds/<role>` |
| `vault.path` | — | Full secret path to read instead of a role, e.g. KV v2 `kv/data/app` or KV v1 `secret/app` |
| `vault.usernameKey` / `vault.passwordKey` | `username` / `password` | Field names inside the secret (useful for KV) |
| `vault.cacheSeconds` | `300` | How long to cache a secret that has no lease or TTL (KV) |

Set either `vault.role` or `vault.path`, not both.

### Login

| Parameter | Default | Description |
|---|---|---|
| `vault.method` | `token` (Vault's default) | Auth method, as in `vault login -method=` (`oidc`, `ldap`, `userpass`, `aws`, `kerberos`, `cert`, …). Setting it turns on automatic login |
| `vault.authPath` | the method name | Mount path of the auth method, as in `vault login -path=` (e.g. `okta_oidc`) |
| `vault.loginArgs` | — | Extra `key=value` arguments for `vault login`, comma-separated and URL-encoded (e.g. `role%3Ddba`) |
| `vault.autoLogin` | `true` when `vault.method` is set | Whether to run `vault login` when the token is missing or rejected. It never runs for the `token` method, which needs a terminal prompt |
| `vault.loginTimeout` | `120` | Seconds to wait for `vault login`, i.e. the time you have to finish the browser flow |
| `vault.cli` | auto-detected | Path to the `vault` binary. Looked up on `PATH`, then in `/opt/homebrew/bin`, `/usr/local/bin` and `/usr/bin` |
| `vault.tokenFile` | `~/.vault-token` | Token file to read. If you don't set it, `VAULT_TOKEN` takes precedence, as in the CLI |

### Real driver

| Parameter | Default | Description |
|---|---|---|
| `vault.driver` | inferred | Class of the real driver. Inferred for `postgresql`, `mysql`, `mariadb` and `aws-wrapper` |
| `vault.driverJar` | — | Comma-separated paths to driver jars to load instead of downloading |
| `vault.driverDownload` | `true` | Set to `false` to never download drivers |
| `vault.driverVersion` | pinned (see below) | Download a different version of the managed driver |
| `vault.driverSha256` | — | Expected SHA-256 of the jar for `vault.driverVersion`. Without it, the repository's published `.sha256` is used |
| `vault.driverRepo` | `https://repo1.maven.org/maven2` | Maven repository to download from, e.g. an internal mirror |
| `vault.driverCacert` | — | PEM/DER file with extra CAs to trust for the download, in addition to the JDK's. Needed behind TLS-inspecting proxies such as Zscaler |
| `vault.driverCache` | `$XDG_CACHE_HOME/vault-jdbc/drivers` or `~/.cache/vault-jdbc/drivers` | Where downloaded drivers are kept |
| `vault.authRetries` | `3` | How many times to retry when the database rejects a credential |

Drivers that can be downloaded automatically:

| Subprotocol | Artifact | Version |
|---|---|---|
| `postgresql` | `org.postgresql:postgresql` | 42.7.14 |
| `mysql` | `com.mysql:mysql-connector-j` | 26.10.0 |
| `mariadb` | `org.mariadb.jdbc:mariadb-java-client` | 4.0.0 |

Aurora PostgreSQL and Aurora MySQL use the PostgreSQL and MySQL drivers.

## How it behaves

**Finding the real driver.** It looks in this order: the jars in `vault.driverJar`; the classpath (for
example, a driver jar you configured next to vault-jdbc); a managed driver from the cache, downloading it
if needed; and finally any registered driver that accepts the URL. A downloaded jar is used only if its
SHA-256 matches. A cached jar that no longer matches is downloaded again.

**Vault token.** It tries, in order: the token from the last automatic login in this process,
`VAULT_TOKEN`, and the token file. If Vault answers 401 or 403, it reads the token file again, since you
may have logged in from a terminal. Only then does it run `vault login`, if allowed. Only one login runs at
a time per Vault server, and other connections wait for it and reuse its token. The CLI saves the new token
as usual, so your terminal sees it too.

**Credentials.** All connections to the same secret share one credential, so a connection pool does not
create one database user per connection. A new credential is fetched once 20% of the lease is left (at
least 30s). Static roles use their rotation TTL instead of a lease.

**Retries.** On an authentication error from the database (SQLState `28xxx`, or MySQL error `1045`), it
fetches a new credential and retries. If the rejected credential was just issued, it first waits 1s,
because a new user may not exist yet on a read replica (for example, an Aurora reader).

**Open sessions.** Sessions that are already open are left alone. When Vault revokes their lease, the
database usually drops them, and the next connection gets a fresh credential.

**Usernames.** Whitespace around usernames is removed, because some `username_template` configurations
add a trailing newline that is not part of the database user.

## Security

- Passwords and tokens never appear in logs or error messages. Sensitive `vault.loginArgs` values
  (`password`, `secret`, `token`, `passcode`, …) are masked.
- TLS certificate and hostname verification cannot be turned off. To trust a private CA or a
  TLS-inspecting proxy, add it with `vault.cacert` or `vault.driverCacert`.
- Downloaded drivers must match a pinned SHA-256. For versions that aren't pinned, pass
  `vault.driverSha256`; the repository's own checksum only catches corrupted downloads, not a malicious
  repository.
- `vault login` runs without a shell, with validated arguments and with stdin closed, so it cannot hang on
  a prompt.
- Prefer browser or machine-identity login methods (`oidc`, `aws`, `kerberos`, `cert`). A password in
  `vault.loginArgs` is stored with the connection URL by your client.

## Client notes

**DBX:** use a *JDBC* connection. Set the connect timeout to at least `vault.loginTimeout` (e.g. 120s),
because DBX applies its own timeout and would otherwise cancel the connection while you finish the browser
login. After replacing the jar, restart DBX, since it keeps the loaded driver in memory.

## Development

```bash
mvn verify
```

The tests use an in-process fake Vault and a fake driver, so they need no Docker and no network.

### Releasing

Set `<version>` in `pom.xml`, commit, and push a matching tag:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

The [release workflow](.github/workflows/release.yml) runs the tests, creates the GitHub release with the
jars and their SHA-256, and publishes to Maven Central when these repository secrets are set:
`CENTRAL_USERNAME` and `CENTRAL_PASSWORD` (a [Central Portal](https://central.sonatype.com) user token),
`GPG_PRIVATE_KEY` (ASCII-armored) and `GPG_PASSPHRASE`.

## License

[MIT](LICENSE)

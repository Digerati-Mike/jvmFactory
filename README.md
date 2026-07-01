# JVM Factory — `jvmFactory.cfc`

Track, audit, and modify the ColdFusion **JVM arguments** that ship with security / breaking‑change
updates. The client flags insecure values against a curated catalog and produces a **weighted secure
score**, so you can see at a glance how hardened a server is after a security update.

> Scope: this component only manages **JVM argument catalogs**. Download/JRE provisioning and garbage
> collector switching are intentionally **out of scope**. Only the arguments documented in the two
> Adobe guides below are surfaced, each tagged with the update it shipped in.

**Sources**

- [JVM arguments in ColdFusion (2025 release)](https://guides.adobe.com/coldfusion/en/docs/install-and-configure-coldfusion/jvm-arguments-coldfusion-2025.html)
- [JVM arguments in 2023 and 2021 updates of ColdFusion](https://guides.adobe.com/coldfusion/en/docs/install-and-configure-coldfusion/new-jvm-arguments-2023-2021-coldfusion-updates.html)

---

## Files

| File | Purpose |
| --- | --- |
| `jvmFactory.cfc` | The client: authentication, listing, modifying, auditing, and hardening JVM arguments. |
| `catalog.2025.json` | The data model for ColdFusion 2025: every documented flag with its security metadata. |
| `catalog.2023.json` | The data model for ColdFusion 2023. |
| `catalog.2021.json` | The data model for ColdFusion 2021. |
| `index.cfm` | Simple harness that instantiates the client. |
| `_backups/` | Timestamped copies of the server `jvm.config`, created on demand by `BackupJvmConfig()`. |

---

## The data model (`catalog.<version>.json`)

There is one catalog file per major ColdFusion version (`catalog.2025.json`, `catalog.2023.json`,
`catalog.2021.json`). The client loads the file matching the running server version, falling back to
`catalog.2025.json`. Each file contains a shared `meta` block and an `arguments` map. Each flag entry
uses this schema:

| Field | Meaning |
| --- | --- |
| `type` | `boolean`, `number`, `string`, or `list`. Drives value validation and comparison. |
| `default` | The Adobe-documented default value. Treated as the secure baseline unless `secure` is present. |
| `secure` | The value considered secure when it differs from `default` (e.g. `searchimplicitscopes` defaults to `true` but is secure at `false`). |
| `security` | `true` when the flag participates in the secure score. |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `none`. |
| `weight` | Score weight (`critical=10`, `high=7`, `medium=4`, `low=2`, `none=0`). |
| `breaking` | `true` when the flag changed default behavior in an update (a breaking change). |
| `removed` | `true` for flags removed in the current version (cannot be set). |
| `update` | The ColdFusion update number the flag shipped in (e.g. `10`). |
| `description` | What the flag does. |
| `recommendation` | The secure guidance for the flag. |

### How the weighted secure score works

```
score = round( sum(weight of security flags in a secure state)
             / sum(weight of all security flags) * 100 )
```

- A flag that is **not present** in `JVMArguments` is evaluated at its documented `default`.
- A flag is **secure** when its effective value matches `secure` (or `default` when `secure` is absent).
- Only flags with `security = true` and `weight > 0` count toward the score.

| Grade | Score |
| --- | --- |
| A | ≥ 90 |
| B | ≥ 80 |
| C | ≥ 70 |
| D | ≥ 60 |
| F | < 60 |

---

## Authentication

**Every public method authenticates against the ColdFusion Administrator before touching the
runtime** and throws `jvmFactory.Unauthorized` if the caller is not a valid administrator.

Credentials are resolved in this order:

1. `userName` / `password` passed to `init()`.
2. The request `Authorization` header (`Basic` or `Bearer`) or `x-api-key` header.

```coldfusion
// Explicit credentials
jvm = new jvmFactory({ userName = "admin", password = mySecret });

// Or rely on the request's Authorization / x-api-key header
jvm = new jvmFactory();
```

> Never hard-code the administrator password in source. Pass it from a secure store or let the request
> headers carry it.

---

## Public API

All methods below authenticate first. All write operations require a **ColdFusion restart** to take
effect and preserve any other JVM arguments already configured (heap sizes, GC flags, custom flags).

### `GetArgumentCatalog() : struct`
Returns the raw catalog metadata for the current ColdFusion version.

```coldfusion
catalog = jvm.GetArgumentCatalog();
```

### `ListJvmArguments() : array`
Returns one row per cataloged flag, merged with the server's current configuration.

```coldfusion
rows = jvm.ListJvmArguments();
```

Each row contains: `name`, `template`, `type`, `version`, `description`, `recommendation`,
`security`, `severity`, `weight`, `breaking`, `removed`, `default`, `secureValue`, `present`,
`currentValue`, `effectiveValue`, `secure`, `status` (`secure` \| `insecure` \| `informational` \|
`removed`), and `argument`.

### `GetJvmArgument(argument) : struct`
Returns the full detail row for a single flag. Accepts the full flag or just its name.

```coldfusion
detail = jvm.GetJvmArgument( "-Dcoldfusion.xml.allowExternalEntities" );
```

### `SetJvmArgument(argument, value) : struct`
Validates `value` against the flag's `type` and writes it. Rejects unknown flags, removed flags, and
values containing whitespace or unsupported characters (argument-injection protection).

```coldfusion
result = jvm.SetJvmArgument( "-Dcoldfusion.sessioncookie.httponly", true );
// result.argument        -> "-Dcoldfusion.sessioncookie.httponly=true"
// result.restartRequired -> true
```

### `RemoveJvmArgument(argument) : struct`
Removes the flag so it reverts to its documented default. Other JVM arguments are untouched.

```coldfusion
result = jvm.RemoveJvmArgument( "-Dcoldfusion.searchimplicitscopes" );
```

### `AuditSecurity() : struct`
Computes the weighted secure score and returns the insecure findings and breaking-change inventory.

```coldfusion
audit = jvm.AuditSecurity();
```

Returns: `cfVersion`, `score`, `grade`, `secureWeight`, `totalWeight`, `securedCount`,
`insecureCount`, `findings[]`, `breakingChanges[]`, `severityCounts{}`, `generated`.

Each `findings` entry: `name`, `template`, `version`, `severity`, `weight`, `breaking`,
`currentValue`, `effectiveValue`, `secureValue`, `recommendation`.

### `ApplySecureDefaults(dryRun = true) : struct`
Hardens every insecure security flag to its secure value. **Defaults to a dry run** — inspect the
planned changes first, then apply.

```coldfusion
// 1) Preview
plan = jvm.ApplySecureDefaults();               // dryRun = true

// 2) Apply
applied = jvm.ApplySecureDefaults( dryRun = false );
// applied.scoreBefore / applied.scoreAfter, applied.changes[], applied.restartRequired
```

### `BackupJvmConfig() : struct`
Copies the live server `jvm.config` into `./_backups/` (relative to the component) under a timestamped,
non-clobbering name (`jvm.config.<yyyymmdd-HHnnss>.bak`). The `_backups/` directory is created on first
use. The source `jvm.config` is resolved from `server.coldfusion.rootDir/bin/jvm.config`.

```coldfusion
backup = jvm.BackupJvmConfig();
// { success, message, fileName, path, source, size, created }
```

> Recommended before applying changes with `SetJvmArgument`, `RemoveJvmArgument`, or
> `ApplySecureDefaults( dryRun = false )` so you can roll back the `jvm.config` if needed.

### `ListJvmConfigBackups() : array`
Returns one row per backup in `./_backups/`, newest first. Returns an empty array when no backups exist.

```coldfusion
backups = jvm.ListJvmConfigBackups();
// [ { fileName, path, size, modified }, ... ]
```

---

## Logging

All operations log through ColdFusion's `writeLog` to **`jvm_factory.log`** in the running instance's
regular log directory (the same directory as `application.log`, `exception.log`, etc. — e.g.
`<cfRootDir>/logs/jvm_factory.log`). Logging is best-effort and never surfaces to the caller: if a log
write fails, the operation still succeeds.

- **Information** — successful writes (`SetJvmArgument`, `RemoveJvmArgument`, `ApplySecureDefaults`,
  `BackupJvmConfig`).
- **Warning** — recoverable issues.
- **Error** — caught exceptions, logged with their type and detail before being rethrown to the caller.

Each line is formatted as `<operation> - <message>`, with an optional `| <detail>` suffix.

---

## Typical workflow

```coldfusion
jvm = new jvmFactory({ userName = "admin", password = adminSecret });


// 1. What exactly is insecure?
audit = jvm.AuditSecurity();

// 2. Back up jvm.config before making any changes.
backup = jvm.BackupJvmConfig();

// 3. Preview the hardening, then apply it.
plan    = jvm.ApplySecureDefaults();
applied = jvm.ApplySecureDefaults( dryRun = false );

// 4. Restart ColdFusion for the JVM changes to take effect.
```

---

## Notes & guarantees

- **Only cataloged flags** (from the two Adobe articles) can be listed or modified; arbitrary flags
  are rejected.
- **Injection-safe:** values may not contain whitespace, so a value can never smuggle in an extra JVM
  flag. Booleans and numbers are type-checked; strings/lists are restricted to a safe character set.
- **Non-destructive:** every write preserves all other configured JVM arguments (heap, GC, custom).
- **Restart required:** JVM argument changes only take effect after a ColdFusion restart.
- **Version-aware:** the catalog is filtered to the running major version (`server.coldfusion.productversion`),
  falling back to `2025` when the version is not in the catalog.

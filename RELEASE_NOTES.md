# TrakBridge Release Notes

## Version 2.2.1 - Threat-Model Follow-Up & Sideload Signature Enforcement

**Release Date:** October 15, 2026
**Focus: Closing the remaining 2.2.0-triage security items — LDAP secure-by-default, inbound anonymous-injection gate, plugin sideload signature enforcement, admin unlock action, UDP source filter validation, and an image-scan vulnerability sweep**

TrakBridge 2.2.1 is a security patch release that closes every item deferred from 2.2.0's threat-model triage. 

This is a straight upgrade from 2.2.0 — no schema migration, no new required secrets. Two configuration behaviours change in ways that could affect running deployments: LDAP configs that were relying on `use_tls: true` actually working (it wasn't) will now fail if the directory server doesn't accept StartTLS, and unsigned files in `external_plugins/` will be refused at startup unless an operator opts in. Both are covered under Upgrade Notes.

---

### LDAP SECURE-BY-DEFAULT

#### `use_tls: true` finally does something
**T4.1 — StartTLS is negotiated before every bind on port 389**

The 2.1.x threat model called this out; the fix landed in 2.2.1. The prior LDAP provider constructed `Connection(..., auto_bind=False)` and never issued `start_tls()`. That meant `use_tls: true` in the config was a silent no-op — the connection dialled port 389 in cleartext and sent every user password and the service bind password over the wire. `validate_cert: true` provided false assurance because no TLS handshake ever occurred to validate against.

`_get_connection()` now calls `connection.start_tls()` between construction and the caller's `.bind()` whenever `use_tls=true` and `use_ssl=false`. LDAPS (`use_ssl=true`) still gets TLS at socket dial time via the Server config; no upgrade needed. If `start_tls()` fails the connection factory raises before any bind is attempted — no cleartext fallback under any circumstance. Anonymous, service-account, and user-credential connection paths all go through the same factory, so all three are covered.

The config validator gained two new refusals. Plaintext LDAP (`use_ssl: false` and `use_tls: false`) is now rejected unless the operator sets `allow_insecure: true`. TLS enabled with `validate_cert: false` gets the same treatment. When `allow_insecure` is honoured, every startup emits a WARNING per-connection naming the server, port, and the specific insecure option — so the choice appears in every log scrape and cannot be forgotten. This is the pattern from 2.2.0's `PROXY_TRUSTED` and `SESSION_COOKIE_SECURE` overrides: insecurity is possible but never accidental.

---

### INBOUND ANONYMOUS-INJECTION GATE

#### `auth_mode: none` on generic inbound plugins requires an ip_allowlist
**T1.3 — no more world-accessible CoT injection endpoints by default**

The generic JSON and XML inbound plugins accept `auth_mode: none` for testing convenience. Left in place in production it leaves `POST /api/inbound/<id>/data` world-accessible — anyone who can reach the endpoint can inject arbitrary CoT into every TAK server on the stream.

`validate_config()` on both plugins now raises with a user-readable message when `auth_mode=none` is chosen without an `ip_allowlist`. `0.0.0.0/0` is accepted as an explicit wildcard, so operators who genuinely need an open endpoint can preserve that behaviour — but it's now an auditable config entry rather than an implicit default. Every other value must parse as an IP address or CIDR block.

The runtime side had a working `_check_ip_allowlist()` already; it's been widened to accept both the legacy JSON-array format (backward compatible for existing streams) and the new comma/newline-separated text the UI now exposes. Malformed values fail closed — no accidental deny-to-allow conversion during upgrade. Save-time validation is wired into `update_stream_safely()` so the error surfaces in the UI immediately, not just when the listener next starts.

#### Validation runs on stream create too
**Closing the create-path gap for every inbound plugin**

The save-time probe originally only ran on update. `create_stream()` skipped it entirely, so a brand-new stream with `auth_mode=none` and an empty allowlist saved without complaint and only failed when the listener tried to start. The same probe-and-catch block now runs immediately after `set_plugin_config()` on create, and the error flashes back to the edit form exactly as it does on update.

The UDP multicast listener had a related defect: its `validate_config()` returned False with a log line instead of raising `ValueError`, and the save-time hook only catches `ValueError`. Invalid multicast groups and source filters were therefore swallowed on both create and update. Every failure path now raises with a message naming the offending field and value, so UDP and the generic inbound plugins behave identically.

---

### PLUGIN SIDELOAD SIGNATURE ENFORCEMENT

#### `external_plugins/` no longer trusts every file it finds
**V1/V2 — signature check on package and loose-`.py` sideload paths**

The ZIP install path added in 2.2.0 already verified plugin signatures via `services/plugin_package_verifier.verify_package_signature()`. The sideload path — files dropped into `external_plugins/` at build time or via a volume mount — did not. An attacker with filesystem write got RCE at the next restart.

`plugins/plugin_manager._load_package_plugins()` now gates on the existing package verifier before importing any code. A new sibling `verify_single_file_signature()` handles loose `.py + .py.sig` pairs using the same Ed25519 trust root and result contract. Refusal semantics respect both tier and a new operator opt-in:

- **Signed** — always load
- **Unsigned community-tier** — refused unless `plugin_settings.allow_community_sideload: true` is set in `config/settings/plugins.yaml`; when the toggle is on, load with a WARNING naming the file so the trust decision appears in every boot log
- **Unsigned pro/enterprise** — refused regardless of the toggle. Loose `.py` files carry no tier declaration and are treated as community for toggle purposes; pro/enterprise plugins must ship as full signed packages

The toggle is deliberately a config-file setting for 2.2.1. Promoting it to a live admin-UI toggle is queued for the 2.3.0 config-into-UI migration and needs a new `SystemSetting` model that isn't worth landing in a security patch. Where signatures come from is documented in the new **Plugin Signing** section of `docs/PLUGIN_SECURITY.md`: TrakBridge Project's offline signing key, with the signing tooling itself living in `trakbridge-plugins-premium`.

---

### ADMIN UNLOCK ACTION

#### Dedicated unlock without status side-effects
**T1.4 — Unlock button on the admin user detail page**

The failed-login counter, `is_locked()` check, `lock_account()`, and `unlock_account()` all existed and integrated correctly with the local auth path. Two gaps remained.

`config/schema.py` declared `lockout_duration: int = 900` (15 minutes in seconds) while the runtime at `services/auth/auth_manager.py:73-101` reads `lockout_duration_minutes` with a 30-minute default. The dataclass field was documentation-only but misleading — an operator reading the schema for expected behaviour got the wrong unit and the wrong number. Renamed to `lockout_duration_minutes: int = 30` with validator bounds of 1-1440 minutes so both artefacts agree with the runtime.

The admin user detail page displayed `failed_login_attempts` and `locked_until` but offered no dedicated action to clear a lock. An admin who wanted to unlock a locked user had to click Enable — which also mutates status. That was an accidental side-effect nobody should have to memorise. Added `POST /auth/admin/users/<id>/unlock` mirroring the existing disable/enable pattern; the Unlock button on the detail page renders only when the user is both locked and still ACTIVE, is CSRF-protected, and its handler is idempotent (info flash if the account isn't currently locked).

---

### UDP MULTICAST SOURCE FILTER VALIDATION

#### Invalid source filter entries caught at config save, not listener startup
**T1.2 — kernel-level SSM was already wired; validation is the new bit**

The IGMPv3 source-specific multicast join (`IP_ADD_SOURCE_MEMBERSHIP`) was already in place. When configured, the kernel drops datagrams from any source not in the filter list before they reach userspace — that's the actual security guarantee, and it prevented spoofed CoT injection from other hosts on the same multicast group.

What was missing: the `source_filter` field wasn't validated at save time. Bad entries (typo, CIDR, hostname) crashed the join with an obscure `inet_aton` error only when the listener started. `validate_config()` now rejects invalid `source_filter` entries and non-multicast `multicast_group` addresses at save time, so operators see the mistake immediately in the UI. The field's help text also gained explicit documentation of the kernel-drop guarantee.

---

### FEED-CONTENT INJECTION HARDENING

#### IRC handler strips CRLF from message payloads
**T5.2 — protocol-command injection via CoT-derived field values**

IRC uses `\r\n` as a command separator. TrakBridge's IRC handler renders CoT-derived values (callsign, remarks, group name) into a message template and writes the result to the socket verbatim. A callsign like `alice\r\nJOIN #evil\r\nPRIVMSG #evil :owned` would be split by the IRC server into three separate commands executed with the bot's privileges. Same class of bug as SQL injection, just against IRC instead of SQL.

Fixed at the socket-write chokepoint in `plugins/irc_handler.py:_send_to_irc()`: a new `_sanitize_irc_payload()` helper replaces CR/LF with a single space and drops NUL bytes. Both the message body AND the channel name get sanitised — belt-and-braces against a compromised config file trying to inject via the channel field.

Regression tests cover every combination of `\r`, `\n`, `\r\n`, and `\x00`, plus a clean-message pass-through guard.

#### Inbound coordinate validator rejects NaN and infinity
**T5.4 — bogus floats slipped past the bounds check into CoT XML**

`float('nan') < -90` returns False. `float('nan') > 90` returns False. The previous `_validate_coordinates()` at `routes/inbound.py:128` used only bounds comparisons, so NaN, +inf, and -inf slid through and reached the CoT XML builder — where they either crashed pytak, produced invalid XML clients couldn't render, or manifested as broken map geometry.

Added a `math.isfinite()` guard with an unambiguous error message naming the offending value. String values (from surprise upstream type coercion) also fail cleanly at the same guard. Valid coordinates including the extremes (`±90`, `±180`) still pass — regression-guarded.

---

### DEPENDENCY VULNERABILITY SWEEP

#### Trivy scan cleared — pip / setuptools / msgpack floors added
**9 CVEs closed, none of them exploitable against TrakBridge as shipped**

A Trivy scan of the runtime image flagged nine CVEs across three packages that didn't appear in `requirements.txt` or `pyproject.toml`. `msgpack@1.1.2` (GHSA-6v7p-g79w-8964, HIGH) came in transitively via `aiocache`. `pip@25.0.1` and `setuptools@70.3.0` were the versions the `python:3.12-slim` base image shipped — `Dockerfile:28` ran `pip install --upgrade …` but "upgrade" is build-time-only and the layer Trivy scanned was produced before newer versions landed on PyPI.

None of the CVEs is a direct runtime attack vector against TrakBridge — pip/setuptools findings require attacker-controlled package indexes or sdists at install time, and the msgpack DoS needs untrusted bytes into a shared Unpacker (TrakBridge doesn't expose one). But leaving HIGH-severity findings in the scan output blocks release promotion through downstream compliance gates, so we pin.

`Dockerfile:28` now carries explicit floors for `pip>=26.2.0` and `setuptools>=83.0.0`. `pyproject.toml` and `requirements.txt` add `msgpack>=1.2.1` (declared explicitly even though transitive, so the resolver can't pick a vulnerable version) and tighten `setuptools>=83.0.0`. The `[build-system].requires` block also lifted to `setuptools>=83.0.0` so the PEP-517 bootstrap resolver picks the safe version at build time.

Floors are not equality pins — the resolver stays free to pick newer versions, but nothing below the fixed threshold can resolve. Rebuild the image and re-run Trivy to pick up the fix; existing running containers keep their old versions.

CVEs closed: GHSA-6v7p-g79w-8964, GHSA-4xh5-x5gv-qwph, GHSA-qwm4-qh6w-59xr, GHSA-58qw-9mgm-455v, GHSA-jp4c-xjxw-mgf9, GHSA-wf93-45jw-7689, GHSA-6vgw-5pg2-w6jp, CVE-2025-47273, CVE-2026-59890.

---

### AUTH & ERROR HANDLING FIXES

#### Lockouts are actually temporary
**Accounts auto-unlock once `locked_until` passes**

`lock_account()` set both a `locked_until` timestamp and `status = LOCKED`, but `is_locked()` only looked at the status. The 30-minute window was decorative — once locked, a user stayed locked until an admin clicked Unlock, and every five-typo login became a support ticket.

`is_active()` and `is_locked()` now check the timestamp first and lazily clear an expired lock: `locked_until` is cleared, `failed_login_attempts` resets to 0, and status flips back to ACTIVE. No background scheduler is needed — the unlock happens at exactly the point that would otherwise refuse the user. DISABLED accounts are never touched.

#### Rate-limit responses return 429, not 500
**HTTPException status preserved through the error handler chain**

The catch-all `@app.errorhandler(Exception)` was catching Flask-Limiter's `HTTPException` and rendering it as a generic 500 "This page isn't working". A user who hit the login rate limit got a misleading server error instead of being told to slow down.

A dedicated `HTTPException` handler now runs first and content-negotiates the response: JSON `{error, description}` for API clients, the matching `errors/<code>.html` template for browsers, and Werkzeug's default response (with the correct status and `Retry-After` header) as a fallback. 429 hits log a WARNING naming the source IP and endpoint so brute-force signals stay visible to operators.

#### OIDC can actually be enabled
**`OIDC_ENABLED=true` no longer dies at startup with "No OIDC provider is enabled"**

Three separate breaks sat on the OIDC login path, and each one hid the next. First, `OIDCAuthProvider` only understood a nested multi-provider schema (`providers.<name>.discovery_url`, `scope` as a string, `role_mappings`) while `config/settings/authentication.yaml`, the docs, and `docker-compose.yml` all produce a flat block (`issuer`, `client_id`, `scopes` as a list, `role_mapping`). The LDAP provider had been taught to read both shapes in an earlier release; OIDC never was, so the constructor found no `providers` map and refused to start. The provider now normalises the flat schema the same way LDAP does: `discovery_url` is derived from `issuer` using the standard `/.well-known/openid-configuration` path (an explicit `discovery_url` still wins), the `scopes` list is joined into the space-separated `scope` string OIDC expects, and `role_mapping` is read as an alias of `role_mappings`. Existing nested configs are unaffected.

Second, the discovery and JWKS cache dictionaries were created *after* the base-class constructor ran — and the base constructor validates the config, which fetches the discovery document, which reads the cache. Any real construction raised `AttributeError`. Every existing test had patched the fetch, so nothing noticed.

Third, `configure_flask_app()` copies a fixed list of settings into Flask config and `APPLICATION_URL` was never on it. The OIDC login route builds its callback redirect from `current_app.config['APPLICATION_URL']` and raised `KeyError` on the first click. It is now copied like the rest.

The new end-to-end test stands up a real local HTTP identity provider serving discovery and JWKS documents, enables OIDC through the flat schema, posts to `/auth/login`, and asserts the browser is redirected to the IdP's authorize endpoint with the right `client_id`, `scope`, `redirect_uri`, and session-bound `state`. No mocks on the path under test.

#### Error pages match the rest of the app
The error templates used a purple gradient, system fonts, and emoji icons that didn't match the app. `base_error.html` now uses the app's palette, Inter font, and Font Awesome icons, with a new 429 rate-limit page alongside the existing ones. The 404 and 503 templates had been wrapped in HTML comments and now render correctly.

---

### UPGRADE NOTES

- **Straight upgrade from 2.2.0.** No schema migration, no new required secrets, no configuration change required for a healthy deployment
- **LDAP deployments where the directory server does not support StartTLS on port 389 will start failing binds.** Prior behaviour silently sent credentials in cleartext despite `use_tls: true` — the fix means credentials now actually get TLS, but the server has to accept the upgrade. Either configure the LDAP server to accept StartTLS on 389, switch to LDAPS on 636, or (as an audited last resort) set `allow_insecure: true` in the provider config to preserve the old cleartext behaviour with a boot-time WARNING
- **Existing streams with `auth_mode=none` and no `ip_allowlist` will fail validation on next save.** The already-running listener keeps operating with its stored (pre-2.2.1) config until the next process restart; on restart the invalid config is refused with the same error. Set an explicit `ip_allowlist` (use `0.0.0.0/0` to preserve the old world-accessible behaviour with an audit trail)
- **Loose `.py` files in `external_plugins/` will be skipped at startup unless signed or the operator opts in.** Signed packages continue to load unchanged. Set `plugin_settings.allow_community_sideload: true` in `config/settings/plugins.yaml` to preserve the pre-2.2.1 behaviour for community-tier plugins; pro/enterprise unsigned sideloads remain refused regardless of the toggle
- **Container image rebuild required to pick up the new pip / setuptools / msgpack floors.** Existing running containers keep their old versions; the fix applies at rebuild

---

## Version 2.2.0 - API Keys, Self-Healing Connections & Security Hardening

**Release Date:** September 6, 2026
**Focus: Scripted API access via personal access tokens, a documented API surface, automatic recovery from TAK server and feed-source outages, and threat-model-driven security hardening**

TrakBridge 2.2.0 pairs the platform's first first-class machine authentication — scoped API keys — with a ground-up rework of outage recovery. A TAK server or GPS feed going down and coming back is now a non-event: TrakBridge backs off, keeps watch, and resumes on its own. Previously it could require an operator to edit and re-save every affected stream.

The release also closes seven items from a full external threat model of v2.1.1: unauthenticated recon and preview endpoints, an outbound-plugin SSL fallback that leaked credentials over MITM, a credential leak from the stream detail page visible to any read-only user, an orphan health subsystem publishing false "healthy" state, and a delete guard blind to the newer many-to-many stream/TAK-server association.

This release includes a schema migration and one new production-required secret (`API_KEY_PEPPER`) — see Upgrade Notes.

---

### API KEY AUTHENTICATION

#### Personal access tokens for scripts and integrations
**`Authorization: Bearer tb_pat_...` now works alongside session auth**

Users can create scoped API keys at `/auth/api-keys` — each key carries an explicit set of permissions (`streams:read`, `api:read`, `tak_servers:read`, and so on), an optional expiry, and last-used tracking. The token is revealed once at creation and stored only as an HMAC-SHA256 hash mixed with a server-side pepper: a database-only compromise cannot verify or forge tokens.

Bearer resolution is wired into the shared auth decorators, so every endpoint that accepts a session also accepts a valid key with the right scope. Tokens with foreign prefixes (`ghp_...`) or malformed bodies are rejected before the resolver does any work, and `tb_pat_` values are redacted from log output.

Administrators get a cross-user view of all keys at `/admin/api-keys` with grouped scope chips for at-a-glance auditing.

#### Privileged surfaces refuse bearer auth
**A leaked API key cannot escalate**

Admin routes, credential mutation (password change, profile edit), logout, and the key-management pages themselves are guarded by `@session_only` — they return 401 to any bearer request regardless of the token's validity or scopes. Managing keys requires a browser session, so a stolen key can read what it's scoped for and nothing more.

CSRF protection is unchanged for session traffic; bearer-authenticated requests bypass it (they carry no ambient credentials for a cross-site attacker to ride).

---

### DOCUMENTED API SURFACE

#### OpenAPI 3.1 spec and Swagger UI
**`/api/openapi.json` and `/api/docs`, auth-gated**

The full API — streams, plugins, inbound endpoints, health and monitoring — is now described by a machine-readable OpenAPI 3.1 spec with an interactive Swagger UI. `API_REFERENCE` has been rewritten from the spec. Both endpoints require authentication (session or bearer): every legitimate consumer is already authenticated for some other reason, and gating keeps the API description out of anonymous-scanner reconnaissance. The spec is generated once per app instance and cached.

---

### SELF-HEALING CONNECTIONS

#### TAK server outages recover without intervention
**The circuit breaker now actually does its job**

The long-standing failure mode: TAK server drops, the per-server circuit breaker opens, and nothing ever recovers — streams stayed dead until an operator edited and re-saved them. The root cause was structural. The transmit path swallowed socket errors into a boolean, so the loop that should have abandoned the dead connection never got the signal; the breaker's recovery probe then wrote to that same dead socket forever, a test that could not pass.

The rework:

- The breaker gates **connection establishment** — the one operation that can genuinely prove recovery. Socket errors propagate, the send loop breaks, the worker reconnects with exponential backoff (5s→120s)
- While the server is down, the breaker sits cleanly OPEN and connection attempts fast-fail — no wasted 30-second timeouts, no OPEN/HALF_OPEN flapping. A lightweight health probe tests the server every 30 seconds
- The moment a probe passes, traffic is re-admitted, and **one successful reconnection closes the breaker**
- Health probes were also being failed by TAK Server itself: probes connected instantly but then waited for a TLS close handshake that TAK Server defers until its subscription reaper runs (~30s). Probe cleanup is now best-effort with a hard cap — the health verdict rests on the connect, not the goodbye

End to end, verified live against a real TAK Server with cross-checked subscription logs: pull the network, watch the breaker open; restore it, and transmission resumes within a couple of minutes with zero human involvement.

#### Streams never permanently deactivate
**Five bad polls no longer switch a stream off**

Consecutive poll errors previously flipped `is_active = False` permanently. Streams now retry forever with backoff capped at five minutes, log at ERROR at the threshold (and every 10th failure after, to keep sustained outages visible without spamming), and surface the condition through the stream's **Last Error** field — which clears itself on recovery.

#### Feed outages are visible
**A dead GPS source no longer looks like a healthy stream**

Plugins report connection failures using an internal sentinel format that the poll loop didn't understand — it counted them as retrieved locations, so a total feed outage showed a green stream delivering nothing. Sentinel results now register as failed polls and drive the same retry/backoff/Last Error machinery; partial results still count as success. Traccar's error paths were additionally normalised so its outages are distinguishable from a legitimately quiet feed. Feed outages log as a single classified line rather than a crash-style traceback.

#### Circuit breaker core hardening
**Fixes to the state machine itself**

- Trips on *consecutive* failures — previously a lifetime cumulative count meant three failures spread across days could open a breaker
- HALF_OPEN probe slots are refunded when calls complete — concurrent healthy callers were being rejected during recovery
- Health checks run in HALF_OPEN as well as OPEN, tolerate sync callables, and log crashes at ERROR with the exception type (previously swallowed at DEBUG — the advertised auto-recovery mechanism could fail silently)
- New tuning knobs documented in `performance.yaml`: `timeout`, `half_open_max_calls`, `success_threshold`, `health_check_interval`, `health_check_timeout`; slow health probes log a per-phase timing breakdown for field diagnosis

---

### SECURITY HARDENING

An external threat model of v2.1.1 identified 48 attack paths across seven tiers. Seven items were triaged for this release; the rest are scheduled for 2.2.1 and 2.3.0. Every fix here landed with focused per-item unit tests (37 new tests) written against the exact failure mode from the threat model, so any regression is caught before it reaches production.

#### Preview endpoints now require authentication
**Anyone with network reach could read captured payloads and re-run parsers**

`GET`/`DELETE /api/inbound/<id>/preview` and `POST /api/inbound/<id>/preview/remap` accepted anonymous calls. The threat model observation was blunt: publishing an inbound stream necessarily publishes the preview path on the same port, and the "gate" was only stream-id validation — trivially enumerable given how few streams a typical deployment runs. Beyond reading captured payloads (which include headers and source IPs of every reporting device), an anonymous caller could wipe the capture buffer or re-run the parser with an attacker-supplied `plugin_config` merged over the stream's decrypted config.

All three endpoints now require a session cookie or `tb_pat_` bearer via `@api_key_or_auth_required`. The CSRF exemptions that were compensating for the missing auth gate are gone; UI writes flow through standard CSRF, bearer requests bypass CSRF via the existing hook.

#### Reconnaissance endpoints tightened
**`/api/status`, `/api/version`, `/api/health/ready`, `/api/health/live` now require auth**

Individually minor, together an attacker's targeting layer: the version pin identifies which known-issues apply, the status endpoint enumerates streams and their state, and the health probes confirm subsystem availability. All four are now gated behind `@api_key_or_auth_required`. `/api/health` remains the sole public probe — the single canonical health check for container and load-balancer use. Orchestrators and monitors that were polling the detailed endpoints already carry a service credential; the change is invisible to them and shuts the drive-by scanner path.

#### Outbound plugin SSL fallback removed
**A MITM only needed to present an invalid cert to harvest credentials**

The Garmin, Discord and Slack plugins caught `ssl.SSLError` and retried the same request with `ssl=False`, re-sending the Garmin account password or the webhook URL over an unverified TLS channel. The retry was in both the message-send path and the test-connection path (the latter previously returned a misleading `success: true, message: "using insecure connection due to certificate issues"` — an operator-facing lie).

All fallback blocks are deleted. SSL errors now propagate as ERROR log entries; test-connection reports `success: false, error: "SSL verification failed"` so the operator sees the real failure and can investigate the certificate rather than accepting a downgrade they didn't know happened.

#### Stream detail page no longer leaks decrypted plugin config
**A VIEWER could Ctrl-U and read every stored credential**

The Test Connection button at `/streams/<id>` iterated `stream.get_plugin_config()` — the *decrypting* accessor — and embedded each value into an inline `<script>` literal as `plugin_<key>: '<value>'`. Any user who could load the page (VIEWER included) could view the page source and read Garmin passwords, API keys, MQTT broker passwords, and Discord/Slack webhook URLs in plaintext.

The button now calls the existing server-side `/streams/<id>/test` endpoint with only `{stream_id}`. The server loads the decrypted config in-process and runs the plugin's `test_connection()` there; no decrypted value crosses the wire back through the browser. The two remaining uses of `get_plugin_config()` in the template render only `global_geofence_bounds` (safe map metadata).

#### Recovery subsystem replaced with real circuit-breaker state
**The health endpoint was reporting "healthy" from a subsystem that had never run**

`services/recovery_service.py` and `services/recovery_implementations.py` (1,181 lines) shipped with the circuit breaker in v1.0.0 as its automated recovery half. In practice the circuit breaker took over the recovery role and the standalone subsystem was orphaned: `initialize_recovery_system()` had no callers, no recovery methods were registered, and `/api/health/recovery` was publishing a fabricated success rate from an idle singleton. Operators watching that endpoint had no way to know it was lying.

Both modules are deleted (−1,181 lines). `/api/health/recovery` now derives status from `CircuitBreakerManager.get_all_status()` — the authoritative source, already actively driving TAK reconnection in production. Status mapping: any breaker OPEN → `unhealthy` (HTTP 503), any HALF_OPEN → `degraded` (HTTP 200), otherwise `healthy`. The endpoint URL is unchanged, so any monitoring pointed at it now gets truthful data.

#### TAK server delete guard covers many-to-many links
**A stream linked via the newer M2M table could be silently orphaned**

The delete guard at `routes/tak_servers.py` checked only `server.streams` — the legacy single-server foreign key. The newer `stream_tak_servers` association table uses `ondelete=CASCADE` on its tak_server FK, so a stream connected only via that table had its association row cascaded away when the server was deleted. The stream kept reporting success while quietly delivering to one fewer destination — exactly the class of failure the threat model file's title-line is about ("the COP that quietly lies").

Guard now checks both: `if server.streams or server.streams_many.count() > 0:`. Delete is refused if either relationship still references the server.

#### Flask-WTF version-compatibility fix
**Bearer-bypass CSRF shim now works against both 1.1 and 1.2**

Discovered while landing T1.1: the shim wrapping `CSRFProtect.protect` had a fixed no-arg signature, but Flask-WTF 1.1 calls the hook as `protect(apply_exemptions=True)` (1.2 dropped the kwarg). Container images on 1.1 500'd on every request before reaching auth. Was masked previously because the preview endpoints were CSRF-exempt; removing that exemption exposed it. Shim now accepts `*args, **kwargs` and forwards through — safe against future Flask-WTF signature changes in either direction.

---

### HOUSEKEEPING

- Parallel configuration systems collapsed into `ConfigLoader`; `utils/config_manager.py` removed
- Duplicate `monitoring:` block in `performance.yaml` merged — the fallback-statistics settings were being silently discarded at load
- Backups directory created automatically on first run
- ~90 new tests (unit, integration, end-to-end), including a real-socket outage/recovery acceptance test that fails on the pre-fix code

---

### UPGRADE NOTES

1. **Schema migration** (`add_user_api_keys`) — Docker deployments migrate automatically via the entrypoint; source deployments run `flask db upgrade`
2. **`API_KEY_PEPPER` is required in production** — the app refuses to boot without it. Generate with `openssl rand -base64 48` and provide as a Docker secret at `./secrets/api_key_pepper` (compose files already reference it) or via `API_KEY_PEPPER`/`API_KEY_PEPPER_FILE`. Non-production environments generate an *ephemeral* pepper per process — keys created there die on restart, with a loud startup WARNING. Rotating the pepper invalidates every existing key by design
3. **Operational model change**: streams no longer stop after repeated errors. Retire any runbook that says "edit and re-save the stream to recover it" — watch the stream's Last Error field and `/api/health/circuit_breaker` instead
4. Existing `performance.yaml` files work unchanged; the new circuit-breaker keys are optional. `failure_threshold` now genuinely counts consecutive failures, matching its long-standing comment
5. Scripted consumers using saved session cookies should migrate to API keys created at `/auth/api-keys`; note that admin and credential routes intentionally refuse bearer auth

---

## Version 2.1.1 - LDAP Login & HTTP Session Fixes

**Release Date:** August 16, 2026
**Focus: Restoring LDAP/OIDC login, unblocking HTTP deployments, cleaning up startup logging, and tightening CI version stamping**

TrakBridge 2.1.1 is a targeted patch release for two production-blocking authentication bugs surfaced by an operator report, plus internal cleanup on plugin registry sync, plugin version-check exception handling, startup logging, and CI version stamping. Straight upgrade from 2.1.0. No schema migration, no configuration change required.

---

### AUTHENTICATION FIXES

#### LDAP and OIDC users no longer trapped in force-password-change flow
**Every external-provider user was blocked on first login**

`services/auth/bootstrap_service.py::force_password_change_required` returned `True` for any user whose `password_changed_at` column was `NULL`. That check made sense for local users (who need to rotate their bootstrap password), but LDAP and OIDC users *legitimately* have `password_changed_at = NULL` — they were created via `User.create_external_user`, have no TrakBridge-managed password, and no code path ever timestamps that column for them.

The result: every LDAP or OIDC user, on their first login through the standard login form, was redirected to `/auth/force_password_change` — a page they had no way to complete. The only workaround was to manually update the Postgres row.

The check now short-circuits `False` for any user whose `auth_provider` is not `AuthProvider.LOCAL`. Local users are unaffected — the `must_change_password` flag and `password_changed_at is None` branches still fire for them.

If you manually cleared `password_changed_at` in the database as a workaround, no action is required — the column is now ignored for external-provider users.

#### `SESSION_COOKIE_SECURE` is now bidirectional
**Operators running HTTP in production had no supported way to disable the Secure flag**

The previous logic was `_is_production or _secure_override in ("1","true","yes")` — an OR, meaning the env-var could only *force Secure on*. There was no value (not `false`, not `0`, not empty) that would turn it off once `FLASK_ENV=production`.

Deployments running TrakBridge over plain HTTP (typically behind a non-TLS-terminating reverse proxy) hit this hard: browsers silently drop cookies with the `Secure` flag on HTTP responses, so the session cookie was set on the login response but never sent back on any subsequent request. Users saw "Session regenerated" in the logs immediately followed by "Unauthenticated access attempt to main.index" — an infinite login loop with no diagnostic pointing at the cookie flag.

The override is now bidirectional:

- `SESSION_COOKIE_SECURE=true`/`1`/`yes` → force Secure on (unchanged)
- `SESSION_COOKIE_SECURE=false`/`0`/`no` → force Secure off (new)
- Unset → defaults to on in production, off elsewhere (unchanged)

A `WARNING` is logged at startup when Secure is explicitly disabled in production, naming the trade-off and pointing at the recommended fix (terminate TLS at a reverse proxy in front of TrakBridge).

**Recommendation:** if at all possible, terminate TLS at a reverse proxy and leave `SESSION_COOKIE_SECURE` unset. The env-var is an escape hatch for deployments that genuinely cannot terminate TLS in front of the app, not a supported production posture.

---

### FIXED

#### Duplicate startup log lines eliminated
Flask attaches a default handler to `app.logger` on first access. Because our logging setup also propagates `app.logger` records to the root logger (which has its own handlers), every startup record was being emitted twice — once via Flask's default handler and once via propagation. The default handler is now removed on startup so records propagate exactly once.

#### Startup banner no longer reports "unknown" for Python version, platform, and user
Two independent bugs collapsed into one visible symptom:

- `log_full_startup_info` was reading `python_version` and `platform` off the top level of `get_version_info()`, but the version service returns those fields nested under an `environment` block. The banner has been updated to read from the correct location.
- The current user was resolved from `USER` / `USERNAME` env vars, which are typically unset in container deployments. A `getpass.getuser()` / `pwd.getpwuid()` fallback chain now handles the container case.

---

### PLUGIN INFRASTRUCTURE

#### Plugin registry sync reconciles manifest drift
`services/plugin_admin_service.py::sync_plugin_registry` now detects when an on-disk `plugin.yaml` manifest differs from the stored `InstalledPlugin` row and updates the row in place, writing a `PluginAuditLog` entry with action `metadata-synced` naming the fields that changed. Previously, drift between the manifest and the database (e.g. from a manual manifest edit or an out-of-band file swap) accumulated silently until the plugin was reinstalled.

The sync is a no-op when manifest, package_format, and is_verified all match the stored row, so audit-log churn stays proportional to real drift rather than firing on every sync pass.

#### Plugin version-compare no longer swallows real bugs
`_version_satisfied` previously wrapped its version parse/compare in a blind `except Exception`, silently logging every failure as "unparseable local version" — including `ImportError`, `RuntimeError`, and other real bugs unrelated to version parsing. The catch has been narrowed to `(ValueError, AttributeError, TypeError)` — the actual failure modes of the packaging-version parser and `.split()` — so real bugs now surface with real tracebacks. Also resolves ruff `BLE001`.

---

### INTERNAL

#### CI setuptools-scm pretend version sourced from `pyproject.toml`
The dev, staging, and main build jobs in `.gitlab/ci/build.yml` previously hardcoded `0.1.0.dev0` as the setuptools-scm pretend version. That number drifted from reality every release — plugin `min_trakbridge_version` gates evaluated against it were meaningless on non-tag builds.

The version being worked toward now lives at `[tool.trakbridge.release].next` in `pyproject.toml` and is read by each build job:

```bash
NEXT_VERSION=$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['trakbridge']['release']['next'])")
export SETUPTOOLS_SCM_PRETEND_VERSION="${NEXT_VERSION}.dev0+g$CI_COMMIT_SHORT_SHA"
```

Tag builds continue to use `$CI_COMMIT_TAG` unchanged. Bumping the next-release target is now a one-line pyproject.toml change, reviewed alongside the work that motivates the bump.

---

### UPGRADE NOTES

- Straight upgrade from 2.1.0. No schema migration, no configuration change required.
- Operators running TrakBridge over plain HTTP in production can now set `SESSION_COOKIE_SECURE=false` to make session cookies functional. Not recommended — terminate TLS at a reverse proxy in front of TrakBridge for production deployments — and a `WARNING` is logged at startup when it's used.
- Existing LDAP or OIDC users who were previously trapped in the force-password-change redirect can now log in normally. If you manually set `password_changed_at` in the database as a workaround, no action is required; the column is now ignored for external-provider users.

---

## Version 2.1.0 - Security Hardening

**Release Date:** August 9, 2026
**Focus: Security defaults tightened across the admin UI, session handling, plugin distribution, and multi-arch container publishing**

TrakBridge 2.1 hardens the security posture across the entire deployment. CSRF protection is now on by default, session cookies carry explicit security attributes, unauthenticated API surface is trimmed, the plugin manager gates unsigned premium packages, and the whitelist writer resists symlink attacks. Container images once again publish for both amd64 and arm64. No schema changes, no new configuration required, straight upgrade from 2.0.1.

---

### SECURITY

#### CSRF protection enabled by default
**Session-authenticated POSTs now require a CSRF token**

`WTF_CSRF_CHECK_DEFAULT` has been flipped from False to True. Every session-authenticated state-changing request (POST/PUT/PATCH/DELETE) now requires a valid CSRF token, either as `csrf_token` in the form body or `X-CSRFToken` in the request header.

- All existing HTML forms in the admin UI already emit the token via Jinja's `{{ csrf_token() }}` helper — no template changes needed for the built-in UI.
- A global `fetch()` interceptor in `base.html` automatically injects the token from a `<meta name="csrf-token">` tag on every same-origin fetch; both URL-string and `Request`-object call patterns are covered.
- Five endpoints are explicitly exempted where session auth isn't the mechanism: the three inbound webhook endpoints (`POST /api/inbound/<stream_id>/data`, `DELETE /api/inbound/<stream_id>/preview`, `POST /api/inbound/<stream_id>/preview/remap`) and the two coordinate-conversion utility endpoints (`POST /api/convert-latlon-to-mgrs`, `POST /api/convert-mgrs-to-latlon`). Each exemption carries an inline comment naming the auth mechanism.
- A dedicated `CSRFError` handler returns a clean `400` with a JSON or plain-text body rather than a `500` stack trace.

CSRF-less session-authenticated POSTs from browsers were already blocked in practice by cross-origin policies; this change makes the rejection explicit and deterministic.

#### Explicit session cookie security attributes
**HttpOnly, SameSite=Lax always; Secure enforced in production**

`SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"` are now set explicitly in every environment. `SESSION_COOKIE_SECURE=True` in production; in other environments it defaults False but can be forced on via the `SESSION_COOKIE_SECURE` environment variable.

Previously these attributes relied on Flask's implicit defaults, which varied between browsers and left `SameSite` unset entirely. Existing user sessions retain their old cookies until expiry or logout; new logins immediately receive cookies with the new attributes.

#### Unauthenticated API surface trimmed
**Eight previously `@optional_auth` endpoints now require authentication**

The following endpoints now return 401 to unauthenticated callers:

- `GET /api/health/detailed`
- `GET /api/health/database`
- `GET /api/health/configuration`
- `GET /api/health/circuit-breakers`
- `GET /api/health/recovery`
- `GET /api/monitoring/dashboard`
- `POST /api/convert-latlon-to-mgrs`
- `POST /api/convert-mgrs-to-latlon`

`GET /api/status` remains unauthenticated for container health-check probes. Detailed operational telemetry that leaked stream and worker counts through the pre-2.1 endpoints is now behind an authenticated session.

#### CA certificate upload filename sanitisation
**Path-traversal filenames in uploaded certificates rejected**

`routes/streams.py::_validate_and_read_ca_cert` now applies `werkzeug.utils.secure_filename()` to uploaded CA certificate filenames before returning them to the caller. Empty results are rejected. A crafted filename like `../../etc/evil.pem` is stripped to a safe basename or refused.

#### Master key value no longer logged at DEBUG
**Prior deployments running at DEBUG log level should rotate their master key**

`services/encryption_service.py` previously emitted the generated master encryption key as a DEBUG log line, guarded only by `logger.isEnabledFor(DEBUG)` — which is not protection: anyone with DEBUG log capture (file, syslog, aggregator) received the key in cleartext. The line has been removed; the adjacent safe log ("Master key generated (not logged for security)") is retained.

**Rotation advisory:** any TrakBridge deployment that ran at `LOG_LEVEL=DEBUG` prior to 2.1.0 and generated a master key at runtime (as opposed to loading one from `TB_MASTER_KEY` or `secrets/tb_master_key`) should treat that key as compromised and rotate it via the admin key-rotation UI or `services/key_rotation_service.py`.

#### Plugin manager: tier badge and upload hint
**Deployment licence tier surfaced up front in the admin UI**

The plugin manager page header now shows a coloured badge with the current deployment tier ("Licence: Community" / "Pro" / "Enterprise"), and the upload modal body includes a hint noting which tier the deployment is licensed as. Tier-mismatch rejections at install time already carried a clear error message; making the current tier visible before upload reduces the surprise.

#### Signed-plugin gate for premium tiers
**Plugins declaring pro or enterprise tier must carry a valid Emfour signature**

`install_plugin` now refuses unsigned plugins whose manifest declares `tier: pro` or `tier: enterprise`, regardless of the deployment tier. The trust guarantee applies to the plugin's claim of premium capability — a Pro deployment installing a plugin that claims to be Pro deserves the signature check.

Unsigned community-tier plugins continue to install on any deployment tier with the existing "UNVERIFIED" warning. Signed plugins install verified as before.

#### Whitelist file hardening
**File mode 0600, symlink writes refused**

`services/plugin_admin_service.py::update_whitelist_file` now sets file mode `0o600` on the plugin allow-list after atomic replace, and refuses to read or write if the target path or its parent directory is a symlink. `PermissionError` from either check is caught at the route layer and returned as a controlled `400` rather than an unhandled `500`.

Prevents information disclosure of the allow-list on shared hosts and blocks a class of symlink redirection attacks against the whitelist writer.

---

### PACKAGING

#### Multi-arch container images restored
**Both amd64 and arm64 images published to GHCR and mirrored to Docker Hub**

The release job previously used `docker pull/tag/push` to publish the release image, which flattens a multi-arch source manifest to whichever platform the runner pulled. In practice that dropped arm64 from every public release since 2.0.0. The publish job now preserves multi-arch manifests end-to-end.

Anyone pulling on Apple Silicon or arm64 servers will no longer see amd64 emulation warnings and will run the native image directly.

---

### UPGRADE NOTES

Straight upgrade from 2.0.1. No schema migration, no configuration change required.

**Upgrade checklist:**

1. Deploy the new image. All Phase 1 security changes take effect immediately for new sessions and requests.
2. Verify admin UI login still works (confirms CSRF token flow is intact).
3. If your deployment previously ran at `LOG_LEVEL=DEBUG` and generated its master key at runtime, rotate the master key via the admin key-rotation UI.
4. Existing user sessions keep their pre-2.1 cookies until expiry or logout; no forced re-login required.

**Known behavioural changes:**

- **Any script or integration that posts to a session-authenticated TrakBridge endpoint using only a saved session cookie (no CSRF token) will now receive `400 Bad Request`.** Migrate such callers to bearer-token or API-key authentication (CSRF-exempt), or include the CSRF token via `X-CSRFToken` header. The bundled admin UI is unaffected.
- The eight previously unauthenticated health/monitoring endpoints listed above now return `401` without a valid session. Any external monitoring probe hitting `/api/health/detailed` (or similar) will need to authenticate.
- The `Set-Cookie` header on session cookies now carries `HttpOnly; SameSite=Lax` on every response, and `Secure` in production. Downstream cookie inspectors will see the new attributes.

---

## Version 2.0.1 - Multi-Server RX Dispatch & Worker Stability

**Release Date:** July 23, 2026
**Focus: Silent data-loss fix for multi-server streams and a long-standing worker-recycling bug that surfaced in 2.0.0**

Two hotfixes for issues introduced or first observed in 2.0.0. The RX dispatch bug caused output plugins to silently miss traffic from every TAK server beyond the first when a stream was attached to multiple servers — the postgres archiver made this visible for the first time. The Hypercorn worker was silently recycling every ~1000 requests (roughly every 30 minutes on a healthy deployment), tearing down long-lived stream state and interrupting CoT delivery; this has been present since Hypercorn was introduced but only became observable in 2.0.0 because plugin whitelist gating and buffering output plugins now depend on continuous worker uptime.

No schema changes. No new configuration. Straight upgrade from 2.0.0.

---

### BUG FIXES

#### RX plugin dispatch now respects the multi-server junction table
**Silent data loss for output plugins on multi-server streams — critical**

The 2.0.0 many-to-many `stream_tak_servers` junction table was correctly consulted on the TX side and during worker startup, but the RX-side plugin dispatch query in `services/cot_service_integration.py` still filtered streams by the legacy single-server `tak_server_id` column. When a stream was attached to multiple TAK servers, every CoT event received from any server other than the one referenced by the legacy foreign key was silently discarded — the output plugin was never called.

- **Symptom**: postgres archiver (or any output plugin) captured traffic from TAK server 1 only; server 2's events were missing entirely with no error log
- **Blast radius**: every output plugin — archivers, forwarders, notifiers, external HTTP outputs — attached to any multi-server stream
- **Fix**: the RX dispatch query now matches streams via either the legacy foreign key or membership in `stream_tak_servers`, mirroring the "multi-first, legacy-fallback" pattern already used elsewhere in the codebase. Backward compatible: single-server streams continue to work unchanged. No migration required.

#### Hypercorn worker no longer recycles every ~1000 requests
**Long-lived stream state and buffered plugin data preserved across worker lifetime**

The Docker entrypoint launched Hypercorn with `--max-requests 1000`, a stateless-web-worker recycling pattern that fights TrakBridge's single-long-lived-worker architecture. Every recycle:

- Tore down every stream worker and TAK server connection
- Triggered graceful shutdown of the plugin cache (draining buffered state)
- Interrupted CoT delivery for the ~1–2 second graceful-shutdown window
- Re-triggered plugin whitelist reload — which in 2.0.0 became a fragile path

The recycling was silent in earlier releases because output plugins had no buffered state and no whitelist gating existed. In 2.0.0 the combination surfaced the bug as observable data loss (buffered rows in the postgres archiver) and unrecoverable startup failures (whitelist reload permission errors on some deployments).

`--max-requests` has been removed from the Hypercorn command line. The `HYPERCORN_MAX_REQUESTS` environment variable is no longer honoured; any override in existing compose files is silently ignored. Worker hygiene is now handled by graceful shutdown and container health checks alone.

#### Full COT service shutdown on process teardown
**Output plugin cleanup and pending output stats now flushed on SIGTERM**

`_cleanup_persistent_cot_service()` in `services/stream_manager.py` only stopped in-flight workers on shutdown; it never awaited `QueuedCOTService.shutdown()`. That meant:

- `cleanup()` hooks on cached output plugins were never called
- Pending output-stat writes were never flushed to the database
- Buffering plugins (like the postgres archiver) lost any in-memory queue on SIGTERM

The teardown path now drives the full async shutdown via `run_coroutine_threadsafe` on the stream manager's event loop, matching the pattern already used for `stop_all()` and `_cleanup_monitoring_services()`. A worker-stop fallback remains for the edge case where no event loop is available, with a warning logged to make skipped plugin cleanup visible.

---

### PLUGIN SDK

No SDK version bump. The lifecycle hooks (`start()`, `cleanup()`) documented in the 2.0.0 SDK are now correctly driven by core on every configured teardown path: stream reconfig, stream deletion, stream stop/restart, and clean process shutdown.

---

### UPGRADE NOTES

Straight upgrade from 2.0.0. No schema migration, no configuration change required.

**Behavioural change**: workers now stay up until the container is explicitly restarted. Health-check based hygiene continues as before. If you were relying on periodic worker recycling for any reason (memory cleanup, garbage collection, socket refresh), your Hypercorn worker will now behave like a genuinely long-lived process — plan container restart cadence accordingly.

The `HYPERCORN_MAX_REQUESTS` environment variable is no longer read. Override entries in existing `docker-compose.yml` files can be removed at your convenience; leaving them in place is harmless.

---

## Version 2.0.0 - Plugin SDK, Tiered Licensing & Plugin Manager

**Release Date:** July 18, 2026
**Focus: Public Plugin SDK, Offline Licence Service, Admin Plugin Manager with Signature Verification and Tier Gating**

TrakBridge 2.0 introduces the foundation for a tiered product model. Plugin base classes are now published as a standalone SDK on PyPI so third parties can build their own plugins. A new offline licence system maps deployments to Community, Pro, or Enterprise tiers. The admin UI gains a plugin manager that installs, verifies, and gates plugins by tier without touching the shell. Together these lay the groundwork for premium plugin distribution while keeping every existing Community capability free and unchanged.

---

### NEW FEATURES

#### `trakbridge-plugin-sdk` — Public Plugin SDK on PyPI
**Third parties can now write TrakBridge plugins without a fork**

Plugin base classes (`BaseGPSPlugin`, `BaseOutputPlugin`, `BaseInboundPlugin`) and their supporting config/metadata infrastructure have been extracted from the core repository into a standalone Apache-2.0 licensed package: **[trakbridge-plugin-sdk](https://pypi.org/project/trakbridge-plugin-sdk/)** on PyPI.

- **`pip install trakbridge-plugin-sdk`** and subclass the base class of your choice — a working plugin is 30-40 lines of Python
- **Runtime provider registry** — core services (encryption, plugin metadata, circuit breaker, CoT delivery) are injected into the SDK at startup via `trakbridge_sdk.configure(...)`. Plugins never import core modules directly, so the SDK works standalone in unit tests
- **Contract documentation and worked examples** for GPS, output, and inbound plugin types ship with the SDK
- **17 built-in plugins now use the SDK** through a re-export shim at `plugins/base_plugin.py`; no behaviour change for existing installs

#### Offline Licence Service
**Ed25519-signed licence files, air-gap friendly, fail-secure**

New `services/license_service.py` verifies signed licence files against an embedded Emfour public key. Zero network calls; no phone-home.

- **Three tiers:** Community (default, no licence required), Pro, Enterprise
- **Licence file location:** `secrets/tb_license.json` by default, overridable via `TRAKBRIDGE_LICENSE_FILE`
- **Fails securely:** missing, tampered, expired, or malformed licences degrade to Community with a logged warning — the app never crashes over licensing
- **Live expiry:** the tier is re-checked on every query, so a licence that lapses while the app is running downgrades in place without a restart
- **Admin about page** shows current tier badge, licence status, customer, and expiry
- **In-app licence installation** — admins upload signed licence files at `/admin/about`; the file is verified before anything is written, rejected uploads preserve the current licence, and installs take effect immediately with an audit log entry

#### Admin Plugin Manager
**Install, enable, disable, and uninstall plugins from the browser**

New `/admin/plugins` blueprint replaces the previous "SSH in and place a `.py` file in `external_plugins/`" workflow.

- **Package format:** plugins ship as `.zip` or `.tar.gz` archives containing a `plugin.yaml` manifest, an entry-point Python file, and any supporting modules
- **12-step install validation chain:** archive safety (traversal, symlinks, decompression bomb caps), manifest structure, minimum TrakBridge version, **tier gate**, **signature verification**, AST code scan (rejects `exec`/`eval`/`os.system`/`subprocess`/`ctypes`), base-class inheritance verification, and identity-rule enforcement — a rejected package leaves no trace on disk, in the database, or in the whitelist
- **Signature verification:** packages signed with the Emfour Ed25519 key show a green "Verified" badge; tampered signatures are rejected outright. Unsigned third-party packages install with an explicit "UNVERIFIED" warning
- **Tier gating:** `plugin.yaml` gains an optional `tier` field enforced at BOTH install time and load time — a premium plugin cannot be loaded on a Community deployment even if the file is manually copied into `external_plugins/`
- **Lifecycle actions:** enable/disable toggles the whitelist without deleting files; uninstall removes files, database record, and whitelist entry. Both block cleanly if any active stream references the plugin
- **Audit logging** on every action (install accepted/rejected, enable/disable/uninstall) with admin username, plugin id, tier, and verification status
- **Sidebar link:** admin users see a new "Plugins" entry alongside Key Rotation

#### Whitelist Gating (Security Hardening)
**External plugins now require explicit allow-listing**

Previously, any Python file dropped into `external_plugins/` would be loaded automatically by the plugin manager. This release removes that blanket allowance: each external plugin now requires an explicit `external_plugins.<plugin_id>` entry in `plugins.yaml` — managed automatically by the plugin manager UI.

**Backwards compatible:** on startup, the plugin manager auto-adds whitelist entries for any pre-existing external plugins so current deployments continue to work without manual intervention. See [Upgrade Notes](#upgrade-notes) below.

---

### DATABASE CHANGES

New tables (added via Alembic migration `add_plugin_management_tables`):

- **`installed_plugins`** — tracks packaged external plugins (id, version, tier, verified flag, enabled state, install metadata)
- **`plugin_audit_log`** — records every plugin lifecycle action (install/enable/disable/uninstall) with admin username, licence id where applicable, and outcome

Docker deployments run migrations automatically via `docker/entrypoint.sh`; source deployments need `flask db upgrade`.

---

### BUG FIXES

- **`add_ca_cert_to_streams` migration** now uses `safe_add_column`/`safe_drop_column` and no longer crashes with `DuplicateColumn` on partially-populated Postgres schemas
- **Plugin category display** in the stream edit UI correctly reflects the CoT Forwarding vs Notifications split introduced in 1.3.0

---

### UPGRADE NOTES

**From 1.3.x → 2.0.0**

- **Run `flask db upgrade`** to create the two new plugin management tables (Docker: automatic on startup; source: manual)
- **External plugins:** anything currently loaded from `external_plugins/` will be auto-registered in the new whitelist on first startup — no action required
- **Docker image size** increased by ~5MB due to new runtime dependencies for the plugin manager (`libpq5` was already present; no new system packages)
- **Global request size limit** raised from 1MB to 12MB to accommodate plugin package uploads. Per-route caps remain the real enforcement (licence 16KB, cert 5MB, plugin 10MB)

**No breaking changes for end users** — every 1.3 workflow continues to work identically. The changes affect plugin authors and administrators managing plugin installations.

---

### FOR PLUGIN DEVELOPERS

The SDK is available now:

```bash
pip install trakbridge-plugin-sdk
```

- **[Plugin contract documentation](https://github.com/emfoursolutions/trakbridge-plugin-sdk/blob/main/docs/plugin_contract.md)** in the SDK repository
- **Example plugins** for all three types (tracker, output, inbound) in `trakbridge-plugin-sdk/examples/`
- **Repository:** [github.com/emfoursolutions/trakbridge-plugin-sdk](https://github.com/emfoursolutions/trakbridge-plugin-sdk) (Apache-2.0)
- **PyPI:** [pypi.org/project/trakbridge-plugin-sdk](https://pypi.org/project/trakbridge-plugin-sdk/)

---



**Release Date:** July 3, 2026
**Focus: Push-Based Inbound Streams, New Outbound Plugins, UDP Multicast CoT Bridge, TAK Worker Stability, Auth Hardening**

---

### NEW FEATURES

#### Inbound Stream Architecture
**Receive Data from External Sources**

TrakBridge can now accept push-based data from external systems via a dedicated inbound stream pipeline.

- **HTTP push endpoint** — `POST /api/inbound/<stream_id>/data` receives location payloads and routes them through the CoT pipeline to configured TAK servers. Security controls include anti-enumeration responses (consistent timing regardless of stream existence), IP allowlist enforcement, coordinate validation, payload size limits, per-stream rate limiting, and API key masking in logs.
- **Capture buffer & preview mode** — Inbound streams can capture received payloads into a bounded buffer for inspection via the stream detail page before committing to live routing. Useful for validating field mappings against real data.
- **`InboundStreamWorker`** — Dedicated worker class manages the lifecycle of push-based streams inside `StreamManager`, with the same health monitoring and registry cleanup as outbound workers.
- **Inbound stream UI** — Stream detail and create/edit pages surface inbound-specific configuration: API key (with generate button), rate limiting, IP allowlist, and Preview Mode badge.

#### Active-Connect Inbound Plugins
**TrakBridge Connects Out to Pull Data In**

- **MQTT active-connect** — TrakBridge connects to an MQTT broker, subscribes to a configurable topic, and forwards received CoT to TAK servers. Supports plain and TLS/mTLS connections via the existing certificate infrastructure (`cert_utils.build_ssl_context()`).
- **WebSocket active-connect** — TrakBridge connects to a WebSocket server and forwards received CoT messages.
- **Generic inbound plugins** — `generic_xml_inbound` and `generic_inbound` provide a baseline push-receive implementation registered in the plugin manager, available for all stream types.
- **CA cert upload** — Inbound streams now support uploading a CA certificate bundle for TLS verification of upstream sources.

#### Inbound Plugin Display Names

Inbound plugin display names have been updated to be more descriptive and consistent:

| Plugin | Previous name | New name |
| ------ | ------------- | -------- |
| `generic_inbound` | Generic Inbound | **JSON Receiver** |
| `generic_xml_inbound` | Generic XML Inbound | **XML Receiver** |
| `inbound_http` | Inbound HTTP | **HTTP Location Endpoint** |
| `inbound_active` | Inbound Active | **MQTT / WebSocket Client** |

#### UDP Multicast CoT Bridge
**Bridge LAN Multicast Across VPN/WAN Links**

The `udp_multicast_listener` inbound plugin joins a UDP multicast group and forwards every received CoT event to all TAK servers configured on the stream — bridging ATAK Mesh SA traffic across network segments where IP multicast does not route.

**Wire format support:**
- **CoT XML** — forwarded verbatim to the TAK output queue
- **TAK Protocol v1 Mesh SA protobuf** — detected by magic bytes (`0xbf 0x01 0xbf`), decoded via `takproto` to CoT XML, then forwarded through the standard TAK output path

**Network configuration:**
- Joins IGMPv2 by default; IGMPv3 source-specific multicast available via `source_filter`
- Configurable bind interface for multi-homed hosts
- Per-source token-bucket rate limiting; first five dropped datagrams per stream sampled into logs with source IP and 200-byte hex preview for triage

**Docker guidance:**
- `macvlan` network (recommended): container gets a LAN IP, keeps reverse-proxy reachability
- `network_mode: host` (simplest): no proxy/reverse-proxy required

> **Note:** ATAK Mesh SA AES encryption is intentionally not yet implemented — wire layout needs verification against ATAK-CIV source before any crypto is written.

#### Plugin Category Split: CoT Forwarding & Notifications

Output plugins are now organised into two distinct categories in the stream creation UI:

**CoT Forwarding** — plugins that forward raw CoT events to external systems:
`outbound_http`, `outbound_mqtt`, `outbound_websocket`, `udp_multicast_publisher`

**Notifications** — plugins that post human-readable alerts to messaging platforms:
`discord_handler`, `slack_handler`, `irc_handler`

Previously all seven appeared under a single "Output Handlers" category. Splitting them makes it easier to find the right plugin for the job.

#### CoT Forwarding Plugins

**Forward CoT to External Systems**

Three focused forwarding plugins replace the legacy `webhook_handler`:

**OutboundHTTP** — POSTs or PUTs CoT events to any HTTP/HTTPS endpoint:
- Payload formats: JSON, raw XML, or custom template
- Full message rules, UID filtering, geofence, and deduplication pipeline
- Scheme allow-listing (http/https only) prevents non-HTTP URLs reaching network I/O
- CRLF injection prevention in custom headers at the field level

**OutboundMQTT** — Publishes CoT events to an MQTT broker topic:
- Persistent paho-mqtt connection with `loop_start`/`loop_stop`
- TLS/mTLS via `cert_utils.build_ssl_context()` for `mqtts://` URLs
- Bounded queue with oldest-drop semantics; every drop increments `events_dropped`
- Bad-auth detection: plugin stays disconnected and logs clearly when credentials are wrong

**OutboundWebSocket** — Maintains a persistent WebSocket connection and streams CoT events:
- Exponential backoff reconnect (cap 30s) with background reader for proactive server-close detection
- Bounded queue with oldest-drop semantics
- URL credential redaction in all log statements
- Scheme allow-listing (ws/wss only)

**UDP Multicast Publisher** — publishes CoT events to a UDP multicast group.
Forwarded event counts are now persisted to the stream DB record via a batched flush (every 30 seconds or on plugin stop), fixing the "0 Messages Sent" display on the stream detail page.

**Shared output-plugin helpers** (`services/output_plugin_helpers.py`):
- CoT variable extraction, template formatting, message rule filtering, geofence evaluation, deduplication, rate limiting, and payload building extracted into a reusable module
- All forwarding plugins compose against this module; no logic duplication

The legacy `webhook_handler.py` plugin and its test files have been removed. Documentation updated throughout.

#### CoT Identity Heartbeat Improvements

- `how` attribute set to `h-e` (human-entered) for team-member CoT types — TAK Server was rejecting machine-generated `m-g` for these events
- `precisionlocation` element added to team-member heartbeats for well-formed XML acceptance
- `__group` always emitted with sensible team colour/role defaults when identity is enabled
- Identity CoT now sent **before** draining the event queue at TX start — TAK Server sees TrakBridge in the roster before any event stream begins

---

### BUG FIXES

#### Expired Password Redirect & Admin Reset Lockout

Users with an expired password were previously dropped into the application with an inconsistent session state instead of being redirected to the change-password flow. Admins triggering a force-reset were similarly affected.

The root cause was that admin-initiated resets set `password_changed_at` to `None`, which the expiry check treated as "never changed" — immediately expired. This locked the user in a redirect loop on next login.

**Fix:** A new `must_change_password` boolean column on the users table decouples forced-change from expiry state. Setting this flag redirects the user to the change-password page on their next login without touching `password_changed_at`. The expiry check only fires for genuinely expired passwords; the forced-change flag fires independently.

A database migration (`add_must_change_password`) adds the column automatically on startup.

#### False-Positive Unhealthy Warnings for Output Plugin Workers

The stream manager's periodic health check emitted WARNING-level logs for output plugin workers (Discord, Slack, IRC, HTTP, MQTT, WebSocket, UDP Multicast Publisher) that were operating normally. These plugins do not hold a persistent TAK connection — they receive dispatched CoT events rather than maintaining a long-lived socket — so the absence of a connection is expected behaviour, not a fault.

**Fix:** Output plugin workers are now recognised as healthy when their task is running, regardless of TAK connection state. Genuine failures (task exited, plugin crashed) still surface as WARNING.

#### TAK Worker Task Leak on Stream Save (Critical)

Saving a stream configuration triggered `restart_worker`, which stopped the old worker and started a new one. The old `_enhanced_transmission_worker` caught `CancelledError` and broke out of its loop — but did **not** cancel the inner `_tx_loop`/`_rx_worker` child tasks it had spawned. Those orphaned tasks continued running against the now-removed queue and stale writer for 2+ seconds after `stop_worker` returned.

**What operators saw:** ~20 `Queue N does not exist` ERROR logs at 10Hz after every stream save, followed by the orphaned loop's writer failing — each failure charged to the circuit breaker for the TAK server ID the new healthy worker was also using. After three failures the breaker opened, locking operators out of the fresh connection for 60 seconds.

**Fix:** Child tasks are now hoisted to a local list at the top of each iteration. Both `except CancelledError` and `except Exception` handlers cancel and await all child tasks with `asyncio.gather(return_exceptions=True)` before breaking or sleeping. Also: `get_batch`'s `Queue N does not exist` log demoted from ERROR to DEBUG (callers handle the empty return; the log was pure noise during the 2s restart window).

#### New Worker Connection Closed on Stream Save

The old worker's `finally` block read `self.connections[tak_server_id]` at finally-execution time, not the connection that particular iteration owned. If the new worker had already stored its own connection under the same key (routine when `wait_for(timeout=5.0)` allows the old task to finish late), the old finally closed the new worker's socket — causing `Connection lost`, three circuit-breaker charges, and a 60-second lockout on a healthy connection.

**Fix:** Each `while True` iteration captures its connection as a local (initialised to `None`). The `finally` closes only that specific connection object and only clears the dict entry when it still points at the same object.

#### Stale Worker Entries Not Reaped

Workers whose streams were disabled without going through `stop_stream` (e.g. a Slack handler whose poll task exited cleanly) remained in `StreamManager.workers` forever, producing a WARNING every 60 seconds indefinitely.

**Fix:** `stop_stream` removes the worker in a `finally` block regardless of whether `worker.stop()` succeeds. `_periodic_health_check` now cross-references the database: workers for gone/inactive streams are reaped at INFO; workers for genuinely active streams still surface as WARNING so real bugs aren't silently swallowed.

#### StreamWriter Not Closed on Stop

`stop_worker` deleted the connection dict entry but relied on the cancelled TX loop's `finally` to close the underlying `StreamWriter`. That `finally` does not deterministically complete within the 5-second `wait_for` window, so the old socket stayed half-open and TAK Server kept the previous subscription alive (duplicate identity heartbeats and event traffic) until its ~60s stale timeout.

**Fix:** `stop_worker` now explicitly awaits `_cleanup_connection()` (`writer.close()` + `writer.wait_closed()`) after task cancellation, sending TCP FIN synchronously before returning.

#### Migration Column Name Missing

`add_inbound_stream_fields` called `sa.Column()` without the column name as the first positional argument, producing `Column` objects with blank `.name`. Alembic's `batch_op.add_column()` raised `ArgumentError: Column must be constructed with a non-blank name`, halting the migration chain and leaving the downstream `ca_cert` column unapplied — causing `column streams.ca_cert does not exist` errors on every query.

**Fix:** Column name added as first positional argument to each `sa.Column()` call.

#### Entrypoint Script Bugs

- `validate_schema()` called `return validate_schema_optimized` — bash returned the function name as a string, not its exit code. Validation was silently a no-op. Fixed to call the function and `return $?`.
- Dead `trap` on SIGTERM/SIGINT removed: `exec hypercorn` replaces the shell as PID 1; the trap could never fire. Hypercorn handles signals directly.
- ANSI colour codes in log output gated on `[[ -t 2 ]]` so `docker logs` and CI capture see plain text instead of raw escape sequences.

---

### INFRASTRUCTURE

#### Development Container
- Dev container now runs Hypercorn instead of `flask run --debug`. Werkzeug's reloader spawned a child process that opened a second TAK connection with the same UID and callsign, causing doubled subscriptions and doubled cleanup work on every restart. All environments now use a single Hypercorn worker — matches production topology so dev-environment bugs are the same class as production bugs.

#### Configuration
- `DevelopmentConfig.SQLALCHEMY_RECORD_QUERIES` now reads from the `SQLALCHEMY_RECORD_QUERIES` environment variable (default `false`) instead of hardcoding `True`. The env var overriding the compose setting was silently ignored before this fix.
- Werkzeug per-request access log level demoted to WARNING — the reverse proxy already records access logs; the per-static-asset lines were pure noise.

#### CI/CD
- Mosquitto and mosquitto-clients installed in all three integration-test jobs (SQLite, PostgreSQL, MySQL) to support real-broker MQTT integration tests
- Mosquitto CI fixture: duplicate `allow_anonymous` directive removed (broke older mosquitto); stderr now captured and included in `RuntimeError` message; passwd file/temp dir permissions relaxed to 0644/0755 for CI non-root mosquitto process

---

### UPGRADE INSTRUCTIONS

#### For New Installations
1. Deploy normally — all features available immediately
2. Create inbound streams via the new "Inbound" stream type option
3. Configure UDP multicast bridge if you have ATAK Mesh SA traffic to bridge
4. Create outbound streams for HTTP, MQTT, or WebSocket forwarding as needed

#### For Existing Deployments

1. **Automatic migration** — `add_inbound_stream_fields`, `add_ca_cert_to_streams`, and `add_must_change_password` migrations apply automatically on startup
2. **Zero configuration changes** — existing outbound streams continue operating unchanged
3. **New features opt-in** — inbound streams, multicast bridge, and new outbound plugins available when creating new streams
4. **Legacy webhook_handler** — if you have custom streams using `webhook_handler`, migrate them to `outbound_http`, `outbound_mqtt`, or `outbound_websocket` as appropriate
5. **Dev container** — `FLASK_ENV=development` containers now run Hypercorn; the duplicate TAK connection issue is resolved automatically
6. **Plugin categories** — existing streams are unaffected; the category split only changes how plugins are grouped in the stream creation UI

#### Validation Steps
1. Verify existing outbound streams operate normally after upgrade
2. Confirm database migrations applied cleanly (check startup logs for migration errors)
3. Test an inbound stream with the preview mode capture buffer before routing live
4. If using multicast bridge: verify `bind_interface` is set to your LAN NIC IP (not left as default in Docker without macvlan/host networking)
5. If migrating from webhook_handler: validate message rules and geofence configuration in the new plugin

---

## Version 1.3.0 - Inbound Streams, Outbound Plugins & Multicast Bridge

**Release Date:** July 3, 2026
**Focus: Push-Based Inbound Streams, New Outbound Plugins, UDP Multicast CoT Bridge, TAK Worker Stability, Auth Hardening**

---

### NEW FEATURES

#### Inbound Stream Architecture
**Receive Data from External Sources**

TrakBridge can now accept push-based data from external systems via a dedicated inbound stream pipeline.

- **HTTP push endpoint** — `POST /api/inbound/<stream_id>/data` receives location payloads and routes them through the CoT pipeline to configured TAK servers. Security controls include anti-enumeration responses (consistent timing regardless of stream existence), IP allowlist enforcement, coordinate validation, payload size limits, per-stream rate limiting, and API key masking in logs.
- **Capture buffer & preview mode** — Inbound streams can capture received payloads into a bounded buffer for inspection via the stream detail page before committing to live routing. Useful for validating field mappings against real data.
- **`InboundStreamWorker`** — Dedicated worker class manages the lifecycle of push-based streams inside `StreamManager`, with the same health monitoring and registry cleanup as outbound workers.
- **Inbound stream UI** — Stream detail and create/edit pages surface inbound-specific configuration: API key (with generate button), rate limiting, IP allowlist, and Preview Mode badge.

#### Active-Connect Inbound Plugins
**TrakBridge Connects Out to Pull Data In**

- **MQTT active-connect** — TrakBridge connects to an MQTT broker, subscribes to a configurable topic, and forwards received CoT to TAK servers. Supports plain and TLS/mTLS connections via the existing certificate infrastructure (`cert_utils.build_ssl_context()`).
- **WebSocket active-connect** — TrakBridge connects to a WebSocket server and forwards received CoT messages.
- **Generic inbound plugins** — `generic_xml_inbound` and `generic_inbound` provide a baseline push-receive implementation registered in the plugin manager, available for all stream types.
- **CA cert upload** — Inbound streams now support uploading a CA certificate bundle for TLS verification of upstream sources.

#### Inbound Plugin Display Names

Inbound plugin display names have been updated to be more descriptive and consistent:

| Plugin | Previous name | New name |
| ------ | ------------- | -------- |
| `generic_inbound` | Generic Inbound | **JSON Receiver** |
| `generic_xml_inbound` | Generic XML Inbound | **XML Receiver** |
| `inbound_http` | Inbound HTTP | **HTTP Location Endpoint** |
| `inbound_active` | Inbound Active | **MQTT / WebSocket Client** |

#### UDP Multicast CoT Bridge
**Bridge LAN Multicast Across VPN/WAN Links**

The `udp_multicast_listener` inbound plugin joins a UDP multicast group and forwards every received CoT event to all TAK servers configured on the stream — bridging ATAK Mesh SA traffic across network segments where IP multicast does not route.

**Wire format support:**
- **CoT XML** — forwarded verbatim to the TAK output queue
- **TAK Protocol v1 Mesh SA protobuf** — detected by magic bytes (`0xbf 0x01 0xbf`), decoded via `takproto` to CoT XML, then forwarded through the standard TAK output path

**Network configuration:**
- Joins IGMPv2 by default; IGMPv3 source-specific multicast available via `source_filter`
- Configurable bind interface for multi-homed hosts
- Per-source token-bucket rate limiting; first five dropped datagrams per stream sampled into logs with source IP and 200-byte hex preview for triage

**Docker guidance:**
- `macvlan` network (recommended): container gets a LAN IP, keeps reverse-proxy reachability
- `network_mode: host` (simplest): no proxy/reverse-proxy required

> **Note:** ATAK Mesh SA AES encryption is intentionally not yet implemented — wire layout needs verification against ATAK-CIV source before any crypto is written.

#### Plugin Category Split: CoT Forwarding & Notifications

Output plugins are now organised into two distinct categories in the stream creation UI:

**CoT Forwarding** — plugins that forward raw CoT events to external systems:
`outbound_http`, `outbound_mqtt`, `outbound_websocket`, `udp_multicast_publisher`

**Notifications** — plugins that post human-readable alerts to messaging platforms:
`discord_handler`, `slack_handler`, `irc_handler`

Previously all seven appeared under a single "Output Handlers" category. Splitting them makes it easier to find the right plugin for the job.

#### CoT Forwarding Plugins

**Forward CoT to External Systems**

Three focused forwarding plugins replace the legacy `webhook_handler`:

**OutboundHTTP** — POSTs or PUTs CoT events to any HTTP/HTTPS endpoint:
- Payload formats: JSON, raw XML, or custom template
- Full message rules, UID filtering, geofence, and deduplication pipeline
- Scheme allow-listing (http/https only) prevents non-HTTP URLs reaching network I/O
- CRLF injection prevention in custom headers at the field level

**OutboundMQTT** — Publishes CoT events to an MQTT broker topic:
- Persistent paho-mqtt connection with `loop_start`/`loop_stop`
- TLS/mTLS via `cert_utils.build_ssl_context()` for `mqtts://` URLs
- Bounded queue with oldest-drop semantics; every drop increments `events_dropped`
- Bad-auth detection: plugin stays disconnected and logs clearly when credentials are wrong

**OutboundWebSocket** — Maintains a persistent WebSocket connection and streams CoT events:
- Exponential backoff reconnect (cap 30s) with background reader for proactive server-close detection
- Bounded queue with oldest-drop semantics
- URL credential redaction in all log statements
- Scheme allow-listing (ws/wss only)

**UDP Multicast Publisher** — publishes CoT events to a UDP multicast group.
Forwarded event counts are now persisted to the stream DB record via a batched flush (every 30 seconds or on plugin stop), fixing the "0 Messages Sent" display on the stream detail page.

**Shared output-plugin helpers** (`services/output_plugin_helpers.py`):
- CoT variable extraction, template formatting, message rule filtering, geofence evaluation, deduplication, rate limiting, and payload building extracted into a reusable module
- All forwarding plugins compose against this module; no logic duplication

The legacy `webhook_handler.py` plugin and its test files have been removed. Documentation updated throughout.

#### CoT Identity Heartbeat Improvements

- `how` attribute set to `h-e` (human-entered) for team-member CoT types — TAK Server was rejecting machine-generated `m-g` for these events
- `precisionlocation` element added to team-member heartbeats for well-formed XML acceptance
- `__group` always emitted with sensible team colour/role defaults when identity is enabled
- Identity CoT now sent **before** draining the event queue at TX start — TAK Server sees TrakBridge in the roster before any event stream begins

---

### BUG FIXES

#### Expired Password Redirect & Admin Reset Lockout

Users with an expired password were previously dropped into the application with an inconsistent session state instead of being redirected to the change-password flow. Admins triggering a force-reset were similarly affected.

The root cause was that admin-initiated resets set `password_changed_at` to `None`, which the expiry check treated as "never changed" — immediately expired. This locked the user in a redirect loop on next login.

**Fix:** A new `must_change_password` boolean column on the users table decouples forced-change from expiry state. Setting this flag redirects the user to the change-password page on their next login without touching `password_changed_at`. The expiry check only fires for genuinely expired passwords; the forced-change flag fires independently.

A database migration (`add_must_change_password`) adds the column automatically on startup.

#### False-Positive Unhealthy Warnings for Output Plugin Workers

The stream manager's periodic health check emitted WARNING-level logs for output plugin workers (Discord, Slack, IRC, HTTP, MQTT, WebSocket, UDP Multicast Publisher) that were operating normally. These plugins do not hold a persistent TAK connection — they receive dispatched CoT events rather than maintaining a long-lived socket — so the absence of a connection is expected behaviour, not a fault.

**Fix:** Output plugin workers are now recognised as healthy when their task is running, regardless of TAK connection state. Genuine failures (task exited, plugin crashed) still surface as WARNING.

#### TAK Worker Task Leak on Stream Save (Critical)

Saving a stream configuration triggered `restart_worker`, which stopped the old worker and started a new one. The old `_enhanced_transmission_worker` caught `CancelledError` and broke out of its loop — but did **not** cancel the inner `_tx_loop`/`_rx_worker` child tasks it had spawned. Those orphaned tasks continued running against the now-removed queue and stale writer for 2+ seconds after `stop_worker` returned.

**What operators saw:** ~20 `Queue N does not exist` ERROR logs at 10Hz after every stream save, followed by the orphaned loop's writer failing — each failure charged to the circuit breaker for the TAK server ID the new healthy worker was also using. After three failures the breaker opened, locking operators out of the fresh connection for 60 seconds.

**Fix:** Child tasks are now hoisted to a local list at the top of each iteration. Both `except CancelledError` and `except Exception` handlers cancel and await all child tasks with `asyncio.gather(return_exceptions=True)` before breaking or sleeping. Also: `get_batch`'s `Queue N does not exist` log demoted from ERROR to DEBUG (callers handle the empty return; the log was pure noise during the 2s restart window).

#### New Worker Connection Closed on Stream Save

The old worker's `finally` block read `self.connections[tak_server_id]` at finally-execution time, not the connection that particular iteration owned. If the new worker had already stored its own connection under the same key (routine when `wait_for(timeout=5.0)` allows the old task to finish late), the old finally closed the new worker's socket — causing `Connection lost`, three circuit-breaker charges, and a 60-second lockout on a healthy connection.

**Fix:** Each `while True` iteration captures its connection as a local (initialised to `None`). The `finally` closes only that specific connection object and only clears the dict entry when it still points at the same object.

#### Stale Worker Entries Not Reaped

Workers whose streams were disabled without going through `stop_stream` (e.g. a Slack handler whose poll task exited cleanly) remained in `StreamManager.workers` forever, producing a WARNING every 60 seconds indefinitely.

**Fix:** `stop_stream` removes the worker in a `finally` block regardless of whether `worker.stop()` succeeds. `_periodic_health_check` now cross-references the database: workers for gone/inactive streams are reaped at INFO; workers for genuinely active streams still surface as WARNING so real bugs aren't silently swallowed.

#### StreamWriter Not Closed on Stop

`stop_worker` deleted the connection dict entry but relied on the cancelled TX loop's `finally` to close the underlying `StreamWriter`. That `finally` does not deterministically complete within the 5-second `wait_for` window, so the old socket stayed half-open and TAK Server kept the previous subscription alive (duplicate identity heartbeats and event traffic) until its ~60s stale timeout.

**Fix:** `stop_worker` now explicitly awaits `_cleanup_connection()` (`writer.close()` + `writer.wait_closed()`) after task cancellation, sending TCP FIN synchronously before returning.

#### Migration Column Name Missing

`add_inbound_stream_fields` called `sa.Column()` without the column name as the first positional argument, producing `Column` objects with blank `.name`. Alembic's `batch_op.add_column()` raised `ArgumentError: Column must be constructed with a non-blank name`, halting the migration chain and leaving the downstream `ca_cert` column unapplied — causing `column streams.ca_cert does not exist` errors on every query.

**Fix:** Column name added as first positional argument to each `sa.Column()` call.

#### Entrypoint Script Bugs

- `validate_schema()` called `return validate_schema_optimized` — bash returned the function name as a string, not its exit code. Validation was silently a no-op. Fixed to call the function and `return $?`.
- Dead `trap` on SIGTERM/SIGINT removed: `exec hypercorn` replaces the shell as PID 1; the trap could never fire. Hypercorn handles signals directly.
- ANSI colour codes in log output gated on `[[ -t 2 ]]` so `docker logs` and CI capture see plain text instead of raw escape sequences.

---

### INFRASTRUCTURE

#### Development Container
- Dev container now runs Hypercorn instead of `flask run --debug`. Werkzeug's reloader spawned a child process that opened a second TAK connection with the same UID and callsign, causing doubled subscriptions and doubled cleanup work on every restart. All environments now use a single Hypercorn worker — matches production topology so dev-environment bugs are the same class as production bugs.

#### Configuration
- `DevelopmentConfig.SQLALCHEMY_RECORD_QUERIES` now reads from the `SQLALCHEMY_RECORD_QUERIES` environment variable (default `false`) instead of hardcoding `True`. The env var overriding the compose setting was silently ignored before this fix.
- Werkzeug per-request access log level demoted to WARNING — the reverse proxy already records access logs; the per-static-asset lines were pure noise.

#### CI/CD
- Mosquitto and mosquitto-clients installed in all three integration-test jobs (SQLite, PostgreSQL, MySQL) to support real-broker MQTT integration tests
- Mosquitto CI fixture: duplicate `allow_anonymous` directive removed (broke older mosquitto); stderr now captured and included in `RuntimeError` message; passwd file/temp dir permissions relaxed to 0644/0755 for CI non-root mosquitto process

---

### UPGRADE INSTRUCTIONS

#### For New Installations
1. Deploy normally — all features available immediately
2. Create inbound streams via the new "Inbound" stream type option
3. Configure UDP multicast bridge if you have ATAK Mesh SA traffic to bridge
4. Create outbound streams for HTTP, MQTT, or WebSocket forwarding as needed

#### For Existing Deployments

1. **Automatic migration** — `add_inbound_stream_fields`, `add_ca_cert_to_streams`, and `add_must_change_password` migrations apply automatically on startup
2. **Zero configuration changes** — existing outbound streams continue operating unchanged
3. **New features opt-in** — inbound streams, multicast bridge, and new outbound plugins available when creating new streams
4. **Legacy webhook_handler** — if you have custom streams using `webhook_handler`, migrate them to `outbound_http`, `outbound_mqtt`, or `outbound_websocket` as appropriate
5. **Dev container** — `FLASK_ENV=development` containers now run Hypercorn; the duplicate TAK connection issue is resolved automatically
6. **Plugin categories** — existing streams are unaffected; the category split only changes how plugins are grouped in the stream creation UI

#### Validation Steps
1. Verify existing outbound streams operate normally after upgrade
2. Confirm database migrations applied cleanly (check startup logs for migration errors)
3. Test an inbound stream with the preview mode capture buffer before routing live
4. If using multicast bridge: verify `bind_interface` is set to your LAN NIC IP (not left as default in Docker without macvlan/host networking)
5. If migrating from webhook_handler: validate message rules and geofence configuration in the new plugin

---

## Version 1.2.3 - TAK Connection Auto-Recovery

**Release Date:** March 23, 2026
**Focus: Automatic TAK Server Reconnection & Circuit Breaker Recovery**

---

### BUG FIXES

#### TX Worker Auto-Reconnect on Connectivity Loss

- **Automatic reconnection with exponential backoff** — When a TAK server connection is lost (network outage, server restart, etc.), the TX worker now automatically retries with exponential backoff (5s → 10s → 20s → ... capped at 120s) instead of exiting permanently. When connectivity is restored, the worker reconnects and resumes transmitting without any manual intervention. Backoff resets to 5s after a successful connection.
- **Circuit breaker reset before reconnection** — The circuit breaker is reset to CLOSED before each connection attempt, preventing stale OPEN state from blocking recovery after transient failures.

#### Circuit Breaker Not Recovering After Stream Edit

- **Circuit breaker reset on worker stop** — When a stream is edited and saved, TrakBridge stops and restarts the stream worker. Previously, the circuit breaker (keyed per TAK server) remained in OPEN state from connection errors during the teardown, blocking the restarted worker from establishing a new connection. The circuit breaker is now reset to CLOSED during worker stop, allowing the restarted stream to connect immediately.
- **Dead worker cleanup resets circuit breaker** — If the stream worker detects a dead TX worker task and attempts to revive it via `start_worker()`, the circuit breaker is now reset as part of dead worker cleanup.
- **Stale connection cleanup** — Worker stop now removes the old connection reference from the connection registry, preventing dead socket reuse on restart.

---

## Version 1.2.2 - Plugin Poll Interval & Queue Capacity

**Release Date:** March 21, 2026
**Focus: Plugin Developer Experience & High-Volume Stream Stability**

---

### ENHANCEMENTS

#### Plugin-Overridable Minimum Poll Interval

- **New `min_poll_interval` metadata key** — Plugins can now declare a minimum poll interval as low as 1 seconds, overriding the previous hard-coded 30-second floor
- **Dynamic UI enforcement** — Stream create/edit forms read the plugin's `min_poll_interval` from metadata and adjust the HTML input minimum accordingly
- **Global floor lowered** — JSON validator schema minimum reduced from 30 to 1 seconds; individual plugins control their own safe minimum
- **Backward compatible** — Plugins without `min_poll_interval` default to the existing 30-second minimum

#### Queue Capacity Increase

- **Max queue size increased** from 500 to 600 events to accommodate high-volume streams (e.g. AIS producing 400+ events per cycle)
- **Warning threshold raised** to 600 to match the new capacity, reducing false-positive queue warnings

### BUG FIXES

#### TAK Connection Stability

- **TX loop clean exit on dead connections** — Connection errors (`ConnectionError`, `OSError`, `SSLError`) now cause the TX loop to break immediately instead of retrying on a dead socket, eliminating error spam when stream config changes tear down SSL connections
- **Identity heartbeat propagates connection errors** — A dead socket during heartbeat write now exits the TX loop cleanly instead of being silently caught
- **Transmit batch aborts on connection loss** — Remaining events in a batch are skipped when the socket is dead, instead of logging errors for each one

#### RX Worker Resilience

- **Exponential backoff on RX errors** — RX worker now backs off from 1s to 60s on repeated errors instead of retrying every second
- **SSL error give-up threshold** — After 5 consecutive SSL failures, the RX worker stops cleanly with a log message suggesting certificate check or disabling `enable_rx`
- **Improved RX error logging** — Error messages now include the TAK server ID, attempt count, and next retry delay

#### Queue Configuration

- **Performance.yaml settings now applied** — Queue manager was ignoring `max_size`, `queue_warning_threshold`, and transmission settings from `performance.yaml` due to config keys living under separate YAML sections (`queue`, `monitoring`, `transmission`) that weren't merged before being passed to the queue manager
- **Stale hardcoded defaults updated** — Internal fallback defaults updated from 500/400 to 600/600 to match `performance.yaml`

### DOCUMENTATION

- Plugin Development Guide (wiki and docs) updated with `min_poll_interval` usage, behaviour table, and code examples

---

## Version 1.2.1 - Stability & Security Patch

**Release Date:** March 17, 2026
**Focus: Production Stability, Log Hygiene, Data Corrections**

---

### BUG FIXES

#### Security & Log Hygiene

- **Database credential sanitisation** — DB connection strings in logs are now masked to prevent credential leakage
- **Reduced handler plugin log noise** — Suppressed repetitive log messages from output handler plugins during normal operation

#### Startup Reliability

- **Migration race condition fix** — Prevented the startup monitoring thread from querying the database before migrations complete, eliminating transient errors on first boot

#### Data Corrections

- **LiveUAMap region IDs** — Corrected region identifiers to match current LiveUAMap API; expanded from 140+ to 180+ selectable regions
- **TrakBridge Identity echo filtering** — Identity heartbeat CoT is no longer re-dispatched to output handler plugins

#### Infrastructure

- **Docker networking cleanup** — Removed external port bindings from dev and staging Docker Compose files; all service communication uses Docker internal networking

---

## Version 1.2.0 - Handler Plugins & Bidirectional TAK Release
**Release Date:** March 6, 2026
**Major Features: Output/Handler Plugin Architecture, LiveUAMap OSINT Plugin, Security Hardening**

---

## NEW FEATURES & ENHANCEMENTS

### Bidirectional TAK Communication
**Receive CoT Messages from TAK Servers**

TrakBridge can now receive CoT messages from connected TAK servers and dispatch them to output handler plugins. This completes the bidirectional communication loop — TrakBridge is no longer send-only.

**Core Capabilities:**
- **RX worker** - Dedicated receive coroutine runs alongside the existing transmit loop on each TAK connection
- **Per-server toggle** - Enable or disable RX independently on each TAK server via `enable_rx` setting
- **Plugin dispatch** - Received CoT messages are routed to all registered output plugins with 10-second per-plugin timeout
- **Security screening** - Inbound XML is validated against XXE attacks and entity expansion before dispatch
- **Stability safeguards** - 1MB buffer limit and 30-second read timeout prevent resource exhaustion

**New Plugin Categories:**
- **Output** - Plugins that receive CoT from TAK and forward externally (IRC, Slack, Discord)
- **Bidirectional** - Reserved for plugins that both send and receive CoT

### IRC Handler Plugin
**Forward TAK Messages to IRC Channels**

- **IRC connectivity** - Connects over plain TCP or SSL (ports 6667/6697) with optional certificate verification
- **Message rules** - Configurable rules matching CoT type patterns with wildcards and optional UID regex filters
- **Template formatting** - Rich message templates with variables: `{callsign}`, `{lat}`, `{lon}`, `{mgrs}`, `{type}`, `{remarks}`, `{group_name}`, `{battery}`, `{speed}`, and more
- **Geofence filtering** - Global geographic bounding box filter to limit forwarded messages by location
- **Deduplication** - 5-second window prevents double-posting from TAK server re-broadcasts
- **Persistent connection** - PING/PONG keepalive with async reader task

### Discord Webhook Output Plugin
**Forward TAK Messages to Discord Channels**

- **Webhook integration** - Posts to Discord channels via incoming webhook URL
- **Rich embeds** - Colour-coded Discord embeds with structured fields for MGRS location, battery, group/role, and remarks
- **Plain text mode** - Alternative template-based plain text formatting
- **Message rules** - Same CoT type matching, UID filtering, and template system as IRC and Slack
- **Geofence filtering** - Global geographic bounding box filter
- **Deduplication** - 5-second TTL window

### Slack Handler Plugin
**Forward TAK Messages to Slack Channels**

- **Block Kit formatting** - Rich Slack messages using the blocks API
- **Webhook integration** - Posts via Slack incoming webhook URL
- **Message rules and templates** - Consistent with IRC and Discord handler plugins
- **Geofence filtering** - Global geographic bounding box filter
- **Sensitive field masking** - Webhook URLs masked on edit to prevent accidental exposure

### LiveUAMap OSINT Plugin
**Geolocated News and Conflict Events on TAK Maps**

- **LiveUAMap API integration** - Pulls geolocated events using a user-supplied API key
- **140+ selectable regions** - Organized into groups: international conflicts, US states, and more
- **CoT marker generation** - Each event becomes a map marker visible in ATAK/WinTAK
- **SPOTMAP iconset colours** - Markers are colour-coded by event type using ARGB values from the SPOTMAP iconset
- **Configurable limits** - 1–500 events per region per poll cycle
- **Historical queries** - Optional event time parameter for historical data
- **Location in remarks** - Event location string included in CoT remarks field

### TrakBridge Identity for TAK Servers
**Announce TrakBridge as a Named TAK Client**

- **Per-server identity toggle** - Control whether TrakBridge appears in the TAK roster on each server
- **Configurable identity** - Set callsign, role, team colour, and optional MGRS grid location
- **30-second heartbeat** - Identity CoT sent every 30 seconds with 60-second stale time
- **Two display modes:**
  - With MGRS location: appears as team member on the map (`a-f-G-U-C`)
  - Without location: appears in roster only (`b-t-c-v`)
- **Deterministic UID** - Consistent identity across restarts, derived from TAK server database ID

### Geofence Map Visualization
**Interactive Map Display for Geofence Boundaries**

- **Leaflet map** - Interactive map on stream detail page showing the configured geofence boundary
- **Visual overlay** - Blue rectangle representing the bounding box with coordinate popup on click
- **Auto-zoom** - Map automatically fits to geofence bounds
- **Output plugin support** - Shown for output plugins with global geofence enabled
- **COT Type card hidden** - Irrelevant COT Type card conditionally hidden for output plugin streams

### Metadata-Driven Plugin Components
**Dynamic UI Rendering from Plugin Metadata**

- **Component system** - Plugin UI components (message rules, geofence, multi-select) described in plugin metadata and rendered dynamically
- **Shared JavaScript** - Extracted ~1,070 lines of duplicated JS into four shared static files
- **Generic grouped multi-select** - Reusable component for any plugin needing multi-select with groups
- **Reduced template complexity** - Removed ~1,400 lines of hardcoded plugin-specific HTML/JS

### Sample Custom Handler Plugin
**Developer Reference Implementation**

- **Production-ready example** - Complete handler plugin demonstrating configuration, filtering, formatting, and lifecycle management
- **Developer guide** - 382-line HANDLER_PLUGIN_DEVELOPMENT_GUIDE.md covering the full development workflow
- **Updated plugin docs** - Distinguishes input (GPS tracker) vs. output (handler) plugin types

---

## SECURITY IMPROVEMENTS

### Comprehensive Security Hardening

- **IP Spoofing Prevention** - `X-Forwarded-For` header only trusted when `PROXY_TRUSTED=true` is explicitly set, with configurable `TRUSTED_PROXY_COUNT`
- **CSRF Protection** - Flask-WTF CSRFProtect added globally with tokens on all 11 HTML forms
- **Session Fixation Prevention** - Session cleared and regenerated on every login for all auth methods
- **HTTP Security Headers** - flask-talisman enforces HSTS, Content-Security-Policy, frame-ancestors, X-Content-Type-Options, and Referrer-Policy
- **XML Security** - Inbound CoT XML screened for XXE attacks and billion-laughs entity expansion
- **Updated SECURITY.md** - Documentation updated with recent security improvements

---

## INFRASTRUCTURE & CI/CD

### Modular CI/CD Pipeline
**Maintainable Pipeline Architecture**

- **Split monolithic pipeline** - ~2,500 line `.gitlab-ci.yml` split into focused modules under `.gitlab/ci/`
- **Pipeline modules:** `test.yml`, `security.yml`, `build.yml`, `deploy.yml`, `release.yml`, `validate.yml`
- **Shared templates** - Reusable anchors for package installation, database services, and common configurations
- **Pipeline documentation** - README.md documenting CI structure and usage

### Deployment Improvements

- **Docker networking** - Removed external ports from dev and staging environments; all communication through Docker internal networking
- **Traefik labels** - Development environment uses configurable `${COMPOSE_PROJECT_NAME}` and `${DOMAIN}` variables
- **Database flexibility** - Dev compose DB config overridable for MySQL and SQLite deployments
- **Staging image tags** - Fixed IMAGE_TAG variable mismatch in staging compose
- **SSL certificate checks** - Disabled for deployment health checks on staging and production

---

## BUG FIXES

### Plugin Fixes
- **Deepstate URL** now optional, falls back to default if left blank
- **Custom CoT attributes** supported in fallback CoT path with debug logging
- **COT Type selector** hidden for plugins that manage their own CoT types
- **Per-point CoT type mode** forced for plugins with `hide_cot_type`
- **Custom component hidden inputs** now include `data-plugin` attribute for proper JS collection
- **SPOTMAP iconset colours** updated to match actual SPOTMAP values

### Infrastructure Fixes
- **LDAP TLS** - Respects `validate_cert` and `ca_cert_file` settings in TLS configuration
- **P12 certificates** - Pre-convert P12 to PEM to avoid pytak crash when CA cert missing
- **Frozen DTO** - Handle frozen DTO when setting `identity_uid_suffix` in heartbeat loop
- **LiveUAMap regions** - Handle regions field as list or JSON string
- **Geofence persistence** - Global geofence enabled state now persists after save
- **Geofence map** - Prevent invalid longitude values in map drawing
- **Output plugin lifecycle** - Proper connection cleanup management
- **Message metrics** - Calculated correctly after template cleanup
- **Event loop** - Handle RuntimeError when awaiting a task created in a different event loop
- **Logging watchdog** - Avoid feedback loop when debug mode is enabled with noisy logging suppression
- **CSP violations** - Resolved Content Security Policy violations and CSRF API exemption issues

---

## DOCUMENTATION

- **User Guide** updated to include handler plugins and LiveUAMap plugin
- **Handler Plugin Development Guide** - Comprehensive guide for building custom output plugins
- **Sample custom handler plugin** with full documentation
- **Plugin development docs** updated to distinguish input vs. output plugin types
- **SECURITY.md** updated with recent improvements

---

## UPGRADE INSTRUCTIONS

### For New Installations
1. **Deploy normally** - All new features available immediately
2. **Configure TAK servers** - Enable RX and TrakBridge identity as needed
3. **Create output streams** - Set up IRC, Slack, or Discord handler plugins
4. **Add LiveUAMap** - Configure with API key and select regions
5. **Verify in ATAK** - Confirm TrakBridge identity appears in roster

### For Existing Deployments
1. **Automatic migration** - Database schema updates applied automatically on startup
2. **Zero configuration changes** - Existing streams continue operating unchanged
3. **New features opt-in** - Handler plugins, identity, and LiveUAMap available when creating new streams
4. **Security improvements active** - CSRF protection, security headers, and session hardening active immediately
5. **CI/CD pipeline** - Update `.gitlab-ci.yml` to use new modular includes if using GitLab CI

### Validation Steps
1. **Verify existing streams** - Confirm current streams operate normally after upgrade
2. **Test RX functionality** - Enable RX on a TAK server and verify CoT messages are received
3. **Test output plugins** - Create a test stream with IRC, Slack, or Discord handler
4. **Check TrakBridge identity** - Enable identity on a TAK server and verify it appears in ATAK roster
5. **Review security** - Confirm CSRF tokens are present on forms and security headers are active

---

## Version 1.1.0 - Team Member COT Enhancement Release
**Release Date:** November 7, 2025
**Major Feature: ATAK Team Member Support**

---

## NEW FEATURES & ENHANCEMENTS

### Team Member COT Support
**Display Trackers as ATAK Team Members**

Transform individual GPS trackers into ATAK team members with full role and color customization through the existing callsign mapping interface.

**Core Capabilities:**
- **Team member CoT format** - Individual trackers displayed as team members in ATAK instead of standard mil2525 points
- **Role assignment** - Choose from 8 tactical roles: Team Member, Team Lead, HQ, Sniper, Medic, Forward Observer, RTO, K9
- **Color customization** - Select from 14 team colors: Teal, Green, Dark Green, Brown, White, Yellow, Orange, Magenta, Red, Maroon, Purple, Dark Blue, Blue, Cyan
- **Seamless integration** - Uses existing callsign mapping UI workflow with new CoT type option
- **Custom callsigns** - Team member names use your configured custom callsigns
- **Mixed configurations** - Configure some trackers as team members and others as standard points in the same stream

**Technical Implementation:**
- **CoT type "a-f-G-U-C"** with "h-e" how attribute for proper ATAK team member display
- **Static endpoint** "*:-1:stcp" for team member contact format
- **Enhanced XML structure** - Includes `<contact>`, `<uid>`, `<__group>`, `<precisionlocation>`, and `<status>` elements
- **Zero performance impact** - Reuses existing COT generation pipeline with minimal overhead
- **Complete test coverage** - Comprehensive TDD approach with end-to-end workflow validation

**Key Benefits:**
- **Enhanced situational awareness** - Team members display with roles and colors in ATAK
- **Operational flexibility** - Quickly identify team roles and assignments on the map
- **Tactical coordination** - Color-coded teams improve coordination and communication
- **Simple configuration** - Integrated into existing callsign mapping workflow
- **Backward compatible** - Existing streams and configurations work unchanged

**Usage Example:**
1. Create or edit a GPS tracker stream (Garmin, SPOT, Traccar)
2. Enable "Custom callsign mapping" and discover trackers
3. For each tracker, select CoT Type: "Team Member"
4. Choose team role (e.g., "Sniper") and color (e.g., "Green")
5. Enter custom callsign (e.g., "Alpha-1")
6. Tracker now displays as a team member in ATAK with role icon and color

### Unknown Air Unit COT Type
**Enhanced Aircraft Tracking**

- **New CoT type** for unidentified aircraft contacts
- **Improved air domain** situational awareness
- **Enhanced COT type system** supporting unknown air contacts

---

## TECHNICAL IMPROVEMENTS

### Database Schema Enhancement
**Team Member Configuration Storage**

- **Extended CallsignMapping model** with team member fields:
  - `cot_type_override` - Stores "team_member" when team member CoT selected
  - `team_role` - Stores selected role (Team Member, Team Lead, HQ, Sniper, etc.)
  - `team_color` - Stores selected color (Red, Blue, Green, etc.)
- **Safe migration** with comprehensive existence checks and rollback capability
- **Backward compatibility** - Existing callsign mappings work unchanged (fields default to null)
- **Data integrity** - Validation ensures only valid roles and colors can be stored

### COT Generation Pipeline Enhancement
**Intelligent Team Member Detection**

- **Enhanced _create_pytak_events** - Detects team member configuration in location additional_data
- **Modified _generate_cot_xml** - Generates proper team member XML structure with all required elements
- **Code reuse** - Leverages existing COT pipeline completely, no duplication
- **Minimal changes** - Surgical enhancements to existing methods maintain stability
- **Performance optimized** - No additional database queries, data loaded with existing mappings

### Plugin Integration
**Seamless Data Flow**

- **Enhanced apply_callsign_mapping** - Adds team member metadata to location's additional_data
- **Consistent interface** - Uses existing BaseGPSPlugin callsign mapping infrastructure
- **Universal support** - Works with all GPS tracker plugins (Garmin, SPOT, Traccar)
- **No plugin changes** - Existing plugin processing logic unchanged

### API Extensions
**Team Member Configuration Endpoints**

- **Extended callsign mapping APIs** - Handle team_role, team_color, and cot_type_override fields
- **Input validation** - Ensures only valid roles and colors accepted
- **Metadata endpoints** - Provide role and color options for UI dropdowns
- **Backward compatible** - Existing API clients continue working unchanged

---

## COMPREHENSIVE TESTING

### End-to-End Testing Framework
**Production-Ready Quality Assurance**

- **Complete workflow tests** - Stream creation → tracker discovery → team member configuration → CoT generation → TAK transmission
- **XML structure validation** - Verifies team member CoT format matches ATAK specification
- **Mixed configuration tests** - Validates streams with both team members and standard points
- **Edge case handling** - Tests with missing fields, invalid roles/colors, and migration scenarios
- **Performance validation** - Confirms zero performance impact on existing functionality
- **Backward compatibility tests** - Ensures existing streams operate unchanged

### Test-Driven Development
**Quality Through TDD**

- **Comprehensive test coverage** - Unit, integration, and end-to-end tests for all features
- **Regression prevention** - Tests ensure future changes don't break team member functionality
- **Clear requirements** - Tests document exact team member feature behavior
- **Refactoring safety** - Can improve code structure while tests ensure behavior unchanged

---

## MIGRATION & COMPATIBILITY

### Automatic Database Migration
**Zero-Downtime Upgrade**

- **Automatic schema updates** - New columns added to callsign_mappings table on startup
- **Data preservation** - All existing streams, callsign mappings, and configurations maintained
- **Safe migration** - Comprehensive existence checks prevent duplicate columns
- **Rollback capability** - Complete downgrade path available if needed

### Backward Compatibility Guarantee
**Seamless Upgrade Experience**

- **Existing functionality preserved** - All current features work exactly as before
- **Configuration compatibility** - Existing callsign mappings continue operating unchanged
- **API compatibility** - All existing API endpoints maintain backward compatibility
- **Performance baseline** - No degradation for existing configurations
- **Opt-in feature** - Team member support only active when explicitly configured

---

## OPERATIONAL BENEFITS

### For Operators and Users
- **Enhanced tactical display** - Team members show with roles and colors in ATAK
- **Improved coordination** - Quickly identify team roles and assignments on the map
- **Operational flexibility** - Configure trackers as team members or standard points per mission needs
- **Simple workflow** - Integrated into existing callsign mapping interface
- **No training required** - Uses familiar callsign mapping workflow with new options

### For System Administrators
- **Zero performance impact** - No overhead on existing functionality
- **Backward compatible** - Safe upgrade with no configuration changes required
- **Comprehensive testing** - Production-ready with extensive test coverage
- **Simple deployment** - Automatic migration handles all database changes
- **Flexible configuration** - Per-tracker team member configuration allows mixed deployments

### For Organizations
- **Enhanced situational awareness** - Better tactical picture with team member roles and colors
- **Operational efficiency** - Faster identification of team assets on the map
- **Cost effective** - Leverages existing GPS tracker infrastructure
- **Future proof** - Architecture designed for continued enhancement
- **Standards compliant** - Proper ATAK team member CoT format

---

## UPGRADE INSTRUCTIONS

### For New Installations
1. **Deploy normally** - Team member support available immediately
2. **Configure streams** - Create GPS tracker streams as usual
3. **Enable team members** - Select "Team Member" CoT type in callsign mapping
4. **Choose role and color** - Pick appropriate role and color for each tracker
5. **Verify in ATAK** - Confirm team members display correctly with roles and colors

### For Existing Deployments
1. **Automatic migration** - Database schema updates applied automatically on startup
2. **Zero configuration changes** - Existing streams continue operating unchanged
3. **Feature activation** - Team member support available when editing streams or creating new ones
4. **Test configuration** - Create test stream to validate team member functionality
5. **Gradual rollout** - Configure team members on new streams or edit existing as needed

### Validation Steps
1. **Verify existing streams** - Confirm current streams operate normally after upgrade
2. **Test team member feature** - Create test stream with team member configuration
3. **Check ATAK display** - Verify team members show correctly with roles and colors
4. **Performance monitoring** - Confirm no performance degradation
5. **Configuration backup** - Standard backup procedures protect against any issues

---

## Version 1.0.0-rc.5 - Scaling Enhancement & Tracker Control Release
**Release Date:** September 18, 2025  
**Major Features: Multi-Server Distribution & Individual Tracker Control**

---

## NEW FEATURES & ENHANCEMENTS

### Individual Tracker Enable/Disable Control 
**Selective Tracker Management for Operational Flexibility**

- **Checkbox controls** for enabling/disabling individual trackers within callsign mapping streams
- **Selective data flow control** - disable trackers to preserve configuration while stopping CoT data transmission
- **Visual feedback system** with smooth transitions and color-coded highlighting (green for enable, red for disable)
- **Bulk operations** - "Enable All" and "Disable All" buttons for rapid management of multiple trackers
- **State persistence** - enabled/disabled status preserved across tracker discovery refreshes
- **Enhanced accessibility** with comprehensive ARIA labels and keyboard navigation support

**Key Benefits:**
- **Operational Control**: Enable/disable individual trackers without losing configuration
- **Bandwidth Management**: Reduce network traffic by disabling unnecessary trackers
- **Tactical Flexibility**: Quickly adapt to changing operational requirements
- **Configuration Preservation**: Disabled trackers remain configured for future activation
- **User Experience**: Intuitive controls with clear visual feedback

### Multi-Server Distribution System
**Enterprise-Grade Scaling with Parallel Processing**

- **Single fetch, multiple distribution** - GPS data retrieved once then distributed to multiple TAK servers simultaneously
- **90% API call reduction** for multi-server scenarios through intelligent data sharing
- **Parallel CoT transformation** processing with 5-10x performance improvement for large datasets (300+ points)
- **Configurable batch processing** with automatic fallback to serial processing on errors
- **Server failure isolation** - problems with one TAK server don't affect others
- **Improved UI** with intuitive checkbox grid for multiple TAK server selection

**Performance Improvements:**
- **Large Datasets**: 5-10x faster processing for 300+ point datasets
- **API Efficiency**: 90% reduction in external API calls for multi-server configurations  
- **Network Optimization**: Massive reduction in bandwidth usage through data sharing
- **Processing Time**: <2 seconds for 100+ trackers with full enable/disable control

**Queue Management System**
- **Bounded queues** - Prevent uncrontolled queue growth with configurable size limits (default 500 events)
- **Configurable** - Overflow strategies (drop_oldest, drop_newest, block) and batch sizes
- **Improved change detection** - On a configuration change streams will immediately flush queues

### Advanced Performance Enhancements
**Production-Ready Scaling Architecture**

- **Parallel processing implementation** using asyncio.gather() for CoT event creation
- **Configurable performance settings** in `config/settings/performance.yaml` with batch size controls
- **Database optimization** with indexed enabled column for efficient tracker filtering
- **Memory efficiency** through optimized data structures and processing pipelines
- **Graceful degradation** with automatic fallback mechanisms for error conditions

---

## TECHNICAL IMPROVEMENTS

### Database Schema Enhancement
**Safe, Backward-Compatible Database Evolution**

- **Added `enabled` column** to `callsign_mappings` table with comprehensive migration safety
- **Many-to-many relationship** between streams and TAK servers via new junction table
- **Migration safety framework** with existence checks, rollback capability, and data integrity validation
- **Backward compatibility guarantee** - existing single-server configurations work unchanged
- **Index optimization** for enhanced query performance on enabled status filtering

### Stream Processing Architecture Evolution
**Modernized Data Processing Pipeline**

- **Updated stream worker** to filter disabled trackers before CoT generation for optimal performance
- **Enhanced distribution logic** for single fetch → multiple server distribution scenarios
- **Improved error handling** with comprehensive fallback mechanisms and detailed logging
- **Network load optimization** through efficient data distribution patterns and connection pooling

### Enhanced User Experience
**Professional UI/UX with Comprehensive Guidance**

- **Comprehensive tooltips** and contextual help text explaining tracker enable/disable functionality
- **Progressive enhancement** - features gracefully degrade if JavaScript is disabled
- **Enhanced information panels** with step-by-step guidance for complex operations
- **Improved visual states** for disabled trackers (opacity changes, background colors, readonly inputs)
- **Accessibility improvements** with screen reader support and keyboard navigation

---

## COMPREHENSIVE TESTING SUITE

### End-to-End Testing Framework
**Production-Ready Quality Assurance**

- **Complete user workflow tests** covering stream creation → tracker discovery → selective disable → CoT output verification
- **Edge case handling** for scenarios with no trackers, all trackers disabled, and migration scenarios
- **Performance benchmarking** with quantified targets for large tracker counts and multi-server configurations
- **Multi-GPS provider testing** across Garmin, SPOT, and Traccar platforms
- **Rollback scenario validation** for migration safety and data integrity

### Quality Assurance Metrics
**Measurable Performance Standards**

- **Processing Performance**: <2 seconds for 100+ trackers with enable/disable control
- **API Efficiency**: 90% reduction in API calls for multi-server scenarios  
- **Memory Usage**: Optimized data structures prevent memory bloat during large operations
- **Error Recovery**: Comprehensive fallback mechanisms with <1 second recovery time
- **UI Responsiveness**: Smooth transitions and visual feedback within 300ms

---

## MIGRATION & COMPATIBILITY

### Safe Database Migration
**Zero-Downtime Upgrade Path**

- **Automatic schema updates** with comprehensive safety checks and existence validation
- **Data preservation guarantee** - all existing streams, callsign mappings, and configurations maintained
- **Rollback capability** - complete downgrade path available if needed
- **Migration validation** with pre and post-migration integrity checks

### Backward Compatibility Guarantee
**Seamless Upgrade Experience**

- **Existing functionality preserved** - all current features work exactly as before when new features disabled
- **Configuration compatibility** - existing single-server streams continue operating unchanged
- **API compatibility** - all existing API endpoints maintain backward compatibility
- **Performance baseline** - no degradation for existing single-server, small dataset configurations

---

## OPERATIONAL BENEFITS

### For System Administrators
- **Scalable architecture** ready for enterprise deployment with multiple TAK servers
- **Performance monitoring** capabilities with detailed metrics and logging
- **Resource optimization** through configurable batch processing and parallel operations
- **Maintenance efficiency** with comprehensive error handling and automatic recovery

### For Operators and Users  
- **Tactical flexibility** through individual tracker control without configuration loss
- **Operational efficiency** with bulk operations and visual status indicators
- **Reduced complexity** through intuitive UI design and comprehensive help text
- **Enhanced situational awareness** with selective data flow control

### For Organizations
- **Cost optimization** through reduced API usage and bandwidth consumption
- **Infrastructure scaling** with multi-server support for high-availability deployments
- **Compliance readiness** with comprehensive audit trails and configuration management
- **Future-proof architecture** designed for continued feature expansion

---

## UPGRADE INSTRUCTIONS

### For New Installations
1. **Deploy normally** - all new features available immediately with sensible defaults
2. **Configure multi-server** support by selecting multiple TAK servers during stream creation
3. **Enable tracker control** by checking "Enable custom callsign mapping" for GPS tracker streams
4. **Performance tuning** available in `config/settings/performance.yaml` for large deployments

### For Existing Deployments  
1. **Automatic migration** - database schema updates applied automatically on startup
2. **Zero configuration changes required** - existing streams continue operating unchanged
3. **Feature activation** - new features available when editing existing streams or creating new ones
4. **Performance benefits** - multi-server and parallel processing active immediately for applicable configurations

### Validation Steps
1. **Verify stream functionality** - confirm existing streams continue operating normally
2. **Test new features** - create test stream with multi-server or tracker control enabled
3. **Performance monitoring** - observe improved processing times for large datasets
4. **Configuration backup** - standard backup procedures protect against any issues

---

## Version 1.0.0-rc.4 - Plugin Architecture & Database Stability Release
**Release Date:** September 5, 2025  
**Plugin Enhancement & Database Concurrency Update**

---

## NEW FEATURES & ENHANCEMENTS

### Enhanced Plugin Architecture
**Improved Stream Configuration Management**

- **Eliminated plugin warnings** - Fixed "No stream object available" warnings in Deepstate plugin during health checks
- **Updated base plugin class** with defensive configuration access methods:
  - `get_stream_config_value()` - Safe stream/plugin configuration fallback
  - `log_config_source()` - Contextual debug logging for configuration sources
  - Automatic production context detection for appropriate log levels
- **Improved plugin lifecycle management** - StreamWorker now properly marks plugins with production context
- **Robust configuration handling** - All plugins now have consistent stream configuration access patterns

**Benefits:**
- **Cleaner logs** - No more confusing warnings during health checks and testing
- **Better debugging** - Clear logging shows which configuration source is being used
- **Reusable patterns** - New helper methods available for all current and future plugins
- **Backward compatibility** - All existing functionality preserved

### MySQL 11 Concurrency Improvements
**Database Stability Enhancement** 

- **Resolved MySQL 11 concurrency errors** with session activity throttling implementation
- **Improved database connection management** to prevent race conditions under high load
- **Improved session handling** for multi-worker deployments
- **Reference:** Detailed implementation in commit `c5bcc778`

**Benefits:**
- **Better database stability** - Eliminates concurrency-related errors in MySQL 11 environments
- **Improved performance** - Optimized session management reduces connection overhead
- **High availability** - Enhanced reliability for production deployments with multiple workers

### Tracker Callsign Mapping System
**Customise callsigns from within TrakBridge**

- **Custom callsign assignment** for individual GPS trackers (Garmin, SPOT, Traccar)
- **Per-tracker COT type overrides** for advanced operational flexibility
- **Stream-isolated configurations** with immediate tracker discovery

**Key Capabilities:**
- **Meaningful identifiers** instead of raw IMEIs or serial numbers
- **Per-callsign COT types** for operational flexibility
- **Live tracker discovery** with auto-assignment and refresh capabilities

### Code Quality & Refactoring
**Systematic Codebase Optimization - Planning Complete**

- **Logging rationalization** - Reduce boilerplate across 56+ files with redundant logger setup
- **Configuration pattern standardization** - Consolidate 19 files with similar config functions
- **Database operation patterns** - Extract common error handling across 24+ files
- **Import optimization** - Dependency consolidation and unused import removal
- **Startup logging improvements** - Fix worker process startup banner spam

**Expected Outcomes:**
- **~500 lines of code reduction** through centralized patterns
- **Improved maintainability** with consistent logging and config patterns
- **Cleaner codebase** with optimized imports and dependencies
- **Better debugging experience** through standardized error handling

---

## Version 1.0.0-rc.3 - Reverse Proxy & Configuration Enhancement Release
**Release Date:** August 26, 2025  
**Configuration Compatibility & Proxy Support Update** 🔧

### **CONFIGURATION FIXES**

#### Reverse Proxy Support
**Production Deployment Enhancement**

- **Added ProxyFix middleware** - Proper handling of X-Forwarded-* headers from reverse proxies
- **Fixed authentication redirects** - Resolves redirect failures when deployed behind Apache/Nginx
- **Enhanced proxy documentation** - Comprehensive reverse proxy setup examples and troubleshooting

#### Certificate Configuration Improvements
**P12 Certificate Password Support**

- **Disabled ConfigParser interpolation** - Supports special characters (%, $, etc.) in P12 certificate passwords
- **Fixed TAK server configuration** - Eliminates interpolation syntax errors in certificate passwords
- **Enhanced COT service configuration** - Robust password handling across all certificate operations

**Technical Changes:**
```python
# app.py: Added ProxyFix middleware
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Certificate services: Disabled interpolation  
config = configparser.ConfigParser(interpolation=None)
```

**Benefits:**
- **Reverse Proxy Fixes** - Full reverse proxy compatibility for enterprise deployments
- **Robust certificates** - Support for complex passwords with special characters
- **Better documentation** - Complete proxy setup guides with troubleshooting

---

## Version 1.0.0-rc.2 - Database Stability & Bootstrap Enhancement Release
**Release Date:** August 26, 2025  
**Critical Database & Authentication Fixes** 🗄️

### **CRITICAL DATABASE FIXES**

#### SQLite Production Reliability
**Database Initialization & Concurrency**

- **Fixed SQLite database initialization loop** - Resolved critical issue causing 120+ second hangs when database file deleted
- **SQLite production optimization** - Automatic worker reduction to 1 for SQLite deployments to prevent concurrency issues
- **WAL mode implementation** - Enhanced SQLite concurrent access with Write-Ahead Logging
- **Bootstrap coordination** - Improved multi-process coordination preventing duplicate admin user creation

#### Authentication System Improvements
**LDAP & Multi-Provider Enhancement**

- **LDAP role mapping debug logging** - Enhanced troubleshooting for group membership and role assignment
- **Docker vs local environment fixes** - Resolved LDAP role mapping discrepancies between deployment types  
- **Active Directory group resolution** - Fixed `memberOf` attribute handling for proper group membership detection
- **Multi-provider fallback** - Robust authentication provider failover system

#### Database Reliability Enhancements
**Connection Management & Error Handling**

- **Multi-process SQLite concurrency** - Proper connection handling for production SQLite deployments
- **Enhanced error messages** - Improved troubleshooting guidance for database connection issues
- **Migration system robustness** - Better handling of missing `alembic_version` table and database state detection
- **Bootstrap loop prevention** - Fixed infinite loop during SQLite startup when database file missing

**Benefits:**
- **Production SQLite support** - Reliable SQLite deployment with appropriate optimizations
- **Enhanced authentication** - Robust LDAP integration with proper role mapping
- **Faster startup** - Reduced application startup time through optimized database checks
- **Error recovery** - Improved graceful degradation when database operations fail

### **BUG FIXES**

#### Critical Application Fixes
- **Bootstrap coordination** - Fixed "cannot access local variable 'db'" error in bootstrap logic
- **Variable scoping** - Resolved scoping errors in database initialization
- **Test suite reliability** - Fixed failing tests in bootstrap service coordination
- **Maritime CoT Types** - Fixed Maritime CoT Type display in ATAK and WinTAK clients

#### Authentication & Session Fixes
- **LDAP group mapping** - Corrected role assignment where LDAP users received incorrect default roles
- **Docker environment** - Fixed environment variable loading differences between development and production
- **Session management** - Improved cross-provider session tracking and lifecycle management

---

## Version 1.0.0-rc.1 - Security & Infrastructure Enhancement Release
**Release Date:** August 14, 2025  
**Critical Security Update** 🔒

---

## CRITICAL SECURITY FIXES

### Password Exposure Elimination (CVE-TBD)
**Risk Level:** CRITICAL - **COMPLETELY FIXED** 
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

- **ELIMINATED** all debug logging that exposed LDAP passwords and credentials in plaintext
- **VERIFIED** zero risk of credential exposure through comprehensive testing
- **REMOVED** vulnerable debug logging from:
  - `config/secrets.py` - LDAP password logging
  - `config/authentication_loader.py` - Authentication debug calls
  - `services/auth/ldap_provider.py` - Bind password exposure

**Impact:** This critical vulnerability could have exposed authentication credentials in application logs. All instances have been completely eliminated with no risk of regression.

---

## NEW FEATURES

### Multiplatform Docker Container Support
**Native ARM64 and AMD64 Architecture Support**

- **Multiplatform builds** now support both Intel/AMD (amd64) and ARM (arm64) architectures
- **Native performance** on Apple Silicon Macs, AWS Graviton instances, and ARM-based devices
- **Automatic architecture detection** - Docker pulls the correct image for your system
- **Enhanced CI/CD pipeline** with Docker Buildx integration for cross-platform builds

**Benefits:**
- **Better performance** on ARM devices (no emulation overhead)
- **Broader deployment options** across heterogeneous infrastructure  
- **ARM device support** for edge deployments and development on Apple Silicon
- **Cloud optimization** for ARM-based cloud instances (AWS Graviton, etc.)

---

## SECURITY ENHANCEMENTS

### Comprehensive Security Assessment
**Professional Security Analysis Completed**

- **342 security rules** analyzed across **214 files** using industry-standard semgrep scanning
- **24 total findings** identified and categorized by risk level
- **0% Critical risk** achieved through complete vulnerability remediation
- **Risk distribution:** 12.5% High, 8.3% Medium, 66.7% Low (infrastructure hardening)

### Enhanced Security Framework
**New Security Utilities and Guidelines**

- **Secure logging utilities** implemented in `utils/security_helpers.py`:
  - `mask_sensitive_value()` - Safe credential masking (e.g., "ab***ef")
  - `safe_debug_log()` - Debug logging with automatic sensitive data protection
  - `sanitize_log_message()` - Log message sanitization with pattern matching

- **Zero-tolerance credential logging policy** enforced across all development
- **Advanced security scanning** integrated into development workflow
- **Comprehensive input validation** and path traversal prevention utilities

---

## DOCUMENTATION IMPROVEMENTS

### Authentication System Documentation
**Complete Multi-Provider Authentication Guide**

- **Comprehensive architecture documentation** for Local, LDAP, and OIDC authentication
- **Configuration examples** for all authentication providers with security best practices
- **Role-based access control** documentation with group mapping examples
- **Session management** and security feature explanations

### Security Documentation Suite
**Professional Security Documentation**

- **`SECURITY_VULNERABILITY_REPORT.md`** - Detailed 24-finding security analysis
  - Executive summary with compliance assessment
  - Complete vulnerability inventory with CWE classifications
  - Remediation status and validation procedures

- **`SECURITY_REMEDIATION_ROADMAP.md`** - 90-day phased implementation plan
  - Immediate actions (7 days): Docker security, CSRF protection
  - Short-term improvements (30 days): Infrastructure hardening
  - Long-term enhancements (90 days): Automated scanning integration


---

## SECURITY COMPLIANCE

### Standards Compliance Achieved
- **OWASP Top 10 2021** - No critical injection, authentication, or design vulnerabilities
- **CWE Top 25** - Input validation and privilege management addressed  
- **NIST Cybersecurity Framework** - Comprehensive identification, protection, and detection controls
- **Container Security** - Preparation for non-root execution and privilege minimization

### Professional Security Assessment
- **Static analysis** with industry-standard tools and comprehensive rule sets
- **Manual security review** of high-risk authentication and authorization code
- **Security architecture evaluation** with detailed recommendations
- **Vulnerability remediation tracking** with professional reporting

---

## TECHNICAL DETAILS

### Container Architecture Changes
```bash
# New multiplatform build process
docker buildx build --platform linux/amd64,linux/arm64 ...

# Automatic architecture selection
docker pull trakbridge:latest  # Pulls correct architecture automatically
```

### Security Command Integration
```bash
# Comprehensive security scanning
semgrep --config=auto --severity=ERROR --severity=WARNING .
bandit -r . -f json
safety check --json
```

### Secure Logging Implementation
```python
# New secure logging utilities
from utils.security_helpers import safe_debug_log, mask_sensitive_value

# Safe credential handling
safe_debug_log(logger, "Authentication attempt", {"username": username})
masked_password = mask_sensitive_value(password)  # Returns "ab***ef"
```

---

## UPGRADE NOTES

### For Existing Deployments
1. **No breaking changes** - All existing functionality preserved
2. **Container images** now provide automatic architecture optimization
3. **Security improvements** are transparent to end users
4. **Enhanced logging** maintains all existing functionality while eliminating security risks

### For Developers
1. **New security guidelines** must be followed for all code contributions
2. **Credential logging is strictly prohibited** - use secure logging utilities
3. **Security scanning** is now integrated into development workflow
4. **Authentication system documentation** available for integration work

### For Operators
1. **Enhanced security monitoring** capabilities available
2. **Comprehensive security reports** for compliance and audit purposes
3. **Professional vulnerability assessment** documentation for security teams
4. **Multi-architecture deployment** options for infrastructure optimization

---

## NEXT STEPS

### Immediate Actions Available
1. **Deploy multiplatform containers** for improved performance on ARM infrastructure
2. **Review security documentation** for compliance and audit purposes  
3. **Implement remaining security recommendations** from the remediation roadmap
4. **Leverage new authentication documentation** for integration projects

### Upcoming Enhancements
- **Enhanced monitoring and alerting** capabilities
- **Third-party security assessment** validation

---

## SUPPORT AND RESOURCES

### Documentation
- **Container Deployment:** Multiplatform deployment examples and best practices
- **Developer Security:** Comprehensive secure coding guidelines and utilities

---
*For technical support or security questions, please refer to the comprehensive documentation or contact the development team.*
# IPFire-API-v2
![IPFire API v2](docs/images/ipfire-api-logo-v2.svg)
A modular, Perl-based API service for IPFire, providing secure remote management and monitoring via WebSocket over TLS.

> **Development status:** Early development. The API is not yet functional.

## Table of Contents

- [Project Goals](#project-goals)
- [Planned Architecture](#planned-architecture)
  - [Module Responsibilities](#module-responsibilities)
- [IPFire Compatibility](#ipfire-compatibility)
  - [Test the TLS listener on IPFire](#test-the-tls-listener-on-ipfire)
  - [Send a JSON request](#send-a-json-request)
  - [Test the API on IPFire](#test-the-api-on-ipfire)
- [Development Roadmap](#development-roadmap)
  - [Phase 1 — Project Foundation](#phase-1--project-foundation)
  - [Phase 2 — TLS Server](#phase-2--tls-server)
  - [Phase 3 — WebSocket Protocol](#phase-3--websocket-protocol)
  - [Phase 4 — JSON API Protocol](#phase-4--json-api-protocol)
  - [Phase 5 — Authentication and Security](#phase-5--authentication-and-security)
  - [Phase 6 — Monitoring and Events](#phase-6--monitoring-and-events)
  - [Phase 7 — IPFire Integration](#phase-7--ipfire-integration)
  - [Phase 8 — Future Compatibility](#phase-8--future-compatibility)
- [Development Notes](#development-notes)
- [License](#license)

## Project Goals

The goal is to develop a modular API for IPFire that supports persistent, bidirectional communication between IPFire and external clients.

The implementation should:

- Use Perl and modules already available on IPFire whenever possible.
- Avoid additional runtime dependencies.
- Provide secure WebSocket connections (WSS).
- Support multiple simultaneous clients.
- Use JSON for requests, responses, and events.
- Support monitoring and, eventually, selected management operations.
- Remain independent of the existing IPFire API v1.

Development will proceed incrementally, with testing on a real IPFire installation.

## Planned Architecture

The API will run as a standalone Perl daemon.

The initial communication protocol will be WebSocket over TLS (WSS), using TCP port `8444`.

The planned project structure is:

```text
IPFire-API-v2/
├── bin/
│   └── ipfire-api-daemon.pl
├── lib/
│   └── IPFire/
│       └── API/
│           ├── Client.pm
│           ├── Config.pm
│           ├── Protocol.pm
│           ├── Server.pm
│           ├── System.pm
│           └── WebSocket.pm
├── t/
├── .gitignore
├── LICENSE
└── README.md
```

### Module Responsibilities

| Module | Responsibility |
|---|---|
| `Config.pm` | Server configuration, listening address, port and TLS certificate paths |
| `Server.pm` | TCP/TLS listener, connection handling and event loop |
| `Client.pm` | Individual client connections and connection state |
| `WebSocket.pm` | WebSocket handshake, frame processing and protocol control |
| `Protocol.pm` | JSON message handling, request dispatching and responses |
| `System.pm` | Read-only system information |
| `ipfire-api-daemon.pl` | Main entry point for the API service |

## IPFire Compatibility

Initial dependency checks were performed on:

- IPFire 2.29 Core Update 205
- Perl 5.42.2

The following modules were confirmed to be available:

| Perl Module | Status |
|---|---|
| `IO::Socket::INET` | Available |
| `IO::Socket::SSL` | Available |
| `Net::SSLeay` | Available |
| `IO::Select` | Available |
| `Digest::SHA` | Available |
| `MIME::Base64` | Available |
| `Protocol::WebSocket` | Not available |

JSON support is already used in the existing API v1 implementation.

The initial assessment suggests that a WebSocket server can be implemented without additional Perl packages. This still requires practical verification.

### Test the TLS listener on IPFire

From the repository checkout on IPFire, run:

```sh
perl bin/ipfire-api-daemon.pl
```

From a second shell on the same IPFire host, connect to the listener:

```sh
openssl s_client -connect 127.0.0.1:8444 \
  -CAfile /etc/httpd/server.crt -verify_return_error </dev/null
```

The daemon allows up to five seconds for the TLS handshake and another five seconds for the WebSocket upgrade.
Stop it with `Ctrl+C`.
If the server certificate was issued by a CA, use that CA's certificate for `-CAfile`.

To check the handshake timeout, open a TCP connection without starting TLS from the second shell on IPFire:

```sh
time timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8444; cat <&3'
```

Expect the connection to close after about five seconds and the daemon to log `TLS handshake failed: timed out`.
Run the [API smoke test](#test-the-api-on-ipfire) immediately afterward to confirm that the daemon serves another client.

To test the WebSocket upgrade from the second shell, run:

```sh
key=$(openssl rand -base64 16)
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1:8444\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' "$key" |
  openssl s_client -quiet -connect 127.0.0.1:8444 \
    -CAfile /etc/httpd/server.crt -verify_return_error
```

Expect `HTTP/1.1 101 Switching Protocols` and a `Sec-WebSocket-Accept` header.
The daemon keeps the connection open after the upgrade and waits up to 30 seconds for each frame.
It allows up to five seconds to send each reply frame and closes connections that time out.
The daemon supports up to 32 simultaneous connections, including clients still negotiating TLS or upgrading to WebSocket.
The message limit is 64 KiB, including fragmented messages.
Ping receives Pong, and Close ends the connection.

### Send a JSON request

Send one JSON object per WebSocket text message. Each request has an `id` string of 1 to 128 characters
and a `method` string. The first method, `system.ping`, accepts no parameters. The `params` field can
be omitted or set to an empty object.

```json
{"id":"ping-1","method":"system.ping"}
```

The reply carries the same ID and a `result` or `error` object. For example:

```json
{"id":"ping-1","result":{"pong":true}}
```

Errors contain `code` and `message`. The reply ID is `null` when the request has no valid ID.
The current error codes are `invalid_json`, `invalid_request`, `method_not_found` and `invalid_params`.

Use `{"id":"info-1","method":"system.info"}` for the hostname, the IPFire release string and whole
seconds since boot. The result fields are `hostname`, `ipfire_release` and `uptime_seconds`.
Release and uptime are `null` if their sources are unavailable. This method also accepts no parameters.

### Test the API on IPFire

Start the updated daemon in the first SSH session. From the local repository checkout, run:

```sh
ssh root@ipfire.mainz 'perl - ipfire.mainz' < t/ipfire-smoke.pl
```

Replace both instances of `ipfire.mainz` with the name on your IPFire certificate.
Expect `Upgrade OK`, `Pong OK`, `system.ping OK`, the system information in JSON,
`system.info OK` and `Close OK`.

Run the local tests from the repository with `prove -l t`. The concurrency test uses loopback
and an ephemeral certificate generated with OpenSSL. It checks that an unfinished TLS handshake
and a partial WebSocket frame leave other clients able to get a response.

| Environment variable | Default |
|---|---|
| `IPFIRE_API_HOST` | `127.0.0.1` |
| `IPFIRE_API_PORT` | `8444` |
| `IPFIRE_API_CERT_FILE` | `/etc/httpd/server.crt` |
| `IPFIRE_API_KEY_FILE` | `/etc/httpd/server.key` |

## Development Roadmap

### Phase 1 — Project Foundation

- [x] Create the GitHub repository.
- [x] Create the `develop` branch.
- [x] Define the initial architecture.
- [x] Create the project directory structure.
- [x] Check Perl and TLS dependencies on IPFire Core 205.
- [x] Create the initial `Config.pm` module.
- [x] Create the initial `Server.pm` skeleton.
- [x] Implement `ipfire-api-daemon.pl`.
- [x] Verify Perl syntax and module loading.
- [x] Confirm usable TLS certificate and private key paths.
- [x] Implement configurable listening address and port.

### Phase 2 — TLS Server

- [x] Implement the TLS listener.
- [x] Accept incoming client connections.
- [x] Implement connection timeouts and error handling.
- [x] Verify TLS handshake timeout and successful handling of the next client on IPFire Core Update 205.
- [x] Use non-blocking TLS operations with `IO::Select`.
- [x] Support multiple simultaneous clients and verify them over TLS on Linux loopback.
- [ ] Verify multiple simultaneous clients on IPFire.
- [ ] Implement clean startup and shutdown.
- [x] Verify a TLS 1.3 handshake on IPFire over loopback.

### Phase 3 — WebSocket Protocol

- [x] Implement the HTTP WebSocket upgrade handshake.
- [x] Validate the `Sec-WebSocket-Key` header.
- [x] Generate the `Sec-WebSocket-Accept` response.
- [x] Verify the HTTP upgrade over TLS on IPFire.
- [x] Parse client frames and encode server control frames.
- [x] Support client masking and fragmented messages.
- [x] Implement Ping/Pong frames.
- [x] Implement Close frames and connection cleanup.
- [x] Enforce message size limits and protocol validation.
- [x] Verify Ping/Pong and Close over TLS on IPFire.
- [x] Verify the WebSocket connection and both JSON methods with `wscat` on Debian 13 over local TLS.

### Phase 4 — JSON API Protocol

- [x] Define a consistent JSON message format.
- [x] Implement request and response identifiers.
- [x] Implement structured error responses.
- [x] Add a basic `system.ping` request.
- [x] Verify `system.ping` and its response ID over TLS on IPFire.
- [x] Add an initial read-only `system.info` request.
- [x] Verify `system.info` over TLS on IPFire Core Update 205.
- [x] Dispatch requests by method name.
- [x] Add automated protocol tests.

### Phase 5 — Authentication and Security

- [ ] Design client authentication.
- [ ] Define authorization and permissions.
- [ ] Restrict access to approved interfaces and networks.
- [ ] Implement connection and request limits.
- [ ] Review input validation and error handling.
- [ ] Ensure sensitive information is not exposed in logs.
- [ ] Review TLS configuration and certificate handling.

### Phase 6 — Monitoring and Events

- [ ] Implement client subscriptions.
- [ ] Define event message formats.
- [ ] Implement server-initiated notifications.
- [ ] Add selected IPFire status and monitoring events.
- [ ] Handle reconnects and subscription cleanup.
- [ ] Evaluate MQTT as a possible future event interface.

### Phase 7 — IPFire Integration

- [ ] Identify reusable IPFire system interfaces and functions.
- [ ] Implement modular, read-only system information endpoints.
- [ ] Evaluate selected configuration and management operations.
- [ ] Define safe validation for configuration changes.
- [ ] Investigate daemon startup and service management on IPFire.
- [ ] Document installation and configuration.

### Phase 8 — Future Compatibility

- [ ] Evaluate reusing API v2 modules from the existing API v1.
- [ ] Preserve API v1 compatibility where practical.
- [ ] Evaluate integration with Home Assistant.
- [ ] Expand the API based on testing and community feedback.

## Development Notes

The existing API v1 will remain independent and should only receive necessary maintenance and bug fixes.

The API v2 is being developed incrementally. Features, interfaces and implementation details may change during development.

The first milestone is a minimal, TLS-protected WebSocket server capable of accepting a connection and responding to a simple JSON request.

## License

GPL-3.0

# IPFire-API-v2
![IPFire API v2](docs/images/ipfire-api-logo-v2.svg)
A modular, Perl-based API service for IPFire, providing secure remote management and monitoring via WebSocket over TLS.

> **Development status:** Early development. The API is not yet functional.

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

## Development Roadmap

### Phase 1 — Project Foundation

- [x] Create the GitHub repository.
- [x] Create the `develop` branch.
- [x] Define the initial architecture.
- [x] Create the project directory structure.
- [x] Check Perl and TLS dependencies on IPFire Core 205.
- [x] Create the initial `Config.pm` module.
- [x] Create the initial `Server.pm` skeleton.
- [ ] Implement `ipfire-api-daemon.pl`.
- [ ] Verify Perl syntax and module loading.
- [ ] Confirm usable TLS certificate and private key paths.
- [ ] Implement configurable listening address and port.

### Phase 2 — TLS Server

- [ ] Implement the TLS listener.
- [ ] Accept incoming client connections.
- [ ] Implement connection timeouts and error handling.
- [ ] Evaluate non-blocking TLS operations with `IO::Select`.
- [ ] Support multiple simultaneous clients.
- [ ] Implement clean startup and shutdown.
- [ ] Test TLS connections on IPFire.

### Phase 3 — WebSocket Protocol

- [ ] Implement the HTTP WebSocket upgrade handshake.
- [ ] Validate the `Sec-WebSocket-Key` header.
- [ ] Generate the `Sec-WebSocket-Accept` response.
- [ ] Implement WebSocket frame parsing and encoding.
- [ ] Support client masking and fragmented messages.
- [ ] Implement Ping/Pong frames.
- [ ] Implement Close frames and connection cleanup.
- [ ] Enforce message size limits and protocol validation.
- [ ] Test WebSocket connections using a standard client.

### Phase 4 — JSON API Protocol

- [ ] Define a consistent JSON message format.
- [ ] Implement request and response identifiers.
- [ ] Implement structured error responses.
- [ ] Add a basic `system.ping` request.
- [ ] Add an initial read-only system information request.
- [ ] Implement request dispatching.
- [ ] Add automated protocol tests.

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

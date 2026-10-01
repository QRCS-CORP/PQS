# PQS: Post Quantum Shell

[![Build](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/pqs/badge)](https://www.codefactor.io/repository/github/qrcs-corp/pqs)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-blue)](#platform-support)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/PQS/security/policy)
[![License: QRCS-PREL](https://img.shields.io/badge/license-QRCS--PREL-blue.svg)](https://github.com/QRCS-CORP/PQS/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Documentation](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/PQS/)
[![GitHub Release](https://img.shields.io/github/v/release/QRCS-CORP/PQS)](https://github.com/QRCS-CORP/PQS/releases)
[![Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/PQS.svg)](https://github.com/QRCS-CORP/PQS/commits/main)
[![PQS Standard](https://img.shields.io/static/v1?label=protocol&message=PQS%201.1&color=blue)](https://qrcs-corp.github.io/PQS/pdf/pqs_specification.pdf)
[![PQS Enterprise](https://img.shields.io/static/v1?label=enterprise&message=PQS--E&color=brightgreen)](https://www.qrcscorp.ca/pqs/pqse_summary.pdf)

**PQS is a post-quantum remote shell, command, and file-transfer protocol designed as a modern replacement for SSH-class server administration.**

## Overview

Post Quantum Shell (PQS) is a high-security remote-administration protocol designed from the ground up for post-quantum security. It replaces classical public-key dependencies with post-quantum key establishment and signature mechanisms, then applies application-layer authentication, policy-controlled command execution, sandbox enforcement, known-host continuity, structured logging, and confined file transfer.

The public PQS repository is the **PQS Standard** proof-of-concept and protocol-reference implementation. It exists to demonstrate and validate the core protocol concepts, support public cryptographic review, enable interoperability testing, and provide an engineering basis for continued development.

**PQS Enterprise (PQS-E)** is the complete commercial implementation. PQS-E replaces the QSMS transport used by the public reference implementation with QSTP, a root-anchored post-quantum transport. QSTP authenticates each application server through a root-signed server certificate. The QSTP root certificate is self-signed by default and may instead be signed by an external post-quantum authority, enabling hierarchical enterprise trust, controlled certificate issuance, key rotation, and scalable authentication across managed servers. PQS-E extends this transport into a managed enterprise server-administration platform with device-aware authentication, persistent service operation, advanced authorization, interactive terminals, network forwarding, protected audit and recording, fleet management, signed deployment, rollback protection, browser and command-line administration, and release qualification.

PQS and PQS-E are intended for environments where long-term confidentiality, administrative control, and cryptographic durability are required, including financial infrastructure, government and defense systems, healthcare networks, cloud administration, industrial systems, and critical infrastructure.

## Documentation

### PQS Standard

- [PQS Help Documentation](https://qrcs-corp.github.io/PQS/)
- [PQS Summary](https://qrcs-corp.github.io/PQS/pdf/pqs_summary.pdf)
- [PQS Protocol Specification](https://qrcs-corp.github.io/PQS/pdf/pqs_specification.pdf)
- [PQS Formal Analysis](https://qrcs-corp.github.io/PQS/pdf/pqs_formal.pdf)

### PQS Enterprise

- [PQS Enterprise Executive Summary](https://www.qrcscorp.ca/pqs/pqse_summary.pdf)
- [PQS Enterprise Technical Specification](https://www.qrcscorp.ca/pqs/pqse_specification.pdf)

## PQS Standard and PQS Enterprise

PQS Standard and PQS Enterprise share the same objective: replace SSH-class server administration with a security model designed specifically for the post-quantum era. They serve different purposes.

| Area | PQS Standard | PQS Enterprise (PQS-E) |
| --- | --- | --- |
| Primary purpose | Public proof-of-concept, protocol validation, research, and interoperability | Commercial production server administration |
| Distribution | Public source repository under the QRCS-PREL license | Separately licensed enterprise product |
| Transport | QSMS Simplex encrypted transport used by the reference implementation | QSTP root-anchored post-quantum transport and enterprise service integration |
| Transport trust | Direct trust in a pinned server verification key | Trusted QSTP root certificate and root-signed application-server certificates |
| Certificate hierarchy | Per-server public-key provisioning and known-host continuity | Self-signed or externally signed post-quantum root with delegated application-server certificate signing |
| Authentication | Server authentication and application-layer user login | Root-authenticated server identity plus user, machine, device, and fleet-agent identity controls |
| Authorization | User, privilege, shell, policy, sandbox, and transfer-root controls | Structured session privileges and operation-specific authorization across all enterprise services |
| Command execution | Policy-controlled commands and sandboxed process execution | Direct commands, managed shells, interactive PTY/ConPTY sessions, bounded execution, and enterprise policy enforcement |
| File operations | Confined upload, download, listing, directory creation, removal, and recursive transfer | Hardened transfer workflows, authenticated state, controlled publication, interruption recovery, and enterprise audit integration |
| Forwarding | Not part of the public reference feature set | Controlled local, remote, dynamic, and jump forwarding |
| Administration | Console administration | Native CLI, local authenticated management endpoint, loopback browser console, and persistent service control |
| Audit and recording | Structured application logging | Authenticated audit chains and encrypted command or terminal recordings |
| Fleet operations | Not part of the public reference feature set | Fleet enrollment, inventory, heartbeat, approvals, job control, retry, interruption recovery, and revocation |
| Deployment | Manual reference deployment | ML-DSA-signed bundles, staged activation, quorum approval, rollback protection, and authenticated deployment state |
| Qualification | Reference tests and public review | Cross-configuration qualification, static analysis, source-integrity verification, and platform-specific security validation |

The public repository should not be interpreted as the complete PQS-E product. It is the standards-facing implementation used to prove the protocol model and expose the core security design for examination. Production deployment, supported enterprise builds, managed fleet operation, and commercial integration are provided through PQS-E under a separate agreement.

## PQS Standard Capabilities

The reference implementation provides:

- QSMS Simplex transport with server-authenticated post-quantum key establishment.
- Pinned server verification keys and client known-host continuity.
- Strict host-key checking for deployments that reject unknown server keys.
- Application-layer user login inside the encrypted transport.
- SCB-hardened passphrase verifiers with per-user salts and no stored plaintext passphrases.
- Persistent user records with enablement state, privilege level, shell assignment, failed-attempt tracking, and account disablement.
- Policy-first command authorization using no-shell, restricted, forced-command, and raw-shell modes.
- Shell-control metacharacter rejection before command execution.
- Shell profile administration separated from command-policy authorization.
- Mandatory sandbox profile enforcement for command execution.
- POSIX run-as and chroot configuration where supported.
- Windows restricted-token and job-object containment where supported.
- Confined file transfer using per-user transfer roots.
- File get, put, list, mkdir, remove, and recursive transfer operations.
- SHA3-256 file hashing and transfer metadata validation.
- Symbolic-link and reparse-point avoidance during recursive transfer.
- Server and client configuration persistence.
- Structured application logging with sanitized fields.
- Console administration for users, shells, policies, keys, fingerprints, sandbox state, and server operation.

## PQS Enterprise Capabilities

PQS-E develops the PQS security model into a complete enterprise administration platform.

### Enterprise Identity and Authentication

- QSTP root-anchored post-quantum server authentication.
- Root-signed application-server certificates.
- A self-signed QSTP root certificate by default.
- Optional external post-quantum signing of the QSTP root certificate for hierarchical trust deployments.
- Centralized certificate issuance, server-key rotation, expiration control, and scalable trust distribution.
- Human-user and machine identities.
- Multiple authorized device profiles per user.
- ML-DSA device keys and proof of private-key possession.
- Device enrollment, disablement, revocation, replacement, and recovery.
- Timing-resistant passphrase verification.
- Protected client and server credential storage.
- Revalidation of identity and authorization during long-running operations.

### Enterprise Authorization and Execution

- Structured session privilege manifests.
- Separation of direct administrative commands, operating-system commands, and interactive shells.
- No-shell, restricted, forced-command, and raw-shell policy modes.
- Shell profile and privilege-mask enforcement.
- Bounded execution time, output, working directory, and environment.
- POSIX privilege transition, chroot, descriptor control, and no-new-privileges handling.
- Windows restricted tokens, job objects, handle inheritance control, and process-tree cleanup.
- Fail-closed behavior when required confinement cannot be applied.

### Enterprise File, Terminal, and Forwarding Services

- Confined per-user file roots.
- Bounded upload, download, recursive transfer, metadata, and integrity validation.
- Controlled temporary-file publication and interruption recovery.
- Interactive POSIX PTY and Windows ConPTY sessions.
- Terminal resize, signal, input, output, timeout, and teardown handling.
- Policy-controlled local, remote, dynamic, and jump forwarding.
- Session-specific quotas and operation limits.

### Enterprise Management and Operations

- Persistent Windows and POSIX service operation.
- Authenticated local administration through named pipes or Unix-domain sockets.
- Native command-line management.
- Loopback-only browser administration with launch tokens, session cookies, CSRF controls, and origin validation.
- Service start, stop, pause, resume, drain, and graceful shutdown.
- Protected configuration and transactional state updates.
- Recovery from interrupted writes and deployments.

### Audit, Fleet, and Deployment

- KMAC-authenticated audit records.
- Audit checkpoints, key epochs, and tamper detection.
- Encrypted and authenticated command and terminal recordings.
- Fleet-agent enrollment, inventory, heartbeat, role control, and revocation.
- Approval and quorum workflows.
- Deployment job scheduling, retry, interruption recovery, and state reconciliation.
- ML-DSA-signed deployment bundles.
- Payload digest verification, monotonic sequence enforcement, staging, transactional activation, rollback protection, and authenticated deployment state.

## Protocol Architecture

PQS Standard and PQS Enterprise use different transport trust models.

### PQS Standard: QSMS Simplex

PQS Standard is composed of two layers.

#### QSMS Simplex Transport

QSMS performs:

- Server authentication.
- Ephemeral post-quantum key encapsulation.
- Transcript binding.
- Sequence validation.
- Timestamp freshness checking.
- Directional key derivation.
- Authenticated encryption and decryption.
- Explicit channel confirmation before application data is accepted.

The client verifies the server by checking signed ephemeral encapsulation material under a pinned server verification key. QSMS derives independent transmit and receive RCS channel states from the KEM shared secret and the session transcript.

#### PQS Application Protocol

PQS application messages are carried inside encrypted QSMS payloads. Each payload begins with an application message type followed by operation-specific data, such as:

- Login credentials.
- Command requests and output.
- File paths and file data.
- Transfer metadata and status.
- Errors and disconnect notices.

The application layer applies user authentication, command authorization, shell selection, sandbox policy, transfer-root confinement, known-host validation, and structured error handling. It does not alter the QSMS key-exchange packet format or transport header serialization.


### PQS Enterprise: QSTP Root-Anchored Transport

PQS-E uses QSTP in place of the QSMS transport used by PQS Standard. QSTP establishes a root-anchored post-quantum trust hierarchy:

1. A QSTP root certificate contains the trusted root verification key and identifying metadata.
2. The root certificate is self-signed by default so that its own canonical fields can be authenticated.
3. Deployments may instead use an externally signed QSTP root certificate, allowing a separate post-quantum authority to authenticate the enterprise root.
4. The root signing key signs application-server certificates.
5. A client that trusts the root certificate verifies the target application-server certificate before accepting the server identity.
6. During tunnel establishment, the application server signs the ephemeral KEM public-key commitment with its server signing key.
7. The client verifies the server certificate chain and the ephemeral-key signature before deriving transport keys.
8. QSTP commits the root certificate, application-server certificate, handshake header, ephemeral KEM key, and encapsulation ciphertext into the transcript used for session-key derivation and explicit key confirmation.

This model differs from the direct pinned-key trust model used by QSMS. A PQS Standard deployment provisions trust separately for each server verification key. A PQS-E deployment can provision one trusted QSTP root and use it to authenticate multiple managed application servers through root-signed certificates. This supports centralized certificate issuance, expiration, rotation, revocation procedures, and enterprise-scale server identity management without introducing classical RSA, ECDSA, ECDH, or X25519 dependencies into the defined PQS-E trust chain.

QSTP remains one-way authenticated at the transport layer: the client authenticates the application server. PQS-E then performs its user, device, machine, and fleet-agent authentication inside the established encrypted channel and applies operation-specific authorization before administrative work is accepted.

## Security Model

PQS Standard uses a one-way server-authenticated trust model. The server owns the long-term signing key. The client obtains the corresponding verification key through a trusted registration, deployment, or out-of-band distribution process. During connection establishment, the server authenticates fresh ephemeral encapsulation material, and the client verifies it under the pinned verification key.

The established transport provides confidentiality, integrity, sequence enforcement, and timestamp-bounded replay resistance. PQS then applies application-layer controls before any command or file operation is accepted.

PQS-E replaces direct per-server QSMS trust with QSTP's root-anchored post-quantum certificate model. The client trusts a QSTP root certificate, verifies the root-signed application-server certificate, and verifies the server's signature over fresh ephemeral KEM material before accepting the tunnel. The root is self-signed by default and may be externally signed by a separate post-quantum authority when a hierarchical trust deployment is required.

PQS-E extends this transport model with enterprise identity, device authorization, protected state, operation-specific privileges, authenticated audit, managed services, fleet administration, and signed deployment. The result is a unified post-quantum security architecture across the complete remote-administration lifecycle rather than a cryptographic upgrade applied only to the transport handshake.

## Application Message Types

PQS defines encrypted application messages for:

- Login requests and authentication results.
- Command requests and command-output continuation or completion.
- Errors and disconnects.
- File download and upload.
- Directory listing and creation.
- File removal.
- Recursive directory and file traversal.
- File data, finalization metadata, and transfer status.

Messages are accepted only in valid application states after the underlying encrypted channel reaches the established state.

## Command, Policy, and Sandbox Enforcement

PQS authorizes commands before execution. A user must authenticate successfully before command or file-transfer requests are considered.

The policy modes are:

- **No-shell:** command execution is denied.
- **Restricted:** only explicitly authorized command verbs are permitted.
- **Forced:** the server substitutes a configured command.
- **Raw-shell:** shell execution is allowed subject to policy, shell-profile, denylist, and safety controls.

The policy engine extracts the leading command verb for allowlist and denylist decisions. It rejects shell-control metacharacters where they could append or combine unapproved shell expressions.

A sandbox profile is mandatory in the hardened implementation. It controls timeout, working directory, environment inheritance, and supported operating-system confinement. POSIX execution can apply run-as identity, group transition, chroot, descriptor closure, and no-new-privileges. Windows execution uses controlled handle inheritance, restricted tokens where available, and job-object containment.

## File Transfer and Confinement

The file-transfer subsystem is implemented in `pqsxfer`. It validates relative paths, extracts bounded paths from authenticated messages, constructs safe local paths, parses transfer metadata, computes SHA3-256 hashes, creates per-user transfer roots, and performs confined file opens.

Server-side operations are restricted to the authenticated user's transfer root. The implementation rejects:

- Empty paths.
- Absolute paths.
- Drive-qualified paths.
- Parent traversal.
- Oversized paths.
- Symbolic-link traversal.
- Windows reparse-point traversal.
- Recursive operations that exceed the configured depth.

POSIX builds use descriptor-relative traversal with no-follow semantics where available. Windows builds use canonical root-prefix validation and reparse-point checks.

## Client Console Commands

| Command | Purpose |
| --- | --- |
| `key` | Display the configured server public verification key. |
| `fp` | Display the server public-key fingerprint. |
| `known` | Display known-host entries. |
| `khremove <host>` | Remove a known-host entry. |
| `get <remote> [local]` | Download a file or directory from the server transfer root. |
| `put <local> [remote]` | Upload a file or directory into the server transfer root. |
| `list [path]` | List a remote transfer-root directory. |
| `mkdir <path>` | Create a directory below the remote transfer root. |
| `remove <path>` | Remove a file below the remote transfer root. |
| `help` | Show client help. |
| `help detail` | Show detailed client operations help. |
| `quit` | Terminate the session. |

## Server Console Administration

| Command | Purpose |
| --- | --- |
| `user` | Enter user administration mode. |
| `shell` | Enter shell-profile administration mode. |
| `policy` | Enter command-policy administration mode. |
| `key` | Display the server public key and fingerprint. |
| `fp` | Display the server public-key fingerprint. |
| `keyscan` | Display the known-hosts entry for the server. |
| `sandbox` | Display command-sandbox status. |
| `help` | Show server help. |
| `detail` | Show detailed setup and operations help. |
| `quit` | Shut down the PQS server. |

## Implementation Modules

| Module | Responsibility |
| --- | --- |
| `pqs.h` | Application messages, session states, privileges, commands, and error codes. |
| `pqsuser` | User database, privilege conversion, verifier generation, timing-neutral verification, and persistence. |
| `pqsshell` | Shell profiles, shell enablement, default-shell selection, and privilege-mask checks. |
| `pqspolicy` | Command policies, allowlists, denylists, forced commands, privilege assignment, and shell-safety checks. |
| `pqssandbox` | Sandbox defaults, timeout clamping, working-directory validation, and POSIX run-as or chroot configuration. |
| `pqsprocess` | Platform process creation, output callbacks, inheritance control, timeout handling, and sandbox application. |
| `pqskey` | Host-key fingerprinting and known-host lookup, storage, removal, and verification. |
| `pqsxfer` | Path validation, metadata parsing, hashing, recursive traversal, confined file access, and transfer roots. |
| `pqsconfig` | Client and server configuration defaults, persistence, loading, and field parsing. |
| `pqslogger` | Structured application logging with sanitized fields. |

## Cryptographic Primitives

PQS uses the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC). The configured protocol profile determines the exact asymmetric algorithms and security level.

### Asymmetric Cryptography

- **ML-KEM / Kyber:** lattice-based post-quantum key encapsulation.
- **McEliece:** code-based post-quantum public-key encryption in supported profiles.
- **ML-DSA / Dilithium:** lattice-based post-quantum digital signatures.
- **SPHINCS+:** stateless hash-based digital signatures in supported profiles.

### Symmetric Cryptography

PQS uses RCS, the Rijndael Cryptographic Stream, for authenticated symmetric encryption. RCS uses a widened Rijndael construction and a Keccak-based key schedule. It protects encrypted transport packets with authenticated encryption and associated-data binding.

### Hashing, Derivation, and Verification

- **SHA3:** hashing for identifiers, fingerprints, transcripts, and integrity values.
- **SHAKE / cSHAKE:** domain-separated session-key and nonce derivation.
- **KMAC:** keyed authentication and protected-state constructions where configured.
- **SCB:** memory- and CPU-costed passphrase verification.

## Cryptographic Dependencies

PQS depends on QSC for post-quantum algorithms, SHA-3-family functions, RCS, memory utilities, socket utilities, threading, platform abstraction, and secure system support.

## Compilation

PQS is written in C23 and targets Windows, Linux, and macOS. QSC must be available through the sibling or configured dependency path expected by the selected build system.

### Prerequisites

- CMake 3.15 or newer for CMake-based builds.
- Visual Studio 2022 or newer on Windows.
- GCC or Clang on Linux.
- Clang through Xcode or Homebrew on macOS.
- The QRCS QSC library source tree.

### Windows

Open the Visual Studio solution and build QSC, the PQS library, the server, the client, and the test projects for the same architecture and instruction-set profile.

All dependent projects must use compatible:

- Target architectures.
- Runtime libraries.
- C language standards.
- Processor instruction sets.
- Debug or release configurations.

### Linux and macOS

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Configure the QSC include and library paths when QSC is not present in the default relative location expected by the build files.

### Hardware Acceleration

Use one compatible acceleration profile across QSC and PQS. Example x86-64 groups include:

- **Baseline:** `-msse2`
- **AVX:** `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2`
- **AVX2:** `-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2`
- **AVX-512:** `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -maes -mpclmul -mrdrnd -mbmi2`

Use only flags supported by the build host and every deployment CPU.

## Platform Support

The PQS Standard implementation is intended for:

- Windows with Visual Studio and the Win32 security and process APIs.
- Linux with POSIX process, filesystem, and socket APIs.
- macOS with POSIX-compatible process, filesystem, and socket APIs.

Platform-specific security features are applied only when the operating system provides the required mechanism. Security-sensitive operations fail closed when a required policy cannot be enforced.

## Production Deployment

This repository is a public research, proof-of-concept, and protocol-reference implementation. It is provided for:

- Cryptographic review.
- Protocol analysis.
- Engineering evaluation.
- Interoperability testing.
- Academic and non-commercial research.
- Validation of the PQS design concepts.

It is not a grant of production or commercial deployment rights.

Organizations requiring a supported, managed, production-grade post-quantum replacement for SSH-class administration should evaluate **PQS Enterprise (PQS-E)**:

- [PQS-E Executive Summary](https://www.qrcscorp.ca/pqs/pqse_summary.pdf)
- [PQS-E Technical Specification](https://www.qrcscorp.ca/pqs/pqse_specification.pdf)
- [QRCS Corporation](https://www.qrcscorp.ca/)
- [Commercial licensing](mailto:licensing@qrcscorp.ca)

## License

### Investment Inquiries

QRCS is seeking strategic investment and commercial partners for this technology.

For licensing, investment, or acquisition inquiries, contact [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca).

A complete inventory of QRCS technologies is available at [qrcscorp.ca](https://www.qrcscorp.ca/).

### Patent Notice

One or more provisional or non-provisional patent applications covering aspects of this software have been filed with the United States Patent and Trademark Office. Unauthorized use may result in patent-infringement liability.

### License and Use Notice

This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation for public review, cryptographic analysis, interoperability testing, and evaluation.

Unless explicitly stated otherwise, all source code and materials are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026**.

The license permits public access and non-commercial research, evaluation, and testing. It does not permit production deployment, operational use, or incorporation into a commercial product or service without a separate written agreement executed with QRCS.

Public availability supports cryptographic transparency, independent security assessment, standards evaluation, and compliance with applicable cryptographic publication and export regulations.

Commercial use, production deployment, supported builds, integration, and PQS Enterprise licensing require a separate commercial license and support agreement.

For licensing inquiries, contact [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca).

Copyright © 2025-2026 Quantum Resistant Cryptographic Solutions Corporation. All rights reserved.

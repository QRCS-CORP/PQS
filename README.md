# PQS: Post Quantum Shell

## Introduction

[![Build](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/pqs/badge)](https://www.codefactor.io/repository/github/qrcs-corp/pqs)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/PQS/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/PQS/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/PQS/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/PQS)](https://github.com/QRCS-CORP/PQS/releases)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/PQS.svg)](https://github.com/QRCS-CORP/PQS/commits/main)
[![Protocol](https://img.shields.io/static/v1?label=Protocol&message=PQS%201.1&color=blue)](https://qrcs-corp.github.io/PQS/pdf/pqs_specification.pdf)
[![Target](https://img.shields.io/static/v1?label=Target&message=Secure%20Remote%20Administration&color=brightgreen)](#)

**PQS: A post-quantum remote shell, command, and file-transfer protocol carried inside the QSMS Simplex encrypted transport.**

## Overview

Post Quantum Shell (PQS) is a high-security remote-administration protocol intended for controlled deployments that require a migration path away from classical SSH-class cryptography. PQS is not an SSH wire-compatible implementation. It is a purpose-built application protocol that combines a one-way server-authenticated QSMS Simplex transport with application-layer login, policy-controlled command execution, sandbox enforcement, known-host continuity, structured logging, and confined file transfer.

The QSMS transport authenticates the server by verifying a signed ephemeral encapsulation key against a pinned server verification key. After QSMS establishes the encrypted channel, PQS performs user authentication inside that channel and authorizes each application operation according to the configured user, shell, policy, sandbox, and transfer-root state.

PQS is designed for environments where long-term confidentiality and controlled administrative access are required, including financial infrastructure, government and defense systems, healthcare networks, cloud administration, industrial control environments, and critical infrastructure.

[PQS Help Documentation](https://qrcs-corp.github.io/PQS/)  
[PQS Summary Document](https://qrcs-corp.github.io/PQS/pdf/pqs_summary.pdf)  
[PQS Protocol Specification](https://qrcs-corp.github.io/PQS/pdf/pqs_specification.pdf)  
[PQS Formal Analysis](https://qrcs-corp.github.io/PQS/pdf/pqs_formal.pdf)  

## Current Capabilities

PQS provides the following reference implementation capabilities:

- QSMS Simplex transport using server-authenticated post-quantum key establishment.
- Pinned server verification keys and client known-host continuity.
- Strict host-key checking for deployments that reject unknown server keys.
- Application-layer user login inside the encrypted QSMS channel.
- SCB-hardened passphrase verifiers with per-user salts and no stored plaintext passphrases.
- Persistent user records with enablement state, privilege level, shell assignment, failed-attempt tracking, and account disablement after configured failures.
- Policy-first command authorization using no-shell, restricted, forced-command, and raw-shell policy modes.
- Shell-control metacharacter rejection before command execution.
- Shell profile administration separated from command-policy authorization.
- Mandatory sandbox profile enforcement for command execution.
- POSIX run-as and chroot configuration fields where supported.
- Windows restricted-token and job-object containment where supported.
- Confined file transfer using per-user transfer roots.
- File get, put, list, mkdir, remove, and recursive transfer support.
- SHA3-256 file hashing and transfer metadata validation.
- Symbolic-link and reparse-point avoidance during recursive transfer.
- Server and client configuration persistence.
- Structured application logging with sanitized fields.
- Console administration for server user, shell, policy, key, fingerprint, sandbox, and operational status controls.

## Protocol Description

PQS is composed of two layers.

The first layer is QSMS Simplex, the encrypted transport. QSMS performs server authentication, ephemeral encapsulation, transcript binding, sequence validation, timestamp freshness checking, encryption, and authenticated decryption. The client verifies the server by checking a signed ephemeral KEM public key under the pinned server verification key. QSMS derives directional RCS channel state from the KEM shared secret and the session cookie, then confirms the channel before PQS accepts application data.

The second layer is the PQS application protocol. PQS application messages are carried inside encrypted QSMS payloads. Each PQS application payload begins with a one-byte application message type, followed by operation-specific data such as a login payload, command string, file path, file data, metadata, status text, disconnect notice, or error notice. PQS does not modify the QSMS key-exchange packets, QSMS packet flags, or QSMS packet header serialization.

The current console server maintains a single active application session instance and clears the active user state when the remote session disconnects. The QSMS encapsulation material used during establishment is ephemeral for the session, and provisional secrets are erased after key derivation and confirmation.

## Security Model

PQS uses a one-way server-authenticated trust model. The server owns the long-term signature key. The client pins or otherwise obtains the corresponding public verification key through an authenticated out-of-band process, a registration event, a deployment image, or another controlled distribution mechanism. During connection establishment, the server signs the authenticated ephemeral encapsulation material, and the client verifies the signature against the pinned verification key.

The established QSMS channel provides encrypted and authenticated transport for PQS application messages. PQS then enforces user authentication, command policy, shell selection, sandbox controls, transfer-root confinement, known-host verification, and structured error handling.

The current implementation is best characterized as a post-quantum SSH replacement candidate for controlled remote-administration environments. It does not claim SSH wire compatibility, SSH channel multiplexing, port forwarding, agent forwarding, mutual public-key client authentication, or implemented post-compromise recovery.

## Application Message Types

PQS defines application-layer message types for login, command execution, command responses, errors, disconnects, file downloads, file uploads, directory listing, directory creation, file removal, recursive download, recursive directory markers, recursive file markers, file data, and file-transfer status. These message types are encoded inside encrypted QSMS payloads after the QSMS channel reaches the established state.

## Command, Policy, and Sandbox Enforcement

PQS performs authorization before command execution. A user must authenticate successfully before remote command or file-transfer operations are accepted. Command policy is evaluated by privilege class and policy configuration.

The implemented policy modes are:

- **no-shell:** command execution is denied.
- **restricted:** only explicitly allowed command verbs are permitted.
- **forced:** the server substitutes the configured forced command.
- **raw-shell:** shell execution is permitted subject to denylists, shell profile constraints, and safety checks.

The policy engine extracts the leading command verb for allow-list and deny-list decisions. It rejects user-supplied command lines containing shell-control metacharacters that could carry an additional shell expression beyond the approved command verb.

The sandbox profile is mandatory for command execution in the hardened implementation. It includes timeout, working directory, environment-clearing behavior, optional POSIX run-as user, optional POSIX run-as group, and optional POSIX chroot configuration. POSIX execution closes non-standard file descriptors before exec and applies no-new-privileges where available. Windows execution uses controlled handle inheritance, restricted-token creation where available, and job-object limits for process containment.

## File Transfer and Confinement

The PQS file-transfer subsystem is implemented in `pqsxfer`. It validates relative paths, extracts bounded relative paths from application messages, constructs safe local paths, formats and parses metadata, computes SHA3-256 file hashes, creates per-user transfer roots, and applies confined open helpers.

Server-side file operations are confined to the authenticated user's transfer root. The implementation rejects empty paths, absolute paths, drive-qualified paths, traversal components, and oversized paths. POSIX builds use descriptor-relative traversal with no-follow semantics where available. Windows builds use canonical root-prefix validation and reject reparse-point targets before opening.

Recursive transfer traversal is centralized through the shared directory walker. Recursive upload and recursive download use the same traversal model, apply the configured recursion limit, and skip symbolic links or reparse points.

## Client Console Commands

The client console supports the following operational command set:

| Command | Purpose |
| --- | --- |
| `key` | Display the configured server public verification key. |
| `fp` | Display the server public-key fingerprint. |
| `known` | Display known-host entries. |
| `khremove <host>` | Remove a known-host entry. |
| `get <remote> [local]` | Download a file or directory from the server transfer root. |
| `put <local> [remote]` | Upload a file or directory into the server transfer root. |
| `list [path]` | List a remote transfer-root directory. |
| `mkdir <path>` | Create a directory under the remote transfer root. |
| `remove <path>` | Remove a file under the remote transfer root. |
| `help` | Show client help. |
| `help detail` | Show detailed client operations help. |
| `quit` | Terminate the session. |

## Server Console Administration

The server console provides administrative control over server configuration and access policy.

| Command | Purpose |
| --- | --- |
| `user` | Enter user administration mode. |
| `shell` | Enter shell profile administration mode. |
| `policy` | Enter command policy administration mode. |
| `key` | Display the server public key and fingerprint. |
| `fp` | Display the server public-key fingerprint. |
| `keyscan` | Display the known-hosts line for this server. |
| `sandbox` | Display command sandbox status. |
| `help` | Show server help. |
| `detail` | Show detailed setup and operations help. |
| `quit` | Shut down the PQS server. |

## Implementation Modules

| Module | Responsibility |
| --- | --- |
| `pqs.h` | Application message types, session states, privilege identifiers, client command identifiers, and PQS error codes. |
| `pqsuser` | User database, privilege conversion, passphrase verifier generation, timing-neutral verification, and user record persistence. |
| `pqsshell` | Shell profile database, shell enablement, default shell selection, and privilege-mask checks. |
| `pqspolicy` | Command policy database, allow-list and deny-list operations, forced command handling, privilege assignment, and shell-safety checks. |
| `pqssandbox` | Sandbox defaults, timeout clamping, working-directory validation, and optional POSIX run-as/chroot configuration. |
| `pqsprocess` | Platform-specific command process creation, output callbacks, descriptor or handle inheritance control, timeout handling, and sandbox application. |
| `pqskey` | Host-key fingerprinting, fingerprint formatting, known-host find, set, remove, and verify operations. |
| `pqsxfer` | File-transfer path validation, metadata parsing, hashing, recursive traversal, confined file opening, and per-user transfer roots. |
| `pqsconfig` | Server and client configuration defaults, save, load, and field parsing. |
| `pqslogger` | Structured application logging with sanitized fields. |

## Cryptographic Primitives

PQS uses the QSC cryptographic library and its post-quantum and SHA-3-family primitives. The configured protocol profile determines the exact asymmetric KEM and signature pairing.

### Asymmetric Cryptographic Primitives

- **ML-KEM / Kyber:** a lattice-based key encapsulation mechanism used for efficient post-quantum shared-secret establishment.
- **McEliece:** a code-based public-key encryption primitive available in supported protocol profiles.
- **ML-DSA / Dilithium:** a lattice-based digital signature scheme used for server authentication in supported profiles.
- **SPHINCS+:** a stateless hash-based signature scheme available in supported protocol profiles.

### Symmetric Cryptographic Primitives

PQS uses RCS, the Rijndael Cryptographic Stream, for authenticated symmetric encryption. RCS extends the Rijndael design with larger internal block configurations and a Keccak-based key schedule. It provides authenticated encryption with associated data through Keccak-derived authentication, preserving confidentiality and integrity for encrypted QSMS packets.

### Hash Functions and Key Derivation

- **SHA3:** collision-resistant hashing for identifiers, public-key fingerprints, and integrity checks.
- **SHAKE / cSHAKE:** extendable-output derivation for transport key material.
- **KMAC:** keyed authentication and transcript or message authentication where configured.
- **SCB:** passphrase-hardening for PQS server-side user verifiers.

## Cryptographic Dependencies

PQS depends on the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC). QSC provides the post-quantum algorithms, SHA-3-family functions, RCS implementation, system utilities, memory utilities, socket utilities, and platform support used by PQS.

## Compilation

PQS is written in C23 and is intended to build on Windows, Linux, and macOS. QSC must be available as a sibling or configured dependency path according to the build files used by the selected platform.

### Prerequisites

- **CMake:** 3.15 or newer for CMake-based builds.
- **Windows:** Visual Studio 2022 or newer.
- **Linux:** GCC or Clang.
- **macOS:** Clang via Xcode or Homebrew.
- **QSC:** the QRCS QSC library source tree.

### Windows (MSVC)

Use the Visual Studio solution to build the QSC library, the PQS library, and the PQS server and client projects. Ensure that the server and client project include paths reference both the PQS source directory and the QSC source directory. Ensure that all projects use the same target architecture and instruction-set configuration.

QSC and PQS support platform-optimized instruction families where available, including AES-NI, AVX, AVX2, and AVX-512. The QSC library, PQS library, server project, and client project must be built with compatible instruction-set settings.

### Linux and macOS (CMake)

A typical CMake build uses the following sequence from the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

When QSC is not in the default relative location expected by the build files, configure the QSC include and library paths according to the local build configuration.

### Hardware Acceleration Flags

Use a consistent hardware acceleration profile across QSC and PQS. Example x86_64 flag groups include:

- **Baseline:** `-msse2`
- **AVX:** `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2`
- **AVX2:** `-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2`
- **AVX-512:** `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -maes -mpclmul -mrdrnd -mbmi2`

Use only the flags supported by the build host and deployment CPU.

## License

INVESTMENT INQUIRIES:
QRCS is currently seeking a corporate investor for this technology.
Parties interested in licensing or investment should connect to us at: contact@qrcscorp.ca  
Visit https://www.qrcscorp.ca for a full inventory of our products and services.  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

License and Use Notice (2025-2026)  
This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.  
All source code and materials in this repository are provided under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026, unless explicitly stated otherwise.  
This license permits public access and non commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.  
The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.  
Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.  
For licensing inquiries, supported implementations, or commercial use, contact: licensing@qrcscorp.ca  
Quantum Resistant Cryptographic Solutions Corporation, 2026.  
_All rights reserved by QRCS Corp. 2026._
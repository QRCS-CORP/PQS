/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef PQS_DOXYMAIN_H
#define PQS_DOXYMAIN_H

/**
 * \mainpage Post Quantum Shell (PQS) Project Documentation
 *
 * \section intro_sec Introduction
 *
 * The Post Quantum Shell (PQS) project implements a post-quantum secure remote shell application. PQS uses the QSMS
 * Simplex transport as its encrypted communications layer and adds an application-layer shell protocol that provides
 * authenticated login, user authorization, command policy enforcement, shell profile selection, structured audit logging,
 * host-key trust management, configuration files, sandbox controls, and an implementation test harness.
 *
 * PQS is intended to provide a compact, quantum-resistant alternative to conventional secure-shell tooling. The transport
 * layer establishes a server-authenticated encrypted channel using post-quantum asymmetric cryptography and RCS authenticated
 * encryption. The PQS application layer then authenticates the connecting user before permitting command execution or
 * administrative actions.
 *
 * \section architecture_sec Architecture
 *
 * PQS is organized into three principal layers:
 *
 * - \b QSMS transport: establishes the encrypted client-server channel using a server-authenticated Simplex key exchange.
 * - \b PQS application protocol: carries login, command, response, error, and disconnect messages inside the encrypted channel.
 * - \b Server policy and execution layer: verifies users, applies privilege and command policy, selects the permitted shell profile,
 *   executes commands, logs events, and enforces sandbox controls.
 *
 * The QSMS transport authenticates the server to the client and provides confidentiality, integrity, sequence protection,
 * and replay resistance for the PQS application messages. PQS does not modify QSMS packet headers or QSMS transport flags;
 * its message identifiers are carried as plaintext fields inside the authenticated encrypted QSMS payload.
 *
 * \section protocol_sec PQS Application Protocol
 *
 * The PQS application protocol defines a message type byte at the start of each encrypted application payload. The defined
 * message classes include login request, login success, login failure, command request, response continuation, final response,
 * error, and disconnect messages. This framing allows command output to be streamed in bounded chunks while preserving prompt
 * handling on the client.
 *
 * A PQS session progresses through explicit application states: none, connected, login required, authenticated, command active,
 * and closing. Command execution is permitted only after the server has verified a PQS username and passphrase and has moved the
 * session to the authenticated state. Command requests received before authentication are rejected.
 *
 * \section authentication_sec Authentication and User Database
 *
 * PQS uses a server-side user database that is separate from the PQS host key. The host key identifies the server, while the user
 * database identifies authorized PQS users. A user record contains the username, privilege level, enabled state, SCB salt, SCB
 * verifier, login failure counter, shell profile assignment, and creation and modification timestamps.
 *
 * The client sends a username and passphrase over the established encrypted QSMS channel. The server looks up the username, checks
 * the account state, recomputes the SCB passphrase verifier using the stored salt, and compares the result using constant-time
 * verification. The server records the authenticated username and privilege level in the session state. Missing, disabled, or
 * incorrect credentials produce a generic login failure response and are logged without exposing passphrase material.
 *
 * \section privilege_sec Privileges and Command Policy
 *
 * PQS defines three operational privilege levels: guest, user, and admin. Each privilege level can be assigned to a named command
 * policy. A policy specifies an enforcement mode, enabled state, allowed privilege mask, allow-list, deny-list, and optional forced
 * command. The supported policy modes are no-shell, restricted command, forced command, and raw-shell.
 *
 * Before command execution, the server evaluates the authenticated user's privilege against the assigned policy. Denied commands are
 * rejected and logged. Restricted policies authorize only configured command verbs. Forced-command policies ignore the client-supplied
 * command and execute the configured forced command. Raw-shell policies allow execution unless the command is explicitly denied.
 *
 * \section shell_profiles_sec Shell Profiles
 *
 * PQS maintains a shell profile database that describes the command interpreters available on the server. A shell profile contains
 * a profile name, shell type, executable path, enabled state, default flag, and privilege mask. Built-in profiles are created for
 * common command shells when available, including cmd, PowerShell, pwsh, sh, bash, and zsh.
 *
 * User records may be assigned a shell profile. If no user-specific profile is configured, the server selects the default permitted
 * profile. A shell profile must be enabled, permitted for the authenticated user's privilege level, and backed by an existing
 * executable before it can be used for command execution.
 *
 * \section execution_sec Command Execution and Sandboxing
 *
 * PQS routes command execution through the authenticated user's command policy and shell profile. On POSIX systems, the server uses
 * a fork, pipe, dup2, exec, and wait execution path. On Windows, the server uses CreateProcessW with redirected pipes and explicit
 * handle cleanup. Command output is streamed to the client using PQS response-continuation and response-final messages.
 *
 * The server supports sandbox configuration controls including an execution working directory, command timeout, and optional minimal
 * environment mode. The POSIX backend applies the configured working directory and terminates commands that exceed the configured
 * timeout. The Windows backend supplies the configured working directory to CreateProcessW and terminates timed-out child processes.
 * These controls provide an enforcement foundation for controlled deployment. Platform service-account controls, restricted tokens,
 * job objects, chroot, seccomp, pledge, unveil, and related operating-system confinement mechanisms are deployment hardening layers.
 *
 * \section console_sec Server Console
 *
 * The PQS server console uses mode-specific prompts derived from the local computer name. Administrative modes include the root server
 * mode, user administration mode, shell profile mode, command policy mode, and logging or status-oriented commands. User administration
 * supports add, remove, enable, disable, password reset, privilege update, show, and list operations. Shell administration supports
 * add, remove, enable, disable, default selection, assignment, privilege allow, privilege deny, show, and list operations. Policy
 * administration supports add, remove, mode change, allow, deny, unallow, undeny, forced command, privilege assignment, show, and list
 * operations.
 *
 * \section host_trust_sec Host-Key Trust
 *
 * PQS computes a server host-key fingerprint from the encoded server public-key identity using SHA3-256. The client maintains a
 * known-hosts database that binds a host name or address to the expected fingerprint. Known hosts are verified before connection.
 * Unknown hosts may be pinned through an explicit trust-on-first-use prompt, and changed host keys are rejected. The server can print
 * its fingerprint and a known-hosts-compatible keyscan line for provisioning.
 *
 * \section logging_sec Logging and Audit
 *
 * PQS provides structured key-value logging for server, client, user, shell, policy, host-trust, sandbox, connection, authentication,
 * and command events. Logs include event identifiers, event names, log levels, usernames when authenticated, peer information where
 * available, and non-secret operational detail. Logs do not contain private keys, passphrases, salts, SCB verifiers, session keys,
 * nonces, transcript hashes, command output, or raw command text.
 *
 * \section configuration_sec Configuration
 *
 * PQS supports server and client configuration files. The server configuration includes storage paths, key paths, user database path,
 * shell database path, policy database path, log path, listen address, listen port, session limits, login limits, login timeout, idle
 * timeout, sandbox state, sandbox working directory, sandbox environment mode, command timeout, and log level. The client configuration
 * includes storage paths, server public key path, known-hosts path, log path, host, port, username, strict host-key checking, and log
 * level. Configuration files are created with safe defaults when missing.
 *
 * \section test_sec Test Harness
 *
 * PQS includes a test harness for the application-layer components that do not require a live QSMS network session. The tests cover
 * message constants, user database operations, passphrase verification, shell profile operations, command policy operations, known-hosts
 * operations, configuration parsing, and sandbox profile defaults. This harness provides a baseline for extending PQS validation to
 * integration, malformed-message, live client-server, and platform execution tests.
 *
 * \section crypto_sec Cryptographic Primitives
 *
 * PQS relies on the QSC cryptographic library and the QSMS Simplex transport. QSMS provides the post-quantum key exchange and
 * authenticated channel construction used by PQS. The principal primitive families used on the PQS path include:
 *
 * - \b Kyber / \b ML-KEM-family key encapsulation for post-quantum shared-secret establishment in supported QSMS configurations.
 * - \b Dilithium / \b ML-DSA-family signatures for server-authenticated transport key exchange in supported QSMS configurations.
 * - \b SHA-3, \b SHAKE, \b cSHAKE, and \b KMAC for hashing, key derivation, message authentication, and verifier construction support.
 * - \b RCS authenticated encryption for protected transport records.
 * - \b SCB for cost-hardened passphrase verifier derivation in the PQS user database.
 *
 * \section dependencies_sec Cryptographic Dependencies
 *
 * PQS uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 *
 * QRCS-PREL evaluation license. See license file for details.
 * All rights reserved by QRCS Corporation.
 *
 * \author John G. Underhill
 * \date 2026-06-03
 */

#endif

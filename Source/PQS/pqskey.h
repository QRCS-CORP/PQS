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

#ifndef PQS_KEY_H
#define PQS_KEY_H

#include "pqscommon.h"
#include "qsms.h"

/**
* \file pqskey.h
* \brief PQS host-key fingerprint and known-hosts helper functions.
*/

/*! \def PQS_KEY_FINGERPRINT_SIZE
 * \brief The binary SHA3-256 host-key fingerprint size.
 */
#define PQS_KEY_FINGERPRINT_SIZE 32U

/*! \def PQS_KEY_FINGERPRINT_STRING_SIZE
 * \brief The NUL-terminated hexadecimal host-key fingerprint string size.
 */
#define PQS_KEY_FINGERPRINT_STRING_SIZE ((PQS_KEY_FINGERPRINT_SIZE * 2U) + PQS_STRING_TERMINATOR_SIZE)

/*! \def PQS_KEY_KNOWN_HOST_LINE_MAX
 * \brief The maximum known-hosts line length.
 */
#define PQS_KEY_KNOWN_HOST_LINE_MAX 384U

/*! \def PQS_KEY_HOST_NAME_MAX
 * \brief The maximum host identifier length in a known-hosts record.
 */
#define PQS_KEY_HOST_NAME_MAX 256U

/*! \def PQS_KEY_KNOWN_HOST_MAGIC
 * \brief The known-hosts database header string.
 */
#define PQS_KEY_KNOWN_HOST_MAGIC "# PQSKNOWNHOSTS1"

/**
 * \brief Test whether a host token is valid for known-host storage.
 *
 * \param host: [const char*] The host identifier.
 *
 * \return [bool] Returns true if the host token is bounded and contains no control characters or record separators.
 */
PQS_EXPORT_API bool pqs_key_host_is_valid(const char* host);

/**
 * \brief Test whether a private key file has strict local permissions where supported.
 *
 * On POSIX systems this requires a regular file with no group or world permissions.
 * On Windows this verifies that the path exists and is not a directory; detailed DACL
 * validation is deployment-specific and should be handled by installer policy.
 *
 * \param fpath: [const char*] The private key path.
 *
 * \return [bool] Returns true if the file permission posture is acceptable for the platform check.
 */
PQS_EXPORT_API bool pqs_key_private_file_permissions_are_strict(const char* fpath);

/**
 * \brief Compute the PQS host-key fingerprint.
 *
 * The fingerprint is SHA3-256 over the QSMS public-key identity fields used by PQS.
 *
 * \param output: [uint8_t*] The fingerprint output buffer.
 * \param pubkey: [const struct] The QSMS public verification key.
 */
PQS_EXPORT_API void pqs_key_fingerprint(uint8_t output[PQS_KEY_FINGERPRINT_SIZE], const qsms_client_verification_key* pubkey);

/**
 * \brief Compute the PQS host-key fingerprint as hexadecimal text.
 *
 * \param output: [char*] The output buffer receiving a NUL-terminated hexadecimal fingerprint.
 * \param outlen: [size_t] The output buffer length.
 * \param pubkey: [const struct] The QSMS public verification key.
 *
 * \return [bool] Returns true if the fingerprint was written.
 */
PQS_EXPORT_API bool pqs_key_fingerprint_string(char* output, size_t outlen, const qsms_client_verification_key* pubkey);

/**
 * \brief Compute the PQS host-key fingerprint from an encoded public-key file.
 *
 * \param output: [char*] The output buffer receiving a NUL-terminated hexadecimal fingerprint.
 * \param outlen: [size_t] The output buffer length.
 * \param fpath: [const char*] The encoded server public-key path.
 *
 * \return [bool] Returns true if the public key was loaded and fingerprinted.
 */
PQS_EXPORT_API bool pqs_key_fingerprint_file(char* output, size_t outlen, const char* fpath);

/**
 * \brief Read the expected fingerprint for a host from a known-hosts file.
 *
 * \param fpath: [const char*] The known-hosts database path.
 * \param host: [const char*] The host identifier.
 * \param fingerprint: [char*] The output buffer receiving the fingerprint.
 * \param fplen: [size_t] The fingerprint output buffer length.
 *
 * \return [bool] Returns true if a matching host entry was found.
 */
PQS_EXPORT_API bool pqs_key_known_host_find(const char* fpath, const char* host, char* fingerprint, size_t fplen);

/**
 * \brief Add or replace a host fingerprint in a known-hosts file.
 *
 * \param fpath: [const char*] The known-hosts database path.
 * \param host: [const char*] The host identifier.
 * \param fingerprint: [const char*] The NUL-terminated hexadecimal fingerprint.
 *
 * \return [bool] Returns true if the known-hosts file was updated.
 */
PQS_EXPORT_API bool pqs_key_known_host_set(const char* fpath, const char* host, const char* fingerprint);

/**
 * \brief Remove a host fingerprint from a known-hosts file.
 *
 * \param fpath: [const char*] The known-hosts database path.
 * \param host: [const char*] The host identifier.
 *
 * \return [bool] Returns true if the known-hosts file was updated.
 */
PQS_EXPORT_API bool pqs_key_known_host_remove(const char* fpath, const char* host);

/**
 * \brief Test whether a string is a valid PQS host-key fingerprint.
 *
 * \param fingerprint: [const char*] The NUL-terminated hexadecimal fingerprint string.
 *
 * \return [bool] Returns true if the fingerprint has the expected length and hex format.
 */
PQS_EXPORT_API bool pqs_key_fingerprint_is_valid(const char* fingerprint);

/**
 * \brief Verify a host fingerprint against the known-hosts file.
 *
 * \param fpath: [const char*] The known-hosts database path.
 * \param host: [const char*] The host identifier.
 * \param fingerprint: [const char*] The NUL-terminated hexadecimal fingerprint.
 *
 * \return [bool] Returns true only if a matching host entry exists and matches the fingerprint.
 */
PQS_EXPORT_API bool pqs_key_known_host_verify(const char* fpath, const char* host, const char* fingerprint);

#endif

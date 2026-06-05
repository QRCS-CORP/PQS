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

#ifndef PQS_SANDBOX_H
#define PQS_SANDBOX_H

#include "pqscommon.h"

/**
* \file pqssandbox.h
* \brief PQS command execution sandbox configuration helpers.
*/

/*! \def PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS
 * \brief The default maximum runtime for a command executed by the PQS server.
 */
#define PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS 120U

/*! \def PQS_SANDBOX_MIN_TIMEOUT_SECONDS
 * \brief The minimum accepted non-zero command timeout.
 */
#define PQS_SANDBOX_MIN_TIMEOUT_SECONDS 5U

/*! \def PQS_SANDBOX_MAX_TIMEOUT_SECONDS
 * \brief The maximum accepted command timeout.
 */
#define PQS_SANDBOX_MAX_TIMEOUT_SECONDS 3600U

/*! \def PQS_SANDBOX_DEFAULT_OUTPUT_BYTES
 * \brief The default maximum number of command-output bytes returned for one command.
 */
#define PQS_SANDBOX_DEFAULT_OUTPUT_BYTES 1048576U

/*! \def PQS_SANDBOX_MIN_OUTPUT_BYTES
 * \brief The minimum accepted non-zero command-output byte limit.
 */
#define PQS_SANDBOX_MIN_OUTPUT_BYTES 4096U

/*! \def PQS_SANDBOX_MAX_OUTPUT_BYTES
 * \brief The maximum accepted command-output byte limit.
 */
#define PQS_SANDBOX_MAX_OUTPUT_BYTES 16777216U

/**
 * \brief The PQS command execution sandbox profile.
 */
PQS_EXPORT_API typedef struct pqs_sandbox_profile
{
	char working_directory[QSC_SYSTEM_MAX_PATH];
	char run_as_user[PQS_USERNAME_MAX];
	char run_as_group[PQS_USERNAME_MAX];
	uint32_t command_timeout_seconds;
	uint32_t max_output_bytes;
	bool enabled;
	bool clear_environment;
	bool chroot_enabled;
	bool allow_same_user;
} pqs_sandbox_profile;

/**
 * \brief Initialize a sandbox profile with safe defaults.
 *
 * \param profile: [struct] The sandbox profile to initialize.
 */
PQS_EXPORT_API void pqs_sandbox_profile_defaults(pqs_sandbox_profile* profile);

/**
 * \brief Configure a sandbox profile.
 *
 * \param profile: [struct] The sandbox profile.
 * \param enabled: [bool] Enables sandbox controls.
 * \param clear_environment: [bool] Enables minimal environment execution.
 * \param timeout_seconds: [uint32_t] The command timeout in seconds.
 * \param working_directory: [const] The confined working directory.
 */
PQS_EXPORT_API void pqs_sandbox_profile_configure(pqs_sandbox_profile* profile, bool enabled, bool clear_environment, uint32_t timeout_seconds, const char* working_directory);

/**
 * \brief Configure a sandbox profile with platform privilege-separation fields.
 *
 * \param profile: [struct] The sandbox profile.
 * \param enabled: [bool] Enables sandbox controls.
 * \param clear_environment: [bool] Enables minimal environment execution.
 * \param timeout_seconds: [uint32_t] The command timeout in seconds.
 * \param working_directory: [const] The confined working directory.
 * \param run_as_user: [const] The POSIX user name used for privilege drop, or NULL/empty.
 * \param run_as_group: [const] The POSIX group name used for privilege drop, or NULL/empty.
 * \param chroot_enabled: [bool] Enables POSIX chroot confinement when the server has the required privilege.
 */
PQS_EXPORT_API void pqs_sandbox_profile_configure_security(pqs_sandbox_profile* profile, bool enabled, bool clear_environment, uint32_t timeout_seconds, const char* working_directory, const char* run_as_user, const char* run_as_group, bool chroot_enabled);


/**
 * \brief Canonicalize the configured sandbox working directory in place.
 *
 * \param profile: [struct] The sandbox profile.
 *
 * \return [bool] Returns true if the configured working directory exists and was canonicalized.
 */
PQS_EXPORT_API bool pqs_sandbox_profile_canonicalize_working_directory(pqs_sandbox_profile* profile);

/**
 * \brief Set the same-user execution override for a sandbox profile.
 *
 * \details
 * When disabled, POSIX command execution requires an explicit run-as identity. This prevents
 * unconfined same-user command execution from being enabled accidentally. The override may be
 * enabled for development or deliberately single-user deployments.
 *
 * \param profile: [struct] The sandbox profile.
 * \param allow_same_user: [bool] Enables execution as the server process user when no run-as identity is configured.
 */
PQS_EXPORT_API void pqs_sandbox_profile_set_allow_same_user(pqs_sandbox_profile* profile, bool allow_same_user);

/**
 * \brief Set the maximum command-output byte count for a sandbox profile.
 *
 * \param profile: [struct] The sandbox profile.
 * \param max_output_bytes: [uint32_t] The maximum command-output byte count.
 */
PQS_EXPORT_API void pqs_sandbox_profile_set_output_limit(pqs_sandbox_profile* profile, uint32_t max_output_bytes);

/**
 * \brief Test whether a sandbox profile has a usable working directory.
 *
 * \param profile: [const struct] The sandbox profile.
 *
 * \return [bool] Returns true if the disabled profile needs no directory, or if the enabled profile has an existing canonicalizable directory.
 */
PQS_EXPORT_API bool pqs_sandbox_working_directory_valid(const pqs_sandbox_profile* profile);

/**
 * \brief Get the command timeout in milliseconds.
 *
 * \param profile: [const struct] The sandbox profile.
 *
 * \return [uint32_t] Returns the timeout in milliseconds, or zero if disabled.
 */
PQS_EXPORT_API uint32_t pqs_sandbox_timeout_milliseconds(const pqs_sandbox_profile* profile);

/**
 * \brief Get the configured command-output byte limit.
 *
 * \param profile: [const struct] The sandbox profile.
 *
 * \return [uint32_t] Returns the output byte limit, or zero if disabled.
 */
PQS_EXPORT_API uint32_t pqs_sandbox_output_limit_bytes(const pqs_sandbox_profile* profile);

#endif

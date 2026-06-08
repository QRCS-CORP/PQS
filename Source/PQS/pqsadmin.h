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

#ifndef PQS_ADMIN_H
#define PQS_ADMIN_H

#include "pqsconfig.h"
#include "pqskey.h"
#include "pqslogger.h"
#include "pqspolicy.h"
#include "pqssandbox.h"
#include "pqsshell.h"
#include "pqsuser.h"

/**
* \file pqsadmin.h
* \brief PQS typed administrative command functions.
*/

/*! \def PQS_ADMIN_ARGUMENT_MAX
 * \brief The maximum administrative command argument buffer size.
 */
#define PQS_ADMIN_ARGUMENT_MAX 128U

/*! \def PQS_ADMIN_OUTPUT_MAX
 * \brief The maximum formatted administrative command response size.
 */
#define PQS_ADMIN_OUTPUT_MAX 2048U

/*! \def PQS_ADMIN_POLICY_PREFIX
 * \brief The administrative policy command namespace prefix.
 */
#define PQS_ADMIN_POLICY_PREFIX "admin."

/*! \enum pqs_admin_command_ids
 * \brief Stable PQS typed administrative command identifiers.
 */
PQS_EXPORT_API typedef enum pqs_admin_command_ids
{
	pqs_admin_command_none = 0x0000U,                /*!< No administrative command. */
	pqs_admin_command_server_status = 0x0001U,       /*!< Print the authenticated server-session status. */
	pqs_admin_command_server_version = 0x0002U,      /*!< Print the PQS server version string. */
	pqs_admin_command_server_fingerprint = 0x0003U,  /*!< Print the server public-key fingerprint. */
	pqs_admin_command_sandbox_status = 0x0004U,      /*!< Print the active sandbox profile status. */
	pqs_admin_command_audit_verify = 0x0005U,        /*!< Verify the configured tamper-evident audit log. */
	pqs_admin_command_config_summary = 0x0006U,      /*!< Print a bounded server configuration summary. */
	pqs_admin_command_user_list = 0x0007U,           /*!< Print a bounded user database summary. */
	pqs_admin_command_policy_list = 0x0008U,         /*!< Print a bounded command-policy summary. */
	pqs_admin_command_shell_list = 0x0009U           /*!< Print a bounded shell-profile summary. */
} pqs_admin_command_ids;

/*! \struct pqs_admin_request
 * \brief A parsed PQS administrative command request.
 */
PQS_EXPORT_API typedef struct pqs_admin_request
{
	pqs_admin_command_ids command;                   /*!< The parsed command identifier. */
	char arguments[PQS_ADMIN_ARGUMENT_MAX];          /*!< The optional bounded argument string. */
} pqs_admin_request;

/*! \struct pqs_admin_context
 * \brief The server-side context made available to a typed administrative command.
 */
PQS_EXPORT_API typedef struct pqs_admin_context
{
	const char* user;                                /*!< The authenticated PQS user name. */
	const char* peer;                                /*!< The authenticated peer address string. */
	pqs_user_privileges privilege;                   /*!< The authenticated PQS privilege level. */
	bool authenticated;                              /*!< The server session authentication state. */
	const pqs_server_config* config;                 /*!< The active server configuration. */
	const pqs_user_store* users;                     /*!< The active user database. */
	const pqs_shell_store* shells;                   /*!< The active shell-profile database. */
	const pqs_policy_store* policies;                /*!< The active command-policy database. */
	const pqs_sandbox_profile* sandbox;              /*!< The active command sandbox profile. */
	const qsms_client_verification_key* public_key;  /*!< The server public verification key. */
	bool logger_failed;                               /*!< True when the audit logger has reported a write failure. */
} pqs_admin_context;

/**
 * \brief Authorize a typed administrative command against privilege and policy.
 *
 * \param context: [const struct] The server-side administrative context.
 * \param request: [const struct] The parsed administrative request.
 *
 * \return Returns true when the request is administratively authorized.
 */
PQS_EXPORT_API bool pqs_admin_authorize(const pqs_admin_context* context, const pqs_admin_request* request);

/**
 * \brief Execute a typed administrative command into a bounded response buffer.
 *
 * \param context: [const struct] The server-side administrative context.
 * \param request: [const struct] The parsed administrative request.
 * \param output: The output buffer receiving the response.
 * \param outlen: The output buffer size.
 *
 * \return Returns true if the command completed and a response was written.
 */
PQS_EXPORT_API bool pqs_admin_execute(const pqs_admin_context* context, const pqs_admin_request* request, char* output, size_t outlen);

/**
 * \brief Parse a bounded administrative request string.
 *
 * \param request: [struct] The parsed administrative request output.
 * \param command: [const] The NUL-terminated request text.
 *
 * \return Returns true if the request text matched a supported typed command.
 */
PQS_EXPORT_API bool pqs_admin_request_parse(pqs_admin_request* request, const char* command);

/**
 * \brief Return the stable command name for a typed administrative command.
 *
 * \param command: [enum] The administrative command identifier.
 *
 * \return Returns the stable command name, or "none".
 */
PQS_EXPORT_API const char* pqs_admin_command_to_string(pqs_admin_command_ids command);

/**
 * \brief Return the policy verb associated with a typed administrative command.
 *
 * \param command: [enum] The administrative command identifier.
 *
 * \return Returns the policy verb, or "admin.none".
 */
PQS_EXPORT_API const char* pqs_admin_policy_verb(pqs_admin_command_ids command);

#endif

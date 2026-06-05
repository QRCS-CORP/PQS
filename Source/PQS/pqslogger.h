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

#ifndef PQS_LOGGER_H
#define PQS_LOGGER_H

#include "pqscommon.h"

/**
* \file pqslogger.h
* \brief The PQS structured logging functions.
*/

/*! \def PQS_LOGGER_LINE_MAX
 * \brief The maximum formatted log line length.
 */
#define PQS_LOGGER_LINE_MAX 1536U

/*! \def PQS_LOGGER_USER_MAX
 * \brief The maximum user identifier length stored in a log event.
 */
#define PQS_LOGGER_USER_MAX 64U

/*! \def PQS_LOGGER_DETAIL_MAX
 * \brief The maximum detail field length stored in a log event.
 */
#define PQS_LOGGER_DETAIL_MAX 384U

/*! \enum pqs_log_level
 * \brief The PQS log severity levels.
 */
PQS_EXPORT_API typedef enum pqs_log_level
{
	pqs_log_level_none = 0x00U,							/*!< Logging is disabled. */
	pqs_log_level_error = 0x01U,						/*!< Error-level events. */
	pqs_log_level_warning = 0x02U,						/*!< Warning-level events. */
	pqs_log_level_info = 0x03U,							/*!< Informational events. */
	pqs_log_level_audit = 0x04U,						/*!< Security audit events. */
	pqs_log_level_debug = 0x05U							/*!< Debug events. */
} pqs_log_level;

/*! \enum pqs_log_event
 * \brief The PQS structured log event identifiers.
 */
PQS_EXPORT_API typedef enum pqs_log_event
{
	pqs_log_event_none = 0x0000U,						/*!< No event. */
	pqs_log_event_application_start = 0x1000U,			/*!< The application started. */
	pqs_log_event_application_stop = 0x1001U,			/*!< The application stopped. */
	pqs_log_event_key_loaded = 0x1100U,					/*!< The PQS key was loaded. */
	pqs_log_event_key_generated = 0x1101U,				/*!< A new PQS key was generated. */
	pqs_log_event_connection_open = 0x1200U,			/*!< A connection opened. */
	pqs_log_event_connection_close = 0x1201U,			/*!< A connection closed. */
	pqs_log_event_connection_refused = 0x1202U,			/*!< A connection was refused. */
	pqs_log_event_command_received = 0x1300U,			/*!< A command request was received. */
	pqs_log_event_command_complete = 0x1301U,			/*!< Command output completed. */
	pqs_log_event_command_failed = 0x1302U,				/*!< Command execution failed. */
	pqs_log_event_auth_success = 0x1400U,				/*!< Authentication succeeded. */
	pqs_log_event_auth_failure = 0x1401U,				/*!< Authentication failed. */
	pqs_log_event_auth_lockout = 0x1402U,				/*!< Authentication failed and the account was locked. */
	pqs_log_event_user_database_loaded = 0x1410U,		/*!< The server user database was loaded. */
	pqs_log_event_user_database_created = 0x1411U,		/*!< The server user database was created. */
	pqs_log_event_user_added = 0x1412U,					/*!< A server user record was added. */
	pqs_log_event_user_removed = 0x1413U,				/*!< A server user record was removed. */
	pqs_log_event_user_updated = 0x1414U,				/*!< A server user record was updated. */
	pqs_log_event_shell_database_loaded = 0x1420U,		/*!< The server shell profile database was loaded. */
	pqs_log_event_shell_database_created = 0x1421U,		/*!< The server shell profile database was created. */
	pqs_log_event_shell_added = 0x1422U,				/*!< A server shell profile was added. */
	pqs_log_event_shell_removed = 0x1423U,				/*!< A server shell profile was removed. */
	pqs_log_event_shell_updated = 0x1424U,				/*!< A server shell profile was updated. */
	pqs_log_event_policy_database_loaded = 0x1430U,		/*!< The server command policy database was loaded. */
	pqs_log_event_policy_database_created = 0x1431U,	/*!< The server command policy database was created. */
	pqs_log_event_policy_added = 0x1432U,				/*!< A server command policy was added. */
	pqs_log_event_policy_removed = 0x1433U,				/*!< A server command policy was removed. */
	pqs_log_event_policy_updated = 0x1434U,				/*!< A server command policy was updated. */
	pqs_log_event_policy_allowed = 0x1435U,				/*!< A command was permitted by policy. */
	pqs_log_event_policy_denied = 0x1436U,				/*!< A command was denied by policy. */
	pqs_log_event_hostkey_loaded = 0x1440U,				/*!< A host key was loaded. */
	pqs_log_event_hostkey_pinned = 0x1441U,				/*!< A host key fingerprint was pinned. */
	pqs_log_event_hostkey_verified = 0x1442U,			/*!< A host key fingerprint was verified. */
	pqs_log_event_hostkey_changed = 0x1443U,			/*!< A host key fingerprint differed from a known-hosts entry. */
	pqs_log_event_sandbox_enabled = 0x1450U,			/*!< The command sandbox was initialized. */
	pqs_log_event_sandbox_violation = 0x1451U,			/*!< The command sandbox rejected an execution condition. */
	pqs_log_event_command_timeout = 0x1452U,			/*!< A command was terminated by the sandbox timeout. */
	pqs_log_event_command_output_limit = 0x1453U,		/*!< A command was terminated by the sandbox output limit. */
	pqs_log_event_file_transfer_start = 0x1460U,		/*!< A file-transfer operation started. */
	pqs_log_event_file_transfer_complete = 0x1461U,		/*!< A file-transfer operation completed. */
	pqs_log_event_file_transfer_failed = 0x1462U,		/*!< A file-transfer operation failed. */
	pqs_log_event_protocol_error = 0x1500U,				/*!< A protocol error was detected. */
	pqs_log_event_admin_request = 0x1550U,			/*!< A typed administrative command was requested. */
	pqs_log_event_admin_allowed = 0x1551U,			/*!< A typed administrative command was authorized. */
	pqs_log_event_admin_denied = 0x1552U,			/*!< A typed administrative command was denied. */
	pqs_log_event_admin_complete = 0x1553U,			/*!< A typed administrative command completed. */
	pqs_log_event_admin_failed = 0x1554U,			/*!< A typed administrative command failed. */
	pqs_log_event_audit_chain_start = 0x1600U		/*!< The audit-log hash chain was initialized. */
} pqs_log_event;

/**
 * \brief Dispose of the PQS logger state.
 */
PQS_EXPORT_API void pqs_logger_dispose(void);

/**
 * \brief Initialize the PQS file logger.
 *
 * \param path: [const char*] The log file path.
 * \param level: [enum] The minimum enabled log level.
 *
 * \return [bool] Returns true if the logger was initialized.
 */
PQS_EXPORT_API bool pqs_logger_initialize(const char* path, pqs_log_level level);

/**
 * \brief Test if the logger has been initialized.
 *
 * \return [bool] Returns true if initialized.
 */
PQS_EXPORT_API bool pqs_logger_is_initialized(void);

/**
 * \brief Test whether a logger write failure has occurred since initialization.
 *
 * \return [bool] Returns true if a logger write or initialization append failed.
 */
PQS_EXPORT_API bool pqs_logger_failure_occurred(void);

/**
 * \brief Verify the tamper-evident PQS audit-log chain.
 *
 * \param path: [const char*] The log file path.
 * \param records: [uint64_t*] The number of verified records, or NULL.
 *
 * \return [bool] Returns true if every chained record verifies.
 */
PQS_EXPORT_API bool pqs_logger_verify_chain(const char* path, uint64_t* records);

/**
 * \brief Write a structured PQS log event.
 *
 * \param level: [enum] The event log level.
 * \param event: [enum] The event identifier.
 * \param user: [const char*] The authenticated PQS user, or NULL.
 * \param peer: [const char*] The peer address, or NULL.
 * \param detail: [const char*] A non-secret event detail string, or NULL.
 *
 * \return [bool] Returns true if the event was written.
 */
PQS_EXPORT_API bool pqs_logger_write(pqs_log_level level, pqs_log_event event, const char* user, const char* peer, const char* detail);

#endif

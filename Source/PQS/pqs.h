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

#ifndef PQS_H
#define PQS_H

#include "pqscommon.h"
#include "qsms.h"

#ifndef PQS_CRYPTO_PHASH_CPU_COST
	/*!
	 * \def PQS_CRYPTO_PHASH_CPU_COST
	 * \brief The default SCB passphrase verifier CPU cost.
	 *
	 * This value is intentionally exposed in pqs.h so integrators can tune verifier
	 * hardening at build time without modifying implementation files.
	 */
#	define PQS_CRYPTO_PHASH_CPU_COST 4U
#endif

#ifndef PQS_CRYPTO_PHASH_MEMORY_COST
	/*!
	 * \def PQS_CRYPTO_PHASH_MEMORY_COST
	 * \brief The default SCB passphrase verifier memory cost in mebibytes.
	 *
	 * This value is intentionally exposed in pqs.h so integrators can tune verifier
	 * hardening at build time without modifying implementation files.
	 */
#	define PQS_CRYPTO_PHASH_MEMORY_COST 1U
#endif

#ifndef PQS_USER_VERIFIER_DOMAIN
	/*!
	 * \def PQS_USER_VERIFIER_DOMAIN
	 * \brief The domain label bound into PQS SCB passphrase verifiers.
	 */
#	define PQS_USER_VERIFIER_DOMAIN "PQS-USER-SCB-VERIFIER-V2"
#endif

/*!
 * \enum pqs_application_messages
 * \brief Enumeration of PQS application-layer message types carried inside the encrypted QSMS channel.
 *
 * These values identify the plaintext payload type after QSMS decryption. They are not QSMS packet
 * flags and do not alter the QSMS wire protocol.
 */
PQS_EXPORT_API typedef enum pqs_application_messages
{
	pqs_application_message_none = 0x00U,						/*!< No PQS application message was specified. */
	pqs_application_message_login_request = 0x10U,				/*!< A client login request. */
	pqs_application_message_login_success = 0x11U,				/*!< A server login success response. */
	pqs_application_message_login_failure = 0x12U,				/*!< A server login failure response. */
	pqs_application_message_command_request = 0x20U,			/*!< A client command execution request. */
	pqs_application_message_response_more = 0x21U,				/*!< A server command response continuation chunk. */
	pqs_application_message_response_final = 0x22U,				/*!< A server command response final chunk. */
	pqs_application_message_admin_request = 0x23U,			/*!< A client typed administrative command request. */
	pqs_application_message_admin_response_more = 0x24U,		/*!< A typed administrative command response continuation chunk. */
	pqs_application_message_admin_response_final = 0x25U,		/*!< A typed administrative command response final chunk. */
	pqs_application_message_file_get_request = 0x40U,			/*!< A client file-download request. */
	pqs_application_message_file_put_start = 0x41U,				/*!< A client file-upload start request. */
	pqs_application_message_file_put_data = 0x42U,				/*!< A client file-upload data chunk. */
	pqs_application_message_file_put_final = 0x43U,				/*!< A client file-upload final chunk. */
	pqs_application_message_file_list_request = 0x44U,			/*!< A client directory-listing request. */
	pqs_application_message_file_mkdir_request = 0x45U,			/*!< A client directory creation request. */
	pqs_application_message_file_remove_request = 0x46U,		/*!< A client file-removal request. */
	pqs_application_message_file_data = 0x47U,					/*!< A server file-transfer data chunk. */
	pqs_application_message_file_final = 0x48U,					/*!< A server file-transfer final marker. */
	pqs_application_message_file_status = 0x49U,				/*!< A file-transfer status message. */
	pqs_application_message_file_get_recursive_request = 0x4AU,	/*!< A client recursive directory-download request. */
	pqs_application_message_file_directory_begin = 0x4BU,		/*!< A server recursive-transfer directory begin marker. */
	pqs_application_message_file_directory_end = 0x4CU,			/*!< A server recursive-transfer directory end marker. */
	pqs_application_message_file_begin = 0x4DU,					/*!< A server recursive-transfer file begin marker. */
	pqs_application_message_error = 0x30U,						/*!< A PQS application-layer error message. */
	pqs_application_message_disconnect = 0x31U					/*!< A PQS application-layer disconnect notice. */
} pqs_application_messages;

/*!
 * \enum pqs_session_states
 * \brief Enumeration of PQS application-layer session states.
 *
 * The QSMS transport state remains authoritative for cryptographic channel establishment. This state
 * tracks PQS application authorization and command-processing status after the QSMS channel is active.
 */
PQS_EXPORT_API typedef enum pqs_session_states
{
	pqs_session_state_none = 0x00U,								/*!< No PQS application session is active. */
	pqs_session_state_connected = 0x01U,						/*!< A QSMS channel is connected but no PQS login state has been assigned. */
	pqs_session_state_login_required = 0x02U,					/*!< The QSMS channel is active and PQS user authentication is required. */
	pqs_session_state_authenticated = 0x03U,					/*!< The PQS user has authenticated and command execution is permitted. */
	pqs_session_state_command_active = 0x04U,					/*!< A command request is being executed for the authenticated session. */
	pqs_session_state_closing = 0x05U							/*!< The PQS application session is closing. */
} pqs_session_states;

/*!
 * \enum pqs_user_privileges
 * \brief Enumeration of PQS server-side user privilege levels.
 */
PQS_EXPORT_API typedef enum pqs_user_privileges
{
	pqs_user_privilege_none = 0x00U,							/*!< No privilege level was assigned. */
	pqs_user_privilege_guest = 0x01U,							/*!< Guest-level access. */
	pqs_user_privilege_user = 0x02U,							/*!< Standard user-level access. */
	pqs_user_privilege_admin = 0x03U							/*!< Administrative access. */
} pqs_user_privileges;

/*!
 * \enum pqs_client_commands
 * \brief Enumeration of client commands in the PQS protocol.
 *
 * These commands are used by the client to indicate the desired operation.
 */
PQS_EXPORT_API typedef enum pqs_client_commands
{
	pqs_client_command_none = 0x00U,							/*!< No command was specified */
	pqs_client_command_cprint = 0x01U,							/*!< The certificate print command */
	pqs_client_command_knownhosts = 0x02U,						/*!< The known-hosts print command */
	pqs_client_command_knownhost_remove = 0x03U,				/*!< The known-hosts remove command */
	pqs_client_command_file_get = 0x04U,						/*!< The PQS file-download command. */
	pqs_client_command_file_put = 0x05U,						/*!< The PQS file-upload command. */
	pqs_client_command_file_list = 0x06U,						/*!< The PQS directory-list command. */
	pqs_client_command_file_mkdir = 0x07U,						/*!< The PQS directory creation command. */
	pqs_client_command_file_remove = 0x08U,						/*!< The PQS file-removal command. */
	pqs_client_command_help = 0x09U,							/*!< The client help command. */
	pqs_client_command_help_detail = 0x0AU,						/*!< The detailed client help command. */
	pqs_client_command_execute = 0x0BU,							/*!< The remote command execution request */
	pqs_client_command_admin = 0x0CU,							/*!< The typed administrative command request */
	pqs_client_command_quit = 0x0DU,							/*!< The session termination command */
} pqs_client_commands;

/*!
 * \enum pqs_errors
 * \brief Enumeration of error codes returned by PQS functions.
 *
 * These error values indicate various failure conditions encountered during
 * connection establishment, encryption/decryption, key exchange, and other operations.
 */
PQS_EXPORT_API typedef enum pqs_errors
{
	pqs_error_none = 0x00U,										/*!< No error was detected */
	pqs_error_accept_fail = 0x01U,								/*!< The socket accept function returned an error */
	pqs_error_authentication_failure = 0x02U,					/*!< The symmetric cipher had an authentication failure */
	pqs_error_bad_keep_alive = 0x03U,							/*!< The keep alive check failed */
	pqs_error_channel_down = 0x04U,								/*!< The communications channel has failed */
	pqs_error_connection_failure = 0x05U,						/*!< The device could not make a connection to the remote host */
	pqs_error_connect_failure = 0x06U,							/*!< The transmission failed at the KEX connection phase */
	pqs_error_decapsulation_failure = 0x07U,					/*!< The asymmetric cipher failed to decapsulate the shared secret */
	pqs_error_decryption_failure = 0x08U,						/*!< The decryption authentication has failed */
	pqs_error_establish_failure = 0x09U,						/*!< The transmission failed at the KEX establish phase */
	pqs_error_exchange_failure = 0x0AU,							/*!< The transmission failed at the KEX exchange phase */
	pqs_error_hash_invalid = 0x0BU,								/*!< The public-key hash is invalid */
	pqs_error_hosts_exceeded = 0x0CU,							/*!< The server has run out of socket connections */
	pqs_error_invalid_input = 0x0DU,							/*!< The expected input was invalid */
	pqs_error_invalid_request = 0x0EU,							/*!< The packet flag was unexpected */
	pqs_error_keepalive_expired = 0x0FU,						/*!< The keep alive has expired with no response */
	pqs_error_keepalive_timeout = 0x10U,						/*!< The keep alive request timed out */
	pqs_error_key_expired = 0x11U,								/*!< The PQS public key has expired  */
	pqs_error_key_unrecognized = 0x12U,							/*!< The key identity is unrecognized */
	pqs_error_keychain_fail = 0x13U,							/*!< The ratchet operation has failed */
	pqs_error_listener_fail = 0x14U,							/*!< The listener function failed to initialize */
	pqs_error_memory_allocation = 0x15U,						/*!< A memory allocation request failed */
	pqs_error_packet_unsequenced = 0x16U,						/*!< The packet was received out of sequence */
	pqs_error_random_failure = 0x17U,							/*!< The random generator has failed */
	pqs_error_receive_failure = 0x18U,							/*!< The receiver failed at the network layer */
	pqs_error_transmit_failure = 0x19U,							/*!< The transmitter failed at the network layer */
	pqs_error_unknown_protocol = 0x1AU,							/*!< The protocol string was not recognized */
	pqs_error_verify_failure = 0x1BU,							/*!< The expected data could not be verified */
	pqs_error_login_failure = 0x1CU,							/*!< The client received an authentication failure response */
	pqs_error_login_success = 0x1DU,							/*!< The client received an authentication success response */
	pqs_error_message_time_invalid = 0x1EU,						/*!< The packet valid time has expired */
	pqs_error_connection_refused = 0x1FU,						/*!< The connection was refused by the remote server */
	pqs_messages_system_message = 0x20U,						/*!< The remote host sent an error or disconnect message */
} pqs_errors;

#endif

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

/*!
 * \enum pqs_client_commands
 * \brief Enumeration of client commands in the PQS protocol.
 *
 * These commands are used by the client to indicate the desired operation.
 */
PQS_EXPORT_API typedef enum pqs_client_commands
{
	pqs_client_command_none = 0x00U,				/*!< No command was specified */
	pqs_client_command_cprint = 0x01U,				/*!< The certificate print command */
	pqs_client_command_execute = 0x02U,				/*!< The execute command */
	pqs_client_command_quit = 0x03U,				/*!< The quit command */
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
	pqs_error_none = 0x00U,							/*!< No error was detected */
	pqs_error_accept_fail = 0x01U,					/*!< The socket accept function returned an error */
	pqs_error_authentication_failure = 0x02U,		/*!< The symmetric cipher had an authentication failure */
	pqs_error_bad_keep_alive = 0x03U,				/*!< The keep alive check failed */
	pqs_error_channel_down = 0x04U,					/*!< The communications channel has failed */
	pqs_error_connection_failure = 0x05U,			/*!< The device could not make a connection to the remote host */
	pqs_error_connect_failure = 0x06U,				/*!< The transmission failed at the KEX connection phase */
	pqs_error_decapsulation_failure = 0x07U,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	pqs_error_decryption_failure = 0x08U,			/*!< The decryption authentication has failed */
	pqs_error_establish_failure = 0x09U,			/*!< The transmission failed at the KEX establish phase */
	pqs_error_exchange_failure = 0x0AU,				/*!< The transmission failed at the KEX exchange phase */
	pqs_error_hash_invalid = 0x0BU,					/*!< The public-key hash is invalid */
	pqs_error_hosts_exceeded = 0x0CU,				/*!< The server has run out of socket connections */
	pqs_error_invalid_input = 0x0DU,				/*!< The expected input was invalid */
	pqs_error_invalid_request = 0x0EU,				/*!< The packet flag was unexpected */
	pqs_error_keepalive_expired = 0x0FU,			/*!< The keep alive has expired with no response */
	pqs_error_keepalive_timeout = 0x10U,			/*!< The decryption authentication has failed */
	pqs_error_key_expired = 0x11U,					/*!< The PQS public key has expired  */
	pqs_error_key_unrecognized = 0x12U,				/*!< The key identity is unrecognized */
	pqs_error_keychain_fail = 0x13U,				/*!< The ratchet operation has failed */
	pqs_error_listener_fail = 0x14U,				/*!< The listener function failed to initialize */
	pqs_error_memory_allocation = 0x15U,			/*!< The server has run out of memory */
	pqs_error_packet_unsequenced = 0x16U,			/*!< The packet was received out of sequence */
	pqs_error_random_failure = 0x17U,				/*!< The random generator has failed */
	pqs_error_receive_failure = 0x18U,				/*!< The receiver failed at the network layer */
	pqs_error_transmit_failure = 0x19U,				/*!< The transmitter failed at the network layer */
	pqs_error_unknown_protocol = 0x1AU,				/*!< The protocol string was not recognized */
	pqs_error_verify_failure = 0x1BU,				/*!< The expected data could not be verified */
	pqs_error_login_failure = 0x1CU,				/*!< The client received an authentication failure response */
	pqs_error_login_success = 0x1DU,				/*!< The client received an authentication success response */
	pqs_error_message_time_invalid = 0x1EU,			/*!< The packet valid time has expired */
	pqs_error_connection_refused = 0x1FU,			/*!< The connection was refused by the remote server */
	pqs_messages_system_message = 0x20U,			/*!< The remote host sent an error or disconnect message */
} pqs_errors;

#endif

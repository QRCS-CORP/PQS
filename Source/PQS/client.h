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

#ifndef PQS_CLIENT_H
#define PQS_CLIENT_H

#include "pqs.h"
#include "rcs.h"
#include "socketclient.h"

/**
 * \file client.h
 * \brief PQS Client functions.
 *
 * \details
 * This header defines the functions used to implement the Post Quantum Shell (PQS)
 * client. The client is responsible for connecting to a remote PQS server using either
 * an IPv4 or IPv6 address, performing the simplex key exchange, and managing the send
 * and receive operations through callback functions.
 *
 * The public API includes the following functions:
 *
 * - pqs_client_connect_ipv4: Establishes a connection to a remote server using an IPv4 address.
 * - pqs_client_connect_ipv6: Establishes a connection to a remote server using an IPv6 address.
 *
 * Both functions initialize the PQS client state, perform the key exchange, and then invoke
 * callback functions to run the send loop (on the main thread) and the receive loop (on a new thread).
 * In case of errors during connection, key exchange, or data transmission, appropriate error logging
 * is performed and the connection is terminated.
 */

/**
 * \brief Connect to the remote server using IPv4 and perform the key exchange.
 *
 * \details
 * This function attempts to establish a connection to the remote PQS server using the provided
 * IPv4 address and port number. After a successful connection, it performs the client key exchange,
 * and returns the connected socket and PQS client state via callback functions. On success, the function
 * returns pqs_error_none; otherwise, it returns the appropriate error code.
 *
 * \param pubk [const] Pointer to the client's public signature verification key.
 * \param address [const] Pointer to the server's IPv4 address.
 * \param port The PQS application port number (typically PQS_SERVER_PORT).
 * \param send_func Pointer to the send callback function which contains the message send loop.
 * \param receive_callback Pointer to the receive callback function used to process the incoming server data stream.
 *
 * \return A pqs_errors value indicating the outcome of the connection and key exchange process.
 */
PQS_EXPORT_API pqs_errors pqs_client_connect_ipv4(const pqs_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(pqs_connection_state*), 
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t));

/**
 * \brief Connect to the remote server using IPv6 and perform the key exchange.
 *
 * \details
 * This function attempts to establish a connection to the remote PQS server using the provided
 * IPv6 address and port number. Following a successful connection, it carries out the client key exchange,
 * and returns the connected socket and PQS client state via callback functions. On success, the function
 * returns pqs_error_none; if any error occurs during the process, an appropriate error code is returned.
 *
 * \param pubk [const] Pointer to the client's public signature verification key.
 * \param address [const] Pointer to the server's IPv6 address.
 * \param port The PQS application port number (typically PQS_SERVER_PORT).
 * \param send_func Pointer to the send callback function which contains the message send loop.
 * \param receive_callback Pointer to the receive callback function used to process the incoming server data stream.
 *
 * \return A pqs_errors value indicating the outcome of the connection and key exchange process.
 */
PQS_EXPORT_API pqs_errors pqs_client_connect_ipv6(const pqs_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(pqs_connection_state*), 
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t));

#endif

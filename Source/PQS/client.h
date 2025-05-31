/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
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

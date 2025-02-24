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
 * Contact: john.underhill@protonmail.com
 */

#ifndef PQS_SERVER_H
#define PQS_SERVER_H

#include "pqs.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/socketserver.h"

/**
 * \file server.h
 * \brief PQS Server functions.
 *
 * \details
 * This header defines the functions used to implement the Post Quantum Shell (PQS)
 * server. These functions enable the server to pause accepting new connections, resume listening,
 * shut down (quitting) by closing all active connections, and to start the multi-threaded server
 * on both IPv4 and IPv6 networks.
 *
 * The multi-threaded server functions require a pointer to the listener socket as well as a pointer
 * to the server's private key (QSMP private key) used for secure communications. Callback functions
 * are provided to process incoming client data streams and to handle client disconnections.
 */

/*!
 * \def PQS_SERVER_PAUSE_INTERVAL
 * \brief The pause interval used by the server pause function.
 *
 * This macro defines the time interval (in milliseconds) during which the server will pause
 * accepting new connection requests.
 */
#define PQS_SERVER_PAUSE_INTERVAL 100

/**
 * \brief Pause the server, suspending new joins.
 *
 * \details
 * This function temporarily suspends the server listener so that no new client connections
 * will be accepted. This is useful during maintenance or when shutting down the server.
 */
PQS_EXPORT_API void pqs_server_pause(void);

/**
 * \brief Quit the server, closing all connections.
 *
 * \details
 * This function terminates the server by closing all active client connections. The provided
 * socket (source) is used as the listener or reference socket which is closed as part of the shutdown process.
 *
 * \param source A pointer to the server listener socket.
 */
PQS_EXPORT_API void pqs_server_quit(qsc_socket* source);

/**
 * \brief Resume the server listener function from a paused state.
 *
 * \details
 * This function resumes the server's listening operations if it was previously paused.
 * New client connections will again be accepted after this function is called.
 */
PQS_EXPORT_API void pqs_server_resume(void);

/**
 * \brief Start the IPv4 multi-threaded server.
 *
 * \details
 * This function starts the PQS server in a multi-threaded mode for IPv4. It initializes the listener
 * socket, performs necessary key exchange operations using the provided server private key, and then
 * spawns threads to handle incoming client data streams and disconnections.
 *
 * \param source A pointer to the listener server socket.
 * \param kset [const] A pointer to the QSMP private key (server signature key) used for the key exchange.
 * \param receive_callback A pointer to the callback function that processes client data streams.
 * \param disconnect_callback A pointer to the callback function invoked upon client disconnection.
 *
 * \return Returns a pqs_errors value indicating the success or failure of the server startup and key exchange process.
 */
PQS_EXPORT_API pqs_errors pqs_server_start_ipv4(qsc_socket* source,
    const pqs_server_signature_key* kset,
    void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t),
    void (*disconnect_callback)(pqs_connection_state*));

/**
 * \brief Start the IPv6 multi-threaded server.
 *
 * \details
 * This function starts the PQS server in a multi-threaded mode for IPv6. It initializes the listener
 * socket, performs the key exchange using the provided server private key, and spawns threads to handle
 * incoming client data streams.
 *
 * \param source A pointer to the listener server socket.
 * \param kset [const] A pointer to the QSMP private key (server signature key) used for the key exchange.
 * \param receive_callback A pointer to the callback function that processes client data streams.
 * \param disconnect_callback A pointer to the callback function invoked upon client disconnection.
 *
 * \return Returns a pqs_errors value indicating the success or failure of the server startup and key exchange process.
 */
PQS_EXPORT_API pqs_errors pqs_server_start_ipv6(qsc_socket* source,
    const pqs_server_signature_key* kset,
    void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t),
    void (*disconnect_callback)(pqs_connection_state*));

#endif
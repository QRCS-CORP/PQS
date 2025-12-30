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

#ifndef PQS_KEX_H
#define PQS_KEX_H

#include "pqscommon.h"
#include "pqs.h"

/**
 * \file kex.h
 * \brief PQS key exchange functions.
 *
 * \details
 * This header defines the internal functions and data structures used to perform the simplex key
 * exchange in the Post Quantum Shell (PQS) protocol. The key exchange functions establish secure
 * session keys between the client and server using post-quantum cryptographic primitives.
 *
 * \note These functions and structures are internal and non-exportable.
 */

/*!
 * \struct pqs_kex_client_state
 * \brief The PQS simplex client state structure.
 *
 * \details
 * This structure holds the state information required for the client-side key exchange in the PQS
 * protocol. It includes the client's key identity, the remote server's verification key, the client's
 * signature key, a session token hash, the client's own verification key, and the expiration time of
 * the keys.
 *
 * Fields:
 * - \c keyid: The key identity string (an array of PQS_KEYID_SIZE bytes).
 * - \c rverkey: The remote asymmetric signature verification key (an array of PQS_ASYMMETRIC_VERIFY_KEY_SIZE bytes).
 * - \c sigkey: The asymmetric signature signing key (an array of PQS_ASYMMETRIC_SIGNING_KEY_SIZE bytes).
 * - \c schash: The session token hash (an array of PQS_SCHASH_SIZE bytes).
 * - \c verkey: The local asymmetric signature verification key (an array of PQS_ASYMMETRIC_VERIFY_KEY_SIZE bytes).
 * - \c expiration: The expiration time, in seconds from epoch.
 */
typedef struct pqs_kex_client_state
{
    uint8_t keyid[PQS_KEYID_SIZE];                          /*!< The key identity string */
    uint8_t rverkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];        /*!< The remote asymmetric signature verification-key */
    uint8_t sigkey[PQS_ASYMMETRIC_SIGNING_KEY_SIZE];        /*!< The asymmetric signature signing-key */
    uint8_t schash[PQS_SCHASH_SIZE];                        /*!< The session token hash */
    uint8_t verkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];         /*!< The local asymmetric signature verification-key */
    uint64_t expiration;                                    /*!< The expiration time, in seconds from epoch */
} pqs_kex_client_state;

/*!
 * \struct pqs_kex_server_state
 * \brief The PQS simplex server state structure.
 *
 * \details
 * This structure holds the state information required for the server-side key exchange in the PQS
 * protocol. It includes the server's key identity, a session token hash, the server's private and public
 * keys for the asymmetric cipher, the server's signature key, the server's verification key, and the key
 * expiration time.
 *
 * Fields:
 * - \c keyid: The key identity string (an array of PQS_KEYID_SIZE bytes).
 * - \c schash: The session token hash (an array of PQS_SCHASH_SIZE bytes).
 * - \c prikey: The asymmetric cipher private key (an array of PQS_ASYMMETRIC_PRIVATE_KEY_SIZE bytes).
 * - \c pubkey: The asymmetric cipher public key (an array of PQS_ASYMMETRIC_PUBLIC_KEY_SIZE bytes).
 * - \c sigkey: The asymmetric signature signing key (an array of PQS_ASYMMETRIC_SIGNING_KEY_SIZE bytes).
 * - \c verkey: The local asymmetric signature verification key (an array of PQS_ASYMMETRIC_VERIFY_KEY_SIZE bytes).
 * - \c expiration: The expiration time, in seconds from epoch.
 */
typedef struct pqs_kex_server_state
{
    uint8_t keyid[PQS_KEYID_SIZE];                          /*!< The key identity string */
    uint8_t schash[PQS_SCHASH_SIZE];                        /*!< The session token hash */
    uint8_t prikey[PQS_ASYMMETRIC_PRIVATE_KEY_SIZE];        /*!< The asymmetric cipher private key */
    uint8_t pubkey[PQS_ASYMMETRIC_PUBLIC_KEY_SIZE];         /*!< The asymmetric cipher public key */
    uint8_t sigkey[PQS_ASYMMETRIC_SIGNING_KEY_SIZE];        /*!< The asymmetric signature signing-key */
    uint8_t verkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];         /*!< The local asymmetric signature verification-key */
    uint64_t expiration;                                    /*!< The expiration time, in seconds from epoch */
} pqs_kex_server_state;

/**
 * \brief Run the network server version of the simplex key exchange.
 *
 * \details
 * This internal function executes the key exchange protocol on the server side. It utilizes the
 * server key exchange state and the current connection state to negotiate and establish a secure
 * session between the server and client.
 *
 * \note This is an internal non-exportable API.
 *
 * \param kss A pointer to the server key exchange state.
 * \param cns A pointer to the connection state.
 *
 * \return Returns a pqs_errors value indicating the outcome of the key exchange process.
 */
pqs_errors pqs_kex_server_key_exchange(pqs_kex_server_state* kss, pqs_connection_state* cns);

/**
 * \brief Run the network client version of the simplex key exchange.
 *
 * \details
 * This internal function executes the key exchange protocol on the client side. It utilizes the
 * client key exchange state and the current connection state to negotiate and establish a secure
 * session with the server.
 *
 * \note This is an internal non-exportable API.
 *
 * \param kcs A pointer to the client key exchange state.
 * \param cns A pointer to the connection state.
 *
 * \return Returns a pqs_errors value indicating the outcome of the key exchange process.
 */
pqs_errors pqs_kex_client_key_exchange(pqs_kex_client_state* kcs, pqs_connection_state* cns);

#endif

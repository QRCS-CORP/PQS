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

#ifndef PQS_SERVER_APP_H
#define PQS_SERVER_APP_H

#include "common.h"
#include "../../QSC/QSC/socketbase.h"
#include "../../QSC/QSC/socketserver.h"

/**
* \file appsrv.h
* \brief The PQS server application
* Version 1.0
*/

#define PQS_SERVER_COMMAND_MAX 1280
#define PQS_SERVER_INPUT_MAX 260
#define PQS_SERVER_MAX_CLIENTS 8192
#define PQS_SERVER_MAX_LOGIN 3
#define PQS_SERVER_PASSWORD_MAX 260
#define PQS_SERVER_PASSWORD_MIN 8
#define PQS_CRYPTO_PHASH_CPU_COST 4
#define PQS_CRYPTO_PHASH_MEMORY_COST 1
#define PQS_SERVER_PROMPT_MAX 32

static const char PQS_PUBKEY_NAME[] = "server_public_key.pqpkey";
static const char PQS_PRIKEY_NAME[] = "server_secret_key.pqskey";
static const char PQS_APP_PATH[] = "PQS";

#endif

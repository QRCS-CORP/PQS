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

#ifndef PQS_CLIENT_APP_H
#define PQS_CLIENT_APP_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "pqscommon.h"

/**
* \file appclt.h
* \brief The PQS client application
* Version 1.0
*/

/*!
 * \def PQS_CLIENT_INPUT_MAX
 * \brief The maximum command input buffer size, including command text storage.
 */
#define PQS_CLIENT_INPUT_MAX 1280U

/*!
 * \def PQS_CLIENT_INPUT_MIN
 * \brief The minimum command length accepted by the client send loop.
 */
#define PQS_CLIENT_INPUT_MIN 3U

/*!
 * \def PQS_CLIENT_INPUT_TEXT_MAX
 * \brief The maximum NUL-terminated command text length copied into the client input buffer.
 */
#define PQS_CLIENT_INPUT_TEXT_MAX (PQS_CLIENT_INPUT_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_CLIENT_COMMAND_PAYLOAD_MAX
 * \brief The maximum client command text payload carried after the PQS application message type.
 */
#define PQS_CLIENT_COMMAND_PAYLOAD_MAX (PQS_CLIENT_INPUT_MAX - PQS_APPLICATION_MESSAGE_HEADER_SIZE - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_CLIENT_LOGIN_ATTEMPTS_MAX
 * \brief The maximum number of failed login attempts before the client login path fails.
 */
#define PQS_CLIENT_LOGIN_ATTEMPTS_MAX 3U

/*!
 * \def PQS_CLIENT_LOGIN_PASSWORD_MIN
 * \brief The minimum accepted login password length.
 */
#define PQS_CLIENT_LOGIN_PASSWORD_MIN 8U

/*!
 * \def PQS_CLIENT_LOGIN_TIME_INCREMENT
 * \brief The retry-delay increment, in milliseconds, applied after failed login attempts.
 */
#define PQS_CLIENT_LOGIN_TIME_INCREMENT 250U

/*!
 * \def PQS_CLIENT_LOGIN_TIME_MAXIMUM
 * \brief The maximum retry delay, in milliseconds, applied after failed login attempts.
 */
#define PQS_CLIENT_LOGIN_TIME_MAXIMUM 3000U

/*!
 * \def PQS_CLIENT_PASSWORD_LENGTH_MAX
 * \brief The maximum login password buffer size.
 */
#define PQS_CLIENT_PASSWORD_LENGTH_MAX 256U

/*!
 * \def PQS_CLIENT_PASSWORD_TEXT_MAX
 * \brief The maximum NUL-terminated login password text length.
 */
#define PQS_CLIENT_PASSWORD_TEXT_MAX (PQS_CLIENT_PASSWORD_LENGTH_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_CLIENT_PROMPT_MAX
 * \brief The fixed client prompt buffer size.
 */
#define PQS_CLIENT_PROMPT_MAX 256U

/*!
 * \def PQS_CLIENT_PROMPT_TEXT_MAX
 * \brief The maximum NUL-terminated prompt text length copied from server output.
 */
#define PQS_CLIENT_PROMPT_TEXT_MAX (PQS_CLIENT_PROMPT_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_CLIENT_TITLE_SIZE
 * \brief The client console title buffer size.
 */
#define PQS_CLIENT_TITLE_SIZE 64U

static const char PQS_PUBKEY_NAME[] = "server_public_key.pqpkey";
static const char PQS_APP_PATH[] = "PQS";
static const char PQS_CLIENT_LOG_NAME[] = "pqs_client.log";

#endif

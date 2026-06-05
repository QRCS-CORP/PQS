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
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef PQSHELP_H
#define PQSHELP_H

#include "pqscommon.h"

/**
 * \brief Return the detailed PQS client setup and operations help text.
 *
 * \return Returns a constant NUL-terminated help string.
 */
PQS_EXPORT_API const char* pqs_help_client_detail(void);

/**
 * \brief Return the detailed PQS server setup and operations help text.
 *
 * \return Returns a constant NUL-terminated help string.
 */
PQS_EXPORT_API const char* pqs_help_server_detail(void);

#endif

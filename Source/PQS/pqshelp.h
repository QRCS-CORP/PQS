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
 * \brief Print the PQS client banner text.
 */
PQS_EXPORT_API void pqs_help_client_print_banner(void);

/**
 * \brief Print the detailed PQS client setup and operations help text.
 */
PQS_EXPORT_API void pqs_help_client_print_detail(void);

/**
 * \brief Print the detailed PQS server setup and operations help text.
 */
PQS_EXPORT_API void pqs_help_client_print_help(void);

/**
 * \brief Print the PQS server banner text.
 */
PQS_EXPORT_API void pqs_help_server_print_banner(void);

/**
 * \brief Print the detailed PQS server setup and operations help text.
 */
PQS_EXPORT_API void pqs_help_server_print_detail(void);

/**
 * \brief Print the detailed PQS server setup and operations help text.
 */
PQS_EXPORT_API void pqs_help_server_print_help(void);

/**
 * \brief Print the detailed PQS server policy help text.
 */
PQS_EXPORT_API void pqs_help_server_print_policy(void);

#endif

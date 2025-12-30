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

#ifndef PQS_LOGGER_H
#define PQS_LOGGER_H

#include "pqscommon.h"

/**
 * \file logger.h
 * \brief PQS logging functions.
 *
 * \details
 * This header defines the internal logging functions used by the PQS protocol implementation.
 * The logger provides capabilities for initializing, writing, reading, printing, and resetting
 * the log file. It also includes functions for checking the existence of the log file and for
 * performing a self-test of the logger functionality.
 *
 * \note These functions and constants are internal and non-exportable.
 */

/*!
 * \def PQS_LOGGING_MESSAGE_MAX
 * \brief The maximum length of a logging message.
 *
 * This macro defines the maximum number of characters allowed in a single log message.
 */
#define PQS_LOGGING_MESSAGE_MAX 256U

/*!
 * \brief The default path for the PQS logger.
 *
 * This constant string defines the default directory or path used for the logger.
 */
static const char PQS_LOGGER_PATH[] = "PQS";

/*!
 * \brief The default log file name for the PQS logger.
 *
 * This constant string defines the default log file name.
 */
static const char PQS_LOGGER_FILE[] = "pqs.log";

/*!
 * \brief The log file header.
 *
 * This constant string is used as the header in the log file to indicate the PQS version.
 */
static const char PQS_LOGGER_HEAD[] = "PQS Version 1.0";

/**
 * \brief Test if the log file exists.
 *
 * \details
 * This function checks whether the log file exists in the default or specified path.
 *
 * \return Returns true if the log file exists; otherwise, returns false.
 */
bool pqs_logger_exists(void);

/**
 * \brief Initialize the logger.
 *
 * \details
 * This function initializes the logging system by setting up the log file path and creating the log file
 * if it does not already exist. The provided path is used as the location for the log file.
 *
 * \param path The log file path to be used for initialization.
 */
void pqs_logger_initialize(const char* path);

/**
 * \brief Print the log file.
 *
 * \details
 * This function outputs the contents of the log file to the console or another standard output.
 */
void pqs_logger_print(void);

/**
 * \brief Read the contents of the log file.
 *
 * \details
 * This function reads the log file into the provided output buffer.
 *
 * \param output The output array where the log file contents will be stored.
 * \param otplen The size (in bytes) of the output array.
 */
void pqs_logger_read(char* output, size_t otplen);

/**
 * \brief Reset the logger.
 *
 * \details
 * This function clears the log file by erasing all its contents, effectively resetting the logger.
 */
void pqs_logger_reset(void);

/**
 * \brief Get the log file size.
 *
 * \details
 * This function retrieves the size of the log file in bytes.
 *
 * \return Returns the size (in bytes) of the log file.
 */
size_t pqs_logger_size(void);

/**
 * \brief Write a message to the log file.
 *
 * \details
 * This function writes the specified log message to the log file. The message should be a null-terminated string.
 *
 * \param message [const] The log message to be written.
 * 
 * \return Returns true on successful writing; otherwise, false.
 */
bool pqs_logger_write(const char* message);

#if defined(PQS_DEBUG_MODE)
/**
 * \brief Perform a manual test of the logger functions.
 *
 * \details
 * This function executes a series of tests on the logger to verify that the logging functions
 * (such as initialization, writing, reading, and resetting) are operating correctly.
 *
 * \return Returns true if the logger self-test is successful; otherwise, false.
 */
bool pqs_logger_test(void);
#endif

#endif

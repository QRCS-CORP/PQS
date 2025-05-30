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
#define PQS_LOGGING_MESSAGE_MAX 256

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

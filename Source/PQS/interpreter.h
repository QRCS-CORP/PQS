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

#ifndef PQS_SERVER_INTERPRETER_H
#define PQS_SERVER_INTERPRETER_H

#include "pqscommon.h"

/**
 * \file interpreter.h
 * \brief The command interpreter functions.
 *
 * \details
 * This header defines the functions and macros used to implement the command interpreter for PQS.
 * The interpreter supports operations such as parameter extraction from command strings, converting
 * files to and from byte streams, and executing system commands with their output captured.
 * Platform-specific support is provided for Windows and non-Windows systems.
 *
 * The public API includes functions to initialize and clean up the interpreter, extract parameters,
 * perform file I/O operations, and execute commands.
 */

/*!
 * \def PQS_INTERPRETER_COMMAND_BUFFER_SIZE
 * \brief The command buffer size.
 *
 * This macro defines the size (in bytes) of the buffer used for reading command output.
 */
#define PQS_INTERPRETER_COMMAND_BUFFER_SIZE 128U

/*!
 * \def PQS_INTERPRETER_COMMAND_EXECUTE_SIZE
 * \brief The command execute buffer size.
 *
 * This macro defines the maximum size (in bytes) for the output buffer when executing a command.
 */
#define PQS_INTERPRETER_COMMAND_EXECUTE_SIZE 10240000UL

/**
 * \brief Extract a parameter from a string.
 *
 * \details
 * This function searches the input message string for a parameter by locating the first space
 * character and extracting the substring that follows. The extracted parameter is copied into the
 * provided buffer.
 *
 * \param param The output buffer that will receive the parameter string.
 * \param message [const] The input message string containing the parameter.
 * 
 * \return Returns true if a parameter was successfully extracted; otherwise, false.
 */
PQS_EXPORT_API bool pqs_interpreter_extract_paramater(char* param, const char* message);

/**
 * \brief Extract two parameters from a string.
 *
 * \details
 * This function parses the input message string to extract two separate parameters. It uses delimiters,
 * such as a comma and space, to determine the boundaries of each parameter and copies the resulting
 * substrings into the provided buffers.
 *
 * \param param1 The output buffer for the first parameter.
 * \param param2 The output buffer for the second parameter.
 * \param message [const] The input message string containing the parameters.
 * 
 * \return Returns true if the parameters were successfully extracted; otherwise, false.
 */
PQS_EXPORT_API bool pqs_interpreter_extract_paramaters(char* param1, char* param2, const char* message);

/**
 * \brief Copy a file to a byte array.
 *
 * \details
 * This function reads the contents of a file specified by the parameter string and writes the file
 * data into a provided byte array. The output includes a constructed result string that contains the file
 * path, name, and extension followed by the file data.
 *
 * \param result The output byte array that will receive the file stream.
 * \param reslen The length (in bytes) of the result buffer.
 * \param parameter [const] The parameter string specifying the file to be read.
 * 
 * \return Returns the total number of bytes written to the result stream.
 */
PQS_EXPORT_API size_t pqs_interpreter_file_to_stream(uint8_t* result, size_t reslen, const char* parameter);

/**
 * \brief Get the length of a file.
 *
 * \details
 * This function retrieves the size (in bytes) of a file specified by the parameter string.
 * It extracts the file path and queries the file system to determine the file length.
 *
 * \param parameter [const] The file path or paths string.
 * 
 * \return Returns the length of the file in bytes.
 */
PQS_EXPORT_API size_t pqs_interpreter_file_buffer_length(const char* parameter);

/**
 * \brief Copy a byte stream to a file.
 *
 * \details
 * This function writes the data from a byte stream to a file. The file destination is determined by the
 * parameter string, and the number of bytes to write is given by the parameter length.
 *
 * \param result The output parameter result string.
 * \param reslen The length (in bytes) of the result buffer.
 * \param parameter [const] The parameter string specifying the destination file.
 * \param parlen The length (in bytes) of the parameter string.
 * 
 * \return Returns the number of bytes written to the file.
 */
PQS_EXPORT_API size_t pqs_interpreter_stream_to_file(uint8_t* result, size_t reslen, const char* parameter, size_t parlen);

/**
 * \brief Execute a command and return its output.
 *
 * \details
 * This function executes a system command specified by the parameter string and captures its output.
 * The command output is stored in the provided result buffer.
 *
 * \param result The output buffer that will receive the command result string.
 * \param reslen The length (in bytes) of the result buffer.
 * \param parameter [const] The command string to be executed.
 * 
 * \return Returns the number of bytes written to the result buffer containing the command output.
 */
PQS_EXPORT_API size_t pqs_interpreter_command_execute(char* result, size_t reslen, const char* parameter);

/**
 * \brief Initialize the command interpreter.
 *
 * \details
 * This function initializes the interpreter. On Windows systems, it creates pipes and launches
 * a hidden command shell (cmd.exe) to execute commands. On non-Windows systems, it sets the internal
 * state to active.
 *
 * \return Returns true if the interpreter was successfully initialized; otherwise, false.
 */
PQS_EXPORT_API bool pqs_interpreter_initialize(void);

/**
 * \brief Clean up the command interpreter.
 *
 * \details
 * This function releases resources allocated by the command interpreter. On Windows, it terminates the
 * command process and closes any associated handles.
 */
PQS_EXPORT_API void pqs_interpreter_cleanup(void);

#endif

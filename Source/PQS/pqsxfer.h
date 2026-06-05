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

#ifndef PQS_XFER_H
#define PQS_XFER_H

#include "pqscommon.h"
#include <stdio.h>

/**
 * \file pqsxfer.h
 * \brief PQS native file-transfer helpers.
 */

 /**
  * \enum pqs_xfer_walk_events
  * \brief File-transfer directory walk event types.
  */
typedef enum pqs_xfer_walk_events
{
	pqs_xfer_walk_event_directory_begin = 0x01U,	/*!< A directory has been entered and its relative transfer path is available to the callback. */
	pqs_xfer_walk_event_file = 0x02U,				/*!< A regular file has been discovered and its local and relative transfer paths are available to the callback. */
	pqs_xfer_walk_event_directory_end = 0x03U		/*!< A directory has been fully processed and its relative transfer path is available to the callback. */
} pqs_xfer_walk_events;

/**
 * \brief File-transfer directory walk callback.
 *
 * \param event: The directory-walk event type.
 * \param localpath: [const] The local file-system path for the event.
 * \param relative: [const] The relative PQS transfer path for the event.
 * \param context: [void] An application-defined callback context.
 *
 * \return Returns true to continue traversal; otherwise, false.
 */
typedef bool (*pqs_xfer_walk_callback)(pqs_xfer_walk_events event, const char* localpath, const char* relative, void* context);

/**
 * \brief Return the plaintext payload length carried after the PQS application message header.
 *
 * \param message: [const] The application message buffer.
 * \param msglen: The application message length.
 *
 * \return Returns the payload length, or zero if the message is not valid.
 */
PQS_EXPORT_API size_t pqs_xfer_payload_size(const uint8_t* message, size_t msglen);

/**
 * \brief Join two local file-system path components.
 */
PQS_EXPORT_API void pqs_xfer_join_path(char* output, size_t outlen, const char* first, const char* second);

/**
 * \brief Join two remote transfer path components using the PQS remote delimiter.
 */
PQS_EXPORT_API void pqs_xfer_join_remote(char* output, size_t outlen, const char* first, const char* second);

/**
 * \brief Test whether a local path is a directory.
 */
PQS_EXPORT_API bool pqs_xfer_local_path_is_directory(const char* path);

/**
 * \brief Create all parent directories for a local output path.
 */
PQS_EXPORT_API bool pqs_xfer_create_parent_directories(const char* fpath);

/**
 * \brief Build a local path for a recursive transfer member.
 */
PQS_EXPORT_API bool pqs_xfer_make_local_recursive_path(char* output, size_t outlen, const char* root, const char* relative);

/**
 * \brief Walk a local directory tree and report PQS transfer paths through a callback.
 *
 * \param localroot: [const] The local root directory to traverse.
 * \param remoteroot: [const] The relative PQS transfer root associated with localroot.
 * \param maxdepth: The maximum recursion depth accepted by the traversal.
 * \param callback: [pqs_xfer_walk_callback] The traversal callback.
 * \param context: [void] The caller-defined callback context.
 *
 * \return Returns true if the traversal completed successfully; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_walk_directory(const char* localroot, const char* remoteroot, size_t maxdepth, pqs_xfer_walk_callback callback, void* context);

/**
 * \brief Build a confined absolute path from a transfer root and a relative remote path.
 *
 * \param output: [char] The output path buffer.
 * \param outlen: The length of the output path buffer.
 * \param root: [const] The configured transfer root directory.
 * \param relative: [const] The remote path supplied by the peer.
 *
 * \return Returns true if the resulting path is confined to the root; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_make_path(char* output, size_t outlen, const char* root, const char* relative);

/**
 * \brief Extract a bounded relative path from a file-transfer application message.
 *
 * \param output: [char] The output path buffer.
 * \param outlen: The length of the output path buffer.
 * \param message: [const] The application message buffer.
 * \param msglen: The application message length.
 *
 * \return Returns true if a NUL-terminated relative path was extracted safely; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_extract_relative(char* output, size_t outlen, const uint8_t* message, size_t msglen);

/**
 * \brief Test whether a local path resolves inside the configured root.
 *
 * \param root: [const] The configured root path.
 * \param path: [const] The path to test.
 * \param existing: Set to true when the target path must already exist.
 *
 * \return Returns true if the resolved path remains inside the root; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_path_is_confined(const char* root, const char* path, bool existing);

/**
 * \brief Test whether a remote file-transfer path is safe.
 *
 * \param relative: [const] The NUL-terminated remote path to test.
 *
 * \return Returns true if the path is a relative, non-traversing PQS transfer path; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_path_is_safe(const char* relative);

/**
 * \brief Build a per-user transfer root path.
 *
 * \param output: [char] The output path buffer.
 * \param outlen: The length of the output path buffer.
 * \param root: [const] The configured global transfer root directory.
 * \param username: [const] The authenticated PQS user name.
 *
 * \return Returns true if the per-user root path was created or already existed; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_make_user_root(char* output, size_t outlen, const char* root, const char* username);

/**
 * \brief Open a confined transfer file for binary reading.
 *
 * \param root: [const] The configured transfer root directory.
 * \param relative: [const] The relative transfer path.
 *
 * \return [FILE*] Returns an open file pointer, or NULL on failure.
 */
PQS_EXPORT_API FILE* pqs_xfer_open_read_confined(const char* root, const char* relative);

/**
 * \brief Open a confined transfer file for binary writing.
 *
 * \param root: [const] The configured transfer root directory.
 * \param relative: [const] The relative transfer path.
 *
 * \return [FILE*] Returns an open file pointer, or NULL on failure.
 */
PQS_EXPORT_API FILE* pqs_xfer_open_write_confined(const char* root, const char* relative);

/**
 * \brief Build a confined temporary upload path from a relative target path.
 *
 * The temporary path remains relative to the same transfer root and is suitable
 * for writing a staged upload before final hash verification.
 *
 * \param output: [char] The output relative temporary path.
 * \param outlen: The length of the output path buffer.
 * \param relative: [const] The final relative target path.
 *
 * \return Returns true if the temporary relative path was created safely.
 */
PQS_EXPORT_API bool pqs_xfer_make_temporary_path(char* output, size_t outlen, const char* relative);

/**
 * \brief Remove a confined file inside the configured transfer root.
 *
 * \param root: [const] The configured transfer root directory.
 * \param relative: [const] The relative transfer path to remove.
 *
 * \return Returns true if the confined file was removed; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_remove_confined(const char* root, const char* relative);

/**
 * \brief Create a confined directory inside the configured transfer root.
 *
 * \param root: [const] The configured transfer root directory.
 * \param relative: [const] The relative directory path to create.
 *
 * \return Returns true if the confined directory was created or already exists; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_make_directory_confined(const char* root, const char* relative);

/**
 * \brief Publish a staged temporary upload as its final confined file.
 *
 * \param root: [const] The configured transfer root directory.
 * \param temporary: [const] The relative temporary upload path.
 * \param relative: [const] The final relative target path.
 *
 * \return Returns true if the temporary file was renamed into its final path; otherwise, false.
 */
PQS_EXPORT_API bool pqs_xfer_publish_temporary_file(const char* root, const char* temporary, const char* relative);

/**
 * \brief Compute the SHA3-256 hash of a local file.
 *
 * \param fpath: [const] The local file path.
 * \param hexhash: [char] The output hexadecimal hash buffer.
 * \param hexlen: The length of the output hexadecimal hash buffer.
 * \param filesize: [size_t] An optional output parameter receiving the file size.
 *
 * \return Returns true if the hash was computed successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_hash_file(const char* fpath, char* hexhash, size_t hexlen, size_t* filesize);

/**
 * \brief Format file-transfer metadata text.
 *
 * \param output: [char] The output metadata buffer.
 * \param outlen: The length of the output metadata buffer.
 * \param filesize: The file size associated with the transfer.
 * \param hexhash: [const] The NUL-terminated SHA3-256 hexadecimal hash.
 *
 * \return Returns true if metadata text was written successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_format_metadata(char* output, size_t outlen, size_t filesize, const char* hexhash);

/**
 * \brief Parse file-transfer metadata text.
 *
 * \param metadata: [const] The NUL-terminated metadata string.
 * \param filesize: [size_t] The parsed file size output parameter.
 * \param hexhash: [char] The output hash text buffer.
 * \param hexlen: The length of the output hash text buffer.
 *
 * \return Returns true if the metadata was parsed successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_parse_metadata(const char* metadata, size_t* filesize, char* hexhash, size_t hexlen);


/**
 * \brief Format recursive file-transfer metadata text.
 *
 * \param output: [char] The output metadata buffer.
 * \param outlen: The length of the output metadata buffer.
 * \param relative: [const] The relative file path inside the recursive transfer root.
 * \param filesize: The file size associated with the transfer.
 * \param hexhash: [const] The NUL-terminated SHA3-256 hexadecimal hash.
 *
 * \return Returns true if metadata text was written successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_format_file_metadata(char* output, size_t outlen, const char* relative, size_t filesize, const char* hexhash);

/**
 * \brief Parse recursive file-transfer metadata text.
 *
 * \param metadata: [const] The NUL-terminated metadata string.
 * \param relative: [char] The output relative path buffer.
 * \param relen: The length of the relative path output buffer.
 * \param filesize: [size_t] The parsed file size output parameter.
 * \param hexhash: [char] The output hash text buffer.
 * \param hexlen: The length of the output hash text buffer.
 *
 * \return Returns true if the metadata was parsed successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_parse_file_metadata(const char* metadata, char* relative, size_t relen, size_t* filesize, char* hexhash, size_t hexlen);

/**
 * \brief Test whether a file-system path is a symbolic link or reparse point.
 *
 * \param path: [const] The local file-system path to test.
 *
 * \return Returns true if the path is a symbolic link or reparse point; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_xfer_path_is_symlink(const char* path);

#endif

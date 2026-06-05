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

#ifndef PQS_MASTER_COMMON_H
#define PQS_MASTER_COMMON_H

#include "qsccommon.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
* \internal
* \file common.h
* \brief PQS common includes and definitions
* \note These are internal definitions.
*/

/** \cond DOXYGEN_IGNORE */

/*!
\def PQS_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define PQS_DLL_API
#endif
/*!
\def PQS_EXPORT_API
* \brief The api export prefix
*/
#if defined(PQS_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(PQS_DLL_IMPORT)
#			define PQS_EXPORT_API __declspec(dllimport)
#		else
#			define PQS_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(PQS_DLL_IMPORT)
#		define PQS_EXPORT_API __attribute__((dllimport))
#		else
#		define PQS_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define PQS_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define PQS_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define PQS_EXPORT_API extern __declspec(dllexport)
#		else
#			define PQS_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define PQS_EXPORT_API
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
    /*!
	 * \def PQS_DEBUG_MODE
	 * \brief Defined when the build is in debug mode.
	 */
#	define PQS_DEBUG_MODE
#endif

#ifdef PQS_DEBUG_MODE
  /*!
   * \def PQS_ASSERT
   * \brief Define the assert function and guarantee it as debug only.
   */
#  define PQS_ASSERT(expr) assert(expr)
#else
#  define PQS_ASSERT(expr) ((void)0)
#endif

/** \endcond DOXYGEN_IGNORE */

/*!
 * \def PQS_STRING_TERMINATOR_SIZE
 * \brief The storage size, in bytes, reserved for a terminating C string character.
 */
#define PQS_STRING_TERMINATOR_SIZE 1U

/*!
 * \def PQS_MINIMUM_MESSAGE_SIZE
 * \brief The minimum non-empty plaintext message length accepted by PQS application helpers.
 */
#define PQS_MINIMUM_MESSAGE_SIZE 1U

/*!
 * \def PQS_APPLICATION_MESSAGE_TYPE_SIZE
 * \brief The size, in bytes, of the PQS application-layer message type prefix.
 */
#define PQS_APPLICATION_MESSAGE_TYPE_SIZE 1U

/*!
 * \def PQS_APPLICATION_MESSAGE_HEADER_SIZE
 * \brief The fixed plaintext header size used by PQS application messages.
 */
#define PQS_APPLICATION_MESSAGE_HEADER_SIZE PQS_APPLICATION_MESSAGE_TYPE_SIZE

#ifndef PQS_SERVER_COMMAND_MAX
	/*!
	 * \def PQS_SERVER_COMMAND_MAX
	 * \brief The maximum server command buffer size.
	 */
#	define PQS_SERVER_COMMAND_MAX 1280U
#endif

#ifndef PQS_SERVER_COMMAND_TEXT_MAX
	/*!
	 * \def PQS_SERVER_COMMAND_TEXT_MAX
	 * \brief The maximum NUL-terminated server command text length.
	 */
#	define PQS_SERVER_COMMAND_TEXT_MAX (PQS_SERVER_COMMAND_MAX - PQS_STRING_TERMINATOR_SIZE)
#endif

#ifndef PQS_INTERPRETER_COMMAND_BUFFER_SIZE
	/*!
	 * \def PQS_INTERPRETER_COMMAND_BUFFER_SIZE
	 * \brief The maximum server command-output chunk buffer size.
	 */
#	define PQS_INTERPRETER_COMMAND_BUFFER_SIZE 128U
#endif

/*!
 * \def PQS_XFER_PATH_MAX
 * \brief The maximum remote file-transfer path buffer size.
 */
#define PQS_XFER_PATH_MAX 256U

/*!
 * \def PQS_XFER_CHUNK_SIZE
 * \brief The maximum file-transfer data chunk carried in one PQS application message.
 */
#define PQS_XFER_CHUNK_SIZE 512U

/*!
 * \def PQS_XFER_LIST_BUFFER_SIZE
 * \brief The maximum directory listing buffer used by the PQS file-transfer subsystem.
 */
#define PQS_XFER_LIST_BUFFER_SIZE 4096U

/*!
 * \def PQS_XFER_HASH_SIZE
 * \brief The SHA3-256 hash size used by the PQS file-transfer subsystem.
 */
#define PQS_XFER_HASH_SIZE 32U

/*!
 * \def PQS_XFER_HASH_TEXT_SIZE
 * \brief The NUL-terminated hexadecimal SHA3-256 hash text size.
 */
#define PQS_XFER_HASH_TEXT_SIZE ((PQS_XFER_HASH_SIZE * 2U) + PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_XFER_METADATA_MAX
 * \brief The maximum transfer metadata text buffer size.
 */
#define PQS_XFER_METADATA_MAX 512U

/*!
 * \def PQS_XFER_USERS_ROOT_NAME
 * \brief The directory name used for per-user PQS transfer roots.
 */
#define PQS_XFER_USERS_ROOT_NAME "users"

/*!
 * \def PQS_XFER_RECURSIVE_PREFIX
 * \brief The command prefix used to request recursive file-transfer operations.
 */
#define PQS_XFER_RECURSIVE_PREFIX "-r"

/**
 * \def PQS_XFER_RECURSION_MAX
 * \brief The maximum recursive file-transfer traversal depth.
 */
#define PQS_XFER_RECURSION_MAX 64U

/*!
 * \def PQS_USERNAME_MAX
 * \brief The maximum storage size, in bytes, of a PQS user name.
 */
#define PQS_USERNAME_MAX 64U

/*!
 * \def PQS_USERNAME_TEXT_MAX
 * \brief The maximum NUL-terminated PQS user name text length.
 */
#define PQS_USERNAME_TEXT_MAX (PQS_USERNAME_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_SHELL_PROFILE_NAME_MAX
 * \brief The maximum storage size, in bytes, of a shell profile name.
 */
#define PQS_SHELL_PROFILE_NAME_MAX 64U

/*!
 * \def PQS_SHELL_PROFILE_TEXT_MAX
 * \brief The maximum NUL-terminated shell profile text length.
 */
#define PQS_SHELL_PROFILE_TEXT_MAX (PQS_SHELL_PROFILE_NAME_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_PASSPHRASE_MIN
 * \brief The minimum accepted PQS passphrase length.
 */
#define PQS_PASSPHRASE_MIN 8U

/*!
 * \def PQS_PASSPHRASE_MAX
 * \brief The maximum accepted PQS passphrase storage size.
 */
#define PQS_PASSPHRASE_MAX 128U

/*!
 * \def PQS_PASSPHRASE_TEXT_MAX
 * \brief The maximum NUL-terminated PQS passphrase text length.
 */
#define PQS_PASSPHRASE_TEXT_MAX (PQS_PASSPHRASE_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_LOGIN_REQUEST_PAYLOAD_SIZE
 * \brief The fixed payload size of a PQS username/passphrase login request.
 */
#define PQS_LOGIN_REQUEST_PAYLOAD_SIZE (PQS_USERNAME_MAX + PQS_PASSPHRASE_MAX)

/*!
 * \def PQS_LOGIN_REQUEST_MESSAGE_SIZE
 * \brief The fixed plaintext size of a PQS login request message, excluding the terminating byte added by the sender.
 */
#define PQS_LOGIN_REQUEST_MESSAGE_SIZE (PQS_APPLICATION_MESSAGE_HEADER_SIZE + PQS_LOGIN_REQUEST_PAYLOAD_SIZE)

/*!
 * \def PQS_USER_SALT_SIZE
 * \brief The PQS user passphrase salt size.
 */
#define PQS_USER_SALT_SIZE 32U

/*!
 * \def PQS_USER_VERIFIER_SIZE
 * \brief The PQS user SCB passphrase verifier size.
 */
#define PQS_USER_VERIFIER_SIZE 32U

/*!
 * \def PQS_USER_DATABASE_MAX
 * \brief The maximum number of records in the PQS server user database.
 */
#define PQS_USER_DATABASE_MAX 128U

/*!
 * \def PQS_USER_DATABASE_VERSION
 * \brief The PQS server user database format version.
 */
#define PQS_USER_DATABASE_VERSION 2U

/*!
 * \def PQS_SHELL_PROFILE_DATABASE_MAX
 * \brief The maximum number of shell profile records in the PQS server shell database.
 */
#define PQS_SHELL_PROFILE_DATABASE_MAX 32U

/*!
 * \def PQS_SHELL_PROFILE_PATH_MAX
 * \brief The maximum shell executable path buffer size.
 */
#define PQS_SHELL_PROFILE_PATH_MAX QSC_SYSTEM_MAX_PATH

/*!
 * \def PQS_SHELL_PROFILE_TYPE_MAX
 * \brief The maximum shell profile type buffer size.
 */
#define PQS_SHELL_PROFILE_TYPE_MAX 24U

/*!
 * \def PQS_SHELL_PROFILE_TYPE_TEXT_MAX
 * \brief The maximum NUL-terminated shell profile type text length.
 */
#define PQS_SHELL_PROFILE_TYPE_TEXT_MAX (PQS_SHELL_PROFILE_TYPE_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_POLICY_DATABASE_MAX
 * \brief The maximum number of command policy records in the PQS server policy database.
 */
#define PQS_POLICY_DATABASE_MAX 64U

/*!
 * \def PQS_POLICY_NAME_MAX
 * \brief The maximum storage size, in bytes, of a command policy name.
 */
#define PQS_POLICY_NAME_MAX 64U

/*!
 * \def PQS_POLICY_NAME_TEXT_MAX
 * \brief The maximum NUL-terminated command policy name text length.
 */
#define PQS_POLICY_NAME_TEXT_MAX (PQS_POLICY_NAME_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_POLICY_COMMAND_MAX
 * \brief The maximum storage size, in bytes, of a command name in a policy list.
 */
#define PQS_POLICY_COMMAND_MAX 64U

/*!
 * \def PQS_POLICY_COMMAND_TEXT_MAX
 * \brief The maximum NUL-terminated command name text length.
 */
#define PQS_POLICY_COMMAND_TEXT_MAX (PQS_POLICY_COMMAND_MAX - PQS_STRING_TERMINATOR_SIZE)

/*!
 * \def PQS_POLICY_COMMAND_LIST_MAX
 * \brief The maximum storage size, in bytes, of a comma-separated command list.
 */
#define PQS_POLICY_COMMAND_LIST_MAX 768U

#endif

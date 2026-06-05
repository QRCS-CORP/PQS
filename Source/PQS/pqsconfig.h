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

#ifndef PQS_CONFIG_H
#define PQS_CONFIG_H

#include "pqscommon.h"
#include "pqslogger.h"
#include "qsms.h"

/**
* \file pqsconfig.h
* \brief PQS client and server configuration file support.
*/

/*! \def PQS_CONFIG_LINE_MAX
 * \brief The maximum length of one configuration line.
 */
#define PQS_CONFIG_LINE_MAX 1024U

/*! \def PQS_CONFIG_KEY_MAX
 * \brief The maximum length of a configuration key.
 */
#define PQS_CONFIG_KEY_MAX 64U

/*! \def PQS_CONFIG_VALUE_MAX
 * \brief The maximum length of a configuration value.
 */
#define PQS_CONFIG_VALUE_MAX QSC_SYSTEM_MAX_PATH

/*! \def PQS_SERVER_CONFIG_NAME
 * \brief The default PQS server configuration file name.
 */
#define PQS_SERVER_CONFIG_NAME "pqsd.conf"

/*! \def PQS_CLIENT_CONFIG_NAME
 * \brief The default PQS client configuration file name.
 */
#define PQS_CLIENT_CONFIG_NAME "pqs.conf"

 /**
  * \brief The PQS server configuration state.
  *
  * This structure contains the resolved server configuration used to initialize
  * the PQS server application, including storage paths, network binding values,
  * authentication limits, logging behavior, and command sandbox settings.
  */
PQS_EXPORT_API typedef struct pqs_server_config
{
	char application_path[QSC_SYSTEM_MAX_PATH];				/*!< The base PQS application storage directory */
	char private_key_path[QSC_SYSTEM_MAX_PATH];				/*!< The path to the encoded PQS server private key file */
	char public_key_path[QSC_SYSTEM_MAX_PATH];				/*!< The path to the encoded PQS server public key file */
	char user_database_path[QSC_SYSTEM_MAX_PATH];			/*!< The path to the PQS user database file */
	char shell_database_path[QSC_SYSTEM_MAX_PATH];			/*!< The path to the PQS shell profile database file */
	char policy_database_path[QSC_SYSTEM_MAX_PATH];			/*!< The path to the PQS command policy database file */
	char log_path[QSC_SYSTEM_MAX_PATH];						/*!< The path to the PQS server log file */
	char listen_address[QSC_IPINFO_IPV4_STRNLEN];			/*!< The IPv4 address used by the server listener */
	uint16_t listen_port;									/*!< The TCP port used by the server listener */
	uint32_t max_sessions;									/*!< The maximum number of authenticated server sessions permitted; PQS currently enforces one active session */
	uint32_t max_login_attempts;							/*!< The maximum number of login attempts permitted before rejecting the session */
	char sandbox_working_directory[QSC_SYSTEM_MAX_PATH];	/*!< The working directory used for sandboxed command execution */
	char sandbox_run_as_user[PQS_USERNAME_MAX];				/*!< The POSIX user name used for command privilege drop */
	char sandbox_run_as_group[PQS_USERNAME_MAX];			/*!< The POSIX group name used for command privilege drop */
	uint32_t login_timeout_seconds;							/*!< The maximum time, in seconds, permitted for a login exchange */
	uint32_t idle_timeout_seconds;							/*!< The maximum idle time, in seconds, permitted for an established session */
	uint32_t command_timeout_seconds;						/*!< The maximum execution time, in seconds, permitted for a server-side command */
	uint32_t command_output_max_bytes;					/*!< The maximum command-output byte count returned for one server-side command */
	pqs_log_level log_level;								/*!< The configured server logging level */
	bool sandbox_enabled;									/*!< A flag indicating whether command sandbox controls are enabled */
	bool sandbox_clear_environment;							/*!< A flag indicating whether the command execution environment is cleared */
	bool sandbox_chroot_enabled;							/*!< A flag indicating whether POSIX chroot confinement is used */
	bool sandbox_allow_same_user;							/*!< A flag indicating whether POSIX same-user command execution is explicitly allowed */
} pqs_server_config;

/**
 * \brief The PQS client configuration state.
 *
 * This structure contains the resolved client configuration used to initialize
 * the PQS client application, including storage paths, the target host,
 * username, host-trust settings, and logging behavior.
 */
PQS_EXPORT_API typedef struct pqs_client_config
{
	char application_path[QSC_SYSTEM_MAX_PATH];				/*!< The base PQS client application storage directory */
	char server_public_key_path[QSC_SYSTEM_MAX_PATH];		/*!< The path to the encoded PQS server public key file */
	char known_hosts_path[QSC_SYSTEM_MAX_PATH];				/*!< The path to the PQS known-hosts database file */
	char log_path[QSC_SYSTEM_MAX_PATH];						/*!< The path to the PQS client log file */
	char host[QSC_IPINFO_IPV4_STRNLEN];						/*!< The IPv4 address or host value used by the client connection */
	char username[PQS_USERNAME_MAX];						/*!< The default PQS username used by the client login dialogue. */
	uint16_t port;											/*!< The TCP port used by the client connection */
	bool strict_host_checking;								/*!< A flag indicating whether strict host-key checking is enabled */
	pqs_log_level log_level;								/*!< The configured client logging level */
} pqs_client_config;

/**
 * \brief Initialize a server configuration with safe defaults.
 *
 * \param cfg: [struct] The server configuration.
 */
PQS_EXPORT_API void pqs_config_server_defaults(pqs_server_config* cfg);

/**
 * \brief Initialize a client configuration with safe defaults.
 *
 * \param cfg: [struct] The client configuration.
 */
PQS_EXPORT_API void pqs_config_client_defaults(pqs_client_config* cfg);

/**
 * \brief Load a PQS server configuration file.
 *
 * \param cfg: [struct] The server configuration.
 * \param fpath: [const] The configuration file path.
 *
 * \return [bool] Returns true if the configuration was loaded or created.
 */
PQS_EXPORT_API bool pqs_config_server_load(pqs_server_config* cfg, const char* fpath);

/**
 * \brief Load a PQS client configuration file.
 *
 * \param cfg: [struct] The client configuration.
 * \param fpath: [const] The configuration file path.
 *
 * \return [bool] Returns true if the configuration was loaded or created.
 */
PQS_EXPORT_API bool pqs_config_client_load(pqs_client_config* cfg, const char* fpath);

/**
 * \brief Convert a log level to a string.
 *
 * \param level: [enum] The log level.
 *
 * \return [const char*] Returns the log level string.
 */
PQS_EXPORT_API const char* pqs_config_log_level_to_string(pqs_log_level level);

#endif

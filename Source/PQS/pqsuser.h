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

#ifndef PQS_USER_H
#define PQS_USER_H

#include "pqs.h"

/**
* \file pqsuser.h
* \brief PQS server-side user database and passphrase verifier functions.
*/

/*! \def PQS_USER_DATABASE_MAGIC
 * \brief The fixed text header written to PQS user database files.
 */
#define PQS_USER_DATABASE_MAGIC "PQSUSERDB1"

/*! \def PQS_USER_DEFAULT_SHELL_PROFILE
 * \brief The default shell profile name assigned to new users.
 */
#define PQS_USER_DEFAULT_SHELL_PROFILE "default"

/*! \struct pqs_user_record
 * \brief A PQS server user account record.
 */
PQS_EXPORT_API typedef struct pqs_user_record
{
	char username[PQS_USERNAME_MAX];				/*!< The PQS user name. */
	char shellprofile[PQS_SHELL_PROFILE_NAME_MAX];	/*!< The assigned shell profile name. */
	uint8_t salt[PQS_USER_SALT_SIZE];				/*!< The SCB verifier salt. */
	uint8_t verifier[PQS_USER_VERIFIER_SIZE];		/*!< The SCB passphrase verifier. */
	uint64_t created;								/*!< The record creation timestamp. */
	uint64_t modified;								/*!< The record modification timestamp. */
	uint32_t failures;								/*!< The consecutive authentication failure count. */
	pqs_user_privileges privilege;					/*!< The user privilege level. */
	bool enabled;									/*!< The account enabled flag. */
} pqs_user_record;

/*! \struct pqs_user_store
 * \brief The fixed-size PQS server user database.
 */
PQS_EXPORT_API typedef struct pqs_user_store
{
	pqs_user_record records[PQS_USER_DATABASE_MAX]; /*!< User account records. */
	char path[QSC_SYSTEM_MAX_PATH];                 /*!< The persistent database file path. */
	size_t count;                                   /*!< The active user record count. */
	bool initialized;                               /*!< The database initialization flag. */
} pqs_user_store;

/**
 * \brief Add a user to the user database.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 * \param passphrase: [const char*] The plaintext passphrase used to create the SCB verifier.
 * \param privilege: [enum] The assigned privilege level.
 *
 * \return [bool] Returns true if the user was added.
 */
PQS_EXPORT_API bool pqs_user_store_add(pqs_user_store* store, const char* username, const char* passphrase, pqs_user_privileges privilege);

/**
 * \brief Disable or enable a user account.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 * \param enabled: [bool] The requested enabled state.
 *
 * \return [bool] Returns true if the user was updated.
 */
PQS_EXPORT_API bool pqs_user_store_enable(pqs_user_store* store, const char* username, bool enabled);

/**
 * \brief Find a user record by name.
 *
 * \param store: [const struct] The user database.
 * \param username: [const char*] The user name.
 *
 * \return [struct] Returns a pointer to the record, or NULL if not found.
 */
PQS_EXPORT_API const pqs_user_record* pqs_user_store_find(const pqs_user_store* store, const char* username);

/**
 * \brief Find a mutable user record by name.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 *
 * \return [struct] Returns a pointer to the record, or NULL if not found.
 */
PQS_EXPORT_API pqs_user_record* pqs_user_store_find_mutable(pqs_user_store* store, const char* username);

/**
 * \brief Initialize and load the user database.
 *
 * \param store: [struct] The user database.
 * \param path: [const char*] The database file path.
 *
 * \return [bool] Returns true if the database was initialized.
 */
PQS_EXPORT_API bool pqs_user_store_initialize(pqs_user_store* store, const char* path);

/**
 * \brief Remove a user from the user database.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 *
 * \return [bool] Returns true if the user was removed.
 */
PQS_EXPORT_API bool pqs_user_store_remove(pqs_user_store* store, const char* username);

/**
 * \brief Save the user database to disk.
 *
 * \param store: [const struct] The user database.
 *
 * \return [bool] Returns true if the database was saved.
 */
PQS_EXPORT_API bool pqs_user_store_save(const pqs_user_store* store);

/**
 * \brief Set the user privilege level.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 * \param privilege: [enum] The requested privilege level.
 *
 * \return [bool] Returns true if the user was updated.
 */
PQS_EXPORT_API bool pqs_user_store_set_privilege(pqs_user_store* store, const char* username, pqs_user_privileges privilege);

/**
 * \brief Set a user's assigned shell profile name.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 * \param shellprofile: [const char*] The shell profile name.
 *
 * \return [bool] Returns true if the user was updated.
 */
PQS_EXPORT_API bool pqs_user_store_set_shell_profile(pqs_user_store* store, const char* username, const char* shellprofile);

/**
 * \brief Set a user's passphrase verifier.
 *
 * \param store: [struct] The user database.
 * \param username: [const char*] The user name.
 * \param passphrase: [const char*] The new passphrase.
 *
 * \return [bool] Returns true if the passphrase verifier was updated.
 */
PQS_EXPORT_API bool pqs_user_store_set_passphrase(pqs_user_store* store, const char* username, const char* passphrase);

/**
 * \brief Test whether a user name is valid for a PQS account and login request.
 *
 * \param username: [const char*] The user name to validate.
 *
 * \return [bool] Returns true if the user name is syntactically valid.
 */
PQS_EXPORT_API bool pqs_user_name_is_valid(const char* username);

/**
 * \brief Test whether a passphrase length is valid for a PQS account and login request.
 *
 * \param passphrase: [const char*] The passphrase to validate.
 *
 * \return [bool] Returns true if the passphrase length is valid.
 */
PQS_EXPORT_API bool pqs_user_passphrase_is_valid(const char* passphrase);

/**
 * \brief Convert a privilege level to its stable text name.
 *
 * \param privilege: [enum] The privilege level.
 *
 * \return [const char*] Returns the privilege name.
 */
PQS_EXPORT_API const char* pqs_user_privilege_to_string(pqs_user_privileges privilege);

/**
 * \brief Convert a stable text name to a privilege level.
 *
 * \param value: [const char*] The privilege name.
 *
 * \return [enum] Returns the privilege level.
 */
PQS_EXPORT_API pqs_user_privileges pqs_user_privilege_from_string(const char* value);

/**
 * \brief Verify a plaintext passphrase against a user record.
 *
 * \param record: [const struct] The user record.
 * \param passphrase: [const char*] The plaintext passphrase.
 *
 * \return [bool] Returns true if the passphrase matches the stored verifier.
 */
PQS_EXPORT_API bool pqs_user_verify_passphrase(const pqs_user_record* record, const char* passphrase);

/**
 * \brief Verify a passphrase using a timing-neutral valid or dummy account path.
 *
 * \param record: [const struct] The user record, or NULL for an unknown account.
 * \param username: [const char*] The requested user name used for the dummy verifier path.
 * \param passphrase: [const char*] The plaintext passphrase.
 *
 * \return [bool] Returns true if the passphrase matches an enabled user record.
 */
PQS_EXPORT_API bool pqs_user_verify_passphrase_timing_neutral(const pqs_user_record* record, const char* username, const char* passphrase);

#endif

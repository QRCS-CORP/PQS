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

#ifndef PQS_SHELL_H
#define PQS_SHELL_H

#include "pqs.h"

/**
* \file pqsshell.h
* \brief PQS server-side shell profile database functions.
*/

/*! \def PQS_SHELL_DATABASE_MAGIC
 * \brief The fixed text header written to PQS shell profile database files.
 */
#define PQS_SHELL_DATABASE_MAGIC "PQSSHELLDB1"

/*! \def PQS_SHELL_PRIVILEGE_GUEST
 * \brief Shell profile privilege mask bit for guest users.
 */
#define PQS_SHELL_PRIVILEGE_GUEST 0x01U

/*! \def PQS_SHELL_PRIVILEGE_USER
 * \brief Shell profile privilege mask bit for standard users.
 */
#define PQS_SHELL_PRIVILEGE_USER 0x02U

/*! \def PQS_SHELL_PRIVILEGE_ADMIN
 * \brief Shell profile privilege mask bit for administrative users.
 */
#define PQS_SHELL_PRIVILEGE_ADMIN 0x04U

/*! \def PQS_SHELL_PRIVILEGE_ALL
 * \brief Shell profile privilege mask for all defined privilege levels.
 */
#define PQS_SHELL_PRIVILEGE_ALL (PQS_SHELL_PRIVILEGE_GUEST | PQS_SHELL_PRIVILEGE_USER | PQS_SHELL_PRIVILEGE_ADMIN)

/*! \struct pqs_shell_profile
 * \brief A PQS server shell profile record.
 */
PQS_EXPORT_API typedef struct pqs_shell_profile
{
	char name[PQS_SHELL_PROFILE_NAME_MAX];						/*!< The shell profile name. */
	char type[PQS_SHELL_PROFILE_TYPE_MAX];						/*!< The shell type name. */
	char path[PQS_SHELL_PROFILE_PATH_MAX];						/*!< The shell executable path. */
	uint32_t privilege_mask;									/*!< The allowed privilege mask. */
	bool enabled;												/*!< The profile enabled flag. */
	bool isdefault;												/*!< The default profile flag. */
} pqs_shell_profile;

/*! \struct pqs_shell_store
 * \brief The fixed-size PQS server shell profile database.
 */
PQS_EXPORT_API typedef struct pqs_shell_store
{
	pqs_shell_profile profiles[PQS_SHELL_PROFILE_DATABASE_MAX];	/*!< Shell profile records. */
	char path[QSC_SYSTEM_MAX_PATH];                             /*!< The persistent database file path. */
	size_t count;                                               /*!< The active shell profile count. */
	bool initialized;                                           /*!< The database initialization flag. */
} pqs_shell_store;

/**
 * \brief Add or replace a shell profile record in a PQS shell profile store.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 * \param type: [const] The shell type identifier, such as cmd, powershell, sh, bash, zsh, or custom.
 * \param path: [const] The absolute or configured executable path for the shell profile.
 * \param privilege_mask: The privilege mask controlling which PQS user privilege levels may use this profile.
 * \param enabled: The profile enabled state.
 *
 * 
 * \return Returns true if the shell profile was added or replaced; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_add(pqs_shell_store* store, const char* name, const char* type, const char* path, uint32_t privilege_mask, bool enabled);

/**
 * \brief Enable or disable an existing shell profile record.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 * \param enabled: The requested enabled state.
 *
 * 
 * \return Returns true if the profile was found and updated; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_enable(pqs_shell_store* store, const char* name, bool enabled);

/**
 * \brief Find a shell profile record by name.
 *
 * \param store: [const struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 *
 * 
 * \return Returns a const pointer to the matching profile, or NULL if the profile was not found.
 */
PQS_EXPORT_API const pqs_shell_profile* pqs_shell_store_find(const pqs_shell_store* store, const char* name);

/**
 * \brief Find a mutable shell profile record by name.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 *
 * 
 * \return Returns a mutable pointer to the matching profile, or NULL if the profile was not found.
 */
PQS_EXPORT_API pqs_shell_profile* pqs_shell_store_find_mutable(pqs_shell_store* store, const char* name);

/**
 * \brief Find the default shell profile in a PQS shell profile store.
 *
 * \param store: [const struct] A pointer to the initialized shell profile store.
 *
 * 
 * \return Returns a const pointer to the default shell profile, or NULL if no default profile is configured.
 */
PQS_EXPORT_API const pqs_shell_profile* pqs_shell_store_default(const pqs_shell_store* store);

/**
 * \brief Initialize a PQS shell profile store and load or create its persistent database file.
 *
 * \param store: [struct] A pointer to the shell profile store to initialize.
 * \param path: [const] The persistent shell profile database file path.
 *
 * 
 * \return Returns true if the store was initialized successfully; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_initialize(pqs_shell_store* store, const char* path);

/**
 * \brief Remove a shell profile record from a PQS shell profile store.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 *
 * 
 * \return Returns true if the profile was found and removed; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_remove(pqs_shell_store* store, const char* name);

/**
 * \brief Save a PQS shell profile store to its persistent database file.
 *
 * \param store: [const struct] A pointer to the initialized shell profile store.
 *
 * 
 * \return Returns true if the store was written successfully; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_save(const pqs_shell_store* store);

/**
 * \brief Set the default shell profile for a PQS shell profile store.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name to mark as the default profile.
 *
 * 
 * \return Returns true if the named profile was found and marked as default; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_set_default(pqs_shell_store* store, const char* name);

/**
 * \brief Enable or disable shell profile access for a specific PQS user privilege level.
 *
 * \param store: [struct] A pointer to the initialized shell profile store.
 * \param name: [const] The shell profile name.
 * \param privilege: [enum] The PQS user privilege level to allow or deny.
 * \param allowed: The requested access state for the privilege level.
 *
 * 
 * \return Returns true if the profile was found and updated; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_store_set_privilege(pqs_shell_store* store, const char* name, pqs_user_privileges privilege, bool allowed);

/**
 * \brief Convert a PQS user privilege value to the corresponding shell profile privilege-mask bit.
 *
 * \param privilege: [enum] The PQS user privilege value.
 *
 * 
 * \return Returns the privilege-mask bit for the supplied privilege, or zero if the privilege is not recognized.
 */
PQS_EXPORT_API uint32_t pqs_shell_privilege_to_mask(pqs_user_privileges privilege);

/**
 * \brief Test whether a shell profile permits access for a specified PQS user privilege level.
 *
 * \param profile: [const struct] A pointer to the shell profile record.
 * \param privilege: [enum] The PQS user privilege value to test.
 *
 * 
 * \return Returns true if the profile is enabled and permits the supplied privilege level; otherwise, false.
 */
PQS_EXPORT_API bool pqs_shell_profile_allows_privilege(const pqs_shell_profile* profile, pqs_user_privileges privilege);

#endif

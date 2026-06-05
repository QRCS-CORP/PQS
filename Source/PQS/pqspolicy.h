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

#ifndef PQS_POLICY_H
#define PQS_POLICY_H

#include "pqs.h"

/**
* \file pqspolicy.h
* \brief PQS server-side command policy database functions.
*/

/*! \def PQS_POLICY_DATABASE_MAGIC
 * \brief The fixed text header written to PQS command policy database files.
 */
#define PQS_POLICY_DATABASE_MAGIC "PQSPOLICYDB1"

/*! \def PQS_POLICY_DEFAULT_GUEST
 * \brief The default guest privilege command policy name.
 */
#define PQS_POLICY_DEFAULT_GUEST "guest"

/*! \def PQS_POLICY_DEFAULT_USER
 * \brief The default user privilege command policy name.
 */
#define PQS_POLICY_DEFAULT_USER "user"

/*! \def PQS_POLICY_DEFAULT_ADMIN
 * \brief The default administrative privilege command policy name.
 */
#define PQS_POLICY_DEFAULT_ADMIN "admin"

/*! \enum pqs_policy_modes
 * \brief Command policy execution modes.
 */
PQS_EXPORT_API typedef enum pqs_policy_modes
{
	pqs_policy_mode_none = 0x00U,						/*!< No command execution is permitted. */
	pqs_policy_mode_restricted = 0x01U,					/*!< Only explicitly allowed commands are permitted. */
	pqs_policy_mode_forced = 0x02U,						/*!< Only the configured forced command is permitted. */
	pqs_policy_mode_raw = 0x03U							/*!< Raw shell command execution is permitted. */
} pqs_policy_modes;

/*! \struct pqs_policy_record
 * \brief A PQS server command policy record.
 */
PQS_EXPORT_API typedef struct pqs_policy_record
{
	char name[PQS_POLICY_NAME_MAX];						/*!< The policy name. */
	char allowlist[PQS_POLICY_COMMAND_LIST_MAX];		/*!< A comma-separated allowed command list. */
	char denylist[PQS_POLICY_COMMAND_LIST_MAX];			/*!< A comma-separated denied command list. */
	char forced[PQS_POLICY_COMMAND_MAX];				/*!< The forced command name or command prefix. */
	uint32_t privilege_mask;							/*!< The allowed privilege mask. */
	pqs_policy_modes mode;								/*!< The policy mode. */
	bool enabled;										/*!< The policy enabled flag. */
} pqs_policy_record;

/*! \struct pqs_policy_store
 * \brief The fixed-size PQS command policy database.
 */
PQS_EXPORT_API typedef struct pqs_policy_store
{
	pqs_policy_record records[PQS_POLICY_DATABASE_MAX];	/*!< Command policy records. */
	char path[QSC_SYSTEM_MAX_PATH];                     /*!< The persistent database file path. */
	char guest_policy[PQS_POLICY_NAME_MAX];             /*!< The assigned guest policy name. */
	char user_policy[PQS_POLICY_NAME_MAX];              /*!< The assigned user policy name. */
	char admin_policy[PQS_POLICY_NAME_MAX];             /*!< The assigned admin policy name. */
	size_t count;                                       /*!< The active policy count. */
	bool initialized;                                   /*!< The database initialization flag. */
} pqs_policy_store;

/**
 * \brief Add a command policy record to a policy store.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param mode: [enum] The policy enforcement mode.
 * \param privilege_mask: The privilege mask allowed to use the policy.
 * \param enabled: A flag indicating whether the policy is enabled.
 *
 * \return Returns true if the policy record was added; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_add(pqs_policy_store* store, const char* name, pqs_policy_modes mode, uint32_t privilege_mask, bool enabled);

/**
 * \brief Add a command verb to a policy allow-list or deny-list.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param command: [const] The NUL-terminated command verb to add.
 * \param allowed: A flag selecting the target list; true adds to the allow-list, false adds to the deny-list.
 *
 * \return Returns true if the command was added to the selected policy list; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_add_command(pqs_policy_store* store, const char* name, const char* command, bool allowed);

/**
 * \brief Assign a named policy to a privilege level.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param privilege: [enum] The privilege level to assign.
 * \param policy: [const] The NUL-terminated policy name to associate with the privilege level.
 *
 * \return Returns true if the privilege assignment was updated; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_assign_privilege(pqs_policy_store* store, pqs_user_privileges privilege, const char* policy);

/**
 * \brief Authorize a command for a privilege level using the active policy assignment.
 *
 * \param store: [const struct] A pointer to the policy store to query.
 * \param privilege: [enum] The authenticated user's privilege level.
 * \param command: [const] The NUL-terminated command string or command verb to evaluate.
 * \param matched: [const struct] A pointer to the matched policy record output parameter.
 *
 * \return Returns true if the command is authorized by the matched policy; otherwise, returns false.
 */

/**
 * \brief Test whether a user-supplied shell command avoids shell-control metacharacters.
 *
 * \param command: [const] The NUL-terminated command string.
 *
 * \return Returns true if the command contains only direct-command characters; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_command_is_safe(const char* command);

/**
 * \brief Authorizes a command request against the policy assigned to a privilege class.
 *
 * \details
 * Evaluates the command policy associated with the supplied privilege level and determines
 * whether the requested command is permitted. The function resolves the policy record assigned
 * to \c privilege, validates the supplied command string, extracts the command verb used for
 * policy matching, and applies the configured policy mode.
 *
 * The authorization result depends on the matched policy mode:
 *
 * \li \c pqs_policy_mode_none denies all command execution.
 * \li \c pqs_policy_mode_restricted permits only commands present in the policy allow list.
 * \li \c pqs_policy_mode_forced permits execution through the configured forced command.
 * \li \c pqs_policy_mode_raw permits commands unless explicitly denied by the policy.
 *
 * User-supplied command strings are also subject to shell-safety validation. Commands containing
 * shell-control metacharacters or unsafe shell syntax are rejected before execution authorization
 * succeeds. This prevents a permitted command verb from being used to carry additional shell
 * expressions that would bypass the policy decision.
 *
 * If \c matched is not NULL, it receives the address of the policy record used for the decision
 * when a policy is resolved. The returned pointer refers to storage owned by \c store and remains
 * valid only while the store remains valid and unmodified.
 *
 * \param store: [const] A pointer to the initialized policy store.
 * \param privilege: [enum] The user privilege class whose assigned policy is evaluated.
 * \param command: [const] A pointer to the NUL-terminated command string to authorize.
 * \param matched: [out] An optional pointer that receives the matched policy record.
 *
 * \return Returns true if the command is authorized by the matched policy; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_authorize(const pqs_policy_store* store, pqs_user_privileges privilege, const char* command, const pqs_policy_record** matched);

/**
 * \brief Enable or disable a command policy record.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param enabled: A flag indicating whether the policy is enabled.
 *
 * \return Returns true if the policy state was updated; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_enable(pqs_policy_store* store, const char* name, bool enabled);

/**
 * \brief Find a command policy record by name.
 *
 * \param store: [const struct] A pointer to the policy store to query.
 * \param name: [const] The NUL-terminated policy name.
 *
 * \return Returns a constant pointer to the matching policy record, or NULL if no matching record exists.
 */
PQS_EXPORT_API const pqs_policy_record* pqs_policy_store_find(const pqs_policy_store* store, const char* name);

/**
 * \brief Find a mutable command policy record by name.
 *
 * \param store: [struct] A pointer to the policy store to query.
 * \param name: [const] The NUL-terminated policy name.
 *
 * \return Returns a mutable pointer to the matching policy record, or NULL if no matching record exists.
 */
PQS_EXPORT_API pqs_policy_record* pqs_policy_store_find_mutable(pqs_policy_store* store, const char* name);

/**
 * \brief Initialize a command policy store from persistent storage.
 *
 * \param store: [struct] A pointer to the policy store to initialize.
 * \param path: [const] The NUL-terminated path to the policy database file.
 *
 * \return Returns true if the policy store was initialized; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_initialize(pqs_policy_store* store, const char* path);

/**
 * \brief Remove a command policy record from a policy store.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 *
 * \return Returns true if the policy record was removed; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_remove(pqs_policy_store* store, const char* name);

/**
 * \brief Remove a command verb from a policy allow-list or deny-list.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param command: [const] The NUL-terminated command verb to remove.
 * \param allowed: A flag selecting the target list; true removes from the allow-list, false removes from the deny-list.
 *
 * \return Returns true if the command was removed from the selected policy list; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_remove_command(pqs_policy_store* store, const char* name, const char* command, bool allowed);

/**
 * \brief Save a command policy store to persistent storage.
 *
 * \param store: [const struct] A pointer to the policy store to save.
 *
 * \return Returns true if the policy store was written successfully; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_save(const pqs_policy_store* store);

/**
 * \brief Set the forced command associated with a command policy.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param command: [const] The NUL-terminated forced command string.
 *
 * \return Returns true if the forced command was updated; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_set_forced(pqs_policy_store* store, const char* name, const char* command);

/**
 * \brief Set the enforcement mode of a command policy.
 *
 * \param store: [struct] A pointer to the policy store to update.
 * \param name: [const] The NUL-terminated policy name.
 * \param mode: [enum] The new policy enforcement mode.
 *
 * \return Returns true if the policy mode was updated; otherwise, returns false.
 */
PQS_EXPORT_API bool pqs_policy_store_set_mode(pqs_policy_store* store, const char* name, pqs_policy_modes mode);

/**
 * \brief Convert a policy mode enumeration value to a string.
 *
 * \param mode: [enum] The policy mode value to convert.
 *
 * \return Returns a constant NUL-terminated string representing the policy mode.
 */
PQS_EXPORT_API const char* pqs_policy_mode_to_string(pqs_policy_modes mode);

/**
 * \brief Convert a policy mode string to a policy mode enumeration value.
 *
 * \param value: [const] The NUL-terminated policy mode string.
 *
 * \return Returns the corresponding policy mode value, or the default invalid/disabled value when the string is not recognized.
 */
PQS_EXPORT_API pqs_policy_modes pqs_policy_mode_from_string(const char* value);

/**
 * \brief Convert a PQS user privilege level to a policy privilege mask.
 *
 * \param privilege: [enum] The user privilege level to convert.
 *
 * \return Returns the policy privilege mask corresponding to the user privilege level.
 */
PQS_EXPORT_API uint32_t pqs_policy_privilege_to_mask(pqs_user_privileges privilege);

#endif

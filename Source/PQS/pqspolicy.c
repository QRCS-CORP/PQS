#include "pqspolicy.h"
#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#define PQS_POLICY_DATABASE_LINE_MAX 2048U

static void pqs_policy_store_add_builtins(pqs_policy_store* store);


static bool pqs_policy_decimal_u32_is_valid(const char* value, uint32_t* output)
{
	char* end;
	unsigned long val;
	bool res;

	end = NULL;
	val = 0UL;
	res = false;

	if (value != NULL && value[0U] != '\0')
	{
		errno = 0;
		val = strtoul(value, &end, 10);

		if (errno == 0 && end != NULL && *end == '\0' && val <= UINT32_MAX)
		{
			if (output != NULL)
			{
				*output = (uint32_t)val;
			}

			res = true;
		}
	}

	return res;
}


static FILE* pqs_policy_file_open(const char* path, const char* mode)
{
	FILE* fp;

	fp = NULL;

	if (path != NULL && mode != NULL)
	{
#if defined(QSC_SYSTEM_COMPILER_MSC)
		if (fopen_s(&fp, path, mode) != 0)
		{
			fp = NULL;
		}
#else
		fp = fopen(path, mode);
#endif
	}

	return fp;
}

static char* pqs_policy_string_token(char* source, const char* delimiters, char** context)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	return strtok_s(source, delimiters, context);
#else
	return strtok_r(source, delimiters, context);
#endif
}

static bool pqs_policy_is_name_valid(const char* name)
{
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (name != NULL)
	{
		slen = qsc_stringutils_string_size(name);

		if (slen > 0U && slen < PQS_POLICY_NAME_MAX)
		{
			res = true;

			for (pos = 0U; pos < slen; ++pos)
			{
				if ((name[pos] >= 'a' && name[pos] <= 'z') ||
					(name[pos] >= 'A' && name[pos] <= 'Z') ||
					(name[pos] >= '0' && name[pos] <= '9') ||
					name[pos] == '_' || name[pos] == '-' || name[pos] == '.')
				{
					continue;
				}
				else
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

static bool pqs_policy_is_command_name_valid(const char* command)
{
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (command != NULL)
	{
		slen = qsc_stringutils_string_size(command);

		if (slen > 0U && slen < PQS_POLICY_COMMAND_MAX)
		{
			res = true;

			for (pos = 0U; pos < slen; ++pos)
			{
				if (command[pos] != ',' && command[pos] != '|' && command[pos] != '\r' && command[pos] != '\n')
				{
					continue;
				}
				else
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

static bool pqs_policy_parse_bool(const char* value)
{
	return (value != NULL && value[0U] == '1');
}

static void pqs_policy_store_set_default_assignments(pqs_policy_store* store)
{
	if (store != NULL)
	{
		qsc_stringutils_copy_string(store->guest_policy, sizeof(store->guest_policy), PQS_POLICY_DEFAULT_GUEST);
		qsc_stringutils_copy_string(store->user_policy, sizeof(store->user_policy), PQS_POLICY_DEFAULT_USER);
		qsc_stringutils_copy_string(store->admin_policy, sizeof(store->admin_policy), PQS_POLICY_DEFAULT_ADMIN);
	}
}

static bool pqs_policy_parse_assignment(pqs_policy_store* store, char* line)
{
	char* token;
	char* ctx;
	char* values[3] = { 0 };
	size_t count;
	bool res;

	ctx = NULL;
	count = 0U;
	res = false;

	if (store != NULL && line != NULL)
	{
		token = pqs_policy_string_token(line, "|\r\n", &ctx);

		while (token != NULL && count < (sizeof(values) / sizeof(values[0U])))
		{
			values[count] = token;
			++count;
			token = pqs_policy_string_token(NULL, "|\r\n", &ctx);
		}

		if (count == 3U && qsc_stringutils_strings_equal(values[0U], "@assign") == true && pqs_policy_is_name_valid(values[2U]) == true)
		{
			if (qsc_stringutils_strings_equal(values[1U], "guest") == true)
			{
				qsc_stringutils_copy_string(store->guest_policy, sizeof(store->guest_policy), values[2U]);
				res = true;
			}
			else if (qsc_stringutils_strings_equal(values[1U], "user") == true)
			{
				qsc_stringutils_copy_string(store->user_policy, sizeof(store->user_policy), values[2U]);
				res = true;
			}
			else if (qsc_stringutils_strings_equal(values[1U], "admin") == true)
			{
				qsc_stringutils_copy_string(store->admin_policy, sizeof(store->admin_policy), values[2U]);
				res = true;
			}
		}
	}

	return res;
}

static bool pqs_policy_record_from_line(pqs_policy_record* record, char* line)
{
	char* token;
	char* ctx;
	char* values[7] = { 0 };
	size_t count;
	bool res;

	ctx = NULL;
	count = 0U;
	res = false;

	if (record != NULL && line != NULL && line[0U] != '#' && line[0U] != '@' && line[0U] != '\0')
	{
		token = pqs_policy_string_token(line, "|\r\n", &ctx);

		while (token != NULL && count < (sizeof(values) / sizeof(values[0U])))
		{
			values[count] = token;
			++count;
			token = pqs_policy_string_token(NULL, "|\r\n", &ctx);
		}

		if (count == 7U && pqs_policy_is_name_valid(values[0U]) == true)
		{
			qsc_memutils_clear((uint8_t*)record, sizeof(pqs_policy_record));
			qsc_stringutils_copy_string(record->name, sizeof(record->name), values[0U]);
			record->mode = pqs_policy_mode_from_string(values[1U]);
			record->enabled = pqs_policy_parse_bool(values[2U]);
			res = pqs_policy_decimal_u32_is_valid(values[3U], &record->privilege_mask);
			qsc_stringutils_copy_string(record->allowlist, sizeof(record->allowlist), values[4U]);
			qsc_stringutils_copy_string(record->denylist, sizeof(record->denylist), values[5U]);
			qsc_stringutils_copy_string(record->forced, sizeof(record->forced), values[6U]);
			res = res && (record->mode != pqs_policy_mode_none || qsc_stringutils_strings_equal(values[1U], "no-shell") == true);
		}
	}

	return res;
}

static size_t pqs_policy_record_to_line(const pqs_policy_record* record, char* line, size_t linelen)
{
	int32_t slen;
	size_t res;

	res = 0U;

	if (record != NULL && line != NULL && linelen != 0U)
	{
		slen = snprintf(line, linelen, "%s|%s|%u|%u|%s|%s|%s\n",
			record->name,
			pqs_policy_mode_to_string(record->mode),
			(record->enabled == true) ? 1U : 0U,
			record->privilege_mask,
			record->allowlist,
			record->denylist,
			record->forced);

		if (slen > 0 && (size_t)slen < linelen)
		{
			res = (size_t)slen;
		}
	}

	return res;
}

static bool pqs_policy_list_contains(const char* list, const char* command)
{
	char tmp[PQS_POLICY_COMMAND_LIST_MAX] = { 0 };
	char* token;
	char* ctx;
	bool res;

	ctx = NULL;
	res = false;

	if (list != NULL && command != NULL && list[0U] != '\0' && command[0U] != '\0')
	{
		qsc_stringutils_copy_string(tmp, sizeof(tmp), list);
		token = pqs_policy_string_token(tmp, ",", &ctx);

		while (token != NULL)
		{
			if (qsc_stringutils_strings_equal(token, command) == true)
			{
				res = true;
				break;
			}

			token = pqs_policy_string_token(NULL, ",", &ctx);
		}
	}

	qsc_memutils_clear((uint8_t*)tmp, sizeof(tmp));

	return res;
}

static bool pqs_policy_list_add(char* list, size_t listlen, const char* command)
{
	size_t clen;
	size_t llen;
	bool res;

	res = false;

	if (list != NULL && command != NULL && pqs_policy_is_command_name_valid(command) == true && pqs_policy_list_contains(list, command) == false)
	{
		clen = qsc_stringutils_string_size(command);
		llen = qsc_stringutils_string_size(list);

		if (llen + clen + 2U < listlen)
		{
			if (llen != 0U)
			{
				qsc_stringutils_concat_strings(list, listlen, ",");
			}

			qsc_stringutils_concat_strings(list, listlen, command);
			res = true;
		}
	}

	return res;
}

static bool pqs_policy_list_remove(char* list, size_t listlen, const char* command)
{
	char src[PQS_POLICY_COMMAND_LIST_MAX] = { 0 };
	char dst[PQS_POLICY_COMMAND_LIST_MAX] = { 0 };
	char* token;
	char* ctx;
	bool found;

	ctx = NULL;
	found = false;

	if (list != NULL && command != NULL && listlen <= sizeof(dst))
	{
		qsc_stringutils_copy_string(src, sizeof(src), list);
		token = pqs_policy_string_token(src, ",", &ctx);

		while (token != NULL)
		{
			if (qsc_stringutils_strings_equal(token, command) == true)
			{
				found = true;
			}
			else
			{
				if (dst[0U] != '\0')
				{
					qsc_stringutils_concat_strings(dst, sizeof(dst), ",");
				}

				qsc_stringutils_concat_strings(dst, sizeof(dst), token);
			}

			token = pqs_policy_string_token(NULL, ",", &ctx);
		}

		if (found == true)
		{
			qsc_stringutils_clear_string(list);
			qsc_stringutils_copy_string(list, listlen, dst);
		}
	}

	qsc_memutils_clear((uint8_t*)src, sizeof(src));
	qsc_memutils_clear((uint8_t*)dst, sizeof(dst));

	return found;
}

static bool pqs_policy_command_verb(const char* command, char* verb, size_t verblen)
{
	size_t pos;
	bool res;

	pos = 0U;
	res = false;

	if (command != NULL && verb != NULL && verblen != 0U)
	{
		while (*command == ' ' || *command == '\t' || *command == '\r' || *command == '\n')
		{
			++command;
		}

		while (command[pos] != '\0' && command[pos] != ' ' && command[pos] != '\t' && command[pos] != '\r' && command[pos] != '\n' && pos < (verblen - 1U))
		{
			verb[pos] = command[pos];
			++pos;
		}

		verb[pos] = '\0';
		res = (pos != 0U);
	}

	return res;
}

static const pqs_policy_record* pqs_policy_store_assigned_policy(const pqs_policy_store* store, pqs_user_privileges privilege)
{
	const char* name;
	const pqs_policy_record* res;

	name = NULL;
	res = NULL;

	if (store != NULL)
	{
		if (privilege == pqs_user_privilege_guest)
		{
			name = store->guest_policy;
		}
		else if (privilege == pqs_user_privilege_user)
		{
			name = store->user_policy;
		}
		else if (privilege == pqs_user_privilege_admin)
		{
			name = store->admin_policy;
		}

		if (name != NULL)
		{
			res = pqs_policy_store_find(store, name);
		}
	}

	return res;
}

static bool pqs_policy_store_repair_defaults(pqs_policy_store* store)
{
	bool changed;
	bool res;

	changed = false;
	res = false;

	if (store != NULL && store->initialized == true)
	{
		pqs_policy_store_add_builtins(store);

		if (pqs_policy_store_find(store, store->guest_policy) == NULL)
		{
			qsc_stringutils_copy_string(store->guest_policy, sizeof(store->guest_policy), PQS_POLICY_DEFAULT_GUEST);
			changed = true;
		}

		if (pqs_policy_store_find(store, store->user_policy) == NULL)
		{
			qsc_stringutils_copy_string(store->user_policy, sizeof(store->user_policy), PQS_POLICY_DEFAULT_USER);
			changed = true;
		}

		if (pqs_policy_store_find(store, store->admin_policy) == NULL)
		{
			qsc_stringutils_copy_string(store->admin_policy, sizeof(store->admin_policy), PQS_POLICY_DEFAULT_ADMIN);
			changed = true;
		}

		if (changed == true)
		{
			res = pqs_policy_store_save(store);
		}
		else
		{
			res = true;
		}
	}

	return res;
}

static void pqs_policy_store_add_builtins(pqs_policy_store* store)
{
	if (store != NULL)
	{
		(void)pqs_policy_store_add(store, PQS_POLICY_DEFAULT_GUEST, pqs_policy_mode_restricted, pqs_policy_privilege_to_mask(pqs_user_privilege_guest), true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "dir", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "ls", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "pwd", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "whoami", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "date", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "list", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_GUEST, "get", true);

		(void)pqs_policy_store_add(store, PQS_POLICY_DEFAULT_USER, pqs_policy_mode_restricted, pqs_policy_privilege_to_mask(pqs_user_privilege_user), true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "dir", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "ls", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "pwd", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "whoami", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "date", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "list", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "get", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "put", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "mkdir", true);
		(void)pqs_policy_store_add_command(store, PQS_POLICY_DEFAULT_USER, "remove", true);

		(void)pqs_policy_store_add(store, PQS_POLICY_DEFAULT_ADMIN, pqs_policy_mode_raw, pqs_policy_privilege_to_mask(pqs_user_privilege_admin), true);
	}
}

bool pqs_policy_store_add(pqs_policy_store* store, const char* name, pqs_policy_modes mode, uint32_t privilege_mask, bool enabled)
{
	pqs_policy_record* record;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->count < PQS_POLICY_DATABASE_MAX &&
		pqs_policy_is_name_valid(name) == true && privilege_mask != 0U && pqs_policy_store_find(store, name) == NULL)
	{
		record = &store->records[store->count];
		qsc_memutils_clear((uint8_t*)record, sizeof(pqs_policy_record));
		qsc_stringutils_copy_string(record->name, sizeof(record->name), name);
		record->mode = mode;
		record->enabled = enabled;
		record->privilege_mask = privilege_mask;
		++store->count;
		res = pqs_policy_store_save(store);
	}

	return res;
}

bool pqs_policy_store_add_command(pqs_policy_store* store, const char* name, const char* command, bool allowed)
{
	pqs_policy_record* record;
	bool res;

	res = false;
	record = pqs_policy_store_find_mutable(store, name);

	if (record != NULL)
	{
		if (allowed == true)
		{
			res = pqs_policy_list_add(record->allowlist, sizeof(record->allowlist), command);
		}
		else
		{
			res = pqs_policy_list_add(record->denylist, sizeof(record->denylist), command);
		}

		if (res == true)
		{
			res = pqs_policy_store_save(store);
		}
	}

	return res;
}

bool pqs_policy_store_assign_privilege(pqs_policy_store* store, pqs_user_privileges privilege, const char* policy)
{
	PQS_ASSERT(store != NULL);

	bool res;

	res = false;

	if (store != NULL && pqs_policy_store_find(store, policy) != NULL)
	{
		if (privilege == pqs_user_privilege_guest)
		{
			qsc_stringutils_copy_string(store->guest_policy, sizeof(store->guest_policy), policy);
			res = true;
		}
		else if (privilege == pqs_user_privilege_user)
		{
			qsc_stringutils_copy_string(store->user_policy, sizeof(store->user_policy), policy);
			res = true;
		}
		else if (privilege == pqs_user_privilege_admin)
		{
			qsc_stringutils_copy_string(store->admin_policy, sizeof(store->admin_policy), policy);
			res = true;
		}

		if (res == true)
		{
			res = pqs_policy_store_save(store);
		}
	}

	return res;
}

bool pqs_policy_command_is_safe(const char* command)
{
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (command != NULL)
	{
		slen = qsc_stringutils_string_size(command);

		if (slen != 0U && slen < PQS_SERVER_COMMAND_MAX)
		{
			res = true;

			for (pos = 0U; pos < slen; ++pos)
			{
				if ((command[pos] >= 'a' && command[pos] <= 'z') ||
					(command[pos] >= 'A' && command[pos] <= 'Z') ||
					(command[pos] >= '0' && command[pos] <= '9') ||
					command[pos] == ' ' || command[pos] == '\t' ||
					command[pos] == '_' || command[pos] == '-' || command[pos] == '.' ||
					command[pos] == '/' || command[pos] == '\\' || command[pos] == ':' ||
					command[pos] == '=' || command[pos] == '+' || command[pos] == ',')
				{
					continue;
				}
				else
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

bool pqs_policy_store_authorize(const pqs_policy_store* store, pqs_user_privileges privilege, const char* command, const pqs_policy_record** matched)
{
	PQS_ASSERT(store != NULL);

	const pqs_policy_record* record;
	const char* evalcmd;
	char verb[PQS_POLICY_COMMAND_MAX] = { 0 };
	uint32_t mask;
	bool res;

	res = false;
	evalcmd = command;
	record = pqs_policy_store_assigned_policy(store, privilege);
	mask = pqs_policy_privilege_to_mask(privilege);

	if (matched != NULL)
	{
		*matched = record;
	}

	if (record != NULL && record->enabled == true && mask != 0U && ((record->privilege_mask & mask) != 0U))
	{
		if (record->mode == pqs_policy_mode_forced)
		{
			evalcmd = record->forced;
		}

		if (evalcmd != NULL &&
			pqs_policy_command_is_safe(evalcmd) == true &&
			pqs_policy_command_verb(evalcmd, verb, sizeof(verb)) == true &&
			pqs_policy_list_contains(record->denylist, verb) == false)
		{
			if (record->mode == pqs_policy_mode_raw)
			{
				res = true;
			}
			else if (record->mode == pqs_policy_mode_restricted)
			{
				res = pqs_policy_list_contains(record->allowlist, verb);
			}
			else if (record->mode == pqs_policy_mode_forced)
			{
				res = true;
			}
		}
	}

	return res;
}

bool pqs_policy_store_enable(pqs_policy_store* store, const char* name, bool enabled)
{
	PQS_ASSERT(store != NULL);

	pqs_policy_record* record;
	bool res;

	res = false;
	record = pqs_policy_store_find_mutable(store, name);

	if (record != NULL)
	{
		record->enabled = enabled;
		res = pqs_policy_store_save(store);
	}

	return res;
}

const pqs_policy_record* pqs_policy_store_find(const pqs_policy_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	const pqs_policy_record* res;
	size_t pos;

	res = NULL;

	if (store != NULL && name != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].name, name) == true)
			{
				res = &store->records[pos];
				break;
			}
		}
	}

	return res;
}

pqs_policy_record* pqs_policy_store_find_mutable(pqs_policy_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	pqs_policy_record* res;
	size_t pos;

	res = NULL;

	if (store != NULL && name != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].name, name) == true)
			{
				res = &store->records[pos];
				break;
			}
		}
	}

	return res;
}

bool pqs_policy_store_initialize(pqs_policy_store* store, const char* path)
{
	PQS_ASSERT(store != NULL);

	FILE* fp;
	char line[PQS_POLICY_DATABASE_LINE_MAX] = { 0 };
	bool res;

	fp = NULL;
	res = false;

	if (store != NULL && path != NULL && path[0U] != '\0')
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(pqs_policy_store));
		qsc_stringutils_copy_string(store->path, sizeof(store->path), path);
		pqs_policy_store_set_default_assignments(store);
		store->initialized = true;
		res = true;

		if (qsc_fileutils_exists(path) == true)
		{
			fp = pqs_policy_file_open(path, "r");

			if (fp != NULL)
			{
				while (fgets(line, sizeof(line), fp) != NULL)
				{
					pqs_policy_record record = { 0 };

					if (line[0U] == '@')
					{
						(void)pqs_policy_parse_assignment(store, line);
					}
					else if (line[0U] != '#' && line[0U] != '\n' && line[0U] != '\r')
					{
						if (pqs_policy_record_from_line(&record, line) == true)
						{
							if (store->count < PQS_POLICY_DATABASE_MAX && pqs_policy_store_find(store, record.name) == NULL)
							{
								qsc_memutils_copy(&store->records[store->count], &record, sizeof(pqs_policy_record));
								++store->count;
							}
						}
					}

					qsc_memutils_clear((uint8_t*)line, sizeof(line));
				}

				fclose(fp);
			}
			else
			{
				res = false;
			}
		}
		else
		{
			pqs_policy_store_add_builtins(store);
			res = pqs_policy_store_save(store);
		}

		if (res == true)
		{
			res = pqs_policy_store_repair_defaults(store);
		}
	}

	return res;
}

bool pqs_policy_store_remove(pqs_policy_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	size_t pos;
	bool res;

	res = false;

	if (store != NULL && name != NULL && qsc_stringutils_strings_equal(name, store->guest_policy) == false &&
		qsc_stringutils_strings_equal(name, store->user_policy) == false && qsc_stringutils_strings_equal(name, store->admin_policy) == false)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].name, name) == true)
			{
				size_t rem;

				rem = store->count - pos - 1U;

				if (rem != 0U)
				{
					qsc_memutils_copy(&store->records[pos], &store->records[pos + 1U], rem * sizeof(pqs_policy_record));
				}

				--store->count;
				qsc_memutils_clear((uint8_t*)&store->records[store->count], sizeof(pqs_policy_record));
				res = pqs_policy_store_save(store);
				break;
			}
		}
	}

	return res;
}

bool pqs_policy_store_remove_command(pqs_policy_store* store, const char* name, const char* command, bool allowed)
{
	PQS_ASSERT(store != NULL);

	pqs_policy_record* record;
	bool res;

	res = false;
	record = pqs_policy_store_find_mutable(store, name);

	if (record != NULL)
	{
		if (allowed == true)
		{
			res = pqs_policy_list_remove(record->allowlist, sizeof(record->allowlist), command);
		}
		else
		{
			res = pqs_policy_list_remove(record->denylist, sizeof(record->denylist), command);
		}

		if (res == true)
		{
			res = pqs_policy_store_save(store);
		}
	}

	return res;
}

bool pqs_policy_store_save(const pqs_policy_store* store)
{
	PQS_ASSERT(store != NULL);

	char line[PQS_POLICY_DATABASE_LINE_MAX] = { 0 };
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->path[0U] != '\0')
	{
		res = qsc_fileutils_copy_stream_to_file(store->path, "# " PQS_POLICY_DATABASE_MAGIC "\n", qsc_stringutils_string_size("# " PQS_POLICY_DATABASE_MAGIC "\n"));

		if (res == true)
		{
			slen = (size_t)snprintf(line, sizeof(line), "@assign|guest|%s\n@assign|user|%s\n@assign|admin|%s\n", store->guest_policy, store->user_policy, store->admin_policy);

			if (slen > 0U && slen < sizeof(line))
			{
				res = qsc_fileutils_append_to_file(store->path, line, slen);
			}
			else
			{
				res = false;
			}

			qsc_memutils_clear((uint8_t*)line, sizeof(line));
		}

		if (res == true)
		{
			for (pos = 0U; pos < store->count; ++pos)
			{
				slen = pqs_policy_record_to_line(&store->records[pos], line, sizeof(line));

				if (slen != 0U)
				{
					res = qsc_fileutils_append_to_file(store->path, line, slen);
				}
				else
				{
					res = false;
				}

				qsc_memutils_clear((uint8_t*)line, sizeof(line));

				if (res == false)
				{
					break;
				}
			}
		}
	}

	return res;
}

bool pqs_policy_store_set_forced(pqs_policy_store* store, const char* name, const char* command)
{
	PQS_ASSERT(store != NULL);

	pqs_policy_record* record;
	bool res;

	res = false;
	record = pqs_policy_store_find_mutable(store, name);

	if (record != NULL && command != NULL && pqs_policy_is_command_name_valid(command) == true)
	{
		qsc_stringutils_clear_string(record->forced);
		qsc_stringutils_copy_string(record->forced, sizeof(record->forced), command);
		res = pqs_policy_store_save(store);
	}

	return res;
}

bool pqs_policy_store_set_mode(pqs_policy_store* store, const char* name, pqs_policy_modes mode)
{
	PQS_ASSERT(store != NULL);

	pqs_policy_record* record;
	bool res;

	res = false;
	record = pqs_policy_store_find_mutable(store, name);

	if (record != NULL)
	{
		record->mode = mode;
		res = pqs_policy_store_save(store);
	}

	return res;
}

const char* pqs_policy_mode_to_string(pqs_policy_modes mode)
{
	const char* res;

	res = "none";

	if (mode == pqs_policy_mode_none)
	{
		res = "no-shell";
	}
	else if (mode == pqs_policy_mode_restricted)
	{
		res = "restricted";
	}
	else if (mode == pqs_policy_mode_forced)
	{
		res = "forced";
	}
	else if (mode == pqs_policy_mode_raw)
	{
		res = "raw-shell";
	}

	return res;
}

pqs_policy_modes pqs_policy_mode_from_string(const char* value)
{
	pqs_policy_modes res;

	res = pqs_policy_mode_none;

	if (value != NULL)
	{
		if (qsc_stringutils_strings_equal(value, "restricted") == true)
		{
			res = pqs_policy_mode_restricted;
		}
		else if (qsc_stringutils_strings_equal(value, "forced") == true)
		{
			res = pqs_policy_mode_forced;
		}
		else if (qsc_stringutils_strings_equal(value, "raw-shell") == true)
		{
			res = pqs_policy_mode_raw;
		}
		else if (qsc_stringutils_strings_equal(value, "no-shell") == true)
		{
			res = pqs_policy_mode_none;
		}
	}

	return res;
}

uint32_t pqs_policy_privilege_to_mask(pqs_user_privileges privilege)
{
	uint32_t res;

	res = 0U;

	if (privilege == pqs_user_privilege_guest)
	{
		res = 0x01U;
	}
	else if (privilege == pqs_user_privilege_user)
	{
		res = 0x02U;
	}
	else if (privilege == pqs_user_privilege_admin)
	{
		res = 0x04U;
	}

	return res;
}

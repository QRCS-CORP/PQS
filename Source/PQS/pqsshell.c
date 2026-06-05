#include "pqsshell.h"
#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#define PQS_SHELL_DATABASE_LINE_MAX 1024U

static FILE* pqs_shell_file_open(const char* path, const char* mode)
{
	FILE* fp;

	fp = NULL;

	if (path != NULL && mode != NULL)
	{
#if defined(_MSC_VER)
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

static char* pqs_shell_string_token(char* source, const char* delimiters, char** context)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	return strtok_s(source, delimiters, context);
#else
	return strtok_r(source, delimiters, context);
#endif
}

static bool pqs_shell_is_name_valid(const char* name)
{
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (name != NULL)
	{
		slen = qsc_stringutils_string_size(name);

		if (slen > 0U && slen < PQS_SHELL_PROFILE_NAME_MAX)
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

static bool pqs_shell_is_type_valid(const char* type)
{
	size_t slen;
	bool res;

	res = false;

	if (type != NULL)
	{
		slen = qsc_stringutils_string_size(type);
		res = (slen > 0U && slen < PQS_SHELL_PROFILE_TYPE_MAX);
	}

	return res;
}

static bool pqs_shell_is_path_valid(const char* path)
{
	size_t slen;
	bool res;

	res = false;

	if (path != NULL)
	{
		slen = qsc_stringutils_string_size(path);
		res = (slen > 0U && slen < PQS_SHELL_PROFILE_PATH_MAX);
	}

	return res;
}


static bool pqs_shell_decimal_u32_is_valid(const char* value, uint32_t* output)
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

static bool pqs_shell_parse_bool(const char* value)
{
	return (value != NULL && value[0U] == '1');
}

static bool pqs_shell_record_from_line(pqs_shell_profile* profile, char* line)
{
	char* token;
	char* ctx;
	char* values[6] = { 0 };
	size_t count;
	bool res;

	res = false;
	ctx = NULL;
	count = 0U;

	if (profile != NULL && line != NULL && line[0U] != '#' && line[0U] != '\0')
	{
		token = pqs_shell_string_token(line, "|\r\n", &ctx);

		while (token != NULL && count < (sizeof(values) / sizeof(values[0U])))
		{
			values[count] = token;
			++count;
			token = pqs_shell_string_token(NULL, "|\r\n", &ctx);
		}

		if (count == 6U && pqs_shell_is_name_valid(values[0U]) == true &&
			pqs_shell_is_type_valid(values[1U]) == true && pqs_shell_is_path_valid(values[5U]) == true)
		{
			qsc_memutils_clear((uint8_t*)profile, sizeof(pqs_shell_profile));
			qsc_stringutils_copy_string(profile->name, sizeof(profile->name), values[0U]);
			qsc_stringutils_copy_string(profile->type, sizeof(profile->type), values[1U]);
			profile->enabled = pqs_shell_parse_bool(values[2U]);
			res = pqs_shell_decimal_u32_is_valid(values[3U], &profile->privilege_mask);
			profile->isdefault = pqs_shell_parse_bool(values[4U]);
			qsc_stringutils_copy_string(profile->path, sizeof(profile->path), values[5U]);
			res = res && (profile->privilege_mask != 0U);
		}
	}

	return res;
}

static size_t pqs_shell_record_to_line(const pqs_shell_profile* profile, char* line, size_t linelen)
{
	int32_t slen;
	size_t res;

	res = 0U;

	if (profile != NULL && line != NULL && linelen != 0U)
	{
		slen = snprintf(line, linelen, "%s|%s|%u|%u|%u|%s\n",
			profile->name,
			profile->type,
			(profile->enabled == true) ? 1U : 0U,
			profile->privilege_mask,
			(profile->isdefault == true) ? 1U : 0U,
			profile->path);

		if (slen > 0 && (size_t)slen < linelen)
		{
			res = (size_t)slen;
		}
	}

	return res;
}

static bool pqs_shell_add_builtin_if_exists(pqs_shell_store* store, const char* name, const char* type, const char* path, bool isdefault)
{
	pqs_shell_profile* profile;
	bool res;

	res = false;

	if (store != NULL && qsc_fileutils_exists(path) == true)
	{
		res = pqs_shell_store_add(store, name, type, path, PQS_SHELL_PRIVILEGE_ALL, true);

		if (res == true && isdefault == true)
		{
			profile = pqs_shell_store_find_mutable(store, name);

			if (profile != NULL)
			{
				profile->isdefault = true;
			}
		}
	}

	return res;
}

static void pqs_shell_store_add_builtins(pqs_shell_store* store)
{
	if (store != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		(void)pqs_shell_add_builtin_if_exists(store, "default", "cmd", "C:\\Windows\\System32\\cmd.exe", true);
		(void)pqs_shell_add_builtin_if_exists(store, "cmd", "cmd", "C:\\Windows\\System32\\cmd.exe", false);
		(void)pqs_shell_add_builtin_if_exists(store, "powershell", "powershell", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false);
		(void)pqs_shell_add_builtin_if_exists(store, "pwsh", "powershell", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", false);
#else
		(void)pqs_shell_add_builtin_if_exists(store, "default", "sh", "/bin/sh", true);
		(void)pqs_shell_add_builtin_if_exists(store, "sh", "sh", "/bin/sh", false);
		(void)pqs_shell_add_builtin_if_exists(store, "bash", "bash", "/bin/bash", false);
		(void)pqs_shell_add_builtin_if_exists(store, "zsh", "zsh", "/bin/zsh", false);
#endif
	}
}

bool pqs_shell_store_add(pqs_shell_store* store, const char* name, const char* type, const char* path, uint32_t privilege_mask, bool enabled)
{
	PQS_ASSERT(store != NULL);

	pqs_shell_profile* profile;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->count < PQS_SHELL_PROFILE_DATABASE_MAX &&
		pqs_shell_is_name_valid(name) == true && pqs_shell_is_type_valid(type) == true &&
		pqs_shell_is_path_valid(path) == true && privilege_mask != 0U && pqs_shell_store_find(store, name) == NULL)
	{
		profile = &store->profiles[store->count];
		qsc_memutils_clear((uint8_t*)profile, sizeof(pqs_shell_profile));
		qsc_stringutils_copy_string(profile->name, sizeof(profile->name), name);
		qsc_stringutils_copy_string(profile->type, sizeof(profile->type), type);
		qsc_stringutils_copy_string(profile->path, sizeof(profile->path), path);
		profile->privilege_mask = privilege_mask;
		profile->enabled = enabled;
		profile->isdefault = (store->count == 0U) ? true : false;
		++store->count;
		res = pqs_shell_store_save(store);
	}

	return res;
}

bool pqs_shell_store_enable(pqs_shell_store* store, const char* name, bool enabled)
{
	PQS_ASSERT(store != NULL);

	pqs_shell_profile* profile;
	bool res;

	res = false;
	profile = pqs_shell_store_find_mutable(store, name);

	if (profile != NULL)
	{
		profile->enabled = enabled;
		res = pqs_shell_store_save(store);
	}

	return res;
}

const pqs_shell_profile* pqs_shell_store_find(const pqs_shell_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	const pqs_shell_profile* res;
	size_t pos;

	res = NULL;

	if (store != NULL && name != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->profiles[pos].name, name) == true)
			{
				res = &store->profiles[pos];
				break;
			}
		}
	}

	return res;
}

pqs_shell_profile* pqs_shell_store_find_mutable(pqs_shell_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	pqs_shell_profile* res;
	size_t pos;

	res = NULL;

	if (store != NULL && name != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->profiles[pos].name, name) == true)
			{
				res = &store->profiles[pos];
				break;
			}
		}
	}

	return res;
}

const pqs_shell_profile* pqs_shell_store_default(const pqs_shell_store* store)
{
	PQS_ASSERT(store != NULL);

	const pqs_shell_profile* res;
	size_t pos;

	res = NULL;

	if (store != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (store->profiles[pos].isdefault == true)
			{
				res = &store->profiles[pos];
				break;
			}
		}

		if (res == NULL && store->count != 0U)
		{
			res = &store->profiles[0U];
		}
	}

	return res;
}

bool pqs_shell_store_initialize(pqs_shell_store* store, const char* path)
{
	PQS_ASSERT(store != NULL);

	FILE* fp;
	char line[PQS_SHELL_DATABASE_LINE_MAX] = { 0 };
	bool res;

	res = false;
	fp = NULL;

	if (store != NULL && path != NULL && path[0U] != '\0')
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(pqs_shell_store));
		qsc_stringutils_copy_string(store->path, sizeof(store->path), path);
		store->initialized = true;
		res = true;

		if (qsc_fileutils_exists(path) == true)
		{
			fp = pqs_shell_file_open(path, "r");

			if (fp != NULL)
			{
				while (fgets(line, sizeof(line), fp) != NULL)
				{
					pqs_shell_profile profile = { 0 };

					if (line[0U] != '#' && line[0U] != '\n' && line[0U] != '\r')
					{
						if (pqs_shell_record_from_line(&profile, line) == true)
						{
							if (store->count < PQS_SHELL_PROFILE_DATABASE_MAX && pqs_shell_store_find(store, profile.name) == NULL)
							{
								qsc_memutils_copy(&store->profiles[store->count], &profile, sizeof(pqs_shell_profile));
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
			pqs_shell_store_add_builtins(store);
			res = pqs_shell_store_save(store);
		}
	}

	return res;
}

bool pqs_shell_store_remove(pqs_shell_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	size_t pos;
	bool res;

	res = false;

	if (store != NULL && name != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->profiles[pos].name, name) == true)
			{
				size_t rem;

				rem = store->count - pos - 1U;

				if (rem != 0U)
				{
					qsc_memutils_copy(&store->profiles[pos], &store->profiles[pos + 1U], rem * sizeof(pqs_shell_profile));
				}

				--store->count;
				qsc_memutils_clear((uint8_t*)&store->profiles[store->count], sizeof(pqs_shell_profile));

				if (store->count != 0U && pqs_shell_store_default(store) == NULL)
				{
					store->profiles[0U].isdefault = true;
				}

				res = pqs_shell_store_save(store);
				break;
			}
		}
	}

	return res;
}

bool pqs_shell_store_save(const pqs_shell_store* store)
{
	PQS_ASSERT(store != NULL);

	char line[PQS_SHELL_DATABASE_LINE_MAX] = { 0 };
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->path[0U] != '\0')
	{
		res = qsc_fileutils_copy_stream_to_file(store->path, "# " PQS_SHELL_DATABASE_MAGIC "\n", qsc_stringutils_string_size("# " PQS_SHELL_DATABASE_MAGIC "\n"));

		if (res == true)
		{
			for (pos = 0U; pos < store->count; ++pos)
			{
				slen = pqs_shell_record_to_line(&store->profiles[pos], line, sizeof(line));

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

bool pqs_shell_store_set_default(pqs_shell_store* store, const char* name)
{
	PQS_ASSERT(store != NULL);

	pqs_shell_profile* profile;
	size_t pos;
	bool res;

	res = false;
	profile = pqs_shell_store_find_mutable(store, name);

	if (store != NULL && profile != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			store->profiles[pos].isdefault = false;
		}

		profile->isdefault = true;
		res = pqs_shell_store_save(store);
	}

	return res;
}

bool pqs_shell_store_set_privilege(pqs_shell_store* store, const char* name, pqs_user_privileges privilege, bool allowed)
{
	PQS_ASSERT(store != NULL);

	pqs_shell_profile* profile;
	uint32_t mask;
	bool res;

	res = false;
	profile = pqs_shell_store_find_mutable(store, name);
	mask = pqs_shell_privilege_to_mask(privilege);

	if (profile != NULL && mask != 0U)
	{
		if (allowed == true)
		{
			profile->privilege_mask |= mask;
		}
		else
		{
			profile->privilege_mask &= ~mask;
		}

		res = pqs_shell_store_save(store);
	}

	return res;
}

uint32_t pqs_shell_privilege_to_mask(pqs_user_privileges privilege)
{
	uint32_t res;

	res = 0U;

	if (privilege == pqs_user_privilege_guest)
	{
		res = PQS_SHELL_PRIVILEGE_GUEST;
	}
	else if (privilege == pqs_user_privilege_user)
	{
		res = PQS_SHELL_PRIVILEGE_USER;
	}
	else if (privilege == pqs_user_privilege_admin)
	{
		res = PQS_SHELL_PRIVILEGE_ADMIN;
	}

	return res;
}

bool pqs_shell_profile_allows_privilege(const pqs_shell_profile* profile, pqs_user_privileges privilege)
{
	uint32_t mask;
	bool res;

	res = false;
	mask = pqs_shell_privilege_to_mask(privilege);

	if (profile != NULL && profile->enabled == true && mask != 0U)
	{
		res = ((profile->privilege_mask & mask) != 0U);
	}

	return res;
}

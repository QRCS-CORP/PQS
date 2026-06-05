#include "pqsuser.h"
#include "acp.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "scb.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#define PQS_USER_DATABASE_LINE_MAX 1024U
#define PQS_USER_SALT_HEX_SIZE ((PQS_USER_SALT_SIZE * 2U) + 1U)
#define PQS_USER_VERIFIER_HEX_SIZE ((PQS_USER_VERIFIER_SIZE * 2U) + 1U)
#define PQS_USER_DUMMY_NAME "pqs-disabled-account"
#define PQS_USER_DUMMY_PASSPHRASE "pqs-dummy-passphrase"

static const uint8_t pqs_user_dummy_salt[PQS_USER_SALT_SIZE] =
{
	0x50U, 0x51U, 0x53U, 0x2DU, 0x44U, 0x55U, 0x4DU, 0x4DU,
	0x59U, 0x2DU, 0x53U, 0x43U, 0x42U, 0x2DU, 0x53U, 0x41U,
	0x4CU, 0x54U, 0x2DU, 0x56U, 0x32U, 0x2DU, 0x30U, 0x30U,
	0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x31U
};

static FILE* pqs_user_file_open(const char* path, const char* mode)
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

static char* pqs_user_string_token(char* source, const char* delimiters, char** context)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	return strtok_s(source, delimiters, context);
#else
	return strtok_r(source, delimiters, context);
#endif
}

static uint64_t pqs_user_timestamp(void)
{
	return (uint64_t)time(NULL);
}

bool pqs_user_name_is_valid(const char* username)
{
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (username != NULL)
	{
		slen = qsc_stringutils_string_size(username);

		if (slen > 0U && slen < PQS_USERNAME_MAX)
		{
			res = true;

			for (pos = 0U; pos < slen; ++pos)
			{
				if ((username[pos] >= 'a' && username[pos] <= 'z') ||
					(username[pos] >= 'A' && username[pos] <= 'Z') ||
					(username[pos] >= '0' && username[pos] <= '9') ||
					username[pos] == '_' || username[pos] == '-' || username[pos] == '.')
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

bool pqs_user_passphrase_is_valid(const char* passphrase)
{
	size_t slen;
	bool res;

	res = false;

	if (passphrase != NULL)
	{
		slen = qsc_stringutils_string_size(passphrase);
		res = (slen >= PQS_PASSPHRASE_MIN && slen < PQS_PASSPHRASE_MAX);
	}

	return res;
}

static bool pqs_user_generate_verifier(const char* username, const char* passphrase, const uint8_t* salt, uint8_t* verifier)
{
	qsc_keccak_state hctx;
	qsc_scb_state ctx = { 0U };
	uint8_t* seed;
	size_t dlen;
	size_t plen;
	size_t ulen;
	bool res;

	res = false;
	seed = NULL;

	if (username != NULL && passphrase != NULL && salt != NULL && verifier != NULL)
	{
		seed = (uint8_t*)qsc_memutils_secure_malloc(QSC_SHA3_256_HASH_SIZE);

		if (seed != NULL)
		{
			dlen = qsc_stringutils_string_size(PQS_USER_VERIFIER_DOMAIN);
			ulen = qsc_stringutils_string_size(username);
			plen = qsc_stringutils_string_size(passphrase);
			qsc_sha3_initialize(&hctx);
			qsc_sha3_update(&hctx, qsc_keccak_rate_256, (const uint8_t*)PQS_USER_VERIFIER_DOMAIN, dlen);
			qsc_sha3_update(&hctx, qsc_keccak_rate_256, (const uint8_t*)username, ulen);
			qsc_sha3_update(&hctx, qsc_keccak_rate_256, (const uint8_t*)passphrase, plen);
			qsc_sha3_finalize(&hctx, qsc_keccak_rate_256, seed);
			qsc_scb_initialize(&ctx, seed, QSC_SHA3_256_HASH_SIZE, salt, PQS_USER_SALT_SIZE, PQS_CRYPTO_PHASH_CPU_COST, PQS_CRYPTO_PHASH_MEMORY_COST);
			res = qsc_scb_generate(&ctx, verifier, PQS_USER_VERIFIER_SIZE);
			qsc_scb_dispose(&ctx);
			qsc_memutils_secure_free(seed, QSC_SHA3_256_HASH_SIZE);
		}
	}

	qsc_memutils_secure_erase(&hctx, sizeof(hctx));
	qsc_memutils_secure_erase(&ctx, sizeof(ctx));

	return res;
}


static bool pqs_user_decimal_u64_is_valid(const char* value, uint64_t* output)
{
	char* end;
	unsigned long long val;
	bool res;

	end = NULL;
	val = 0ULL;
	res = false;

	if (value != NULL && value[0U] != '\0')
	{
		errno = 0;
		val = strtoull(value, &end, 10);

		if (errno == 0 && end != NULL && *end == '\0')
		{
			if (output != NULL)
			{
				*output = (uint64_t)val;
			}

			res = true;
		}
	}

	return res;
}

static bool pqs_user_decimal_u32_is_valid(const char* value, uint32_t* output)
{
	uint64_t val;
	bool res;

	val = 0U;
	res = pqs_user_decimal_u64_is_valid(value, &val);
	res = res && (val <= UINT32_MAX);

	if (res == true && output != NULL)
	{
		*output = (uint32_t)val;
	}

	return res;
}

static bool pqs_user_hex_field_is_valid(const char* value, size_t hexlen)
{
	size_t i;
	bool res;

	res = false;

	if (value != NULL && qsc_stringutils_string_size(value) == hexlen)
	{
		res = true;

		for (i = 0U; i < hexlen; ++i)
		{
			if (((value[i] >= '0' && value[i] <= '9') ||
				(value[i] >= 'a' && value[i] <= 'f') ||
				(value[i] >= 'A' && value[i] <= 'F')) == false)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

static bool pqs_user_parse_bool(const char* value)
{
	return (value != NULL && value[0U] == '1');
}

static bool pqs_user_record_from_line(pqs_user_record* record, char* line)
{
	char* token;
	char* ctx;
	char* values[9] = { 0 };
	size_t count;
	bool res;

	res = false;
	ctx = NULL;
	count = 0U;

	if (record != NULL && line != NULL && line[0U] != '#' && line[0U] != '\0')
	{
		token = pqs_user_string_token(line, "|\r\n", &ctx);

		while (token != NULL && count < (sizeof(values) / sizeof(values[0U])))
		{
			values[count] = token;
			++count;
			token = pqs_user_string_token(NULL, "|\r\n", &ctx);
		}

		if (count == 9U && pqs_user_name_is_valid(values[0U]) == true &&
			pqs_user_hex_field_is_valid(values[3U], PQS_USER_SALT_HEX_SIZE - 1U) == true &&
			pqs_user_hex_field_is_valid(values[4U], PQS_USER_VERIFIER_HEX_SIZE - 1U) == true)
		{
			qsc_memutils_clear((uint8_t*)record, sizeof(pqs_user_record));
			qsc_stringutils_copy_string(record->username, sizeof(record->username), values[0U]);
			record->privilege = pqs_user_privilege_from_string(values[1U]);
			record->enabled = pqs_user_parse_bool(values[2U]);
			qsc_intutils_hex_to_bin(values[3U], record->salt, PQS_USER_SALT_SIZE);
			qsc_intutils_hex_to_bin(values[4U], record->verifier, PQS_USER_VERIFIER_SIZE);
			res = pqs_user_decimal_u32_is_valid(values[5U], &record->failures);
			qsc_stringutils_copy_string(record->shellprofile, sizeof(record->shellprofile), values[6U]);
			res = res && pqs_user_decimal_u64_is_valid(values[7U], &record->created);
			res = res && pqs_user_decimal_u64_is_valid(values[8U], &record->modified);
			res = res && (record->privilege != pqs_user_privilege_none && record->shellprofile[0U] != '\0');
		}
	}

	return res;
}

static size_t pqs_user_record_to_line(const pqs_user_record* record, char* line, size_t linelen)
{
	char salt[PQS_USER_SALT_HEX_SIZE] = { 0 };
	char verifier[PQS_USER_VERIFIER_HEX_SIZE] = { 0 };
	int32_t slen;
	size_t res;

	res = 0U;

	if (record != NULL && line != NULL && linelen != 0U)
	{
		qsc_intutils_bin_to_hex(record->salt, salt, PQS_USER_SALT_SIZE);
		qsc_intutils_bin_to_hex(record->verifier, verifier, PQS_USER_VERIFIER_SIZE);

		slen = snprintf(line, linelen, "%s|%s|%u|%s|%s|%u|%s|%llu|%llu\n",
			record->username,
			pqs_user_privilege_to_string(record->privilege),
			(record->enabled == true) ? 1U : 0U,
			salt,
			verifier,
			record->failures,
			record->shellprofile,
			(unsigned long long)record->created,
			(unsigned long long)record->modified);

		if (slen > 0 && (size_t)slen < linelen)
		{
			res = (size_t)slen;
		}
	}

	return res;
}

bool pqs_user_store_add(pqs_user_store* store, const char* username, const char* passphrase, pqs_user_privileges privilege)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* record;
	uint64_t ts;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->count < PQS_USER_DATABASE_MAX &&
		pqs_user_name_is_valid(username) == true && pqs_user_passphrase_is_valid(passphrase) == true &&
		privilege != pqs_user_privilege_none && pqs_user_store_find(store, username) == NULL)
	{
		record = &store->records[store->count];
		qsc_memutils_clear((uint8_t*)record, sizeof(pqs_user_record));
		qsc_stringutils_copy_string(record->username, sizeof(record->username), username);
		qsc_stringutils_copy_string(record->shellprofile, sizeof(record->shellprofile), PQS_USER_DEFAULT_SHELL_PROFILE);
		record->privilege = privilege;
		record->enabled = true;
		ts = pqs_user_timestamp();
		record->created = ts;
		record->modified = ts;
		res = qsc_acp_generate(record->salt, sizeof(record->salt));

		if (res == true)
		{
			res = pqs_user_generate_verifier(username, passphrase, record->salt, record->verifier);
		}

		if (res == true)
		{
			++store->count;
			res = pqs_user_store_save(store);
		}
		else
		{
			qsc_memutils_clear((uint8_t*)record, sizeof(pqs_user_record));
		}
	}

	return res;
}

bool pqs_user_store_enable(pqs_user_store* store, const char* username, bool enabled)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* record;
	bool res;

	res = false;
	record = pqs_user_store_find_mutable(store, username);

	if (record != NULL)
	{
		record->enabled = enabled;

		if (enabled == true)
		{
			record->failures = 0U;
		}

		record->modified = pqs_user_timestamp();
		res = pqs_user_store_save(store);
	}

	return res;
}

const pqs_user_record* pqs_user_store_find(const pqs_user_store* store, const char* username)
{
	PQS_ASSERT(store != NULL);

	const pqs_user_record* res;
	size_t pos;

	res = NULL;

	if (store != NULL && username != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].username, username) == true)
			{
				res = &store->records[pos];
				break;
			}
		}
	}

	return res;
}

pqs_user_record* pqs_user_store_find_mutable(pqs_user_store* store, const char* username)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* res;
	size_t pos;

	res = NULL;

	if (store != NULL && username != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].username, username) == true)
			{
				res = &store->records[pos];
				break;
			}
		}
	}

	return res;
}

bool pqs_user_store_initialize(pqs_user_store* store, const char* path)
{
	PQS_ASSERT(store != NULL);

	FILE* fp;
	char line[PQS_USER_DATABASE_LINE_MAX] = { 0 };
	bool res;

	res = false;
	fp = NULL;

	if (store != NULL && path != NULL && path[0U] != '\0')
	{
		qsc_memutils_clear((uint8_t*)store, sizeof(pqs_user_store));
		qsc_stringutils_copy_string(store->path, sizeof(store->path), path);
		store->initialized = true;
		res = true;

		if (qsc_fileutils_exists(path) == true)
		{
			fp = pqs_user_file_open(path, "r");

			if (fp != NULL)
			{
				while (fgets(line, sizeof(line), fp) != NULL)
				{
					pqs_user_record record = { 0 };

					if (line[0U] != '#' && line[0U] != '\n' && line[0U] != '\r')
					{
						if (pqs_user_record_from_line(&record, line) == true)
						{
							if (store->count < PQS_USER_DATABASE_MAX && pqs_user_store_find(store, record.username) == NULL)
							{
								qsc_memutils_copy(&store->records[store->count], &record, sizeof(pqs_user_record));
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
			res = pqs_user_store_save(store);
		}
	}

	return res;
}

bool pqs_user_store_remove(pqs_user_store* store, const char* username)
{
	PQS_ASSERT(store != NULL);

	size_t pos;
	bool res;

	res = false;

	if (store != NULL && username != NULL)
	{
		for (pos = 0U; pos < store->count; ++pos)
		{
			if (qsc_stringutils_strings_equal(store->records[pos].username, username) == true)
			{
				size_t rem;

				rem = store->count - pos - 1U;

				if (rem != 0U)
				{
					qsc_memutils_copy(&store->records[pos], &store->records[pos + 1U], rem * sizeof(pqs_user_record));
				}

				--store->count;
				qsc_memutils_clear((uint8_t*)&store->records[store->count], sizeof(pqs_user_record));
				res = pqs_user_store_save(store);
				break;
			}
		}
	}

	return res;
}

bool pqs_user_store_save(const pqs_user_store* store)
{
	PQS_ASSERT(store != NULL);

	char line[PQS_USER_DATABASE_LINE_MAX] = { 0 };
	size_t pos;
	size_t slen;
	bool res;

	res = false;

	if (store != NULL && store->initialized == true && store->path[0U] != '\0')
	{
		res = qsc_fileutils_copy_stream_to_file(store->path, "# " PQS_USER_DATABASE_MAGIC "\n", qsc_stringutils_string_size("# " PQS_USER_DATABASE_MAGIC "\n"));

		if (res == true)
		{
			for (pos = 0U; pos < store->count; ++pos)
			{
				slen = pqs_user_record_to_line(&store->records[pos], line, sizeof(line));

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

bool pqs_user_store_set_privilege(pqs_user_store* store, const char* username, pqs_user_privileges privilege)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* record;
	bool res;

	res = false;
	record = pqs_user_store_find_mutable(store, username);

	if (record != NULL && privilege != pqs_user_privilege_none)
	{
		record->privilege = privilege;
		record->modified = pqs_user_timestamp();
		res = pqs_user_store_save(store);
	}

	return res;
}

bool pqs_user_store_set_shell_profile(pqs_user_store* store, const char* username, const char* shellprofile)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* record;
	size_t slen;
	bool res;

	res = false;
	record = pqs_user_store_find_mutable(store, username);

	if (record != NULL && shellprofile != NULL)
	{
		slen = qsc_stringutils_string_size(shellprofile);

		if (slen > 0U && slen < PQS_SHELL_PROFILE_NAME_MAX)
		{
			qsc_stringutils_clear_string(record->shellprofile);
			qsc_stringutils_copy_string(record->shellprofile, sizeof(record->shellprofile), shellprofile);
			record->modified = pqs_user_timestamp();
			res = pqs_user_store_save(store);
		}
	}

	return res;
}

bool pqs_user_store_set_passphrase(pqs_user_store* store, const char* username, const char* passphrase)
{
	PQS_ASSERT(store != NULL);

	pqs_user_record* record;
	bool res;

	res = false;
	record = pqs_user_store_find_mutable(store, username);

	if (record != NULL && pqs_user_passphrase_is_valid(passphrase) == true)
	{
		res = qsc_acp_generate(record->salt, sizeof(record->salt));

		if (res == true)
		{
			res = pqs_user_generate_verifier(username, passphrase, record->salt, record->verifier);
		}

		if (res == true)
		{
			record->failures = 0U;
			record->modified = pqs_user_timestamp();
			res = pqs_user_store_save(store);
		}
	}

	return res;
}

const char* pqs_user_privilege_to_string(pqs_user_privileges privilege)
{
	const char* res;

	res = "none";

	if (privilege == pqs_user_privilege_guest)
	{
		res = "guest";
	}
	else if (privilege == pqs_user_privilege_user)
	{
		res = "user";
	}
	else if (privilege == pqs_user_privilege_admin)
	{
		res = "admin";
	}

	return res;
}

pqs_user_privileges pqs_user_privilege_from_string(const char* value)
{
	pqs_user_privileges res;

	res = pqs_user_privilege_none;

	if (value != NULL)
	{
		if (qsc_stringutils_strings_equal(value, "guest") == true)
		{
			res = pqs_user_privilege_guest;
		}
		else if (qsc_stringutils_strings_equal(value, "user") == true)
		{
			res = pqs_user_privilege_user;
		}
		else if (qsc_stringutils_strings_equal(value, "admin") == true)
		{
			res = pqs_user_privilege_admin;
		}
	}

	return res;
}

bool pqs_user_verify_passphrase(const pqs_user_record* record, const char* passphrase)
{
	uint8_t* verifier;
	bool res;

	res = false;
	verifier = (uint8_t*)qsc_memutils_secure_malloc(PQS_USER_VERIFIER_SIZE);

	if (verifier != NULL)
	{
		qsc_memutils_clear(verifier, PQS_USER_VERIFIER_SIZE);

		if (record != NULL && record->enabled == true && pqs_user_passphrase_is_valid(passphrase) == true)
		{
			res = pqs_user_generate_verifier(record->username, passphrase, record->salt, verifier);

			if (res == true)
			{
				res = (qsc_intutils_verify(record->verifier, verifier, PQS_USER_VERIFIER_SIZE) == 0);
			}
		}

		qsc_memutils_secure_free(verifier, PQS_USER_VERIFIER_SIZE);
	}

	return res;
}

bool pqs_user_verify_passphrase_timing_neutral(const pqs_user_record* record, const char* username, const char* passphrase)
{
	uint8_t* verifier;
	uint8_t* target;
	const uint8_t* salt;
	const char* uname;
	const char* pword;
	bool valid;
	bool res;

	valid = false;
	res = false;
	salt = pqs_user_dummy_salt;
	uname = (username != NULL && username[0U] != '\0') ? username : PQS_USER_DUMMY_NAME;
	pword = (passphrase != NULL) ? passphrase : PQS_USER_DUMMY_PASSPHRASE;
	verifier = (uint8_t*)qsc_memutils_secure_malloc(PQS_USER_VERIFIER_SIZE);
	target = (uint8_t*)qsc_memutils_secure_malloc(PQS_USER_VERIFIER_SIZE);

	if (verifier != NULL && target != NULL)
	{
		qsc_memutils_clear(verifier, PQS_USER_VERIFIER_SIZE);
		qsc_memutils_clear(target, PQS_USER_VERIFIER_SIZE);

		if (record != NULL && record->enabled == true && pqs_user_passphrase_is_valid(passphrase) == true)
		{
			salt = record->salt;
			uname = record->username;
			qsc_memutils_copy(target, record->verifier, PQS_USER_VERIFIER_SIZE);
			valid = true;
		}

		if (pqs_user_generate_verifier(uname, pword, salt, verifier) == true)
		{
			res = (qsc_intutils_verify(target, verifier, PQS_USER_VERIFIER_SIZE) == 0 && valid == true);
		}
	}

	if (verifier != NULL)
	{
		qsc_memutils_secure_free(verifier, PQS_USER_VERIFIER_SIZE);
	}

	if (target != NULL)
	{
		qsc_memutils_secure_free(target, PQS_USER_VERIFIER_SIZE);
	}

	return res;
}

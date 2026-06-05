#include "pqslogger.h"
#include "async.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"
#include <stdio.h>
#include <string.h>

#define PQS_LOGGER_HASH_SIZE 32U
#define PQS_LOGGER_HASH_TEXT_SIZE ((PQS_LOGGER_HASH_SIZE * 2U) + 1U)

typedef struct pqs_logger_state
{
	char path[QSC_SYSTEM_MAX_PATH];
	uint8_t previous[PQS_LOGGER_HASH_SIZE];
	qsc_mutex mutex;
	uint64_t sequence;
	pqs_log_level level;
	bool initialized;
	bool failed;
} pqs_logger_state;

static pqs_logger_state m_pqs_logger_state;

static const char* pqs_logger_level_to_string(pqs_log_level level)
{
	const char* res;

	res = "NONE";

	if (level == pqs_log_level_error)
	{
		res = "ERROR";
	}
	else if (level == pqs_log_level_warning)
	{
		res = "WARN";
	}
	else if (level == pqs_log_level_info)
	{
		res = "INFO";
	}
	else if (level == pqs_log_level_audit)
	{
		res = "AUDIT";
	}
	else if (level == pqs_log_level_debug)
	{
		res = "DEBUG";
	}

	return res;
}

static const char* pqs_logger_event_to_string(pqs_log_event event)
{
	const char* res;

	res = "none";

	if (event == pqs_log_event_application_start)
	{
		res = "application_start";
	}
	else if (event == pqs_log_event_application_stop)
	{
		res = "application_stop";
	}
	else if (event == pqs_log_event_key_loaded)
	{
		res = "key_loaded";
	}
	else if (event == pqs_log_event_key_generated)
	{
		res = "key_generated";
	}
	else if (event == pqs_log_event_connection_open)
	{
		res = "connection_open";
	}
	else if (event == pqs_log_event_connection_close)
	{
		res = "connection_close";
	}
	else if (event == pqs_log_event_connection_refused)
	{
		res = "connection_refused";
	}
	else if (event == pqs_log_event_command_received)
	{
		res = "command_received";
	}
	else if (event == pqs_log_event_command_complete)
	{
		res = "command_complete";
	}
	else if (event == pqs_log_event_command_failed)
	{
		res = "command_failed";
	}
	else if (event == pqs_log_event_auth_success)
	{
		res = "auth_success";
	}
	else if (event == pqs_log_event_auth_failure)
	{
		res = "auth_failure";
	}
	else if (event == pqs_log_event_auth_lockout)
	{
		res = "auth_lockout";
	}
	else if (event == pqs_log_event_user_database_loaded)
	{
		res = "user_database_loaded";
	}
	else if (event == pqs_log_event_user_database_created)
	{
		res = "user_database_created";
	}
	else if (event == pqs_log_event_user_added)
	{
		res = "user_added";
	}
	else if (event == pqs_log_event_user_removed)
	{
		res = "user_removed";
	}
	else if (event == pqs_log_event_user_updated)
	{
		res = "user_updated";
	}
	else if (event == pqs_log_event_shell_database_loaded)
	{
		res = "shell_database_loaded";
	}
	else if (event == pqs_log_event_shell_database_created)
	{
		res = "shell_database_created";
	}
	else if (event == pqs_log_event_shell_added)
	{
		res = "shell_added";
	}
	else if (event == pqs_log_event_shell_removed)
	{
		res = "shell_removed";
	}
	else if (event == pqs_log_event_shell_updated)
	{
		res = "shell_updated";
	}
	else if (event == pqs_log_event_policy_database_loaded)
	{
		res = "policy_database_loaded";
	}
	else if (event == pqs_log_event_policy_database_created)
	{
		res = "policy_database_created";
	}
	else if (event == pqs_log_event_policy_added)
	{
		res = "policy_added";
	}
	else if (event == pqs_log_event_policy_removed)
	{
		res = "policy_removed";
	}
	else if (event == pqs_log_event_policy_updated)
	{
		res = "policy_updated";
	}
	else if (event == pqs_log_event_policy_allowed)
	{
		res = "policy_allowed";
	}
	else if (event == pqs_log_event_policy_denied)
	{
		res = "policy_denied";
	}
	else if (event == pqs_log_event_hostkey_loaded)
	{
		res = "hostkey_loaded";
	}
	else if (event == pqs_log_event_hostkey_pinned)
	{
		res = "hostkey_pinned";
	}
	else if (event == pqs_log_event_hostkey_verified)
	{
		res = "hostkey_verified";
	}
	else if (event == pqs_log_event_hostkey_changed)
	{
		res = "hostkey_changed";
	}
	else if (event == pqs_log_event_sandbox_enabled)
	{
		res = "sandbox_enabled";
	}
	else if (event == pqs_log_event_sandbox_violation)
	{
		res = "sandbox_violation";
	}
	else if (event == pqs_log_event_command_timeout)
	{
		res = "command_timeout";
	}
	else if (event == pqs_log_event_command_output_limit)
	{
		res = "command_output_limit";
	}
	else if (event == pqs_log_event_file_transfer_start)
	{
		res = "file_transfer_start";
	}
	else if (event == pqs_log_event_file_transfer_complete)
	{
		res = "file_transfer_complete";
	}
	else if (event == pqs_log_event_file_transfer_failed)
	{
		res = "file_transfer_failed";
	}
	else if (event == pqs_log_event_protocol_error)
	{
		res = "protocol_error";
	}
	else if (event == pqs_log_event_admin_request)
	{
		res = "admin_request";
	}
	else if (event == pqs_log_event_admin_allowed)
	{
		res = "admin_allowed";
	}
	else if (event == pqs_log_event_admin_denied)
	{
		res = "admin_denied";
	}
	else if (event == pqs_log_event_admin_complete)
	{
		res = "admin_complete";
	}
	else if (event == pqs_log_event_admin_failed)
	{
		res = "admin_failed";
	}
	else if (event == pqs_log_event_audit_chain_start)
	{
		res = "audit_chain_start";
	}

	return res;
}

static void pqs_logger_copy_field(char* output, size_t outlen, const char* input, const char* fallback)
{
	const char* src;
	size_t pos;
	size_t wpos;

	src = fallback;
	wpos = 0U;

	if (input != NULL && input[0U] != '\0')
	{
		src = input;
	}

	if (output != NULL && outlen != 0U && src != NULL)
	{
		qsc_memutils_clear((uint8_t*)output, outlen);

		for (pos = 0U; src[pos] != '\0' && wpos < (outlen - 1U); ++pos)
		{
			if (src[pos] == '\r' || src[pos] == '\n' || src[pos] == '\t' || src[pos] == '"')
			{
				output[wpos] = '_';
			}
			else if ((uint8_t)src[pos] < 0x20U || (uint8_t)src[pos] == 0x7FU)
			{
				output[wpos] = '_';
			}
			else
			{
				output[wpos] = src[pos];
			}

			++wpos;
		}

		output[wpos] = '\0';
	}
}

static bool pqs_logger_hash_to_hex(const uint8_t* hash, char* output, size_t outlen)
{
	bool res;

	res = false;

	if (hash != NULL && output != NULL && outlen >= PQS_LOGGER_HASH_TEXT_SIZE)
	{
		res = qsc_encoding_hex_encode(hash, PQS_LOGGER_HASH_SIZE, output, outlen);
	}

	return res;
}

static bool pqs_logger_hex_to_hash(const char* input, uint8_t* hash)
{
	size_t declen;
	bool res;

	declen = 0U;
	res = false;

	if (input != NULL && hash != NULL && qsc_stringutils_string_size(input) == (PQS_LOGGER_HASH_TEXT_SIZE - 1U))
	{
		res = qsc_encoding_hex_decode(input, PQS_LOGGER_HASH_TEXT_SIZE - 1U, hash, PQS_LOGGER_HASH_SIZE, &declen);
		res = res && (declen == PQS_LOGGER_HASH_SIZE);
	}

	return res;
}

static bool pqs_logger_format_line(char* line, size_t linelen, uint64_t sequence, const uint8_t* previous, pqs_log_level level, pqs_log_event event, const char* user, const char* peer, const char* detail, uint8_t* outhash)
{
	char datetime[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char loguser[PQS_LOGGER_USER_MAX] = { 0 };
	char logpeer[QSC_SYSTEM_MAX_PATH] = { 0 };
	char logdetail[PQS_LOGGER_DETAIL_MAX] = { 0 };
	char prevhex[PQS_LOGGER_HASH_TEXT_SIZE] = { 0 };
	char hashhex[PQS_LOGGER_HASH_TEXT_SIZE] = { 0 };
	uint8_t hash[PQS_LOGGER_HASH_SIZE] = { 0 };
	int32_t slen;
	bool res;

	res = false;

	if (line != NULL && linelen != 0U && previous != NULL && outhash != NULL)
	{
		pqs_logger_copy_field(loguser, sizeof(loguser), user, "none");
		pqs_logger_copy_field(logpeer, sizeof(logpeer), peer, "none");
		pqs_logger_copy_field(logdetail, sizeof(logdetail), detail, "none");
		qsc_timestamp_current_datetime(datetime);

		res = pqs_logger_hash_to_hex(previous, prevhex, sizeof(prevhex));

		if (res == true)
		{
			slen = snprintf(line, linelen, "%s level=%s event=%u name=%s user=%s peer=%s detail=\"%s\" seq=%llu prev=%s",
				datetime,
				pqs_logger_level_to_string(level),
				(uint32_t)event,
				pqs_logger_event_to_string(event),
				loguser,
				logpeer,
				logdetail,
				(unsigned long long)sequence,
				prevhex);

			res = (slen > 0 && (size_t)slen < linelen);
		}

		if (res == true)
		{
			qsc_sha3_compute256(hash, (const uint8_t*)line, qsc_stringutils_string_size(line));
			res = pqs_logger_hash_to_hex(hash, hashhex, sizeof(hashhex));
		}

		if (res == true)
		{
			slen = snprintf(line + qsc_stringutils_string_size(line), linelen - qsc_stringutils_string_size(line), " hash=%s\n", hashhex);
			res = (slen > 0 && qsc_stringutils_string_size(line) < linelen);
		}

		if (res == true)
		{
			qsc_memutils_copy(outhash, hash, PQS_LOGGER_HASH_SIZE);
		}
	}

	return res;
}

static bool pqs_logger_write_internal(pqs_log_level level, pqs_log_event event, const char* user, const char* peer, const char* detail, bool force)
{
	char line[PQS_LOGGER_LINE_MAX] = { 0 };
	uint8_t hash[PQS_LOGGER_HASH_SIZE] = { 0 };
	bool res;

	res = false;

	if (m_pqs_logger_state.initialized == true && level != pqs_log_level_none && (force == true || level <= m_pqs_logger_state.level))
	{
		if (pqs_logger_format_line(line, sizeof(line), m_pqs_logger_state.sequence, m_pqs_logger_state.previous, level, event, user, peer, detail, hash) == true)
		{
			res = qsc_fileutils_append_to_file(m_pqs_logger_state.path, line, qsc_stringutils_string_size(line));

			if (res == true)
			{
				qsc_memutils_copy(m_pqs_logger_state.previous, hash, sizeof(m_pqs_logger_state.previous));
				++m_pqs_logger_state.sequence;
			}
			else
			{
				m_pqs_logger_state.failed = true;
			}
		}
	}

	return res;
}

static const char* pqs_logger_last_hash_field(const char* line)
{
	const char* cur;
	const char* res;

	res = NULL;
	cur = line;

	if (line != NULL)
	{
		while ((cur = strstr(cur, " hash=")) != NULL)
		{
			res = cur;
			cur += 6U;
		}
	}

	return res;
}

static bool pqs_logger_verify_line(const char* line, uint64_t expected, uint8_t* previous, bool* chainstart, uint64_t* nextseq)
{
	char prefix[PQS_LOGGER_LINE_MAX] = { 0 };
	char prevhex[PQS_LOGGER_HASH_TEXT_SIZE] = { 0 };
	char hashhex[PQS_LOGGER_HASH_TEXT_SIZE] = { 0 };
	uint8_t calculated[PQS_LOGGER_HASH_SIZE] = { 0 };
	uint8_t linehash[PQS_LOGGER_HASH_SIZE] = { 0 };
	uint8_t lineprev[PQS_LOGGER_HASH_SIZE] = { 0 };
	uint8_t zero[PQS_LOGGER_HASH_SIZE] = { 0 };
	const char* hpos;
	const char* ppos;
	const char* spos;
	const char* end;
	unsigned long long seqval;
	size_t plen;
	bool res;

	seqval = 0ULL;
	res = false;

	if (line != NULL && previous != NULL && chainstart != NULL && nextseq != NULL)
	{
		hpos = pqs_logger_last_hash_field(line);
		spos = strstr(line, " seq=");
		ppos = strstr(line, " prev=");

		if (hpos != NULL && spos != NULL && ppos != NULL && ppos < hpos)
		{
			plen = (size_t)(hpos - line);

			if (plen < sizeof(prefix))
			{
				qsc_memutils_copy(prefix, line, plen);
				prefix[plen] = '\0';

				#if defined(_MSC_VER)
				if (sscanf_s(spos + 5U, "%llu", &seqval) == 1)
				#else
				if (sscanf(spos + 5U, "%llu", &seqval) == 1)
				#endif
				{
					end = hpos;

					if ((size_t)(end - (ppos + 6U)) == (PQS_LOGGER_HASH_TEXT_SIZE - 1U))
					{
						qsc_memutils_copy(prevhex, ppos + 6U, PQS_LOGGER_HASH_TEXT_SIZE - 1U);
						prevhex[PQS_LOGGER_HASH_TEXT_SIZE - 1U] = '\0';

						qsc_memutils_copy(hashhex, hpos + 6U, PQS_LOGGER_HASH_TEXT_SIZE - 1U);
						hashhex[PQS_LOGGER_HASH_TEXT_SIZE - 1U] = '\0';

						if (pqs_logger_hex_to_hash(prevhex, lineprev) == true && pqs_logger_hex_to_hash(hashhex, linehash) == true)
						{
							qsc_sha3_compute256(calculated, (const uint8_t*)prefix, qsc_stringutils_string_size(prefix));
							res = (qsc_memutils_are_equal(calculated, linehash, PQS_LOGGER_HASH_SIZE) == true);
						}
					}
				}
			}
		}

		if (res == true && strstr(line, " name=audit_chain_start ") != NULL)
		{
			res = (seqval == 0ULL);
			res = res && (qsc_memutils_are_equal(lineprev, zero, PQS_LOGGER_HASH_SIZE) == true);
			*chainstart = true;
			*nextseq = 1U;
		}
		else if (res == true)
		{
			res = (*chainstart == true);
			res = res && (seqval == (unsigned long long)expected);
			res = res && (qsc_memutils_are_equal(lineprev, previous, PQS_LOGGER_HASH_SIZE) == true);
			*nextseq = expected + 1U;
		}

		if (res == true)
		{
			qsc_memutils_copy(previous, linehash, PQS_LOGGER_HASH_SIZE);
		}
	}

	return res;
}

void pqs_logger_dispose(void)
{
	if (m_pqs_logger_state.mutex != NULL)
	{
		qsc_async_mutex_destroy(m_pqs_logger_state.mutex);
	}

	qsc_memutils_clear((uint8_t*)&m_pqs_logger_state, sizeof(m_pqs_logger_state));
}

bool pqs_logger_initialize(const char* path, pqs_log_level level)
{
	PQS_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL && path[0U] != '\0' && level != pqs_log_level_none)
	{
		pqs_logger_dispose();
		qsc_stringutils_copy_string(m_pqs_logger_state.path, sizeof(m_pqs_logger_state.path), path);
		m_pqs_logger_state.mutex = qsc_async_mutex_create();
		m_pqs_logger_state.level = level;
		m_pqs_logger_state.sequence = 0U;
		m_pqs_logger_state.failed = false;
		m_pqs_logger_state.initialized = (m_pqs_logger_state.mutex != NULL);
		res = m_pqs_logger_state.initialized;

		if (res == true)
		{
			qsc_async_mutex_lock(m_pqs_logger_state.mutex);
			res = pqs_logger_write_internal(pqs_log_level_audit, pqs_log_event_audit_chain_start, "system", "local", "chain initialized", true);
			qsc_async_mutex_unlock(m_pqs_logger_state.mutex);
			m_pqs_logger_state.initialized = res;

			if (res == false)
			{
				pqs_logger_dispose();
			}
		}
	}

	return res;
}

bool pqs_logger_is_initialized(void)
{
	return m_pqs_logger_state.initialized;
}

bool pqs_logger_failure_occurred(void)
{
	return m_pqs_logger_state.failed;
}

bool pqs_logger_verify_chain(const char* path, uint64_t* records)
{
	char line[PQS_LOGGER_LINE_MAX] = { 0 };
	uint8_t previous[PQS_LOGGER_HASH_SIZE] = { 0 };
	FILE* fp;
	uint64_t count;
	uint64_t nextseq;
	bool chainstart;
	bool res;

	count = 0U;
	nextseq = 0U;
	chainstart = false;
	fp = NULL;
	res = false;

	if (records != NULL)
	{
		*records = 0U;
	}

	if (path != NULL && path[0U] != '\0')
	{
#if defined(_MSC_VER)
		if (fopen_s(&fp, path, "rb") != 0)
		{
			fp = NULL;
		}
#else
		fp = fopen(path, "rb");
#endif

		if (fp != NULL)
		{
			res = true;

			while (fgets(line, sizeof(line), fp) != NULL)
			{
				if (strchr(line, '\n') == NULL)
				{
					res = false;
				}

				if (res == true)
				{
					res = pqs_logger_verify_line(line, nextseq, previous, &chainstart, &nextseq);
				}

				if (res == false)
				{
					break;
				}

				++count;
			}

			if (ferror(fp) != 0)
			{
				res = false;
			}

			(void)fclose(fp);

			res = res && chainstart;
		}
	}

	if (records != NULL && res == true)
	{
		*records = count;
	}

	return res;
}

bool pqs_logger_write(pqs_log_level level, pqs_log_event event, const char* user, const char* peer, const char* detail)
{
	bool res;

	res = false;

	if (m_pqs_logger_state.initialized == true && level <= m_pqs_logger_state.level && level != pqs_log_level_none)
	{
		qsc_async_mutex_lock(m_pqs_logger_state.mutex);
		res = pqs_logger_write_internal(level, event, user, peer, detail, false);
		qsc_async_mutex_unlock(m_pqs_logger_state.mutex);
	}

	return res;
}

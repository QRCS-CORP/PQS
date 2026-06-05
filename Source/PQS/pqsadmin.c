#include "pqsadmin.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <string.h>

#define PQS_ADMIN_VERSION_STRING "1.1.0.0a"

static bool pqs_admin_append(char* output, size_t outlen, const char* text)
{
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && text != NULL)
	{
		if ((qsc_stringutils_string_size(output) + qsc_stringutils_string_size(text)) < outlen)
		{
			qsc_stringutils_concat_strings(output, outlen, text);
			res = true;
		}
	}

	return res;
}

static bool pqs_admin_append_line(char* output, size_t outlen, const char* key, const char* value)
{
	char line[256] = { 0 };
	bool res;

	res = false;

	if (key != NULL && value != NULL)
	{
		if (snprintf(line, sizeof(line), "%s=%s\n", key, value) > 0)
		{
			res = pqs_admin_append(output, outlen, line);
		}
	}

	return res;
}

static bool pqs_admin_append_u32(char* output, size_t outlen, const char* key, uint32_t value)
{
	char line[128] = { 0 };
	bool res;

	res = false;

	if (key != NULL)
	{
		if (snprintf(line, sizeof(line), "%s=%u\n", key, value) > 0)
		{
			res = pqs_admin_append(output, outlen, line);
		}
	}

	return res;
}

static bool pqs_admin_append_size(char* output, size_t outlen, const char* key, size_t value)
{
	char line[128] = { 0 };
	bool res;

	res = false;

	if (key != NULL)
	{
		if (snprintf(line, sizeof(line), "%s=%zu\n", key, value) > 0)
		{
			res = pqs_admin_append(output, outlen, line);
		}
	}

	return res;
}

static bool pqs_admin_output_status(const pqs_admin_context* context, char* output, size_t outlen)
{
	bool res;

	res = pqs_admin_append(output, outlen, "PQS_ADMIN_STATUS\n");
	res = res && pqs_admin_append_line(output, outlen, "user", (context->user != NULL) ? context->user : "anonymous");
	res = res && pqs_admin_append_line(output, outlen, "peer", (context->peer != NULL) ? context->peer : "none");
	res = res && pqs_admin_append_line(output, outlen, "privilege", pqs_user_privilege_to_string(context->privilege));
	res = res && pqs_admin_append_line(output, outlen, "authenticated", (context->authenticated == true) ? "true" : "false");
	res = res && pqs_admin_append_line(output, outlen, "audit_logger_failed", (context->logger_failed == true) ? "true" : "false");

	return res;
}

static bool pqs_admin_output_version(char* output, size_t outlen)
{
	bool res;

	res = pqs_admin_append(output, outlen, "PQS_ADMIN_VERSION\n");
	res = res && pqs_admin_append_line(output, outlen, "version", PQS_ADMIN_VERSION_STRING);

	return res;
}

static bool pqs_admin_output_fingerprint(const pqs_admin_context* context, char* output, size_t outlen)
{
	char fp[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	bool res;

	res = false;

	if (context != NULL && context->public_key != NULL)
	{
		res = pqs_key_fingerprint_string(fp, sizeof(fp), context->public_key);
	}

	if (res == true)
	{
		res = pqs_admin_append(output, outlen, "PQS_ADMIN_FINGERPRINT\n");
		res = res && pqs_admin_append_line(output, outlen, "sha3_256", fp);
	}
	else
	{
		res = pqs_admin_append(output, outlen, "PQS_ADMIN_FINGERPRINT\nsha3_256=unavailable\n");
	}

	return res;
}

static bool pqs_admin_output_sandbox(const pqs_admin_context* context, char* output, size_t outlen)
{
	const pqs_sandbox_profile* sandbox;
	bool res;

	sandbox = context->sandbox;
	res = pqs_admin_append(output, outlen, "PQS_ADMIN_SANDBOX\n");

	if (sandbox != NULL)
	{
		res = res && pqs_admin_append_line(output, outlen, "enabled", (sandbox->enabled == true) ? "true" : "false");
		res = res && pqs_admin_append_line(output, outlen, "clear_environment", (sandbox->clear_environment == true) ? "true" : "false");
		res = res && pqs_admin_append_line(output, outlen, "allow_same_user", (sandbox->allow_same_user == true) ? "true" : "false");
		res = res && pqs_admin_append_line(output, outlen, "working_directory", sandbox->working_directory);
		res = res && pqs_admin_append_u32(output, outlen, "timeout_seconds", sandbox->command_timeout_seconds);
		res = res && pqs_admin_append_u32(output, outlen, "output_max_bytes", sandbox->max_output_bytes);
	}
	else
	{
		res = res && pqs_admin_append_line(output, outlen, "enabled", "false");
	}

	return res;
}

static bool pqs_admin_output_audit_verify(const pqs_admin_context* context, char* output, size_t outlen)
{
	uint64_t records;
	bool verified;
	bool res;

	records = 0U;
	verified = false;
	res = pqs_admin_append(output, outlen, "PQS_ADMIN_AUDIT_VERIFY\n");

	if (context != NULL && context->config != NULL && context->config->log_path[0U] != '\0')
	{
		verified = pqs_logger_verify_chain(context->config->log_path, &records);
	}

	res = res && pqs_admin_append_line(output, outlen, "verified", (verified == true) ? "true" : "false");
	res = res && pqs_admin_append_size(output, outlen, "records", (size_t)records);

	return res;
}

static bool pqs_admin_output_config(const pqs_admin_context* context, char* output, size_t outlen)
{
	const pqs_server_config* cfg;
	bool res;

	cfg = context->config;
	res = pqs_admin_append(output, outlen, "PQS_ADMIN_CONFIG\n");

	if (cfg != NULL)
	{
		res = res && pqs_admin_append_line(output, outlen, "listen_address", cfg->listen_address);
		res = res && pqs_admin_append_u32(output, outlen, "listen_port", cfg->listen_port);
		res = res && pqs_admin_append_u32(output, outlen, "max_sessions", 1U);
		res = res && pqs_admin_append_line(output, outlen, "session_model", "single-session");
		res = res && pqs_admin_append_u32(output, outlen, "max_login_attempts", cfg->max_login_attempts);
		res = res && pqs_admin_append_u32(output, outlen, "login_timeout_seconds", cfg->login_timeout_seconds);
		res = res && pqs_admin_append_u32(output, outlen, "idle_timeout_seconds", cfg->idle_timeout_seconds);
		res = res && pqs_admin_append_u32(output, outlen, "command_timeout_seconds", cfg->command_timeout_seconds);
		res = res && pqs_admin_append_u32(output, outlen, "command_output_max_bytes", cfg->command_output_max_bytes);
		res = res && pqs_admin_append_line(output, outlen, "sandbox_enabled", (cfg->sandbox_enabled == true) ? "true" : "false");
	}

	return res;
}

static bool pqs_admin_output_users(const pqs_admin_context* context, char* output, size_t outlen)
{
	char line[192] = { 0 };
	size_t pos;
	bool res;

	res = pqs_admin_append(output, outlen, "PQS_ADMIN_USERS\n");

	if (context->users != NULL)
	{
		res = res && pqs_admin_append_size(output, outlen, "count", context->users->count);

		for (pos = 0U; pos < context->users->count && res == true; ++pos)
		{
			if (snprintf(line, sizeof(line), "user=%s privilege=%s enabled=%s failed=%u\n",
				context->users->records[pos].username,
				pqs_user_privilege_to_string(context->users->records[pos].privilege),
				(context->users->records[pos].enabled == true) ? "true" : "false",
				context->users->records[pos].failures) > 0)
			{
				res = pqs_admin_append(output, outlen, line);
			}
		}
	}

	return res;
}

static bool pqs_admin_output_policies(const pqs_admin_context* context, char* output, size_t outlen)
{
	char line[192] = { 0 };
	size_t pos;
	bool res;

	res = pqs_admin_append(output, outlen, "PQS_ADMIN_POLICIES\n");

	if (context->policies != NULL)
	{
		res = res && pqs_admin_append_size(output, outlen, "count", context->policies->count);

		for (pos = 0U; pos < context->policies->count && res == true; ++pos)
		{
			if (snprintf(line, sizeof(line), "policy=%s mode=%s enabled=%s\n",
				context->policies->records[pos].name,
				pqs_policy_mode_to_string(context->policies->records[pos].mode),
				(context->policies->records[pos].enabled == true) ? "true" : "false") > 0)
			{
				res = pqs_admin_append(output, outlen, line);
			}
		}
	}

	return res;
}

static bool pqs_admin_output_shells(const pqs_admin_context* context, char* output, size_t outlen)
{
	char line[256] = { 0 };
	size_t pos;
	bool res;

	res = pqs_admin_append(output, outlen, "PQS_ADMIN_SHELLS\n");

	if (context->shells != NULL)
	{
		res = res && pqs_admin_append_size(output, outlen, "count", context->shells->count);

		for (pos = 0U; pos < context->shells->count && res == true; ++pos)
		{
			if (snprintf(line, sizeof(line), "shell=%s type=%s default=%s enabled=%s\n",
				context->shells->profiles[pos].name,
				context->shells->profiles[pos].type,
				(context->shells->profiles[pos].isdefault == true) ? "true" : "false",
				(context->shells->profiles[pos].enabled == true) ? "true" : "false") > 0)
			{
				res = pqs_admin_append(output, outlen, line);
			}
		}
	}

	return res;
}

bool pqs_admin_authorize(const pqs_admin_context* context, const pqs_admin_request* request)
{
	const pqs_policy_record* matched;
	bool res;

	matched = NULL;
	res = false;

	if (context != NULL && request != NULL && request->command != pqs_admin_command_none &&
		context->privilege == pqs_user_privilege_admin && context->policies != NULL)
	{
		res = pqs_policy_store_authorize(context->policies, context->privilege, pqs_admin_policy_verb(request->command), &matched);
	}

	return res;
}

bool pqs_admin_execute(const pqs_admin_context* context, const pqs_admin_request* request, char* output, size_t outlen)
{
	bool res;

	res = false;

	if (context != NULL && request != NULL && output != NULL && outlen > 1U)
	{
		qsc_memutils_clear((uint8_t*)output, outlen);

		switch (request->command)
		{
			case pqs_admin_command_server_status:
				res = pqs_admin_output_status(context, output, outlen);
				break;
			case pqs_admin_command_server_version:
				res = pqs_admin_output_version(output, outlen);
				break;
			case pqs_admin_command_server_fingerprint:
				res = pqs_admin_output_fingerprint(context, output, outlen);
				break;
			case pqs_admin_command_sandbox_status:
				res = pqs_admin_output_sandbox(context, output, outlen);
				break;
			case pqs_admin_command_audit_verify:
				res = pqs_admin_output_audit_verify(context, output, outlen);
				break;
			case pqs_admin_command_config_summary:
				res = pqs_admin_output_config(context, output, outlen);
				break;
			case pqs_admin_command_user_list:
				res = pqs_admin_output_users(context, output, outlen);
				break;
			case pqs_admin_command_policy_list:
				res = pqs_admin_output_policies(context, output, outlen);
				break;
			case pqs_admin_command_shell_list:
				res = pqs_admin_output_shells(context, output, outlen);
				break;
			default:
				break;
		}
	}

	return res;
}

bool pqs_admin_request_parse(pqs_admin_request* request, const char* command)
{
	char tmp[PQS_ADMIN_ARGUMENT_MAX] = { 0 };
	size_t slen;
	bool res;

	res = false;

	if (request != NULL && command != NULL)
	{
		qsc_memutils_clear((uint8_t*)request, sizeof(pqs_admin_request));
		slen = qsc_stringutils_string_size(command);

		if (slen > 0U && slen < sizeof(tmp))
		{
			qsc_stringutils_copy_string(tmp, sizeof(tmp), command);

			if (qsc_stringutils_strings_equal(tmp, "status") == true || qsc_stringutils_strings_equal(tmp, "server status") == true)
			{
				request->command = pqs_admin_command_server_status;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "version") == true || qsc_stringutils_strings_equal(tmp, "server version") == true)
			{
				request->command = pqs_admin_command_server_version;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "fingerprint") == true || qsc_stringutils_strings_equal(tmp, "server fingerprint") == true)
			{
				request->command = pqs_admin_command_server_fingerprint;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "sandbox") == true || qsc_stringutils_strings_equal(tmp, "sandbox status") == true)
			{
				request->command = pqs_admin_command_sandbox_status;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "audit verify") == true || qsc_stringutils_strings_equal(tmp, "audit chain verify") == true)
			{
				request->command = pqs_admin_command_audit_verify;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "config") == true || qsc_stringutils_strings_equal(tmp, "config summary") == true)
			{
				request->command = pqs_admin_command_config_summary;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "users") == true || qsc_stringutils_strings_equal(tmp, "user list") == true)
			{
				request->command = pqs_admin_command_user_list;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "policies") == true || qsc_stringutils_strings_equal(tmp, "policy list") == true)
			{
				request->command = pqs_admin_command_policy_list;
				res = true;
			}
			else if (qsc_stringutils_strings_equal(tmp, "shells") == true || qsc_stringutils_strings_equal(tmp, "shell list") == true)
			{
				request->command = pqs_admin_command_shell_list;
				res = true;
			}

			if (res == true)
			{
				qsc_stringutils_copy_string(request->arguments, sizeof(request->arguments), tmp);
			}
		}
	}

	return res;
}

const char* pqs_admin_command_to_string(pqs_admin_command_ids command)
{
	const char* res;

	res = "none";

	switch (command)
	{
		case pqs_admin_command_server_status:
			res = "server_status";
			break;
		case pqs_admin_command_server_version:
			res = "server_version";
			break;
		case pqs_admin_command_server_fingerprint:
			res = "server_fingerprint";
			break;
		case pqs_admin_command_sandbox_status:
			res = "sandbox_status";
			break;
		case pqs_admin_command_audit_verify:
			res = "audit_verify";
			break;
		case pqs_admin_command_config_summary:
			res = "config_summary";
			break;
		case pqs_admin_command_user_list:
			res = "user_list";
			break;
		case pqs_admin_command_policy_list:
			res = "policy_list";
			break;
		case pqs_admin_command_shell_list:
			res = "shell_list";
			break;
		default:
			break;
	}

	return res;
}

const char* pqs_admin_policy_verb(pqs_admin_command_ids command)
{
	const char* res;

	res = "admin.none";

	switch (command)
	{
		case pqs_admin_command_server_status:
			res = "admin.status";
			break;
		case pqs_admin_command_server_version:
			res = "admin.version";
			break;
		case pqs_admin_command_server_fingerprint:
			res = "admin.fingerprint";
			break;
		case pqs_admin_command_sandbox_status:
			res = "admin.sandbox";
			break;
		case pqs_admin_command_audit_verify:
			res = "admin.audit.verify";
			break;
		case pqs_admin_command_config_summary:
			res = "admin.config";
			break;
		case pqs_admin_command_user_list:
			res = "admin.users";
			break;
		case pqs_admin_command_policy_list:
			res = "admin.policies";
			break;
		case pqs_admin_command_shell_list:
			res = "admin.shells";
			break;
		default:
			break;
	}

	return res;
}

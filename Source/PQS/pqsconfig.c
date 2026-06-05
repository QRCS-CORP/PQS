#include "pqsconfig.h"
#include "pqssandbox.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void pqs_config_trim(char* str)
{
	size_t len;
	size_t pos;

	if (str != NULL)
	{
		len = qsc_stringutils_string_size(str);

		while (len > 0U && (str[len - 1U] == '\n' || str[len - 1U] == '\r' || str[len - 1U] == ' ' || str[len - 1U] == '\t'))
		{
			str[len - 1U] = '\0';
			--len;
		}

		pos = 0U;

		while (str[pos] == ' ' || str[pos] == '\t')
		{
			++pos;
		}

		if (pos > 0U)
		{
			memmove(str, str + pos, len - pos + 1U);
		}
	}
}

static bool pqs_config_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, "PQS");
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static void pqs_config_make_path(char* output, size_t outlen, const char* directory, const char* name)
{
	qsc_memutils_clear(output, outlen);
	qsc_stringutils_copy_string(output, outlen, directory);
	qsc_folderutils_append_delimiter(output);
	qsc_stringutils_concat_strings(output, outlen, name);
}

static pqs_log_level pqs_config_log_level_from_string(const char* str)
{
	pqs_log_level level;

	level = pqs_log_level_audit;

	if (str != NULL)
	{
		if (qsc_stringutils_string_compare(str, "none", 4U) == true)
		{
			level = pqs_log_level_none;
		}
		else if (qsc_stringutils_string_compare(str, "error", 5U) == true)
		{
			level = pqs_log_level_error;
		}
		else if (qsc_stringutils_string_compare(str, "warning", 7U) == true || qsc_stringutils_string_compare(str, "warn", 4U) == true)
		{
			level = pqs_log_level_warning;
		}
		else if (qsc_stringutils_string_compare(str, "info", 4U) == true)
		{
			level = pqs_log_level_info;
		}
		else if (qsc_stringutils_string_compare(str, "debug", 5U) == true)
		{
			level = pqs_log_level_debug;
		}
	}

	return level;
}

static bool pqs_config_parse_bool(const char* str)
{
	bool res;

	res = false;

	if (str != NULL)
	{
		if (qsc_stringutils_string_compare(str, "true", 4U) == true ||
			qsc_stringutils_string_compare(str, "yes", 3U) == true ||
			qsc_stringutils_string_compare(str, "1", 1U) == true ||
			qsc_stringutils_string_compare(str, "on", 2U) == true)
		{
			res = true;
		}
	}

	return res;
}

static uint32_t pqs_config_parse_u32(const char* str, uint32_t defval)
{
	unsigned long val;
	uint32_t res;

	res = defval;

	if (str != NULL && str[0] != '\0')
	{
		val = strtoul(str, NULL, 10);

		if (val <= 0xFFFFFFFFUL)
		{
			res = (uint32_t)val;
		}
	}

	return res;
}

static uint16_t pqs_config_parse_port(const char* str, uint16_t defval)
{
	unsigned long val;
	uint16_t res;

	res = defval;

	if (str != NULL && str[0] != '\0')
	{
		val = strtoul(str, NULL, 10);

		if (val > 0UL && val <= 65535UL)
		{
			res = (uint16_t)val;
		}
	}

	return res;
}

static bool pqs_config_write_server_template(const char* fpath, const pqs_server_config* cfg)
{
	char line[PQS_CONFIG_LINE_MAX] = { 0 };
	FILE* fp;
	bool res;

	res = false;
	fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_write, false);

	if (fp != NULL)
	{
		qsc_fileutils_write("# PQS server configuration\n", 27U, 0U, fp);
		snprintf(line, sizeof(line), "application-path=%s\n", cfg->application_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "private-key=%s\n", cfg->private_key_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "public-key=%s\n", cfg->public_key_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "user-database=%s\n", cfg->user_database_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "shell-database=%s\n", cfg->shell_database_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "policy-database=%s\n", cfg->policy_database_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "log-file=%s\n", cfg->log_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "log-level=%s\n", pqs_config_log_level_to_string(cfg->log_level));
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "listen-address=%s\n", cfg->listen_address);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "listen-port=%u\n", cfg->listen_port);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "max-sessions=1\n");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "max-login-attempts=%u\n", cfg->max_login_attempts);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "login-timeout-seconds=%u\n", cfg->login_timeout_seconds);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "idle-timeout-seconds=%u\n", cfg->idle_timeout_seconds);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "command-timeout-seconds=%u\n", cfg->command_timeout_seconds);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "command-output-max-bytes=%u\n", cfg->command_output_max_bytes);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-enabled=%s\n", cfg->sandbox_enabled == true ? "true" : "false");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-clear-environment=%s\n", cfg->sandbox_clear_environment == true ? "true" : "false");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-working-directory=%s\n", cfg->sandbox_working_directory);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-run-as-user=%s\n", cfg->sandbox_run_as_user);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-run-as-group=%s\n", cfg->sandbox_run_as_group);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-chroot-enabled=%s\n", cfg->sandbox_chroot_enabled == true ? "true" : "false");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "sandbox-allow-same-user=%s\n", cfg->sandbox_allow_same_user == true ? "true" : "false");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		qsc_fileutils_close(fp);
		res = true;
	}

	return res;
}

static bool pqs_config_write_client_template(const char* fpath, const pqs_client_config* cfg)
{
	char line[PQS_CONFIG_LINE_MAX] = { 0 };
	FILE* fp;
	bool res;

	res = false;
	fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_write, false);

	if (fp != NULL)
	{
		qsc_fileutils_write("# PQS client configuration\n", 27U, 0U, fp);
		snprintf(line, sizeof(line), "application-path=%s\n", cfg->application_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "server-public-key=%s\n", cfg->server_public_key_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "known-hosts=%s\n", cfg->known_hosts_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "log-file=%s\n", cfg->log_path);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "log-level=%s\n", pqs_config_log_level_to_string(cfg->log_level));
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "host=%s\n", cfg->host);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "port=%u\n", cfg->port);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "username=%s\n", cfg->username);
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		snprintf(line, sizeof(line), "strict-host-checking=%s\n", cfg->strict_host_checking == true ? "true" : "false");
		qsc_fileutils_write(line, qsc_stringutils_string_size(line), qsc_fileutils_get_size(fpath), fp);
		qsc_fileutils_close(fp);
		res = true;
	}

	return res;
}

static bool pqs_config_server_apply(pqs_server_config* cfg, const char* key, const char* value)
{
	bool res;

	res = true;

	if (qsc_stringutils_string_compare(key, "application-path", 16U) == true)
	{
		qsc_stringutils_copy_string(cfg->application_path, sizeof(cfg->application_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "private-key", 11U) == true)
	{
		qsc_stringutils_copy_string(cfg->private_key_path, sizeof(cfg->private_key_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "public-key", 10U) == true)
	{
		qsc_stringutils_copy_string(cfg->public_key_path, sizeof(cfg->public_key_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "user-database", 13U) == true)
	{
		qsc_stringutils_copy_string(cfg->user_database_path, sizeof(cfg->user_database_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "shell-database", 14U) == true)
	{
		qsc_stringutils_copy_string(cfg->shell_database_path, sizeof(cfg->shell_database_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "policy-database", 15U) == true)
	{
		qsc_stringutils_copy_string(cfg->policy_database_path, sizeof(cfg->policy_database_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "log-file", 8U) == true)
	{
		qsc_stringutils_copy_string(cfg->log_path, sizeof(cfg->log_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "log-level", 9U) == true)
	{
		cfg->log_level = pqs_config_log_level_from_string(value);
	}
	else if (qsc_stringutils_string_compare(key, "listen-address", 14U) == true)
	{
		qsc_stringutils_copy_string(cfg->listen_address, sizeof(cfg->listen_address), value);
	}
	else if (qsc_stringutils_string_compare(key, "listen-port", 11U) == true)
	{
		cfg->listen_port = pqs_config_parse_port(value, cfg->listen_port);
	}
	else if (qsc_stringutils_string_compare(key, "max-sessions", 12U) == true)
	{
		(void)value;
		cfg->max_sessions = 1U;
	}
	else if (qsc_stringutils_string_compare(key, "max-login-attempts", 18U) == true)
	{
		cfg->max_login_attempts = pqs_config_parse_u32(value, cfg->max_login_attempts);
	}
	else if (qsc_stringutils_string_compare(key, "login-timeout-seconds", 21U) == true)
	{
		cfg->login_timeout_seconds = pqs_config_parse_u32(value, cfg->login_timeout_seconds);
	}
	else if (qsc_stringutils_string_compare(key, "idle-timeout-seconds", 20U) == true)
	{
		cfg->idle_timeout_seconds = pqs_config_parse_u32(value, cfg->idle_timeout_seconds);
	}
	else if (qsc_stringutils_string_compare(key, "command-timeout-seconds", 23U) == true)
	{
		cfg->command_timeout_seconds = pqs_config_parse_u32(value, cfg->command_timeout_seconds);
	}
	else if (qsc_stringutils_string_compare(key, "command-output-max-bytes", 24U) == true)
	{
		cfg->command_output_max_bytes = pqs_config_parse_u32(value, cfg->command_output_max_bytes);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-enabled", 15U) == true)
	{
		cfg->sandbox_enabled = pqs_config_parse_bool(value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-clear-environment", 25U) == true)
	{
		cfg->sandbox_clear_environment = pqs_config_parse_bool(value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-working-directory", 25U) == true)
	{
		qsc_stringutils_copy_string(cfg->sandbox_working_directory, sizeof(cfg->sandbox_working_directory), value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-run-as-user", 19U) == true)
	{
		qsc_stringutils_copy_string(cfg->sandbox_run_as_user, sizeof(cfg->sandbox_run_as_user), value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-run-as-group", 20U) == true)
	{
		qsc_stringutils_copy_string(cfg->sandbox_run_as_group, sizeof(cfg->sandbox_run_as_group), value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-chroot-enabled", 22U) == true)
	{
		cfg->sandbox_chroot_enabled = pqs_config_parse_bool(value);
	}
	else if (qsc_stringutils_string_compare(key, "sandbox-allow-same-user", 23U) == true)
	{
		cfg->sandbox_allow_same_user = pqs_config_parse_bool(value);
	}
	else
	{
		res = false;
	}

	return res;
}

static bool pqs_config_client_apply(pqs_client_config* cfg, const char* key, const char* value)
{
	bool res;

	res = true;

	if (qsc_stringutils_string_compare(key, "application-path", 16U) == true)
	{
		qsc_stringutils_copy_string(cfg->application_path, sizeof(cfg->application_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "server-public-key", 17U) == true)
	{
		qsc_stringutils_copy_string(cfg->server_public_key_path, sizeof(cfg->server_public_key_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "known-hosts", 11U) == true)
	{
		qsc_stringutils_copy_string(cfg->known_hosts_path, sizeof(cfg->known_hosts_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "log-file", 8U) == true)
	{
		qsc_stringutils_copy_string(cfg->log_path, sizeof(cfg->log_path), value);
	}
	else if (qsc_stringutils_string_compare(key, "log-level", 9U) == true)
	{
		cfg->log_level = pqs_config_log_level_from_string(value);
	}
	else if (qsc_stringutils_string_compare(key, "host", 4U) == true)
	{
		qsc_stringutils_copy_string(cfg->host, sizeof(cfg->host), value);
	}
	else if (qsc_stringutils_string_compare(key, "port", 4U) == true)
	{
		cfg->port = pqs_config_parse_port(value, cfg->port);
	}
	else if (qsc_stringutils_string_compare(key, "username", 8U) == true)
	{
		qsc_stringutils_copy_string(cfg->username, sizeof(cfg->username), value);
	}
	else if (qsc_stringutils_string_compare(key, "strict-host-checking", 20U) == true)
	{
		cfg->strict_host_checking = pqs_config_parse_bool(value);
	}
	else
	{
		res = false;
	}

	return res;
}

static bool pqs_config_load_file(const char* fpath, bool server, void* cfg)
{
	char line[PQS_CONFIG_LINE_MAX] = { 0 };
	char key[PQS_CONFIG_KEY_MAX] = { 0 };
	char value[PQS_CONFIG_VALUE_MAX] = { 0 };
	char* eq;
	size_t lnum;
	int64_t rlen;
	bool res;

	res = true;
	lnum = 0U;

	while (res == true)
	{
		rlen = qsc_fileutils_read_line(fpath, line, sizeof(line), lnum);

		if (rlen <= 0)
		{
			break;
		}

		pqs_config_trim(line);

		if (line[0] != '\0' && line[0] != '#')
		{
			eq = strchr(line, '=');

			if (eq != NULL)
			{
				*eq = '\0';
				qsc_memutils_clear(key, sizeof(key));
				qsc_memutils_clear(value, sizeof(value));
				qsc_stringutils_copy_string(key, sizeof(key), line);
				qsc_stringutils_copy_string(value, sizeof(value), eq + 1);
				pqs_config_trim(key);
				pqs_config_trim(value);

				if (server == true)
				{
					res = pqs_config_server_apply((pqs_server_config*)cfg, key, value);
				}
				else
				{
					res = pqs_config_client_apply((pqs_client_config*)cfg, key, value);
				}
			}
		}

		++lnum;
	}

	return res;
}

const char* pqs_config_log_level_to_string(pqs_log_level level)
{
	const char* res;

	res = "audit";

	switch (level)
	{
		case pqs_log_level_none:
		{
			res = "none";
			break;
		}
		case pqs_log_level_error:
		{
			res = "error";
			break;
		}
		case pqs_log_level_warning:
		{
			res = "warning";
			break;
		}
		case pqs_log_level_info:
		{
			res = "info";
			break;
		}
		case pqs_log_level_debug:
		{
			res = "debug";
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

void pqs_config_server_defaults(pqs_server_config* cfg)
{
	PQS_ASSERT(cfg != NULL);

	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };

	if (cfg != NULL)
	{
		qsc_memutils_clear(cfg, sizeof(pqs_server_config));
		pqs_config_get_storage_path(dir, sizeof(dir));
		qsc_stringutils_copy_string(cfg->application_path, sizeof(cfg->application_path), dir);
		pqs_config_make_path(cfg->private_key_path, sizeof(cfg->private_key_path), dir, "server_secret_key.pqskey");
		pqs_config_make_path(cfg->public_key_path, sizeof(cfg->public_key_path), dir, "server_public_key.pqpkey");
		pqs_config_make_path(cfg->user_database_path, sizeof(cfg->user_database_path), dir, "pqs_users.db");
		pqs_config_make_path(cfg->shell_database_path, sizeof(cfg->shell_database_path), dir, "pqs_shells.db");
		pqs_config_make_path(cfg->policy_database_path, sizeof(cfg->policy_database_path), dir, "pqs_policy.db");
		pqs_config_make_path(cfg->log_path, sizeof(cfg->log_path), dir, "pqs_server.log");
		qsc_stringutils_copy_string(cfg->sandbox_working_directory, sizeof(cfg->sandbox_working_directory), dir);
		qsc_stringutils_copy_string(cfg->sandbox_run_as_user, sizeof(cfg->sandbox_run_as_user), "");
		qsc_stringutils_copy_string(cfg->sandbox_run_as_group, sizeof(cfg->sandbox_run_as_group), "");
		qsc_stringutils_copy_string(cfg->listen_address, sizeof(cfg->listen_address), "127.0.0.1");

		cfg->listen_port = QSMS_SERVER_PORT;
		cfg->max_sessions = 1U;
		cfg->max_login_attempts = 3U;
		cfg->login_timeout_seconds = 30U;
		cfg->idle_timeout_seconds = 600U;
		cfg->command_timeout_seconds = 120U;
		cfg->command_output_max_bytes = PQS_SANDBOX_DEFAULT_OUTPUT_BYTES;
		cfg->sandbox_enabled = true;
		cfg->sandbox_clear_environment = true;
		cfg->sandbox_chroot_enabled = false;
		cfg->sandbox_allow_same_user = false;
		cfg->log_level = pqs_log_level_audit;
	}
}

void pqs_config_client_defaults(pqs_client_config* cfg)
{
	PQS_ASSERT(cfg != NULL);

	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };

	if (cfg != NULL)
	{
		qsc_memutils_clear(cfg, sizeof(pqs_client_config));
		pqs_config_get_storage_path(dir, sizeof(dir));
		qsc_stringutils_copy_string(cfg->application_path, sizeof(cfg->application_path), dir);
		pqs_config_make_path(cfg->server_public_key_path, sizeof(cfg->server_public_key_path), dir, "server_public_key.pqpkey");
		pqs_config_make_path(cfg->known_hosts_path, sizeof(cfg->known_hosts_path), dir, "pqs_known_hosts.db");
		pqs_config_make_path(cfg->log_path, sizeof(cfg->log_path), dir, "pqs_client.log");
		qsc_stringutils_copy_string(cfg->host, sizeof(cfg->host), "");
		qsc_stringutils_copy_string(cfg->username, sizeof(cfg->username), "");

		cfg->port = QSMS_SERVER_PORT;
		cfg->strict_host_checking = false;
		cfg->log_level = pqs_log_level_audit;
	}
}

bool pqs_config_server_load(pqs_server_config* cfg, const char* fpath)
{
	PQS_ASSERT(cfg != NULL);
	PQS_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (cfg != NULL && fpath != NULL)
	{
		pqs_config_server_defaults(cfg);

		if (qsc_fileutils_exists(fpath) == false)
		{
			res = pqs_config_write_server_template(fpath, cfg);
		}
		else
		{
			res = pqs_config_load_file(fpath, true, cfg);
		}
	}

	return res;
}

bool pqs_config_client_load(pqs_client_config* cfg, const char* fpath)
{
	PQS_ASSERT(cfg != NULL);
	PQS_ASSERT(fpath != NULL);

	bool res;

	res = false;

	if (cfg != NULL && fpath != NULL)
	{
		pqs_config_client_defaults(cfg);

		if (qsc_fileutils_exists(fpath) == false)
		{
			res = pqs_config_write_client_template(fpath, cfg);
		}
		else
		{
			res = pqs_config_load_file(fpath, false, cfg);
		}
	}

	return res;
}

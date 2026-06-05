#include "pqs_test.h"
#include "pqs.h"
#include "pqsadmin.h"
#include "pqscommon.h"
#include "pqsconfig.h"
#include "pqskey.h"
#include "pqslogger.h"
#include "pqspolicy.h"
#include "pqssandbox.h"
#include "pqsshell.h"
#include "pqsuser.h"
#include "pqsxfer.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#if !defined(QSC_SYSTEM_OS_WINDOWS)
#	include <sys/stat.h>
#endif

#define PQS_TEST_USER_DB "pqs_test_users.db"
#define PQS_TEST_SHELL_DB "pqs_test_shells.db"
#define PQS_TEST_POLICY_DB "pqs_test_policy.db"
#define PQS_TEST_KNOWN_HOSTS_DB "pqs_test_known_hosts.db"
#define PQS_TEST_SERVER_CONFIG "pqs_test_pqsd.conf"
#define PQS_TEST_CLIENT_CONFIG "pqs_test_pqs.conf"
#define PQS_TEST_XFER_FILE "pqs_test_xfer_file.bin"
#define PQS_TEST_LOG_FILE "pqs_test_log.txt"
#define PQS_TEST_XFER_ROOT "pqs_test_xfer_root"

typedef struct pqs_test_state
{
	uint32_t total;
	uint32_t passed;
	uint32_t failed;
} pqs_test_state;

static void pqs_test_print_banner(void)
{
	qsc_consoleutils_print_line("PQS: Post Quantum Shell Test");
	qsc_consoleutils_print_line("Quantum-Secure remote command shell test.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.1.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      June 03, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool pqs_test_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, PQS_TEST_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static void pqs_test_get_file_path(char* fpath, const char* fname)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = pqs_test_get_storage_path(dir, sizeof(dir));

	if (res == true)
	{
		qsc_stringutils_clear_string(fpath);
		qsc_stringutils_copy_string(fpath, QSC_SYSTEM_MAX_PATH, dir);
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, QSC_SYSTEM_MAX_PATH, fname);
	}
}

static void pqs_test_get_folder_path(char* path, const char* subfolder)
{
	bool res;

	res = pqs_test_get_storage_path(path, QSC_SYSTEM_MAX_PATH);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(path);
		qsc_stringutils_concat_strings(path, QSC_SYSTEM_MAX_PATH, subfolder);
	}
}

static void pqs_test_delete_folder(const char* subfolder)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = pqs_test_get_storage_path(dir, sizeof(dir));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(dir);
		qsc_stringutils_concat_strings(dir, QSC_SYSTEM_MAX_PATH, subfolder);
		(void)qsc_folderutils_delete_directory(dir);
	}
}

static void pqs_test_delete_file(const char* path)
{
	if (path != NULL && qsc_fileutils_exists(path) == true)
	{
		(void)qsc_fileutils_delete(path);
	}
}

static void pqs_test_cleanup_files(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };

	pqs_test_get_file_path(fpath, PQS_TEST_USER_DB);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_SHELL_DB);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_POLICY_DB);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_KNOWN_HOSTS_DB);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_SERVER_CONFIG);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_CLIENT_CONFIG);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_XFER_FILE);
	pqs_test_delete_file(fpath);
	pqs_test_get_file_path(fpath, PQS_TEST_LOG_FILE);
	pqs_test_delete_file(fpath);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "\\users\\alice");
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "\\users");
#else
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "/users/alice");
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "/users");
#endif
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT);
}

bool pqs_test_message_constants(pqs_test_state* state)
{
	bool res;

	res = (pqs_application_message_login_request != pqs_application_message_command_request);
	res = res && (pqs_application_message_response_more != pqs_application_message_response_final);
	res = res && (pqs_session_state_login_required != pqs_session_state_authenticated);
	res = res && (PQS_LOGIN_REQUEST_MESSAGE_SIZE == (PQS_APPLICATION_MESSAGE_HEADER_SIZE + PQS_LOGIN_REQUEST_PAYLOAD_SIZE));
	
	return res;
}

static bool pqs_test_user_database(pqs_test_state* state)
{
	const pqs_user_record* record;
	pqs_user_store store = { 0 };
	pqs_user_store loaded = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	pqs_test_get_file_path(fpath, PQS_TEST_USER_DB);

	pqs_user_store_initialize(&store, fpath);
	res = pqs_user_store_add(&store, "alice", "correct horse battery staple", pqs_user_privilege_user);
	record = pqs_user_store_find(&store, "alice");
	res = res && (record != NULL);

	if (record != NULL)
	{
		res = res && pqs_user_verify_passphrase(record, "correct horse battery staple");
		res = res && (pqs_user_verify_passphrase(record, "wrong passphrase") == false);
		res = res && pqs_user_store_set_privilege(&store, "alice", pqs_user_privilege_admin);
		res = res && pqs_user_store_set_shell_profile(&store, "alice", "default");
		res = res && pqs_user_store_enable(&store, "alice", false);
		res = res && pqs_user_store_initialize(&loaded, fpath);
		record = pqs_user_store_find(&loaded, "alice");
		res = res && (record != NULL);

		if (record != NULL)
		{
			res = res && (record->privilege == pqs_user_privilege_admin);
			res = res && (record->enabled == false);
			res = res && pqs_user_store_remove(&loaded, "alice");
			res = res && (pqs_user_store_find(&loaded, "alice") == NULL);
		}
	}

	return res;
}

static bool pqs_test_login_hardening(pqs_test_state* state)
{
	const pqs_user_record* alice;
	const pqs_user_record* bob;
	pqs_user_record* mutable;
	pqs_user_store store = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	(void)state;
	mutable = NULL;
	pqs_test_get_file_path(fpath, PQS_TEST_USER_DB);
	pqs_test_delete_file(fpath);

	res = (PQS_USER_DATABASE_VERSION == 2U);
	res = res && (PQS_CRYPTO_PHASH_CPU_COST == 4U);
	res = res && (PQS_CRYPTO_PHASH_MEMORY_COST == 1U);
	res = res && pqs_user_name_is_valid("alice");
	res = res && pqs_user_name_is_valid("ops.admin-01");
	res = res && (pqs_user_name_is_valid("") == false);
	res = res && (pqs_user_name_is_valid("bad user") == false);
	res = res && (pqs_user_name_is_valid("bad|user") == false);
	res = res && (pqs_user_name_is_valid("bad\nuser") == false);
	res = res && pqs_user_passphrase_is_valid("correct horse battery staple");
	res = res && (pqs_user_passphrase_is_valid("short") == false);
	res = res && pqs_user_store_initialize(&store, fpath);
	res = res && (pqs_user_store_add(&store, "bad user", "correct horse battery staple", pqs_user_privilege_user) == false);
	res = res && (pqs_user_store_add(&store, "alice", "short", pqs_user_privilege_user) == false);
	res = res && pqs_user_store_add(&store, "alice", "correct horse battery staple", pqs_user_privilege_user);
	res = res && pqs_user_store_add(&store, "bob", "correct horse battery staple", pqs_user_privilege_user);

	alice = pqs_user_store_find(&store, "alice");
	bob = pqs_user_store_find(&store, "bob");
	res = res && (alice != NULL && bob != NULL);

	if (alice != NULL && bob != NULL)
	{
		res = res && (qsc_memutils_are_equal(alice->verifier, bob->verifier, PQS_USER_VERIFIER_SIZE) == false);
		res = res && pqs_user_verify_passphrase_timing_neutral(alice, "alice", "correct horse battery staple");
		res = res && (pqs_user_verify_passphrase_timing_neutral(alice, "alice", "wrong passphrase") == false);
		res = res && (pqs_user_verify_passphrase_timing_neutral(NULL, "missing", "correct horse battery staple") == false);
		res = res && (pqs_user_verify_passphrase_timing_neutral(NULL, "bad user", "correct horse battery staple") == false);
		res = res && (pqs_user_verify_passphrase_timing_neutral(NULL, NULL, "short") == false);
		mutable = pqs_user_store_find_mutable(&store, "alice");

		if (mutable != NULL)
		{
			mutable->failures = 3U;
			res = res && pqs_user_store_enable(&store, "alice", true);
			alice = pqs_user_store_find(&store, "alice");
			res = res && (alice != NULL && alice->failures == 0U);
		}

		res = res && pqs_user_store_enable(&store, "alice", false);
		alice = pqs_user_store_find(&store, "alice");

		if (alice != NULL)
		{
			res = res && (pqs_user_verify_passphrase_timing_neutral(alice, "alice", "correct horse battery staple") == false);
		}
	}

	return res;
}

static bool pqs_test_shell_database(pqs_test_state* state)
{
	const pqs_shell_profile* profile;
	pqs_shell_store store = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;
	pqs_test_get_file_path(fpath, PQS_TEST_SHELL_DB);
	pqs_test_delete_file(fpath);

	res = pqs_shell_store_initialize(&store, fpath);
	res = res && pqs_shell_store_add(&store, "testshell", "sh", "/bin/sh", PQS_SHELL_PRIVILEGE_ALL, true);
	res = res && pqs_shell_store_set_privilege(&store, "testshell", pqs_user_privilege_guest, false);

	profile = pqs_shell_store_find(&store, "testshell");

	if (profile != NULL)
	{
		res = res && (pqs_shell_profile_allows_privilege(profile, pqs_user_privilege_guest) == false);
		res = res && pqs_shell_profile_allows_privilege(profile, pqs_user_privilege_user);
		res = res && pqs_shell_store_enable(&store, "testshell", false);

		profile = pqs_shell_store_find(&store, "testshell");

		if (profile != NULL && profile->enabled == false)
		{
			res = res && pqs_shell_store_remove(&store, "testshell");
			res = (pqs_shell_store_find(&store, "testshell") == NULL);
		}
	}

	return res;
}

static bool pqs_test_policy_database(pqs_test_state* state)
{
	const pqs_policy_record* matched;
	pqs_policy_store store = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	matched = NULL;
	pqs_test_get_file_path(fpath, PQS_TEST_POLICY_DB);
	pqs_test_delete_file(fpath);

	res = pqs_policy_store_initialize(&store, fpath);
	res = res && pqs_policy_store_add(&store, "readonly", pqs_policy_mode_restricted, pqs_policy_privilege_to_mask(pqs_user_privilege_guest), true);
	res = res && pqs_policy_store_add_command(&store, "readonly", "whoami", true);
	res = res && pqs_policy_store_add_command(&store, "readonly", "rm", false);
	res = res && pqs_policy_store_assign_privilege(&store, pqs_user_privilege_guest, "readonly");
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "whoami /all", &matched);
	res = res && (matched != NULL);

	if (matched != NULL)
	{
		res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "rm -rf /", &matched) == false);
		res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "whoami & dir", &matched) == false);
		res = res && pqs_policy_store_set_forced(&store, "readonly", "whoami");
		res = res && pqs_policy_store_set_mode(&store, "readonly", pqs_policy_mode_forced);
		res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "ignored", &matched);
		res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "ignored & unsafe", &matched);
		res = res && pqs_policy_store_add_command(&store, "readonly", "whoami", false);
		res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "ignored", &matched) == false);
		res = res && pqs_policy_store_remove_command(&store, "readonly", "whoami", false);
		res = res && pqs_policy_store_set_forced(&store, "readonly", "whoami & unsafe");
		res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "ignored", &matched) == false);
		res = res && pqs_policy_store_set_forced(&store, "readonly", "whoami");
		res = res && pqs_policy_store_remove_command(&store, "readonly", "rm", false);
	}

	return res;
}


static size_t pqs_test_count_known_host_lines(const char* fpath, const char* host)
{
	FILE* fp;
	char line[PQS_KEY_KNOWN_HOST_LINE_MAX] = { 0 };
	size_t hlen;
	size_t count;

	count = 0U;

	if (fpath != NULL && host != NULL)
	{
		hlen = qsc_stringutils_string_size(host);
#if defined(_MSC_VER)
		if (fopen_s(&fp, fpath, "r") != 0)
		{
			fp = NULL;
		}
#else
		fp = fopen(fpath, "r");
#endif

		if (fp != NULL)
		{
			while (fgets(line, sizeof(line), fp) != NULL)
			{
				if (strncmp(line, host, hlen) == 0 && line[hlen] == '|')
				{
					++count;
				}
			}

			fclose(fp);
		}
	}

	return count;
}

static bool pqs_test_known_hosts(pqs_test_state* state)
{
	FILE* fp;
	char fingerprint[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	pqs_test_get_file_path(fpath, PQS_TEST_KNOWN_HOSTS_DB);
	pqs_test_delete_file(fpath);
	qsc_stringutils_copy_string(fingerprint, sizeof(fingerprint), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

	res = pqs_key_fingerprint_is_valid(fingerprint);
	res = res && pqs_key_host_is_valid("127.0.0.1");
	res = res && pqs_key_known_host_set(fpath, "127.0.0.1", fingerprint);
	res = res && pqs_key_known_host_verify(fpath, "127.0.0.1", fingerprint);
	res = res && pqs_key_known_host_set(fpath, "127.0.0.1", fingerprint);
	res = res && (pqs_test_count_known_host_lines(fpath, "127.0.0.1") == 1U);

	if (res == true)
	{
#if defined(_MSC_VER)
		if (fopen_s(&fp, fpath, "w") != 0)
		{
			fp = NULL;
		}
#else
		fp = fopen(fpath, "w");
#endif

		if (fp != NULL)
		{
			fprintf(fp, "%s\n", PQS_KEY_KNOWN_HOST_MAGIC);
			fprintf(fp, "%s|%s\n", "127.0.0.1", fingerprint);
			fprintf(fp, "%s|%s\n", "127.0.0.1", fingerprint);
			fclose(fp);
		}
		else
		{
			res = false;
		}
	}

	res = res && pqs_key_known_host_set(fpath, "127.0.0.1", fingerprint);
	res = res && (pqs_test_count_known_host_lines(fpath, "127.0.0.1") == 1U);
	res = res && (pqs_key_known_host_verify(fpath, "example", fingerprint) == false);
	res = res && pqs_key_known_host_remove(fpath, "127.0.0.1");
	res = res && (pqs_key_known_host_find(fpath, "127.0.0.1", fingerprint, sizeof(fingerprint)) == false);
	
	return res;
}

static bool pqs_test_config_parser(pqs_test_state* state)
{
	pqs_client_config client = { 0 };
	pqs_server_config server = { 0 };
	char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char spath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	pqs_test_get_file_path(spath, PQS_TEST_SERVER_CONFIG);
	pqs_test_delete_file(spath);
	pqs_test_get_file_path(cpath, PQS_TEST_CLIENT_CONFIG);
	pqs_test_delete_file(cpath);

	res = pqs_config_server_load(&server, spath);
	res = res && (server.listen_port != 0U);
	res = res && (server.max_login_attempts != 0U);
	res = res && (server.command_timeout_seconds != 0U);
	res = res && (server.command_output_max_bytes == PQS_SANDBOX_DEFAULT_OUTPUT_BYTES);
	res = res && (qsc_stringutils_strings_equal(server.listen_address, "127.0.0.1") == true);
	res = res && (server.sandbox_allow_same_user == false);
	res = res && pqs_config_client_load(&client, cpath);
	res = res && (client.port != 0U);
	res = res && (client.log_level != pqs_log_level_none);
	
	return res;
}

static bool pqs_test_sandbox_profile(pqs_test_state* state)
{
	char folder[QSC_SYSTEM_MAX_PATH] = { 0 };
	char invalid[QSC_SYSTEM_MAX_PATH] = { 0 };
	char relative[QSC_SYSTEM_MAX_PATH] = { 0 };
	pqs_sandbox_profile profile = { 0 };
	bool res;

	(void)state;
	pqs_sandbox_profile_defaults(&profile);

	res = (profile.enabled == true);
	res = res && (profile.allow_same_user == false);
	res = res && (profile.command_timeout_seconds == PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS);
	res = res && (profile.max_output_bytes == PQS_SANDBOX_DEFAULT_OUTPUT_BYTES);
	pqs_sandbox_profile_configure(&profile, true, true, 1U, "");
	res = res && (profile.allow_same_user == false);
	pqs_sandbox_profile_set_allow_same_user(&profile, true);
	res = res && (profile.allow_same_user == true);
	res = res && (profile.command_timeout_seconds == PQS_SANDBOX_MIN_TIMEOUT_SECONDS);
	pqs_sandbox_profile_set_output_limit(&profile, 1U);
	res = res && (profile.max_output_bytes == PQS_SANDBOX_MIN_OUTPUT_BYTES);
	pqs_sandbox_profile_set_output_limit(&profile, PQS_SANDBOX_MAX_OUTPUT_BYTES + 1U);
	res = res && (profile.max_output_bytes == PQS_SANDBOX_MAX_OUTPUT_BYTES);
	res = res && (pqs_sandbox_timeout_milliseconds(&profile) == (PQS_SANDBOX_MIN_TIMEOUT_SECONDS * 1000U));
	res = res && (pqs_sandbox_output_limit_bytes(&profile) == PQS_SANDBOX_MAX_OUTPUT_BYTES);

	pqs_test_delete_folder(PQS_TEST_XFER_ROOT);
	pqs_test_get_folder_path(folder, PQS_TEST_XFER_ROOT);
	res = res && qsc_folderutils_create_directory_tree(folder);
	qsc_stringutils_copy_string(relative, sizeof(relative), folder);
	qsc_folderutils_append_delimiter(relative);
	qsc_stringutils_concat_strings(relative, sizeof(relative), ".");
	pqs_sandbox_profile_configure(&profile, true, true, PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS, relative);
	res = res && pqs_sandbox_working_directory_valid(&profile);
	res = res && pqs_sandbox_profile_canonicalize_working_directory(&profile);
	res = res && (strstr(profile.working_directory, "..") == NULL);
	res = res && (strstr(profile.working_directory, "\n") == NULL);
	qsc_stringutils_copy_string(invalid, sizeof(invalid), folder);
	qsc_folderutils_append_delimiter(invalid);
	qsc_stringutils_concat_strings(invalid, sizeof(invalid), "missing-subdir");
	pqs_sandbox_profile_configure(&profile, true, true, PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS, invalid);
	res = res && (pqs_sandbox_working_directory_valid(&profile) == false);

	return res;
}

static bool pqs_test_file_transfer_paths(pqs_test_state* state)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
#endif
	char outpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char userroot[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "\\users\\alice");
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "\\users");
#else
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "/users/alice");
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT "/users");
#endif

	pqs_test_delete_folder(PQS_TEST_XFER_ROOT);
	pqs_test_delete_folder(PQS_TEST_XFER_ROOT);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = pqs_xfer_path_is_safe("logs\\app.log");
	res = res && pqs_xfer_path_is_safe("upload\\file.txt");
	res = res && pqs_xfer_path_is_safe("logs\\app..log");
	res = res && pqs_xfer_path_is_safe("logs\\.hidden");
	res = res && (pqs_xfer_path_is_safe("logs\\\\app.log") == false);
	res = res && (pqs_xfer_path_is_safe("logs\\") == false);
	res = res && (pqs_xfer_path_is_safe("..\\escape.txt") == false);
	res = res && (pqs_xfer_path_is_safe("logs\\..\\escape.txt") == false);
	res = res && (pqs_xfer_path_is_safe("\\absolute\\path") == false);
	res = res && (pqs_xfer_path_is_safe("C:\\absolute\\path") == false);
	res = res && (pqs_xfer_path_is_safe("NUL") == false);
	res = res && (pqs_xfer_path_is_safe("COM1") == false);
	res = res && (pqs_xfer_path_is_safe("logs\\bad.") == false);
	res = res && (pqs_xfer_path_is_safe("logs\\bad ") == false);
	res = res && pqs_xfer_make_path(outpath, sizeof(outpath), PQS_TEST_XFER_ROOT, "logs\\app.log");
	res = res && (strstr(outpath, "logs") != NULL);

	pqs_test_get_folder_path(dpath, PQS_TEST_XFER_ROOT);
	res = res && pqs_xfer_make_user_root(userroot, sizeof(userroot), dpath, "alice");
	res = res && qsc_folderutils_directory_exists(userroot);
	res = res && (pqs_xfer_make_user_root(userroot, sizeof(userroot), PQS_TEST_XFER_ROOT, "..\\alice") == false);
#else
	res = pqs_xfer_path_is_safe("logs/app.log");
	res = res && pqs_xfer_path_is_safe("upload/file.txt");
	res = res && pqs_xfer_path_is_safe("logs/app..log");
	res = res && pqs_xfer_path_is_safe("logs/.hidden");
	res = res && (pqs_xfer_path_is_safe("logs//app.log") == false);
	res = res && (pqs_xfer_path_is_safe("logs/") == false);
	res = res && (pqs_xfer_path_is_safe("../escape.txt") == false);
	res = res && (pqs_xfer_path_is_safe("logs/../escape.txt") == false);
	res = res && (pqs_xfer_path_is_safe("/absolute/path") == false);
	res = res && (pqs_xfer_path_is_safe("C:\\absolute\\path") == false);
	res = res && (pqs_xfer_path_is_safe("logs/bad.") == false);
	res = res && (pqs_xfer_path_is_safe("logs/bad ") == false);
	res = res && pqs_xfer_make_path(outpath, sizeof(outpath), PQS_TEST_XFER_ROOT, "logs/app.log");
	res = res && (strstr(outpath, "logs") != NULL);
	res = res && pqs_xfer_make_user_root(userroot, sizeof(userroot), PQS_TEST_XFER_ROOT, "alice");
	res = res && qsc_folderutils_directory_exists(userroot);
	res = res && (pqs_xfer_make_user_root(userroot, sizeof(userroot), PQS_TEST_XFER_ROOT, "../alice") == false);
#endif

	return res;
}

static bool pqs_test_file_transfer_confined_open(pqs_test_state* state)
{
	FILE* fp;
	char folder[QSC_SYSTEM_MAX_PATH] = { 0 };
	char logdir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char userroot[QSC_SYSTEM_MAX_PATH] = { 0 };
	char temporary[PQS_XFER_PATH_MAX] = { 0 };
	char tempabs[QSC_SYSTEM_MAX_PATH] = { 0 };
	uint8_t buffer[4U] = { 0U };
	bool res;

	(void)state;
	fp = NULL;
	pqs_test_get_folder_path(folder, PQS_TEST_XFER_ROOT);
	res = pqs_xfer_make_user_root(userroot, sizeof(userroot), folder, "alice");

	if (res == true)
	{
		qsc_stringutils_copy_string(logdir, sizeof(logdir), userroot);
		qsc_folderutils_append_delimiter(logdir);
		qsc_stringutils_concat_strings(logdir, sizeof(logdir), "logs");
		res = qsc_folderutils_create_directory_tree(logdir);
	}

	if (res == true)
	{
		fp = pqs_xfer_open_write_confined(userroot, "logs/app.log");
		res = (fp != NULL);
	}

	if (res == true && fp != NULL)
	{
		res = (fwrite("test", sizeof(uint8_t), 4U, fp) == 4U);
		qsc_fileutils_close(fp);
		fp = NULL;
	}

	if (res == true)
	{
		fp = pqs_xfer_open_read_confined(userroot, "logs/app.log");
		res = (fp != NULL);
	}

	if (res == true && fp != NULL)
	{
		res = (fread(buffer, sizeof(uint8_t), sizeof(buffer), fp) == sizeof(buffer));
		res = res && (memcmp(buffer, "test", sizeof(buffer)) == 0);
		qsc_fileutils_close(fp);
		fp = NULL;
	}

	if (fp != NULL)
	{
		qsc_fileutils_close(fp);
	}

	res = res && pqs_xfer_make_temporary_path(temporary, sizeof(temporary), "logs/app.log");
	res = res && (strstr(temporary, ".pqs-upload") != NULL);
	res = res && pqs_xfer_make_path(tempabs, sizeof(tempabs), userroot, temporary);

	if (res == true)
	{
		fp = pqs_xfer_open_write_confined(userroot, temporary);
		res = (fp != NULL);
	}

	if (res == true && fp != NULL)
	{
		res = (fwrite("done", sizeof(uint8_t), 4U, fp) == 4U);
		qsc_fileutils_close(fp);
		fp = NULL;
	}

	res = res && qsc_fileutils_exists(tempabs);
	res = res && pqs_xfer_publish_temporary_file(userroot, temporary, "logs/app.log");
	res = res && (qsc_fileutils_exists(tempabs) == false);

	if (res == true)
	{
		fp = pqs_xfer_open_read_confined(userroot, "logs/app.log");
		res = (fp != NULL);
	}

	if (res == true && fp != NULL)
	{
		res = (fread(buffer, sizeof(uint8_t), sizeof(buffer), fp) == sizeof(buffer));
		res = res && (memcmp(buffer, "done", sizeof(buffer)) == 0);
		qsc_fileutils_close(fp);
		fp = NULL;
	}

	if (fp != NULL)
	{
		qsc_fileutils_close(fp);
	}

	res = res && (pqs_xfer_open_read_confined(userroot, "../escape.txt") == NULL);
	res = res && (pqs_xfer_open_write_confined(userroot, "../escape.txt") == NULL);
	res = res && (pqs_xfer_remove_confined(userroot, "../escape.txt") == false);

	return res;
}

static bool pqs_test_file_transfer_metadata(pqs_test_state* state)
{
	char hash[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char meta[PQS_XFER_METADATA_MAX] = { 0 };
	char parsedhash[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char relative[PQS_XFER_PATH_MAX] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t filesize;
	size_t parsedsize;
	bool res;

	filesize = 0U;
	parsedsize = 0U;

	pqs_test_get_file_path(fpath, PQS_TEST_SERVER_CONFIG);
	pqs_test_delete_file(fpath);
	res = qsc_fileutils_copy_stream_to_file(fpath, "abc", 3U);

	res = res && pqs_xfer_hash_file(fpath, hash, sizeof(hash), &filesize);
	res = res && (filesize == 3U);
	res = res && (qsc_stringutils_string_size(hash) == (PQS_XFER_HASH_TEXT_SIZE - 1U));
	res = res && pqs_xfer_format_metadata(meta, sizeof(meta), filesize, hash);
	res = res && pqs_xfer_parse_metadata(meta, &parsedsize, parsedhash, sizeof(parsedhash));
	res = res && (parsedsize == filesize);
	res = res && (strcmp(hash, parsedhash) == 0);

	qsc_memutils_clear((uint8_t*)meta, sizeof(meta));
	qsc_memutils_clear((uint8_t*)parsedhash, sizeof(parsedhash));

	res = res && pqs_xfer_format_file_metadata(meta, sizeof(meta), "logs/app.log", filesize, hash);
	res = res && pqs_xfer_parse_file_metadata(meta, relative, sizeof(relative), &parsedsize, parsedhash, sizeof(parsedhash));
	res = res && (strcmp(relative, "logs/app.log") == 0);
	res = res && (parsedsize == filesize);
	res = res && (strcmp(hash, parsedhash) == 0);
	res = res && (pqs_xfer_format_file_metadata(meta, sizeof(meta), "../escape.txt", filesize, hash) == false);
	res = res && (pqs_xfer_parse_file_metadata("path=../escape.txt;size=3;sha3=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", relative, sizeof(relative), &parsedsize, parsedhash, sizeof(parsedhash)) == false);
	
	return res;
}


static bool pqs_test_logger_baseline(pqs_test_state* state)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char line[12288U] = { 0 };
	size_t flen;
	uint64_t records;
	bool res;

	(void)state;
	flen = 0U;
	records = 0U;
	pqs_logger_dispose();
	pqs_test_get_file_path(fpath, PQS_TEST_LOG_FILE);
	pqs_test_delete_file(fpath);

	res = pqs_logger_initialize(fpath, pqs_log_level_debug);
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_hostkey_loaded, "alice\nadmin", "127.0.0.1", "loaded\tkey\nrecord");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_hostkey_pinned, "alice", "127.0.0.1", "pinned");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_hostkey_verified, "alice", "127.0.0.1", "verified");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_hostkey_changed, "alice", "127.0.0.1", "changed");
	res = res && pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_lockout, "alice", "127.0.0.1", "account locked");
	res = res && pqs_logger_write(pqs_log_level_warning, pqs_log_event_command_output_limit, "alice", "127.0.0.1", "output limit");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_request, "alice", "127.0.0.1", "admin request");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_allowed, "alice", "127.0.0.1", "admin allowed");
	res = res && pqs_logger_write(pqs_log_level_warning, pqs_log_event_admin_denied, "alice", "127.0.0.1", "admin denied");
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_complete, "alice", "127.0.0.1", "admin complete");
	res = res && pqs_logger_write(pqs_log_level_warning, pqs_log_event_admin_failed, "alice", "127.0.0.1", "admin failed");
	pqs_logger_dispose();
	res = res && pqs_logger_verify_chain(fpath, &records);
	res = res && (records == 12U);

	if (res == true && qsc_fileutils_exists(fpath) == true)
	{
		flen = qsc_fileutils_get_size(fpath);
		if (flen < sizeof(line))
		{
			(void)qsc_fileutils_copy_file_to_stream(fpath, line, flen);
			line[flen] = '\0';
		}
		else
		{
			res = false;
		}
	}

	res = res && (strstr(line, "name=audit_chain_start") != NULL);
	res = res && (strstr(line, "seq=0") != NULL);
	res = res && (strstr(line, "prev=0000000000000000000000000000000000000000000000000000000000000000") != NULL);
	res = res && (strstr(line, " hash=") != NULL);
	res = res && (strstr(line, "name=hostkey_loaded") != NULL);
	res = res && (strstr(line, "name=hostkey_pinned") != NULL);
	res = res && (strstr(line, "name=hostkey_verified") != NULL);
	res = res && (strstr(line, "name=hostkey_changed") != NULL);
	res = res && (strstr(line, "name=auth_lockout") != NULL);
	res = res && (strstr(line, "name=command_output_limit") != NULL);
	res = res && (strstr(line, "name=admin_request") != NULL);
	res = res && (strstr(line, "name=admin_allowed") != NULL);
	res = res && (strstr(line, "name=admin_denied") != NULL);
	res = res && (strstr(line, "name=admin_complete") != NULL);
	res = res && (strstr(line, "name=admin_failed") != NULL);
	res = res && (strstr(line, "alice_admin") != NULL);
	res = res && (strstr(line, "loaded_key_record") != NULL);
	res = res && (strstr(line, "name=none") == NULL);
	res = res && qsc_fileutils_append_to_file(fpath, "tamper\n", 7U);
	res = res && (pqs_logger_verify_chain(fpath, &records) == false);

	return res;
}

static bool pqs_test_policy_defaults_extended(pqs_test_state* state)
{
	const pqs_policy_record* matched;
	pqs_policy_store store = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	(void)state;

	matched = NULL;
	pqs_test_get_file_path(fpath, PQS_TEST_POLICY_DB);
	pqs_test_delete_file(fpath);

	res = pqs_policy_store_initialize(&store, fpath);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "dir .", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "get logs\\app.log", &matched);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "put local remote", &matched) == false);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "mkdir uploads", &matched) == false);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "remove uploads\\file.txt", &matched) == false);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "put local remote", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "mkdir uploads", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "remove uploads\\file.txt", &matched);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_admin, "dir & whoami", &matched) == false);
#else
	res = pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "list .", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "get logs/app.log", &matched);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "put local remote", &matched) == false);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "mkdir uploads", &matched) == false);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_guest, "remove uploads/file.txt", &matched) == false);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "put local remote", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "mkdir uploads", &matched);
	res = res && pqs_policy_store_authorize(&store, pqs_user_privilege_user, "remove uploads/file.txt", &matched);
	res = res && (pqs_policy_store_authorize(&store, pqs_user_privilege_admin, "ls;whoami", &matched) == false);
#endif

	return res;
}


static bool pqs_test_admin_subsystem(pqs_test_state* state)
{
	pqs_admin_context context = { 0 };
	pqs_admin_request request = { 0 };
	pqs_policy_store policy = { 0 };
	pqs_server_config config = { 0 };
	pqs_sandbox_profile sandbox = { 0 };
	pqs_user_store users = { 0 };
	pqs_shell_store shells = { 0 };
	char ppath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char upath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char spath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char logpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char output[PQS_ADMIN_OUTPUT_MAX] = { 0 };
	bool res;

	(void)state;
	pqs_test_get_file_path(ppath, PQS_TEST_POLICY_DB);
	pqs_test_get_file_path(upath, PQS_TEST_USER_DB);
	pqs_test_get_file_path(spath, PQS_TEST_SHELL_DB);
	pqs_test_get_file_path(logpath, PQS_TEST_LOG_FILE);
	pqs_test_delete_file(ppath);
	pqs_test_delete_file(upath);
	pqs_test_delete_file(spath);
	pqs_test_delete_file(logpath);

	pqs_config_server_defaults(&config);
	qsc_stringutils_copy_string(config.log_path, sizeof(config.log_path), logpath);
	pqs_sandbox_profile_defaults(&sandbox);
	res = pqs_policy_store_initialize(&policy, ppath);
	res = res && pqs_user_store_initialize(&users, upath);
	res = res && pqs_shell_store_initialize(&shells, spath);
	res = res && pqs_user_store_add(&users, "admin", "A-valid-admin-passphrase-0001", pqs_user_privilege_admin);
	res = res && (pqs_shell_store_find(&shells, "default") != NULL);
	res = res && pqs_logger_initialize(logpath, pqs_log_level_debug);
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_request, "admin", "127.0.0.1", "seed audit chain");
	pqs_logger_dispose();

	context.user = "admin";
	context.peer = "127.0.0.1";
	context.privilege = pqs_user_privilege_admin;
	context.authenticated = true;
	context.config = &config;
	context.users = &users;
	context.shells = &shells;
	context.policies = &policy;
	context.sandbox = &sandbox;
	context.public_key = NULL;

	res = res && pqs_admin_request_parse(&request, "status");
	res = res && (request.command == pqs_admin_command_server_status);
	res = res && qsc_stringutils_strings_equal(pqs_admin_policy_verb(request.command), "admin.status");
	res = res && pqs_admin_authorize(&context, &request);
	res = res && pqs_admin_execute(&context, &request, output, sizeof(output));
	res = res && (strstr(output, "PQS_ADMIN_STATUS") != NULL);
	res = res && (strstr(output, "privilege=admin") != NULL);
	res = res && (strstr(output, "authenticated=true") != NULL);

	context.privilege = pqs_user_privilege_user;
	res = res && (pqs_admin_authorize(&context, &request) == false);
	context.privilege = pqs_user_privilege_admin;

	qsc_memutils_clear((uint8_t*)output, sizeof(output));
	res = res && pqs_admin_request_parse(&request, "audit verify");
	res = res && pqs_admin_authorize(&context, &request);
	res = res && pqs_admin_execute(&context, &request, output, sizeof(output));
	res = res && (strstr(output, "PQS_ADMIN_AUDIT_VERIFY") != NULL);
	res = res && (strstr(output, "verified=true") != NULL);

	res = res && pqs_policy_store_add_command(&policy, PQS_POLICY_DEFAULT_ADMIN, "admin.audit.verify", false);
	res = res && (pqs_admin_authorize(&context, &request) == false);

	qsc_memutils_clear((uint8_t*)output, sizeof(output));
	res = res && pqs_admin_request_parse(&request, "config summary");
	res = res && pqs_admin_execute(&context, &request, output, sizeof(output));
	res = res && (strstr(output, "PQS_ADMIN_CONFIG") != NULL);
	res = res && (strstr(output, "command_output_max_bytes=") != NULL);

	qsc_memutils_clear((uint8_t*)output, sizeof(output));
	res = res && pqs_admin_request_parse(&request, "users");
	res = res && pqs_admin_execute(&context, &request, output, sizeof(output));
	res = res && (strstr(output, "PQS_ADMIN_USERS") != NULL);
	res = res && (strstr(output, "user=admin") != NULL);

	res = res && (pqs_admin_request_parse(&request, "users delete admin") == false);
	res = res && (pqs_admin_request_parse(&request, "raw shell") == false);

	return res;
}

static bool pqs_test_known_hosts_negative(pqs_test_state* state)
{
	char fingerprint[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	pqs_test_get_file_path(fpath, PQS_TEST_KNOWN_HOSTS_DB);
	pqs_test_delete_file(fpath);
	qsc_stringutils_copy_string(fingerprint, sizeof(fingerprint), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

	res = (pqs_key_fingerprint_is_valid("0123") == false);
	res = res && (pqs_key_fingerprint_is_valid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") == false);
	res = res && (pqs_key_fingerprint_is_valid("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") == false);
	res = res && (pqs_key_host_is_valid("bad|host") == false);
	res = res && (pqs_key_host_is_valid("bad\nhost") == false);
	res = res && (pqs_key_host_is_valid("bad host") == false);
	res = res && (pqs_key_known_host_set(fpath, "bad|host", fingerprint) == false);
	res = res && (pqs_key_known_host_set(fpath, "bad\nhost", fingerprint) == false);
	res = res && (pqs_key_known_host_set(fpath, "bad host", fingerprint) == false);
	res = res && pqs_key_known_host_set(fpath, "127.0.0.1", fingerprint);
	fingerprint[0U] = '1';
	res = res && (pqs_key_known_host_verify(fpath, "127.0.0.1", fingerprint) == false);
	res = res && (pqs_key_known_host_verify(fpath, "127.0.0.1", "short") == false);
	
	return res;
}


static bool pqs_test_key_file_permissions(pqs_test_state* state)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	const char data[] = "private-key-placeholder";
	bool res;

	(void)state;
	pqs_test_get_file_path(fpath, "pqs_test_private.key");
	pqs_test_delete_file(fpath);
	res = qsc_fileutils_copy_stream_to_file(fpath, data, sizeof(data) - 1U);

#if !defined(QSC_SYSTEM_OS_WINDOWS)
	if (res == true)
	{
		(void)chmod(fpath, S_IRUSR | S_IWUSR | S_IRGRP);
		res = (pqs_key_private_file_permissions_are_strict(fpath) == false);
	}

	if (res == true)
	{
		(void)chmod(fpath, S_IRUSR | S_IWUSR);
		res = pqs_key_private_file_permissions_are_strict(fpath);
	}
#else
	if (res == true)
	{
		res = pqs_key_private_file_permissions_are_strict(fpath);
	}
#endif

	pqs_test_delete_file(fpath);
	res = res && (pqs_key_private_file_permissions_are_strict(fpath) == false);

	return res;
}

static bool pqs_test_replace_file_text(const char* fpath, const char* search, const char* replace)
{
	char buffer[12288U] = { 0 };
	FILE* fp;
	size_t flen;
	char* pos;
	bool res;

	res = false;
	flen = 0U;
	pos = NULL;
	fp = NULL;

	if (fpath != NULL && search != NULL && replace != NULL && qsc_stringutils_string_size(search) == qsc_stringutils_string_size(replace))
	{
		flen = qsc_fileutils_get_size(fpath);

		if (flen > 0U && flen < sizeof(buffer))
		{
			(void)qsc_fileutils_copy_file_to_stream(fpath, buffer, flen);
			buffer[flen] = '\0';
			pos = strstr(buffer, search);

			if (pos != NULL)
			{
				qsc_memutils_copy((uint8_t*)pos, (const uint8_t*)replace, qsc_stringutils_string_size(replace));
#if defined(_MSC_VER)
				if (fopen_s(&fp, fpath, "wb") != 0)
				{
					fp = NULL;
				}
#else
				fp = fopen(fpath, "wb");
#endif

				if (fp != NULL)
				{
					res = (fwrite(buffer, sizeof(uint8_t), flen, fp) == flen);
					fclose(fp);
				}
			}
		}
	}

	return res;
}

static bool pqs_test_stage11_regression_boundaries(pqs_test_state* state)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char longhost[PQS_KEY_HOST_NAME_MAX + 2U] = { 0 };
	char longadmin[PQS_ADMIN_ARGUMENT_MAX + 16U] = { 0 };
	char temporary[PQS_XFER_PATH_MAX] = { 0 };
	pqs_admin_request request = { 0 };
	uint64_t records;
	bool res;

	(void)state;
	records = 0U;
	qsc_memutils_set_value((uint8_t*)longhost, sizeof(longhost) - 1U, (uint8_t)'a');
	longhost[sizeof(longhost) - 1U] = '\0';
	qsc_memutils_set_value((uint8_t*)longadmin, sizeof(longadmin) - 1U, (uint8_t)'s');
	longadmin[sizeof(longadmin) - 1U] = '\0';

	res = (pqs_application_message_admin_request != pqs_application_message_command_request);
	res = res && (pqs_application_message_admin_response_more != pqs_application_message_response_more);
	res = res && (pqs_application_message_admin_response_final != pqs_application_message_response_final);
	res = res && (pqs_client_command_admin != pqs_client_command_none);
	res = res && pqs_admin_request_parse(&request, "audit verify");
	res = res && (request.command == pqs_admin_command_audit_verify);
	res = res && (pqs_admin_request_parse(&request, longadmin) == false);
	res = res && (pqs_key_host_is_valid(longhost) == false);
	res = res && (pqs_xfer_make_temporary_path(temporary, sizeof(temporary), "../escape.txt") == false);
	res = res && (pqs_xfer_make_temporary_path(temporary, sizeof(temporary), "logs/app.log") == true);

	pqs_logger_dispose();
	pqs_test_get_file_path(fpath, "pqs_test_stage11_chain.log");
	pqs_test_delete_file(fpath);
	res = res && pqs_logger_initialize(fpath, pqs_log_level_debug);
	res = res && pqs_logger_write(pqs_log_level_audit, pqs_log_event_hostkey_verified, "alice", "127.0.0.1", "verified");
	pqs_logger_dispose();
	res = res && pqs_logger_verify_chain(fpath, &records);
	res = res && (records == 2U);
	res = res && pqs_test_replace_file_text(fpath, "verified", "verifxed");
	res = res && (pqs_logger_verify_chain(fpath, &records) == false);
	pqs_test_delete_file(fpath);

	return res;
}


int main(void)
{
	pqs_test_state state = { 0U };
	bool res;

	res = true;
	pqs_test_print_banner();

	if (pqs_test_message_constants(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS application message and session constants.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS application message and session constants.");
		res = false;
	}

	if (pqs_test_user_database(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS user database add verify update reload remove.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS user database add verify update reload remove.");
		res = false;
	}

	if (pqs_test_login_hardening(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS login validation, lockout reset, verifier domain binding, and dummy path.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS login validation, lockout reset, verifier domain binding, and dummy path.");
		res = false;
	}

	if (pqs_test_shell_database(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS shell profile database add privilege enable remove.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS shell profile database add privilege enable remove.");
		res = false;
	}

	if (pqs_test_policy_database(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS policy database restricted forced deny authorization.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS policy database restricted forced deny authorization.");
		res = false;
	}

	if (pqs_test_known_hosts(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS known-hosts set verify remove.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS known-hosts set verify remove.");
		res = false;
	}

	if (pqs_test_known_hosts_negative(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS known-hosts malformed and changed-key rejection.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS known-hosts malformed and changed-key rejection.");
		res = false;
	}

	if (pqs_test_key_file_permissions(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS key-file permission checks.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS key-file permission checks.");
		res = false;
	}

	if (pqs_test_file_transfer_paths(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS file-transfer path confinement and per-user root.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS file-transfer path confinement and per-user root.");
		res = false;
	}

	if (pqs_test_file_transfer_confined_open(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS file-transfer descriptor-relative confined open.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS file-transfer descriptor-relative confined open.");
		res = false;
	}

	if (pqs_test_file_transfer_metadata(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS file-transfer hash and metadata parse validation.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS file-transfer hash and metadata parse validation.");
		res = false;
	}

	if (pqs_test_logger_baseline(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS logger sanitization and event-name coverage.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS logger sanitization and event-name coverage.");
		res = false;
	}

	if (pqs_test_policy_defaults_extended(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS default file-transfer policy authorization.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS default file-transfer policy authorization.");
		res = false;
	}

	if (pqs_test_admin_subsystem(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS typed administrative command subsystem.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS typed administrative command subsystem.");
		res = false;
	}

	if (pqs_test_config_parser(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS configuration default creation and parsing.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS configuration default creation and parsing.");
		res = false;
	}

	if (pqs_test_sandbox_profile(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS sandbox defaults timeout clamp.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS sandbox defaults timeout clamp.");
		res = false;
	}

	if (pqs_test_stage11_regression_boundaries(&state) == true)
	{
		qsc_consoleutils_print_line("[PASS] PQS Stage 11 regression boundaries and same-length log tamper detection.");
	}
	else
	{
		qsc_consoleutils_print_line("[FAIL] PQS Stage 11 regression boundaries and same-length log tamper detection.");
		res = false;
	}

	qsc_consoleutils_print_line("");
	pqs_test_cleanup_files();

	if (res == true)
	{
		qsc_consoleutils_print_line("Completed: all PQS baseline tests passed.");
	}
	else
	{
		qsc_consoleutils_print_line("Completed: one or more PQS baseline tests failed.");
	}

	qsc_consoleutils_print_line("Testing completed, press any key to close.");
	qsc_consoleutils_get_wait();

	return (res == true) ? 0 : 1;
}

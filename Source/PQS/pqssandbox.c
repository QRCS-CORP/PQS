#include "pqssandbox.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   include <windows.h>
#else
#   include <stdlib.h>
#endif


static bool pqs_sandbox_canonicalize_path(const char* path, char* output, size_t outlen)
{
	bool res;

	res = false;

	if (path != NULL && output != NULL && outlen != 0U && path[0U] != '\0')
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		DWORD rlen;
		char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };

		rlen = GetFullPathNameA(path, (DWORD)sizeof(cpath), cpath, NULL);

		if (rlen != 0U && rlen < (DWORD)sizeof(cpath) && qsc_folderutils_directory_exists(cpath) == true &&
			qsc_stringutils_string_size(cpath) < outlen)
		{
			qsc_stringutils_copy_string(output, outlen, cpath);
			res = true;
		}
#else
		char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };

		if (realpath(path, cpath) != NULL && qsc_folderutils_directory_exists(cpath) == true &&
			qsc_stringutils_string_size(cpath) < outlen)
		{
			qsc_stringutils_copy_string(output, outlen, cpath);
			res = true;
		}
#endif
	}

	return res;
}

static uint32_t pqs_sandbox_clamp_output(uint32_t max_output_bytes)
{
	uint32_t res;

	res = max_output_bytes;

	if (res == 0U)
	{
		res = PQS_SANDBOX_DEFAULT_OUTPUT_BYTES;
	}
	else if (res < PQS_SANDBOX_MIN_OUTPUT_BYTES)
	{
		res = PQS_SANDBOX_MIN_OUTPUT_BYTES;
	}
	else if (res > PQS_SANDBOX_MAX_OUTPUT_BYTES)
	{
		res = PQS_SANDBOX_MAX_OUTPUT_BYTES;
	}

	return res;
}

static uint32_t pqs_sandbox_clamp_timeout(uint32_t timeout_seconds)
{
	uint32_t res;

	res = timeout_seconds;

	if (res == 0U)
	{
		res = PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS;
	}
	else if (res < PQS_SANDBOX_MIN_TIMEOUT_SECONDS)
	{
		res = PQS_SANDBOX_MIN_TIMEOUT_SECONDS;
	}
	else if (res > PQS_SANDBOX_MAX_TIMEOUT_SECONDS)
	{
		res = PQS_SANDBOX_MAX_TIMEOUT_SECONDS;
	}

	return res;
}

void pqs_sandbox_profile_defaults(pqs_sandbox_profile* profile)
{
	PQS_ASSERT(profile != NULL);

	if (profile != NULL)
	{
		qsc_memutils_clear((uint8_t*)profile, sizeof(pqs_sandbox_profile));
		profile->command_timeout_seconds = PQS_SANDBOX_DEFAULT_TIMEOUT_SECONDS;
		profile->max_output_bytes = PQS_SANDBOX_DEFAULT_OUTPUT_BYTES;
		profile->enabled = true;
		profile->clear_environment = true;
		profile->chroot_enabled = false;
		profile->allow_same_user = false;
	}
}

void pqs_sandbox_profile_configure(pqs_sandbox_profile* profile, bool enabled, bool clear_environment, uint32_t timeout_seconds, const char* working_directory)
{
	PQS_ASSERT(profile != NULL);

	pqs_sandbox_profile_configure_security(profile, enabled, clear_environment, timeout_seconds, working_directory, NULL, NULL, false);
}

void pqs_sandbox_profile_configure_security(pqs_sandbox_profile* profile, bool enabled, bool clear_environment, uint32_t timeout_seconds, const char* working_directory, const char* run_as_user, const char* run_as_group, bool chroot_enabled)
{
	PQS_ASSERT(profile != NULL);

	if (profile != NULL)
	{
		pqs_sandbox_profile_defaults(profile);
		profile->enabled = enabled;
		profile->clear_environment = clear_environment;
		profile->command_timeout_seconds = pqs_sandbox_clamp_timeout(timeout_seconds);
		profile->max_output_bytes = PQS_SANDBOX_DEFAULT_OUTPUT_BYTES;
		profile->chroot_enabled = chroot_enabled;

		if (working_directory != NULL && working_directory[0U] != '\0')
		{
			qsc_stringutils_copy_string(profile->working_directory, sizeof(profile->working_directory), working_directory);
			(void)pqs_sandbox_profile_canonicalize_working_directory(profile);
		}

		if (run_as_user != NULL && run_as_user[0U] != '\0')
		{
			qsc_stringutils_copy_string(profile->run_as_user, sizeof(profile->run_as_user), run_as_user);
		}

		if (run_as_group != NULL && run_as_group[0U] != '\0')
		{
			qsc_stringutils_copy_string(profile->run_as_group, sizeof(profile->run_as_group), run_as_group);
		}
	}
}


bool pqs_sandbox_profile_canonicalize_working_directory(pqs_sandbox_profile* profile)
{
	char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	PQS_ASSERT(profile != NULL);

	res = false;

	if (profile != NULL && profile->working_directory[0U] != '\0')
	{
		res = pqs_sandbox_canonicalize_path(profile->working_directory, cpath, sizeof(cpath));

		if (res == true)
		{
			qsc_memutils_clear((uint8_t*)profile->working_directory, sizeof(profile->working_directory));
			qsc_stringutils_copy_string(profile->working_directory, sizeof(profile->working_directory), cpath);
		}
	}

	return res;
}

void pqs_sandbox_profile_set_allow_same_user(pqs_sandbox_profile* profile, bool allow_same_user)
{
	PQS_ASSERT(profile != NULL);

	if (profile != NULL)
	{
		profile->allow_same_user = allow_same_user;
	}
}


void pqs_sandbox_profile_set_output_limit(pqs_sandbox_profile* profile, uint32_t max_output_bytes)
{
	PQS_ASSERT(profile != NULL);

	if (profile != NULL)
	{
		profile->max_output_bytes = pqs_sandbox_clamp_output(max_output_bytes);
	}
}

bool pqs_sandbox_working_directory_valid(const pqs_sandbox_profile* profile)
{
	char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	PQS_ASSERT(profile != NULL);

	res = true;

	if (profile != NULL && profile->enabled == true)
	{
		res = (profile->working_directory[0U] != '\0' &&
			pqs_sandbox_canonicalize_path(profile->working_directory, cpath, sizeof(cpath)) == true);
	}

	return res;
}

uint32_t pqs_sandbox_timeout_milliseconds(const pqs_sandbox_profile* profile)
{
	PQS_ASSERT(profile != NULL);

	uint32_t res;

	res = 0U;

	if (profile != NULL && profile->enabled == true && profile->command_timeout_seconds != 0U)
	{
		res = profile->command_timeout_seconds * 1000U;
	}

	return res;
}

uint32_t pqs_sandbox_output_limit_bytes(const pqs_sandbox_profile* profile)
{
	PQS_ASSERT(profile != NULL);

	uint32_t res;

	res = 0U;

	if (profile != NULL && profile->enabled == true)
	{
		res = profile->max_output_bytes;
	}

	return res;
}

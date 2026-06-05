#include "pqskey.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
#	include <windows.h>
#else
#	include <sys/stat.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif

static FILE* pqs_key_file_open(const char* path, const char* mode)
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

bool pqs_key_host_is_valid(const char* host)
{
	uint8_t b;
	size_t pos;
	size_t hlen;
	bool res;

	res = false;

	if (host != NULL)
	{
		hlen = qsc_stringutils_string_size(host);

		if (hlen != 0U && hlen < PQS_KEY_HOST_NAME_MAX)
		{
			res = true;

			for (pos = 0U; pos < hlen; ++pos)
			{
				b = (uint8_t)host[pos];

				if (b <= 0x20U || b == 0x7FU || b == (uint8_t)'|')
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}


static bool pqs_key_make_temporary_path(char* output, size_t outlen, const char* fpath)
{
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && fpath != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		unsigned long pid;

		pid = (unsigned long)GetCurrentProcessId();
		res = (snprintf(output, outlen, "%s.tmp.%lu", fpath, pid) > 0);
#else
		long pid;

		pid = (long)getpid();
		res = (snprintf(output, outlen, "%s.tmp.%ld", fpath, pid) > 0);
#endif

		if (res == true)
		{
			res = (qsc_stringutils_string_size(output) < outlen);
		}
	}

	return res;
}

static bool pqs_key_replace_file(const char* source, const char* destination)
{
	bool res;

	res = false;

	if (source != NULL && destination != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (MoveFileExA(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0);
#else
		res = (rename(source, destination) == 0);
#endif
	}

	return res;
}

static bool pqs_key_line_get_host(const char* line, char* host, size_t hostlen)
{
	size_t pos;
	bool res;

	res = false;

	if (line != NULL && host != NULL && hostlen != 0U)
	{
		pos = 0U;

		while (line[pos] != '\0' && line[pos] != '|')
		{
			++pos;
		}

		if (line[pos] == '|' && pos != 0U && pos < hostlen)
		{
			qsc_memutils_clear(host, hostlen);
			qsc_memutils_copy(host, line, pos);
			host[pos] = '\0';
			res = pqs_key_host_is_valid(host);
		}
	}

	return res;
}

static bool pqs_key_line_get_fingerprint(const char* line, char* fingerprint, size_t fplen)
{
	const char* fp;
	size_t len;
	bool res;

	res = false;

	if (line != NULL && fingerprint != NULL && fplen >= PQS_KEY_FINGERPRINT_STRING_SIZE)
	{
		fp = strchr(line, '|');

		if (fp != NULL)
		{
			++fp;
			len = qsc_stringutils_string_size(fp);

			while (len != 0U && (fp[len - 1U] == '\r' || fp[len - 1U] == '\n'))
			{
				--len;
			}

			if (len == (PQS_KEY_FINGERPRINT_STRING_SIZE - PQS_STRING_TERMINATOR_SIZE))
			{
				qsc_memutils_clear(fingerprint, fplen);
				qsc_memutils_copy(fingerprint, fp, len);
				fingerprint[len] = '\0';
				res = pqs_key_fingerprint_is_valid(fingerprint);
			}
		}
	}

	return res;
}

void pqs_key_fingerprint(uint8_t output[PQS_KEY_FINGERPRINT_SIZE], const qsms_client_verification_key* pubkey)
{
	PQS_ASSERT(output != NULL);
	PQS_ASSERT(pubkey != NULL);

	uint8_t msg[QSMS_CONFIG_SIZE + QSMS_KEYID_SIZE + QSMS_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
	size_t pos;

	if (output != NULL && pubkey != NULL)
	{
		pos = 0U;
		qsc_memutils_copy(msg + pos, pubkey->config, QSMS_CONFIG_SIZE);
		pos += QSMS_CONFIG_SIZE;
		qsc_memutils_copy(msg + pos, pubkey->keyid, QSMS_KEYID_SIZE);
		pos += QSMS_KEYID_SIZE;
		qsc_memutils_copy(msg + pos, pubkey->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
		pos += QSMS_ASYMMETRIC_VERIFY_KEY_SIZE;
		qsc_sha3_compute256(output, msg, pos);
		qsc_memutils_clear(msg, sizeof(msg));
	}
}

bool pqs_key_fingerprint_string(char* output, size_t outlen, const qsms_client_verification_key* pubkey)
{
	PQS_ASSERT(output != NULL);
	PQS_ASSERT(pubkey != NULL);

	uint8_t fp[PQS_KEY_FINGERPRINT_SIZE] = { 0U };
	bool res;

	res = false;

	if (output != NULL && outlen >= PQS_KEY_FINGERPRINT_STRING_SIZE && pubkey != NULL)
	{
		pqs_key_fingerprint(fp, pubkey);
		qsc_intutils_bin_to_hex(fp, output, sizeof(fp));
		output[PQS_KEY_FINGERPRINT_STRING_SIZE - PQS_STRING_TERMINATOR_SIZE] = '\0';
		res = true;
	}

	qsc_memutils_clear(fp, sizeof(fp));

	return res;
}

bool pqs_key_fingerprint_is_valid(const char* fingerprint)
{
	uint8_t b;
	size_t pos;
	bool res;

	res = false;

	if (fingerprint != NULL && qsc_stringutils_string_size(fingerprint) == (PQS_KEY_FINGERPRINT_STRING_SIZE - PQS_STRING_TERMINATOR_SIZE))
	{
		res = true;

		for (pos = 0U; pos < (PQS_KEY_FINGERPRINT_STRING_SIZE - PQS_STRING_TERMINATOR_SIZE); ++pos)
		{
			b = (uint8_t)fingerprint[pos];

			if (!((b >= (uint8_t)'0' && b <= (uint8_t)'9') ||
				(b >= (uint8_t)'a' && b <= (uint8_t)'f')))
			{
				res = false;
				break;
			}
		}
	}

	return res;
}


bool pqs_key_private_file_permissions_are_strict(const char* fpath)
{
	bool res;

	res = false;

	if (fpath != NULL && qsc_fileutils_exists(fpath) == true)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		DWORD attrs;

		attrs = GetFileAttributesA(fpath);
		res = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0U);
#else
		struct stat st;

		if (stat(fpath, &st) == 0)
		{
			res = (S_ISREG(st.st_mode) && ((st.st_mode & (S_IRWXG | S_IRWXO)) == 0U));
		}
#endif
	}

	return res;
}

bool pqs_key_fingerprint_file(char* output, size_t outlen, const char* fpath)
{
	qsms_client_verification_key pubkey = { 0 };
	char* spub;
	size_t flen;
	size_t plen;
	bool res;

	spub = NULL;
	res = false;

	if (output != NULL && outlen >= PQS_KEY_FINGERPRINT_STRING_SIZE && 
		fpath != NULL && qsc_fileutils_exists(fpath) == true)
	{
		plen = qsms_public_key_encoding_size();
		flen = qsc_fileutils_get_size(fpath);

		if (flen != 0U && flen < plen)
		{
			spub = qsc_memutils_malloc(plen);

			if (spub != NULL)
			{
				qsc_memutils_clear(spub, plen);
				(void)qsc_fileutils_copy_file_to_stream(fpath, spub, flen);
				spub[flen] = '\0';

				if (qsms_public_key_decode(&pubkey, spub, flen + PQS_STRING_TERMINATOR_SIZE) == true)
				{
					res = pqs_key_fingerprint_string(output, outlen, &pubkey);
				}

				qsc_memutils_alloc_free(spub);
			}
		}
	}

	qsc_memutils_clear(&pubkey, sizeof(pubkey));

	return res;
}

bool pqs_key_known_host_remove(const char* fpath, const char* host)
{
	FILE* infp;
	FILE* outfp;
	char line[PQS_KEY_KNOWN_HOST_LINE_MAX] = { 0 };
	char lname[PQS_KEY_HOST_NAME_MAX] = { 0 };
	char tpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool found;
	bool res;

	found = false;
	res = false;

	if (fpath != NULL && pqs_key_host_is_valid(host) == true)
	{
		if (pqs_key_make_temporary_path(tpath, sizeof(tpath), fpath) == true && qsc_fileutils_exists(tpath) == true)
		{
			qsc_fileutils_delete(tpath);
		}

		if (tpath[0U] != '\0')
		{
			outfp = pqs_key_file_open(tpath, "w");
		}
		else
		{
			outfp = NULL;
		}

		if (outfp != NULL)
		{
			fprintf(outfp, "%s\n", PQS_KEY_KNOWN_HOST_MAGIC);
			infp = pqs_key_file_open(fpath, "r");

			if (infp != NULL)
			{
				while (fgets(line, sizeof(line), infp) != NULL)
				{
					if (line[0U] != '#' && pqs_key_line_get_host(line, lname, sizeof(lname)) == true)
					{
						if (strcmp(lname, host) == 0)
						{
							found = true;
						}
						else
						{
							fputs(line, outfp);
						}
					}
				}

				fclose(infp);
			}

			fclose(outfp);

			if (found == true)
			{
				res = pqs_key_replace_file(tpath, fpath);
			}

			if (res == false && qsc_fileutils_exists(tpath) == true)
			{
				qsc_fileutils_delete(tpath);
			}
		}
	}

	return res;
}

bool pqs_key_known_host_find(const char* fpath, const char* host, char* fingerprint, size_t fplen)
{
	FILE* fp;
	char line[PQS_KEY_KNOWN_HOST_LINE_MAX] = { 0 };
	char lname[PQS_KEY_HOST_NAME_MAX] = { 0 };
	bool res;

	res = false;

	if (fpath != NULL && pqs_key_host_is_valid(host) == true && fingerprint != NULL && fplen >= PQS_KEY_FINGERPRINT_STRING_SIZE)
	{
		fp = pqs_key_file_open(fpath, "r");

		if (fp != NULL)
		{
			while (fgets(line, sizeof(line), fp) != NULL)
			{
				if (line[0U] != '#' && pqs_key_line_get_host(line, lname, sizeof(lname)) == true)
				{
					if (strcmp(lname, host) == 0)
					{
						res = pqs_key_line_get_fingerprint(line, fingerprint, fplen);
						break;
					}
				}
			}

			fclose(fp);
		}
	}

	return res;
}

bool pqs_key_known_host_set(const char* fpath, const char* host, const char* fingerprint)
{
	FILE* infp;
	FILE* outfp;
	char line[PQS_KEY_KNOWN_HOST_LINE_MAX] = { 0 };
	char lname[PQS_KEY_HOST_NAME_MAX] = { 0 };
	char tpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool found;
	bool res;

	found = false;
	res = false;

	if (fpath != NULL && pqs_key_host_is_valid(host) == true && fingerprint != NULL &&
		pqs_key_fingerprint_is_valid(fingerprint) == true)
	{
		if (pqs_key_make_temporary_path(tpath, sizeof(tpath), fpath) == true && qsc_fileutils_exists(tpath) == true)
		{
			qsc_fileutils_delete(tpath);
		}

		if (tpath[0U] != '\0')
		{
			outfp = pqs_key_file_open(tpath, "w");
		}
		else
		{
			outfp = NULL;
		}

		if (outfp != NULL)
		{
			fprintf(outfp, "%s\n", PQS_KEY_KNOWN_HOST_MAGIC);
			infp = pqs_key_file_open(fpath, "r");

			if (infp != NULL)
			{
				while (fgets(line, sizeof(line), infp) != NULL)
				{
					if (line[0U] != '#' && pqs_key_line_get_host(line, lname, sizeof(lname)) == true)
					{
						if (strcmp(lname, host) == 0)
						{
							if (found == false)
							{
								fprintf(outfp, "%s|%s\n", host, fingerprint);
								found = true;
							}
						}
						else
						{
							fputs(line, outfp);
						}
					}
				}

				fclose(infp);
			}

			if (found == false)
			{
				fprintf(outfp, "%s|%s\n", host, fingerprint);
			}

			fclose(outfp);

			res = pqs_key_replace_file(tpath, fpath);

			if (res == false && qsc_fileutils_exists(tpath) == true)
			{
				qsc_fileutils_delete(tpath);
			}
		}
	}

	return res;
}

bool pqs_key_known_host_verify(const char* fpath, const char* host, const char* fingerprint)
{
	char stored[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	bool res;

	res = false;

	if (pqs_key_fingerprint_is_valid(fingerprint) == true &&
		pqs_key_known_host_find(fpath, host, stored, sizeof(stored)) == true)
	{
		res = (qsc_intutils_verify((const uint8_t*)stored, (const uint8_t*)fingerprint, PQS_KEY_FINGERPRINT_STRING_SIZE - PQS_STRING_TERMINATOR_SIZE) == 0);
	}

	return res;
}

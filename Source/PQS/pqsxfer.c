#include "pqsxfer.h"
#include "fileutils.h"
#include "folderutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#	include <windows.h>
#	include <fcntl.h>
#	include <io.h>
#else
#	include <errno.h>
#	include <fcntl.h>
#	include <dirent.h>
#	include <sys/stat.h>
#	include <unistd.h>
#	if !defined(O_CLOEXEC)
#		define O_CLOEXEC 0
#	endif
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool pqs_xfer_is_path_separator(char ch)
{
	return (ch == '/' || ch == '\\');
}

static bool pqs_xfer_component_name_equals(const char* component, size_t length, const char* name)
{
	size_t nlen;
	size_t i;
	char ca;
	char na;
	bool res;

	res = false;

	if (component != NULL && name != NULL)
	{
		nlen = qsc_stringutils_string_size(name);

		if (length == nlen)
		{
			res = true;

			for (i = 0U; i < length; ++i)
			{
				ca = component[i];
				na = name[i];

				if (ca >= 'a' && ca <= 'z')
				{
					ca = (char)(ca - ('a' - 'A'));
				}

				if (na >= 'a' && na <= 'z')
				{
					na = (char)(na - ('a' - 'A'));
				}

				if (ca != na)
				{
					res = false;
					break;
				}
			}
		}
	}

	return res;
}

static bool pqs_xfer_component_is_windows_reserved(const char* component, size_t length)
{
	bool res;

	res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (component != NULL)
	{
		res = pqs_xfer_component_name_equals(component, length, "CON") ||
			pqs_xfer_component_name_equals(component, length, "PRN") ||
			pqs_xfer_component_name_equals(component, length, "AUX") ||
			pqs_xfer_component_name_equals(component, length, "NUL") ||
			pqs_xfer_component_name_equals(component, length, "COM1") ||
			pqs_xfer_component_name_equals(component, length, "COM2") ||
			pqs_xfer_component_name_equals(component, length, "COM3") ||
			pqs_xfer_component_name_equals(component, length, "COM4") ||
			pqs_xfer_component_name_equals(component, length, "COM5") ||
			pqs_xfer_component_name_equals(component, length, "COM6") ||
			pqs_xfer_component_name_equals(component, length, "COM7") ||
			pqs_xfer_component_name_equals(component, length, "COM8") ||
			pqs_xfer_component_name_equals(component, length, "COM9") ||
			pqs_xfer_component_name_equals(component, length, "LPT1") ||
			pqs_xfer_component_name_equals(component, length, "LPT2") ||
			pqs_xfer_component_name_equals(component, length, "LPT3") ||
			pqs_xfer_component_name_equals(component, length, "LPT4") ||
			pqs_xfer_component_name_equals(component, length, "LPT5") ||
			pqs_xfer_component_name_equals(component, length, "LPT6") ||
			pqs_xfer_component_name_equals(component, length, "LPT7") ||
			pqs_xfer_component_name_equals(component, length, "LPT8") ||
			pqs_xfer_component_name_equals(component, length, "LPT9");
	}
#else
	(void)component;
	(void)length;
#endif

	return res;
}

static bool pqs_xfer_component_is_safe(const char* component, size_t length)
{
	bool res;

	res = false;

	if (component != NULL && length != 0U)
	{
		if (length == 1U && component[0U] == '.')
		{
			res = false;
		}
		else if (length == 2U && component[0U] == '.' && component[1U] == '.')
		{
			res = false;
		}
		else if (component[length - 1U] == '.' || component[length - 1U] == ' ')
		{
			res = false;
		}
		else if (pqs_xfer_component_is_windows_reserved(component, length) == true)
		{
			res = false;
		}
		else
		{
			res = true;
		}
	}

	return res;
}

static bool pqs_xfer_relative_components_are_safe(const char* relative)
{
	size_t rlen;
	size_t pos;
	size_t start;
	bool res;

	res = false;

	if (relative != NULL)
	{
		rlen = qsc_stringutils_string_size(relative);

		if (rlen == 1U && relative[0U] == '.')
		{
			res = true;
		}
		else if (rlen != 0U && rlen < PQS_XFER_PATH_MAX && pqs_xfer_is_path_separator(relative[0U]) == false &&
			strchr(relative, ':') == NULL)
		{
			pos = 0U;
			res = true;

			while (pos < rlen && res == true)
			{
				start = pos;

				while (pos < rlen && pqs_xfer_is_path_separator(relative[pos]) == false)
				{
					++pos;
				}

				res = pqs_xfer_component_is_safe(relative + start, pos - start);

				if (pos < rlen)
				{
					++pos;

					if (pos == rlen || pqs_xfer_is_path_separator(relative[pos]) == true)
					{
						res = false;
					}
				}
			}
		}
	}

	return res;
}

#if defined(QSC_SYSTEM_OS_WINDOWS)
static bool pqs_xfer_windows_parent_path_is_secure(const char* root, const char* relative)
{
	char current[QSC_SYSTEM_MAX_PATH] = { 0 };
	char component[PQS_XFER_PATH_MAX] = { 0 };
	DWORD attrs;
	size_t offset;
	size_t cpos;
	bool final;
	bool res;

	res = false;
	offset = 0U;

	if (root != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true &&
		qsc_stringutils_string_size(root) < sizeof(current))
	{
		qsc_stringutils_copy_string(current, sizeof(current), root);
		attrs = GetFileAttributesA(current);

		if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0U &&
			(attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
		{
			res = true;

			while (relative[offset] != '\0' && res == true)
			{
				while (pqs_xfer_is_path_separator(relative[offset]) == true)
				{
					++offset;
				}

				cpos = 0U;

				while (relative[offset] != '\0' && pqs_xfer_is_path_separator(relative[offset]) == false && cpos < (sizeof(component) - 1U))
				{
					component[cpos] = relative[offset];
					++cpos;
					++offset;
				}

				component[cpos] = '\0';

				while (pqs_xfer_is_path_separator(relative[offset]) == true)
				{
					++offset;
				}

				final = (relative[offset] == '\0');

				if (cpos == 0U || final == true)
				{
					break;
				}

				qsc_folderutils_append_delimiter(current);
				qsc_stringutils_concat_strings(current, sizeof(current), component);
				attrs = GetFileAttributesA(current);
				res = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0U &&
					(attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0U);
			}
		}
	}

	return res;
}

static FILE* pqs_xfer_open_confined_windows(const char* root, const char* relative, bool write)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	DWORD access;
	DWORD creation;
	DWORD attrs;
	HANDLE hfile;
	intptr_t osfd;
	int32_t fdesc;
	FILE* res;

	res = NULL;
	hfile = INVALID_HANDLE_VALUE;

	if (root != NULL && relative != NULL &&
		pqs_xfer_make_path(fpath, sizeof(fpath), root, relative) == true &&
		pqs_xfer_path_is_confined(root, fpath, write == false) == true &&
		pqs_xfer_windows_parent_path_is_secure(root, relative) == true)
	{
		attrs = GetFileAttributesA(fpath);

		if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
		{
			access = (write == true) ? GENERIC_WRITE : GENERIC_READ;
			creation = (write == true) ? CREATE_ALWAYS : OPEN_EXISTING;
			hfile = CreateFileA(fpath, access, 0U, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
		}
	}

	if (hfile != INVALID_HANDLE_VALUE)
	{
		osfd = _open_osfhandle((intptr_t)hfile, (write == true) ? (_O_WRONLY | _O_BINARY) : (_O_RDONLY | _O_BINARY));

		if (osfd >= 0)
		{
			fdesc = (int32_t)osfd;
			res = _fdopen(fdesc, (write == true) ? "wb" : "rb");

			if (res == NULL)
			{
				_close(fdesc);
			}
		}
		else
		{
			CloseHandle(hfile);
		}
	}

	return res;
}
#else
static int pqs_xfer_open_root_directory(const char* root)
{
	int res;

	res = -1;

	if (root != NULL)
	{
		res = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	}

	return res;
}

static bool pqs_xfer_next_component(const char* path, size_t* offset, char* component, size_t complen, bool* final)
{
	size_t opos;
	size_t cpos;
	bool res;

	res = false;

	if (path != NULL && offset != NULL && component != NULL && complen != 0U && final != NULL)
	{
		opos = *offset;
		cpos = 0U;

		while (path[opos] == '/' || path[opos] == '\\')
		{
			++opos;
		}

		while (path[opos] != '\0' && path[opos] != '/' && path[opos] != '\\' && cpos < (complen - 1U))
		{
			component[cpos] = path[opos];
			++cpos;
			++opos;
		}

		component[cpos] = '\0';

		while (path[opos] == '/' || path[opos] == '\\')
		{
			++opos;
		}

		*offset = opos;
		*final = (path[opos] == '\0');
		res = pqs_xfer_component_is_safe(component, cpos);
	}

	return res;
}

static FILE* pqs_xfer_open_confined_posix(const char* root, const char* relative, bool write)
{
	char component[PQS_XFER_PATH_MAX] = { 0 };
	size_t offset;
	int current;
	int next;
	int flags;
	bool final;
	bool ok;
	FILE* res;

	res = NULL;
	current = -1;
	offset = 0U;
	ok = false;

	if (root != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		current = pqs_xfer_open_root_directory(root);

		if (current >= 0)
		{
			ok = true;

			while (pqs_xfer_next_component(relative, &offset, component, sizeof(component), &final) == true)
			{
				if (final == true)
				{
					flags = (write == true) ? (O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC) : (O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
					next = openat(current, component, flags, S_IRUSR | S_IWUSR);
				}
				else
				{
					next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
				}

				if (next < 0)
				{
					ok = false;
					break;
				}

				close(current);
				current = next;

				if (final == true)
				{
					break;
				}
			}
		}
	}

	if (ok == true && current >= 0)
	{
		res = fdopen(current, (write == true) ? "wb" : "rb");

		if (res == NULL)
		{
			close(current);
		}
	}
	else if (current >= 0)
	{
		close(current);
	}

	return res;
}
#endif

static bool pqs_xfer_walk_directory_internal(const char* localroot, const char* remoteroot, size_t depth, size_t maxdepth, pqs_xfer_walk_callback callback, void* context)
{
	bool res;

	res = false;

	if (localroot != NULL && remoteroot != NULL && callback != NULL && depth <= maxdepth &&
		pqs_xfer_local_path_is_directory(localroot) == true && pqs_xfer_path_is_safe(remoteroot) == true &&
		pqs_xfer_path_is_symlink(localroot) == false)
	{
		res = callback(pqs_xfer_walk_event_directory_begin, localroot, remoteroot, context);

#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (res == true)
		{
			WIN32_FIND_DATAA ffd;
			HANDLE hfind;
			char pattern[QSC_SYSTEM_MAX_PATH] = { 0 };
			char lpath[QSC_SYSTEM_MAX_PATH] = { 0 };
			char rpath[PQS_XFER_PATH_MAX] = { 0 };

			pqs_xfer_join_path(pattern, sizeof(pattern), localroot, "*");
			hfind = FindFirstFileA(pattern, &ffd);

			if (hfind != INVALID_HANDLE_VALUE)
			{
				do
				{
					if (strcmp(ffd.cFileName, ".") != 0 && strcmp(ffd.cFileName, "..") != 0 &&
						(ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
					{
						pqs_xfer_join_path(lpath, sizeof(lpath), localroot, ffd.cFileName);
						pqs_xfer_join_remote(rpath, sizeof(rpath), remoteroot, ffd.cFileName);

						if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U)
						{
							res = pqs_xfer_walk_directory_internal(lpath, rpath, depth + 1U, maxdepth, callback, context) && res;
						}
						else
						{
							res = callback(pqs_xfer_walk_event_file, lpath, rpath, context) && res;
						}
					}
				} while (FindNextFileA(hfind, &ffd) != 0 && res == true);

				FindClose(hfind);
			}
		}
#else
		if (res == true)
		{
			DIR* dir;
			struct dirent* ent;
			char lpath[QSC_SYSTEM_MAX_PATH] = { 0 };
			char rpath[PQS_XFER_PATH_MAX] = { 0 };

			dir = opendir(localroot);

			if (dir != NULL)
			{
				while ((ent = readdir(dir)) != NULL && res == true)
				{
					if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
					{
						pqs_xfer_join_path(lpath, sizeof(lpath), localroot, ent->d_name);
						pqs_xfer_join_remote(rpath, sizeof(rpath), remoteroot, ent->d_name);

						if (pqs_xfer_path_is_symlink(lpath) == false)
						{
							if (pqs_xfer_local_path_is_directory(lpath) == true)
							{
								res = pqs_xfer_walk_directory_internal(lpath, rpath, depth + 1U, maxdepth, callback, context) && res;
							}
							else
							{
								res = callback(pqs_xfer_walk_event_file, lpath, rpath, context) && res;
							}
						}
					}
				}

				closedir(dir);
			}
			else
			{
				res = false;
			}
		}
#endif

		if (res == true)
		{
			res = callback(pqs_xfer_walk_event_directory_end, localroot, remoteroot, context);
		}
	}

	return res;
}

size_t pqs_xfer_payload_size(const uint8_t* message, size_t msglen)
{
	size_t res;

	res = 0U;

	if (message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE)
	{
		res = msglen - PQS_APPLICATION_MESSAGE_HEADER_SIZE;
	}

	return res;
}

void pqs_xfer_join_path(char* output, size_t outlen, const char* first, const char* second)
{
	PQS_ASSERT(output != NULL);

	if (output != NULL && outlen != 0U && first != NULL && second != NULL)
	{
		qsc_memutils_clear((uint8_t*)output, outlen);
		qsc_stringutils_copy_string(output, outlen, first);
		qsc_folderutils_append_delimiter(output);
		qsc_stringutils_concat_strings(output, outlen, second);
	}
}

void pqs_xfer_join_remote(char* output, size_t outlen, const char* first, const char* second)
{
	PQS_ASSERT(output != NULL);

	size_t flen;

	if (output != NULL && outlen != 0U && first != NULL && second != NULL)
	{
		qsc_memutils_clear((uint8_t*)output, outlen);
		qsc_stringutils_copy_string(output, outlen, first);
		flen = qsc_stringutils_string_size(output);

		if (flen != 0U && output[flen - 1U] != '/')
		{
			qsc_stringutils_concat_strings(output, outlen, "/");
		}

		qsc_stringutils_concat_strings(output, outlen, second);
	}
}

bool pqs_xfer_local_path_is_directory(const char* path)
{
	PQS_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		DWORD attr;

		attr = GetFileAttributesA(path);
		res = (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0U);
#else
		struct stat st;

		res = (stat(path, &st) == 0 && S_ISDIR(st.st_mode) != 0);
#endif
	}

	return res;
}

bool pqs_xfer_create_parent_directories(const char* fpath)
{
	PQS_ASSERT(fpath != NULL);

	char tmp[QSC_SYSTEM_MAX_PATH] = { 0 };
	char* ptr;
	bool res;

	res = false;

	if (fpath != NULL && qsc_stringutils_string_size(fpath) < sizeof(tmp))
	{
		qsc_stringutils_copy_string(tmp, sizeof(tmp), fpath);
		ptr = strrchr(tmp, QSC_FOLDERUTILS_DELIMITER);

#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (ptr == NULL)
		{
			ptr = strrchr(tmp, '/');
		}
#endif

		if (ptr != NULL)
		{
			*ptr = '\0';

			if (qsc_folderutils_directory_exists(tmp) == true || qsc_folderutils_create_directory_tree(tmp) == true)
			{
				res = true;
			}
		}
	}

	return res;
}

bool pqs_xfer_make_local_recursive_path(char* output, size_t outlen, const char* root, const char* relative)
{
	PQS_ASSERT(output != NULL);

	bool res;

	res = false;

	if (output != NULL && outlen != 0U && root != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		pqs_xfer_join_path(output, outlen, root, relative);
		res = (qsc_stringutils_string_size(output) != 0U && qsc_stringutils_string_size(output) < outlen);
	}

	return res;
}

bool pqs_xfer_walk_directory(const char* localroot, const char* remoteroot, size_t maxdepth, pqs_xfer_walk_callback callback, void* context)
{
	PQS_ASSERT(localroot != NULL);
	PQS_ASSERT(remoteroot != NULL);
	PQS_ASSERT(callback != NULL);

	bool res;

	res = false;

	if (localroot != NULL && remoteroot != NULL && callback != NULL && maxdepth != 0U &&
		pqs_xfer_local_path_is_directory(localroot) == true && pqs_xfer_path_is_safe(remoteroot) == true)
	{
		res = pqs_xfer_walk_directory_internal(localroot, remoteroot, 0U, maxdepth, callback, context);
	}

	return res;
}

bool pqs_xfer_path_is_safe(const char* relative)
{
	bool res;

	res = pqs_xfer_relative_components_are_safe(relative);

	return res;
}

bool pqs_xfer_extract_relative(char* output, size_t outlen, const uint8_t* message, size_t msglen)
{
	PQS_ASSERT(output != NULL);

	size_t plen;
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE)
	{
		plen = msglen - PQS_APPLICATION_MESSAGE_HEADER_SIZE;

		if (plen > PQS_STRING_TERMINATOR_SIZE && plen < outlen && plen <= PQS_XFER_PATH_MAX && message[msglen - 1U] == '\0')
		{
			qsc_memutils_clear((uint8_t*)output, outlen);
			qsc_memutils_copy(output, message + PQS_APPLICATION_MESSAGE_HEADER_SIZE, plen);
			output[plen - 1U] = '\0';
			res = pqs_xfer_path_is_safe(output);
		}
	}

	return res;
}

bool pqs_xfer_path_is_confined(const char* root, const char* path, bool existing)
{
	PQS_ASSERT(root != NULL);
	PQS_ASSERT(path != NULL);

	char croot[QSC_SYSTEM_MAX_PATH] = { 0 };
	char cpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	const char* rptr;
	const char* pptr;
	size_t rlen;
	bool res;

	res = false;

	if (root != NULL && path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		DWORD rsize;
		DWORD psize;
		char parent[QSC_SYSTEM_MAX_PATH] = { 0 };
		char* last;

		rsize = GetFullPathNameA(root, (DWORD)sizeof(croot), croot, NULL);

		if (existing == true)
		{
			psize = GetFullPathNameA(path, (DWORD)sizeof(cpath), cpath, NULL);
		}
		else
		{
			qsc_stringutils_copy_string(parent, sizeof(parent), path);
			last = strrchr(parent, '\\');

			if (last == NULL)
			{
				last = strrchr(parent, '/');
			}

			if (last != NULL)
			{
				*last = '\0';
			}

			psize = GetFullPathNameA(parent, (DWORD)sizeof(cpath), cpath, NULL);
		}

		if (rsize != 0U && rsize < sizeof(croot) && psize != 0U && psize < sizeof(cpath))
		{
			rptr = croot;
			pptr = cpath;
			rlen = qsc_stringutils_string_size(croot);
			res = (_strnicmp(rptr, pptr, rlen) == 0 && (pptr[rlen] == '\0' || pqs_xfer_is_path_separator(pptr[rlen]) == true));
		}
#else
		char parent[QSC_SYSTEM_MAX_PATH] = { 0 };
		char* last;

		if (realpath(root, croot) != NULL)
		{
			if (existing == true)
			{
				if (realpath(path, cpath) == NULL)
				{
					cpath[0U] = '\0';
				}
			}
			else
			{
				qsc_stringutils_copy_string(parent, sizeof(parent), path);
				last = strrchr(parent, '/');

				if (last != NULL)
				{
					*last = '\0';
				}

				if (realpath(parent, cpath) == NULL)
				{
					cpath[0U] = '\0';
				}
			}

			if (cpath[0U] != '\0')
			{
				rptr = croot;
				pptr = cpath;
				rlen = qsc_stringutils_string_size(croot);
				res = (strncmp(rptr, pptr, rlen) == 0 && (pptr[rlen] == '\0' || pqs_xfer_is_path_separator(pptr[rlen]) == true));
			}
		}
#endif
	}

	return res;
}

bool pqs_xfer_make_path(char* output, size_t outlen, const char* root, const char* relative)
{
	PQS_ASSERT(output != NULL);
	PQS_ASSERT(root != NULL);

	char base[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t blen;
	size_t rlen;
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && root != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		blen = qsc_stringutils_string_size(root);
		rlen = qsc_stringutils_string_size(relative);

		if (blen != 0U && blen < sizeof(base) && (blen + rlen + 2U) < outlen)
		{
			qsc_memutils_clear((uint8_t*)output, outlen);
			qsc_stringutils_copy_string(base, sizeof(base), root);
			qsc_folderutils_append_delimiter(base);
			qsc_stringutils_copy_string(output, outlen, base);
			qsc_stringutils_concat_strings(output, outlen, relative);
			res = true;
		}
	}

	return res;
}

bool pqs_xfer_make_user_root(char* output, size_t outlen, const char* root, const char* username)
{
	PQS_ASSERT(output != NULL);
	PQS_ASSERT(root != NULL);

	char upath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && root != NULL && username != NULL && pqs_xfer_path_is_safe(username) == true)
	{
		qsc_memutils_clear((uint8_t*)output, outlen);
		qsc_stringutils_copy_string(upath, sizeof(upath), root);
		qsc_folderutils_append_delimiter(upath);
		qsc_stringutils_concat_strings(upath, sizeof(upath), PQS_XFER_USERS_ROOT_NAME);
		qsc_folderutils_append_delimiter(upath);
		qsc_stringutils_concat_strings(upath, sizeof(upath), username);

		if (qsc_folderutils_directory_exists(upath) == false)
		{
			(void)qsc_folderutils_create_directory_tree(upath);
		}

		if (qsc_folderutils_directory_exists(upath) == true && qsc_stringutils_string_size(upath) < outlen)
		{
			qsc_stringutils_copy_string(output, outlen, upath);
			res = true;
		}
	}

	return res;
}

bool pqs_xfer_make_temporary_path(char* output, size_t outlen, const char* relative)
{
	PQS_ASSERT(output != NULL);
	PQS_ASSERT(relative != NULL);

	size_t rlen;
	bool res;

	res = false;

	if (output != NULL && outlen != 0U && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		rlen = qsc_stringutils_string_size(relative);

		if ((rlen + 16U) < outlen && (rlen + 16U) < PQS_XFER_PATH_MAX)
		{
			qsc_memutils_clear((uint8_t*)output, outlen);
			qsc_stringutils_copy_string(output, outlen, relative);
			qsc_stringutils_concat_strings(output, outlen, ".pqs-upload");
			res = pqs_xfer_path_is_safe(output);
		}
	}

	return res;
}


bool pqs_xfer_make_directory_confined(const char* root, const char* relative)
{
	PQS_ASSERT(root != NULL);
	PQS_ASSERT(relative != NULL);

	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (root != NULL && relative != NULL && pqs_xfer_make_path(dpath, sizeof(dpath), root, relative) == true &&
		pqs_xfer_path_is_confined(root, dpath, false) == true)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (pqs_xfer_windows_parent_path_is_secure(root, relative) == true)
		{
			res = qsc_folderutils_create_directory_tree(dpath);
		}
#else
		res = qsc_folderutils_create_directory_tree(dpath);
#endif
	}

	return res;
}

bool pqs_xfer_remove_confined(const char* root, const char* relative)
{
	PQS_ASSERT(root != NULL);
	PQS_ASSERT(relative != NULL);

	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (root != NULL && relative != NULL && pqs_xfer_make_path(fpath, sizeof(fpath), root, relative) == true &&
		pqs_xfer_path_is_confined(root, fpath, true) == true && qsc_fileutils_exists(fpath) == true &&
		pqs_xfer_path_is_symlink(fpath) == false)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (pqs_xfer_windows_parent_path_is_secure(root, relative) == true)
		{
			res = qsc_fileutils_delete(fpath);
		}
#else
		res = qsc_fileutils_delete(fpath);
#endif
	}

	return res;
}

bool pqs_xfer_publish_temporary_file(const char* root, const char* temporary, const char* relative)
{
	PQS_ASSERT(root != NULL);
	PQS_ASSERT(temporary != NULL);
	PQS_ASSERT(relative != NULL);

	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char tpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (root != NULL && temporary != NULL && relative != NULL && pqs_xfer_path_is_safe(temporary) == true &&
		pqs_xfer_path_is_safe(relative) == true && pqs_xfer_make_path(tpath, sizeof(tpath), root, temporary) == true &&
		pqs_xfer_make_path(fpath, sizeof(fpath), root, relative) == true &&
		pqs_xfer_path_is_confined(root, tpath, true) == true &&
		pqs_xfer_path_is_confined(root, fpath, false) == true && qsc_fileutils_exists(tpath) == true &&
		pqs_xfer_path_is_symlink(tpath) == false
#if defined(QSC_SYSTEM_OS_WINDOWS)
		&& pqs_xfer_windows_parent_path_is_secure(root, temporary) == true &&
		pqs_xfer_windows_parent_path_is_secure(root, relative) == true
#endif
		)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			if (pqs_xfer_path_is_confined(root, fpath, true) == true && pqs_xfer_path_is_symlink(fpath) == false)
			{
				(void)qsc_fileutils_delete(fpath);
			}
		}

		if (qsc_fileutils_exists(fpath) == false)
		{
			res = (rename(tpath, fpath) == 0);
		}
	}

	return res;
}

FILE* pqs_xfer_open_read_confined(const char* root, const char* relative)
{
	PQS_ASSERT(relative != NULL);
	PQS_ASSERT(root != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return pqs_xfer_open_confined_windows(root, relative, false);
#else
	return pqs_xfer_open_confined_posix(root, relative, false);
#endif
}

FILE* pqs_xfer_open_write_confined(const char* root, const char* relative)
{
	PQS_ASSERT(relative != NULL);
	PQS_ASSERT(root != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return pqs_xfer_open_confined_windows(root, relative, true);
#else
	return pqs_xfer_open_confined_posix(root, relative, true);
#endif
}

bool pqs_xfer_hash_file(const char* fpath, char* hexhash, size_t hexlen, size_t* filesize)
{
	PQS_ASSERT(fpath != NULL);
	
	FILE* fp;
	qsc_keccak_state ctx;
	uint8_t buffer[4096U] = { 0U };
	uint8_t hash[PQS_XFER_HASH_SIZE] = { 0U };
	size_t rlen;
	size_t total;
	bool res;

	fp = NULL;
	total = 0U;
	res = false;

	if (fpath != NULL && hexhash != NULL && hexlen >= PQS_XFER_HASH_TEXT_SIZE)
	{
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			qsc_sha3_initialize(&ctx);

			while (true)
			{
				rlen = fread(buffer, sizeof(uint8_t), sizeof(buffer), fp);

				if (rlen != 0U)
				{
					qsc_sha3_update(&ctx, qsc_keccak_rate_256, buffer, rlen);
					total += rlen;
					qsc_memutils_clear(buffer, sizeof(buffer));
				}
				else
				{
					break;
				}
			}

			qsc_sha3_finalize(&ctx, qsc_keccak_rate_256, hash);
			qsc_intutils_bin_to_hex(hash, hexhash, sizeof(hash));
			hexhash[PQS_XFER_HASH_TEXT_SIZE - 1U] = '\0';

			if (filesize != NULL)
			{
				*filesize = total;
			}

			res = true;
			qsc_fileutils_close(fp);
		}
	}

	return res;
}

bool pqs_xfer_format_metadata(char* output, size_t outlen, size_t filesize, const char* hexhash)
{
	PQS_ASSERT(output != NULL);

	bool res;

	res = false;

	if (output != NULL && outlen >= PQS_XFER_METADATA_MAX && hexhash != NULL && 
		qsc_stringutils_string_size(hexhash) == (PQS_XFER_HASH_TEXT_SIZE - 1U))
	{
		qsc_memutils_clear((uint8_t*)output, outlen);
		snprintf(output, outlen, "size=%zu;sha3=%s", filesize, hexhash);
		res = true;
	}

	return res;
}

bool pqs_xfer_parse_metadata(const char* metadata, size_t* filesize, char* hexhash, size_t hexlen)
{
	PQS_ASSERT(metadata != NULL);

	const char* sptr;
	const char* hptr;
	char* endp;
	unsigned long long fsz;
	bool res;

	res = false;

	if (metadata != NULL && filesize != NULL && hexhash != NULL && hexlen >= PQS_XFER_HASH_TEXT_SIZE)
	{
		sptr = strstr(metadata, "size=");
		hptr = strstr(metadata, ";sha3=");

		if (sptr == metadata && hptr != NULL)
		{
			endp = NULL;
			fsz = strtoull(sptr + 5U, &endp, 10);

			if (endp == hptr && qsc_stringutils_string_size(hptr + 6U) == (PQS_XFER_HASH_TEXT_SIZE - 1U))
			{
				*filesize = (size_t)fsz;
				qsc_stringutils_copy_string(hexhash, hexlen, hptr + 6U);
				res = true;
			}
		}
	}

	return res;
}

bool pqs_xfer_format_file_metadata(char* output, size_t outlen, const char* relative, size_t filesize, const char* hexhash)
{
	PQS_ASSERT(output != NULL);

	bool res;

	res = false;

	if (output != NULL && outlen >= PQS_XFER_METADATA_MAX && relative != NULL && hexhash != NULL &&
		pqs_xfer_path_is_safe(relative) == true && qsc_stringutils_string_size(hexhash) == (PQS_XFER_HASH_TEXT_SIZE - 1U))
	{
		qsc_memutils_clear((uint8_t*)output, outlen);
		snprintf(output, outlen, "path=%s;size=%zu;sha3=%s", relative, filesize, hexhash);
		res = true;
	}

	return res;
}

bool pqs_xfer_parse_file_metadata(const char* metadata, char* relative, size_t relen, size_t* filesize, char* hexhash, size_t hexlen)
{
	PQS_ASSERT(metadata != NULL);
	PQS_ASSERT(relative != NULL);

	const char* pptr;
	const char* sptr;
	const char* hptr;
	char* endp;
	unsigned long long fsz;
	size_t plen;
	bool res;

	res = false;

	if (metadata != NULL && relative != NULL && relen != 0U && filesize != NULL && hexhash != NULL && hexlen >= PQS_XFER_HASH_TEXT_SIZE)
	{
		pptr = strstr(metadata, "path=");
		sptr = strstr(metadata, ";size=");
		hptr = strstr(metadata, ";sha3=");

		if (pptr == metadata && sptr != NULL && hptr != NULL && sptr < hptr)
		{
			plen = (size_t)(sptr - (pptr + 5U));

			if (plen != 0U && plen < relen && plen < PQS_XFER_PATH_MAX)
			{
				qsc_memutils_clear((uint8_t*)relative, relen);
				qsc_memutils_copy(relative, pptr + 5U, plen);
				relative[plen] = '\0';

				endp = NULL;
				fsz = strtoull(sptr + 6U, &endp, 10);

				if (endp == hptr && qsc_stringutils_string_size(hptr + 6U) == (PQS_XFER_HASH_TEXT_SIZE - 1U) &&
					pqs_xfer_path_is_safe(relative) == true)
				{
					*filesize = (size_t)fsz;
					qsc_stringutils_copy_string(hexhash, hexlen, hptr + 6U);
					res = true;
				}
			}
		}
	}

	return res;
}

bool pqs_xfer_path_is_symlink(const char* path)
{
	PQS_ASSERT(path != NULL);

	bool res;

	res = false;

	if (path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		DWORD attr;

		attr = GetFileAttributesA(path);

		if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0U)
		{
			res = true;
		}
#else
		struct stat st;

		if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode) != 0)
		{
			res = true;
		}
#endif
	}

	return res;
}

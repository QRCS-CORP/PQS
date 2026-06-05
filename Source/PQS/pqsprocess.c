#include "pqsprocess.h"
#if defined(QSC_SYSTEM_OS_MAC) && !defined(_DARWIN_C_SOURCE)
#	define _DARWIN_C_SOURCE 1
#endif
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(_WIN32_WINNT)
#       define _WIN32_WINNT 0x0600
#   endif
#   include <windows.h>
#else
#   include <errno.h>
#   include <fcntl.h>
#   include <grp.h>
#   include <pwd.h>
#   include <signal.h>
#   include <sys/resource.h>
#   include <sys/select.h>
#   include <sys/time.h>
#   include <sys/types.h>
#   include <sys/wait.h>
#   include <time.h>
#   include <unistd.h>
#   if defined(QSC_SYSTEM_OS_LINUX)
#       include <sys/prctl.h>
#   endif
#endif

static bool pqs_process_shell_type_is_powershell(const char* type)
{
	bool res;

	res = false;

	if (type != NULL)
	{
		res = (qsc_stringutils_strings_equal(type, "powershell") == true ||
			qsc_stringutils_strings_equal(type, "pwsh") == true);
	}

	return res;
}

static bool pqs_process_sandbox_is_valid(const pqs_sandbox_profile* sandbox)
{
	bool res;

	res = false;

	if (sandbox != NULL && sandbox->enabled == true && sandbox->working_directory[0U] != '\0' &&
		pqs_sandbox_working_directory_valid(sandbox) == true)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = true;
#else
		res = (sandbox->allow_same_user == true ||
			sandbox->run_as_user[0U] != '\0' ||
			sandbox->run_as_group[0U] != '\0' ||
			sandbox->chroot_enabled == true);
#endif
	}

	return res;
}

#if defined(QSC_SYSTEM_OS_WINDOWS)
static bool pqs_process_utf8_to_wide(const char* input, wchar_t* output, size_t outlen)
{
	int32_t wlen;
	bool res;

	res = false;

	if (input != NULL && output != NULL && outlen != 0U && outlen <= (size_t)INT32_MAX)
	{
		wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, output, (int32_t)outlen);

		if (wlen == 0)
		{
			wlen = MultiByteToWideChar(CP_ACP, 0, input, -1, output, (int32_t)outlen);
		}

		res = (wlen > 0 && (size_t)wlen <= outlen);
	}

	return res;
}

static bool pqs_process_build_windows_shell_command(const pqs_shell_profile* profile, const char* command, char* output, size_t outlen)
{
	int32_t slen;
	bool res;

	res = false;

	if (profile != NULL && command != NULL && output != NULL && outlen != 0U)
	{
		if (pqs_process_shell_type_is_powershell(profile->type) == true)
		{
			slen = snprintf(output, outlen, "\"%s\" -NoProfile -ExecutionPolicy Bypass -Command %s", profile->path, command);
		}
		else
		{
			slen = snprintf(output, outlen, "\"%s\" /C %s", profile->path, command);
		}

		res = (slen > 0 && (size_t)slen < outlen);
	}

	return res;
}

static HANDLE pqs_process_create_restricted_token(void)
{
	HANDLE hproc;
	HANDLE hres;
	HANDLE htok;

	hres = NULL;
	htok = NULL;
	hproc = GetCurrentProcess();

	if (OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &htok) == TRUE)
	{
		if (CreateRestrictedToken(htok, DISABLE_MAX_PRIVILEGE, 0U, NULL, 0U, NULL, 0U, NULL, &hres) != TRUE)
		{
			hres = NULL;
		}

		CloseHandle(htok);
	}

	return hres;
}

static bool pqs_process_create_handle_list(LPPROC_THREAD_ATTRIBUTE_LIST* attrlist, HANDLE* handles, DWORD hcount)
{
	SIZE_T asize;
	bool res;

	res = false;
	asize = 0U;
	*attrlist = NULL;
	(void)InitializeProcThreadAttributeList(NULL, 1U, 0U, &asize);

	if (asize != 0U)
	{
		*attrlist = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, asize);

		if (*attrlist != NULL)
		{
			if (InitializeProcThreadAttributeList(*attrlist, 1U, 0U, &asize) == TRUE)
			{
				res = (UpdateProcThreadAttribute(*attrlist, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(HANDLE) * hcount, NULL, NULL) == TRUE);
			}
		}
	}

	return res;
}

static bool pqs_process_execute_windows(const char* command, const pqs_shell_profile* profile, const pqs_sandbox_profile* sandbox, pqs_process_output_callback callback, void* context, bool* timedout, bool* outputlimited)
{
	STARTUPINFOEXW si;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jli;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE handles[2U];
	HANDLE hjob;
	HANDLE hnul;
	HANDLE hrd;
	HANDLE htok;
	HANDLE hwr;
	DWORD avail;
	DWORD brd;
	DWORD elapsed;
	DWORD flags;
	DWORD timeout;
	DWORD waitres;
	size_t cbsize;
	size_t outputcount;
	size_t outputlimit;
	LPPROC_THREAD_ATTRIBUTE_LIST attrlist;
	char rbuf[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0 };
	char scmd[PQS_SERVER_COMMAND_MAX + PQS_SHELL_PROFILE_PATH_MAX + 96U] = { 0 };
	wchar_t wapp[PQS_SHELL_PROFILE_PATH_MAX] = { 0 };
	wchar_t wcwd[QSC_SYSTEM_MAX_PATH] = { 0 };
	wchar_t wcmd[PQS_SERVER_COMMAND_MAX + PQS_SHELL_PROFILE_PATH_MAX + 96U] = { 0 };
	wchar_t wenv[] = L"PATH=C:\\Windows\\System32\0SystemRoot=C:\\Windows\0\0";
	bool created;
	bool running;
	bool res;

	res = false;
	created = false;
	running = false;
	hrd = NULL;
	hwr = NULL;
	hnul = NULL;
	htok = NULL;
	hjob = NULL;
	attrlist = NULL;
	avail = 0U;
	brd = 0U;
	elapsed = 0U;
	timeout = pqs_sandbox_timeout_milliseconds(sandbox);
	outputcount = 0U;
	outputlimit = pqs_sandbox_output_limit_bytes(sandbox);
	cbsize = 0U;
	flags = CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;

	if (sandbox != NULL && sandbox->clear_environment == true)
	{
		flags |= CREATE_UNICODE_ENVIRONMENT;
	}

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&sa, sizeof(sa));
	ZeroMemory(&jli, sizeof(jli));

	if (timedout != NULL)
	{
		*timedout = false;
	}

	if (outputlimited != NULL)
	{
		*outputlimited = false;
	}

	if (command != NULL && profile != NULL && sandbox != NULL && callback != NULL &&
		pqs_process_sandbox_is_valid(sandbox) == true &&
		pqs_process_build_windows_shell_command(profile, command, scmd, sizeof(scmd)) == true &&
		pqs_process_utf8_to_wide(profile->path, wapp, sizeof(wapp) / sizeof(wapp[0U])) == true &&
		pqs_process_utf8_to_wide(scmd, wcmd, sizeof(wcmd) / sizeof(wcmd[0U])) == true &&
		pqs_process_utf8_to_wide(sandbox->working_directory, wcwd, sizeof(wcwd) / sizeof(wcwd[0U])) == true)
	{
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		if (CreatePipe(&hrd, &hwr, &sa, 0U) == TRUE)
		{
			(void)SetHandleInformation(hrd, HANDLE_FLAG_INHERIT, 0U);
			(void)SetHandleInformation(hwr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
			hnul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

			if (hnul != INVALID_HANDLE_VALUE)
			{
				(void)SetHandleInformation(hnul, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
				handles[0U] = hwr;
				handles[1U] = hnul;

				if (pqs_process_create_handle_list(&attrlist, handles, 2U) == true)
				{
					si.StartupInfo.cb = sizeof(si);
					si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
					si.StartupInfo.hStdInput = hnul;
					si.StartupInfo.hStdOutput = hwr;
					si.StartupInfo.hStdError = hwr;
					si.lpAttributeList = attrlist;

					htok = pqs_process_create_restricted_token();
					created = false;

					if (htok != NULL)
					{
						created = (CreateProcessAsUserW(htok, NULL, wcmd, NULL, NULL, TRUE, flags, sandbox->clear_environment == true ? wenv : NULL, wcwd, &si.StartupInfo, &pi) == TRUE);
					}

					if (created == false && sandbox->allow_same_user == true)
					{
						created = (CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, flags, sandbox->clear_environment == true ? wenv : NULL, wcwd, &si.StartupInfo, &pi) == TRUE);
					}

					if (created == true)
					{
							CloseHandle(hwr);
							hwr = NULL;
							hjob = CreateJobObjectW(NULL, NULL);

							if (hjob != NULL)
							{
								jli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
								(void)SetInformationJobObject(hjob, JobObjectExtendedLimitInformation, &jli, sizeof(jli));
								(void)AssignProcessToJobObject(hjob, pi.hProcess);
							}

							if (pi.hThread != NULL)
							{
								CloseHandle(pi.hThread);
								pi.hThread = NULL;
							}

							running = true;
							res = true;

							while (running == true)
							{
								if (PeekNamedPipe(hrd, NULL, 0U, NULL, &avail, NULL) == TRUE && avail != 0U)
								{
									if (ReadFile(hrd, rbuf, (DWORD)sizeof(rbuf), &brd, NULL) == TRUE && brd != 0U)
									{
										cbsize = (size_t)brd;

										if (outputlimit != 0U && outputcount + cbsize > outputlimit)
										{
											cbsize = outputlimit - outputcount;
										}

										if (cbsize != 0U && callback(context, rbuf, cbsize) == false)
										{
											running = false;
										}

										outputcount += cbsize;

										if (outputlimit != 0U && outputcount >= outputlimit)
										{
											(void)TerminateProcess(pi.hProcess, 125U);

											if (outputlimited != NULL)
											{
												*outputlimited = true;
											}

											running = false;
										}

										qsc_memutils_clear((uint8_t*)rbuf, sizeof(rbuf));
									}
								}
								else
								{
									waitres = WaitForSingleObject(pi.hProcess, 50U);

									if (waitres == WAIT_OBJECT_0)
									{
										running = false;
									}
									else if (timeout != 0U)
									{
										elapsed += 50U;

										if (elapsed >= timeout)
										{
											(void)TerminateProcess(pi.hProcess, 124U);

											if (timedout != NULL)
											{
												*timedout = true;
											}

											running = false;
										}
									}
								}
							}

							while (PeekNamedPipe(hrd, NULL, 0U, NULL, &avail, NULL) == TRUE && avail != 0U)
							{
								if (ReadFile(hrd, rbuf, (DWORD)sizeof(rbuf), &brd, NULL) == TRUE && brd != 0U)
								{
									cbsize = (size_t)brd;

									if (outputlimit != 0U && outputcount + cbsize > outputlimit)
									{
										cbsize = outputlimit - outputcount;
									}

									if (cbsize != 0U)
									{
										(void)callback(context, rbuf, cbsize);
										outputcount += cbsize;
									}

									qsc_memutils_clear((uint8_t*)rbuf, sizeof(rbuf));

									if (outputlimit != 0U && outputcount >= outputlimit)
									{
										break;
									}
								}
								else
								{
									break;
								}
							}

							(void)WaitForSingleObject(pi.hProcess, INFINITE);
							CloseHandle(pi.hProcess);
							pi.hProcess = NULL;
						}
					}
				}
			}
		}

	if (attrlist != NULL)
	{
		DeleteProcThreadAttributeList(attrlist);
		HeapFree(GetProcessHeap(), 0U, attrlist);
	}

	if (hjob != NULL)
	{
		CloseHandle(hjob);
	}

	if (htok != NULL)
	{
		CloseHandle(htok);
	}

	if (hwr != NULL)
	{
		CloseHandle(hwr);
	}

	if (hrd != NULL)
	{
		CloseHandle(hrd);
	}

	if (hnul != NULL && hnul != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hnul);
	}

	qsc_memutils_secure_erase((uint8_t*)scmd, sizeof(scmd));
	qsc_memutils_secure_erase((uint8_t*)wapp, sizeof(wapp));
	qsc_memutils_secure_erase((uint8_t*)wcwd, sizeof(wcwd));
	qsc_memutils_secure_erase((uint8_t*)wcmd, sizeof(wcmd));

	return res;
}
#else
typedef struct pqs_process_identity
{
	uid_t uid;
	gid_t gid;
	bool uidset;
	bool gidset;
} pqs_process_identity;

static bool pqs_process_resolve_identity(const pqs_sandbox_profile* sandbox, pqs_process_identity* identity)
{
	const struct passwd* pw;
	const struct group* gr;
	bool res;

	res = false;
	pw = NULL;
	gr = NULL;

	if (sandbox != NULL && identity != NULL)
	{
		identity->uid = (uid_t)0;
		identity->gid = (gid_t)0;
		identity->uidset = false;
		identity->gidset = false;
		res = true;

		if (sandbox->run_as_group[0U] != '\0')
		{
			gr = getgrnam(sandbox->run_as_group);
			res = (gr != NULL);

			if (res == true)
			{
				identity->gid = gr->gr_gid;
				identity->gidset = true;
			}
		}

		if (res == true && sandbox->run_as_user[0U] != '\0')
		{
			pw = getpwnam(sandbox->run_as_user);
			res = (pw != NULL);

			if (res == true)
			{
				identity->uid = pw->pw_uid;
				identity->uidset = true;

				if (identity->gidset == false)
				{
					identity->gid = pw->pw_gid;
					identity->gidset = true;
				}
			}
		}
	}

	return res;
}

static void pqs_process_close_child_descriptors(void)
{
	long maxfd;
	int32_t fd;

	maxfd = sysconf(_SC_OPEN_MAX);

	if (maxfd < 0L || maxfd > 65536L)
	{
		maxfd = 65536L;
	}

	for (fd = 3; fd < (int32_t)maxfd; ++fd)
	{
		(void)close(fd);
	}
}

static bool pqs_process_create_pipe(int32_t fds[2U])
{
	bool res;

	res = false;
	fds[0U] = -1;
	fds[1U] = -1;

	if (pipe(fds) == 0)
	{
		(void)fcntl(fds[0U], F_SETFD, FD_CLOEXEC);
		(void)fcntl(fds[1U], F_SETFD, FD_CLOEXEC);
		res = true;
	}

	return res;
}

static void pqs_process_apply_limits(const pqs_sandbox_profile* sandbox)
{
	struct rlimit rl;

	if (sandbox != NULL)
	{
		if (sandbox->command_timeout_seconds != 0U)
		{
			rl.rlim_cur = (rlim_t)(sandbox->command_timeout_seconds + 1U);
			rl.rlim_max = (rlim_t)(sandbox->command_timeout_seconds + 1U);
			(void)setrlimit(RLIMIT_CPU, &rl);
		}

#if defined(RLIMIT_NOFILE)
		rl.rlim_cur = 16U;
		rl.rlim_max = 16U;
		(void)setrlimit(RLIMIT_NOFILE, &rl);
#endif

#if defined(RLIMIT_NPROC)
		rl.rlim_cur = 16U;
		rl.rlim_max = 16U;
		(void)setrlimit(RLIMIT_NPROC, &rl);
#endif

#if defined(RLIMIT_FSIZE)
		rl.rlim_cur = 16U * 1024U * 1024U;
		rl.rlim_max = 16U * 1024U * 1024U;
		(void)setrlimit(RLIMIT_FSIZE, &rl);
#endif
	}
}

static bool pqs_process_apply_confinement(const pqs_sandbox_profile* sandbox, const pqs_process_identity* identity)
{
	bool res;

	res = false;

	if (sandbox != NULL && identity != NULL)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		(void)prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
		(void)prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL);
#endif
#if !defined(QSC_SYSTEM_OS_MAC)
		if (getuid() == (uid_t)0 && chroot(sandbox->working_directory) == 0 && chdir("/") == 0)
		{
			res = true;
		}
		else
#endif
		{
			if (chdir(sandbox->working_directory) == 0)
			{
				res = true;
			}
		}

		if (res == true && getuid() == (uid_t)0)
		{
			if (identity->uidset == true && identity->gidset == true)
			{
				if (sandbox->run_as_user[0U] != '\0')
				{
					(void)initgroups(sandbox->run_as_user, identity->gid);
				}

				res = (setgid(identity->gid) == 0 && setuid(identity->uid) == 0);
			}
			else
			{
				res = false;
			}
		}
		else if (res == true && identity->uidset == true)
		{
			res = (getuid() == identity->uid);
		}
	}

	return res;
}

static bool pqs_process_execute_posix(const char* command, const pqs_shell_profile* profile, const pqs_sandbox_profile* sandbox, pqs_process_output_callback callback, void* context, bool* timedout, bool* outputlimited)
{
	char* const penv[] = { "PATH=/usr/bin:/bin", "LANG=C", NULL };
	fd_set readset;
	pqs_process_identity identity;
	pid_t pid;
	struct timeval tv;
	time_t startt;
	time_t nowt;
	int32_t devnull;
	int32_t fds[2U];
	int32_t sel;
	int32_t status;
	ssize_t rlen;
	size_t cbsize;
	size_t outputcount;
	size_t outputlimit;
	char rbuf[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0 };
	bool exited;
	bool running;
	bool res;

	res = false;
	devnull = -1;
	fds[0U] = -1;
	fds[1U] = -1;
	status = 0;
	exited = false;
	running = false;
	startt = time(NULL);
	outputcount = 0U;
	outputlimit = pqs_sandbox_output_limit_bytes(sandbox);
	cbsize = 0U;

	if (timedout != NULL)
	{
		*timedout = false;
	}

	if (outputlimited != NULL)
	{
		*outputlimited = false;
	}

	if (command != NULL && profile != NULL && sandbox != NULL && callback != NULL &&
		pqs_process_sandbox_is_valid(sandbox) == true &&
		pqs_process_resolve_identity(sandbox, &identity) == true &&
		pqs_process_create_pipe(fds) == true)
	{
#if defined(O_CLOEXEC)
		devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
#else
		devnull = open("/dev/null", O_RDONLY);
#endif

		if (devnull >= 0)
		{
			(void)fcntl(devnull, F_SETFD, FD_CLOEXEC);
			pid = fork();

			if (pid == 0)
			{
				(void)close(fds[0U]);
				(void)dup2(devnull, STDIN_FILENO);
				(void)dup2(fds[1U], STDOUT_FILENO);
				(void)dup2(fds[1U], STDERR_FILENO);
				(void)close(devnull);
				(void)close(fds[1U]);
				pqs_process_close_child_descriptors();
				pqs_process_apply_limits(sandbox);

				if (pqs_process_apply_confinement(sandbox, &identity) == false)
				{
					_exit(126);
				}

				if (pqs_process_shell_type_is_powershell(profile->type) == true)
				{
					if (sandbox->clear_environment == true)
					{
						execle(profile->path, profile->path, "-NoProfile", "-Command", command, (char*)NULL, penv);
					}
					else
					{
						execl(profile->path, profile->path, "-NoProfile", "-Command", command, (char*)NULL);
					}
				}
				else
				{
					if (sandbox->clear_environment == true)
					{
						execle(profile->path, profile->path, "-c", command, (char*)NULL, penv);
					}
					else
					{
						execl(profile->path, profile->path, "-c", command, (char*)NULL);
					}
				}

				_exit(127);
			}
			else if (pid > 0)
			{
				(void)close(fds[1U]);
				(void)close(devnull);
				fds[1U] = -1;
				devnull = -1;
				running = true;
				res = true;

				while (running == true)
				{
					FD_ZERO(&readset);
					FD_SET(fds[0U], &readset);
					tv.tv_sec = 0;
					tv.tv_usec = 250000;
					sel = select(fds[0U] + 1, &readset, NULL, NULL, &tv);

					if (sel > 0 && FD_ISSET(fds[0U], &readset))
					{
						rlen = read(fds[0U], rbuf, sizeof(rbuf));

						if (rlen > 0)
						{
							cbsize = (size_t)rlen;

							if (outputlimit != 0U && outputcount + cbsize > outputlimit)
							{
								cbsize = outputlimit - outputcount;
							}

							if (cbsize != 0U && callback(context, rbuf, cbsize) == false)
							{
								running = false;
							}

							outputcount += cbsize;

							if (outputlimit != 0U && outputcount >= outputlimit)
							{
								(void)kill(pid, SIGKILL);

								if (outputlimited != NULL)
								{
									*outputlimited = true;
								}

								running = false;
							}

							qsc_memutils_clear((uint8_t*)rbuf, sizeof(rbuf));
						}
						else
						{
							running = false;
						}
					}

					if (waitpid(pid, &status, WNOHANG) == pid)
					{
						exited = true;
						running = false;
					}

					if (sandbox->command_timeout_seconds != 0U)
					{
						nowt = time(NULL);

						if (nowt != (time_t)-1 && startt != (time_t)-1 && (uint32_t)(nowt - startt) >= sandbox->command_timeout_seconds)
						{
							(void)kill(pid, SIGKILL);
							(void)waitpid(pid, &status, 0);

							if (timedout != NULL)
							{
								*timedout = true;
							}

							exited = true;
							running = false;
						}
					}
				}

				while (true)
				{
					FD_ZERO(&readset);
					FD_SET(fds[0U], &readset);
					tv.tv_sec = 0;
					tv.tv_usec = 0;
					sel = select(fds[0U] + 1, &readset, NULL, NULL, &tv);

					if (sel > 0 && FD_ISSET(fds[0U], &readset))
					{
						rlen = read(fds[0U], rbuf, sizeof(rbuf));

						if (rlen > 0)
						{
							cbsize = (size_t)rlen;

							if (outputlimit != 0U && outputcount + cbsize > outputlimit)
							{
								cbsize = outputlimit - outputcount;
							}

							if (cbsize != 0U)
							{
								(void)callback(context, rbuf, cbsize);
								outputcount += cbsize;
							}

							qsc_memutils_clear((uint8_t*)rbuf, sizeof(rbuf));

							if (outputlimit != 0U && outputcount >= outputlimit)
							{
								break;
							}
						}
						else
						{
							break;
						}
					}
					else
					{
						break;
					}
				}

				if (exited == false)
				{
					(void)waitpid(pid, &status, 0);
				}
			}
		}
	}

	if (devnull >= 0)
	{
		(void)close(devnull);
	}

	if (fds[0U] >= 0)
	{
		(void)close(fds[0U]);
	}

	if (fds[1U] >= 0)
	{
		(void)close(fds[1U]);
	}

	return res;
}
#endif

bool pqs_process_execute(const char* command, size_t cmdlen, const pqs_shell_profile* profile, const pqs_sandbox_profile* sandbox, pqs_process_output_callback callback, void* context, bool* timedout, bool* outputlimited)
{
	bool res;

	res = false;

	if (command != NULL && cmdlen != 0U && cmdlen < PQS_SERVER_COMMAND_MAX && profile != NULL && sandbox != NULL && callback != NULL && profile->path[0U] != '\0')
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = pqs_process_execute_windows(command, profile, sandbox, callback, context, timedout, outputlimited);
#else
		res = pqs_process_execute_posix(command, profile, sandbox, callback, context, timedout, outputlimited);
#endif
	}

	return res;
}

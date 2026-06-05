#include "pqshelp.h"
#include "consoleutils.h"


void pqs_help_client_print_banner(void)
{
	qsc_consoleutils_print_line("PQS: Post Quantum Shell Client");
	qsc_consoleutils_print_line("Quantum-Secure remote command shell client.");
	qsc_consoleutils_print_line("Enter the address, server public key, and password to connect.");
	qsc_consoleutils_print_line("Type ':quit' to close the connection and exit the application after login.");
	qsc_consoleutils_print_line("Local PQS commands use ':' after login: :key, :fp, :known, :khremove [host], :get, :put, :list, :mkdir, :remove, :help, :detail, :quit.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.1.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      June 03, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

void pqs_help_client_print_detail(void)
{
	qsc_consoleutils_print_line("***PQS CLIENT SETUP AND OPERATIONS***");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Purpose**");
	qsc_consoleutils_print_line("The PQS client connects to a PQS server over the QSMS encrypted transport.");
	qsc_consoleutils_print_line("After the encrypted channel is established, the client authenticates with");
	qsc_consoleutils_print_line("a PQS username and passphrase. The authenticated session can execute");
	qsc_consoleutils_print_line("permitted commands and use the PQS encrypted file-transfer subsystem.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Initial setup**");
	qsc_consoleutils_print_line("1. Obtain the server public key from the server administrator.");
	qsc_consoleutils_print_line("2. Verify the server public-key fingerprint out-of-band.");
	qsc_consoleutils_print_line("3. Start the client and enter the server address, public-key path,");
	qsc_consoleutils_print_line("   username, and passphrase when prompted.");
	qsc_consoleutils_print_line("4. On first contact with a server, review the displayed SHA3-256");
	qsc_consoleutils_print_line("   fingerprint before saving the known-hosts entry.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Host trust commands**");
	qsc_consoleutils_print_line("*key, fp, fingerprint -Display the loaded server public key and SHA3-256 fingerprint.");
	qsc_consoleutils_print_line("*known, khlist -Display the client known-hosts database.");
	qsc_consoleutils_print_line("*khremove [host] -Remove a pinned known-hosts entry.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Remote command execution**");
	qsc_consoleutils_print_line("Any input that is not a client control command is sent as a remote");
	qsc_consoleutils_print_line("command request. The server authorizes the request using the authenticated");
	qsc_consoleutils_print_line("user's privilege level, command policy, and assigned shell profile.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**File-transfer commands**");
	qsc_consoleutils_print_line("get [remote-path] [local-path] -Download one remote file.");
	qsc_consoleutils_print_line("get -r [remote-directory] [local-directory] -Recursively download a remote directory.");
	qsc_consoleutils_print_line("put [local-path] [remote-path] -Upload one local file.");
	qsc_consoleutils_print_line("put -r [local-directory] [remote-directory] -Recursively upload a local directory.");
	qsc_consoleutils_print_line("list [remote-path] -List a remote directory.");
	qsc_consoleutils_print_line("mkdir [remote-path] -Create a remote directory.");
	qsc_consoleutils_print_line("remove [remote-path] -Remove a remote file.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**File-transfer security**");
	qsc_consoleutils_print_line("Transfers are carried inside the authenticated QSMS/PQS channel. The");
	qsc_consoleutils_print_line("server confines remote paths under the authenticated user's transfer root.");
	qsc_consoleutils_print_line("Absolute paths, drive-letter paths, parent traversal, and symbolic-link");
	qsc_consoleutils_print_line("escapes are rejected. File transfers include SHA3-256 metadata and progress reporting.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Session commands**");
	qsc_consoleutils_print_line("help -Display the short client command help.");
	qsc_consoleutils_print_line("detail - Display this detailed setup and operations guide.");
	qsc_consoleutils_print_line("quit -Close the PQS session and exit the client.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Configuration**");
	qsc_consoleutils_print_line("The client uses pqs.conf for persistent defaults such as application path,");
	qsc_consoleutils_print_line("server public-key path, known-hosts path, log path, target host, target");
	qsc_consoleutils_print_line("port, default username, log level, and strict host-key checking.");
	qsc_consoleutils_print_line("");
}

void pqs_help_client_print_help(void)
{
	qsc_consoleutils_print_line("client mode commands:");
	qsc_consoleutils_print_line(":key -Display the connected server public key and fingerprint.");
	qsc_consoleutils_print_line(":fp -Display the connected server public-key fingerprint.");
	qsc_consoleutils_print_line(":known -List known-host entries.");
	qsc_consoleutils_print_line(":khremove [host] -Remove a host entry from the known-hosts database.");
	qsc_consoleutils_print_line(":get [rpath] [lpath] -Download a file from the server.");
	qsc_consoleutils_print_line(":get -r [rdir] [ldir] -Recursively download a directory from the server.");
	qsc_consoleutils_print_line(":put [lpath] [rpath] -Upload a file to the server.");
	qsc_consoleutils_print_line(":put -r [ldir] [rdir] -Recursively upload a directory from the client to the server.");
	qsc_consoleutils_print_line(":list [rpath] -List files using the PQS file-transfer subsystem.");
	qsc_consoleutils_print_line(":mkdir [rpath] -Create a directory using the PQS file-transfer subsystem.");
	qsc_consoleutils_print_line(":remove [rpath] -Remove a file using the PQS file-transfer subsystem.");
	qsc_consoleutils_print_line(":admin [status|version|fingerprint|sandbox|audit verify|config|users|policies|shells] -Run a typed administrative command.");
	qsc_consoleutils_print_line(":help -Show this help.");
	qsc_consoleutils_print_line(":detail -Show detailed setup and operations help.");
	qsc_consoleutils_print_line(":quit -Shut down the PQS client.");
	qsc_consoleutils_print_line("After login, unprefixed input is sent to the remote shell.");
}

void pqs_help_server_print_banner(void)
{
	qsc_consoleutils_print_line("PQS: Post Quantum Shell Server");
	qsc_consoleutils_print_line("Quantum-Secure remote command shell server.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.1.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      June 03, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

void pqs_help_server_print_detail(void)
{
	qsc_consoleutils_print_line("PQS SERVER SETUP AND OPERATIONS");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("***Purpose***");
	qsc_consoleutils_print_line("The PQS server provides a post-quantum secure remote command and file");
	qsc_consoleutils_print_line("transfer service over QSMS. The server authenticates users through the");
	qsc_consoleutils_print_line("PQS user database, applies privilege and command policy, selects an");
	qsc_consoleutils_print_line("authorized shell profile, and records security-relevant events in the");
	qsc_consoleutils_print_line("structured audit log.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Initial setup**");
	qsc_consoleutils_print_line("1. Start the server once to create the application directory, configuration");
	qsc_consoleutils_print_line("   file, server key material, user database, shell database, policy database, and log file.");
	qsc_consoleutils_print_line("2. Run the key or fingerprint command and distribute the server public key");
	qsc_consoleutils_print_line("   and SHA3-256 fingerprint to clients through an authenticated channel.");
	qsc_consoleutils_print_line("3. Enter user mode and create at least one administrative user.");
	qsc_consoleutils_print_line("4. Review shell profiles and command policies before allowing remote shell access.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Root server commands");
	qsc_consoleutils_print_line("user -Enter user administration mode.");
	qsc_consoleutils_print_line("shell -Enter shell profile administration mode.");
	qsc_consoleutils_print_line("policy -Enter command policy administration mode.");
	qsc_consoleutils_print_line("key -Display the encoded server public key and fingerprint.");
	qsc_consoleutils_print_line("fp, fingerprint -Display the server public-key fingerprint.");
	qsc_consoleutils_print_line("keyscan -Display a known-hosts-compatible host|fingerprint line.");
	qsc_consoleutils_print_line("sandbox -Display command sandbox status.");
	qsc_consoleutils_print_line("help -Display the short server command help.");
	qsc_consoleutils_print_line("detail -Display this detailed setup and operations guide.");
	qsc_consoleutils_print_line("quit -Stop the PQS server.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**User mode commands**");
	qsc_consoleutils_print_line("add [username] [guest|user|admin] -Create a user and print a generated passphrase once.");
	qsc_consoleutils_print_line("remove [username] -Remove a user record.");
	qsc_consoleutils_print_line("enable [username] / disable [username] -Enable or disable a user account.");
	qsc_consoleutils_print_line("passwd [username] -Generate a new user passphrase and update the SCB verifier.");
	qsc_consoleutils_print_line("privilege [username] [guest|user|admin] -Change a user's privilege level.");
	qsc_consoleutils_print_line("show [username] -Display a user record without secret material.");
	qsc_consoleutils_print_line("list -List configured users.");
	qsc_consoleutils_print_line("exit -Return to server mode.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Shell mode commands**");
	qsc_consoleutils_print_line("list -List configured shell profiles.");
	qsc_consoleutils_print_line("add [name] [type] [path] -Add a shell profile. Common types include cmd, powershell, pwsh, sh, bash, zsh, and custom.");
	qsc_consoleutils_print_line("remove [name] -Remove a shell profile.");
	qsc_consoleutils_print_line("enable [name] / disable [name] -Enable or disable a shell profile.");
	qsc_consoleutils_print_line("default [name] -Set the default shell profile.");
	qsc_consoleutils_print_line("assign [username] [name] -Assign a shell profile to a user.");
	qsc_consoleutils_print_line("allow [guest|user|admin] [name] / deny [guest|user|admin] [name] -Update the privilege mask for a shell profile.");
	qsc_consoleutils_print_line("show [name] -Display a shell profile.");
	qsc_consoleutils_print_line("exit -Return to server mode.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Policy mode commands** ");
	qsc_consoleutils_print_line("list -List command policies.");
	qsc_consoleutils_print_line("add [name] [no-shell|restricted|forced|raw-shell] -Add a command policy.");
	qsc_consoleutils_print_line("remove [name] -Remove a command policy.");
	qsc_consoleutils_print_line("enable [name] / disable [name] -Enable or disable a policy.");
	qsc_consoleutils_print_line("mode [name] [no-shell|restricted|forced|raw-shell] -Change a policy enforcement mode.");
	qsc_consoleutils_print_line("allow [name] [command] / deny [name] [command] -Add a command verb to a policy allow-list or deny-list.");
	qsc_consoleutils_print_line("unallow [name] [command] / undeny [name] [command] -Remove a command verb from a policy allow-list or deny-list.");
	qsc_consoleutils_print_line("force [name] [command] -Set the forced command for a forced-command policy.");
	qsc_consoleutils_print_line("assign [guest|user|admin] [name] -Assign a policy to a privilege level.");
	qsc_consoleutils_print_line("show [name] -Display a policy record.");
	qsc_consoleutils_print_line("exit -Return to server mode.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("**Authentication and authorization**");
	qsc_consoleutils_print_line("Users authenticate with a username and passphrase over the encrypted QSMS");
	qsc_consoleutils_print_line("channel. The server stores only SCB verifier material and never stores the");
	qsc_consoleutils_print_line("plaintext passphrase. After login, command execution is authorized by the");
	qsc_consoleutils_print_line("user's privilege, assigned command policy, and permitted shell profile.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("File-transfer operations");
	qsc_consoleutils_print_line("The server supports get, put, list, mkdir, remove, recursive upload, and");
	qsc_consoleutils_print_line("recursive download over the encrypted PQS channel. Remote file paths are");
	qsc_consoleutils_print_line("confined under a per-user transfer root. File metadata includes SHA3-256");
	qsc_consoleutils_print_line("hashes, and symbolic-link or traversal escapes are rejected.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Configuration and logs");
	qsc_consoleutils_print_line("The server uses pqsd.conf for paths, logging, sandbox settings, timeouts,");
	qsc_consoleutils_print_line("and operational limits. User, shell, and policy records are stored in");
	qsc_consoleutils_print_line("separate server database files. Logs record operational and audit events");
	qsc_consoleutils_print_line("without writing passphrases, verifiers, private keys, session keys, nonces,");
	qsc_consoleutils_print_line("transcript hashes, or command output.");
	qsc_consoleutils_print_line("");
}

void pqs_help_server_print_help(void)
{
	qsc_consoleutils_print_line("shell mode commands:");
	qsc_consoleutils_print_line("list -List shell profiles.");
	qsc_consoleutils_print_line("add [name] [type] [path] -Add a shell profile.");
	qsc_consoleutils_print_line("remove [name] -Remove a shell profile.");
	qsc_consoleutils_print_line("enable [name] -Enable a shell profile.");
	qsc_consoleutils_print_line("disable [name] -Disable a shell profile.");
	qsc_consoleutils_print_line("default [name] -Set the default shell profile.");
	qsc_consoleutils_print_line("assign [username] [name] -Assign a shell profile to a user.");
	qsc_consoleutils_print_line("allow [guest|user|admin] [name] -Allow a privilege to use a profile.");
	qsc_consoleutils_print_line("deny [guest|user|admin] [name] -Deny a privilege from using a profile.");
	qsc_consoleutils_print_line("show [name] -Show a shell profile.");
	qsc_consoleutils_print_line("help -Show this help.");
	qsc_consoleutils_print_line("detail -Show detailed setup and operations help.");
	qsc_consoleutils_print_line("exit -Return to server mode.");
}

void pqs_help_server_print_policy(void)
{
	qsc_consoleutils_print_line("policy mode commands:");
	qsc_consoleutils_print_line("list -List command policies and privilege assignments.");
	qsc_consoleutils_print_line("add [name] [no-shell|restricted|forced|raw-shell]  -Add a command policy.");
	qsc_consoleutils_print_line("remove [name] -Remove an unassigned command policy.");
	qsc_consoleutils_print_line("enable [name] -Enable a command policy.");
	qsc_consoleutils_print_line("disable [name] -Disable a command policy.");
	qsc_consoleutils_print_line("mode [name] [no-shell|restricted|forced|raw-shell] -Set a policy mode.");
	qsc_consoleutils_print_line("force [name] [command] -Set the forced command for a policy.");
	qsc_consoleutils_print_line("allow [name] [command] -Add a command to the policy allow-list.");
	qsc_consoleutils_print_line("deny [name] [command] -Add a command to the policy deny-list.");
	qsc_consoleutils_print_line("unallow [name] [command] -Remove a command from the allow-list.");
	qsc_consoleutils_print_line("undeny [name] [command] -Remove a command from the deny-list.");
	qsc_consoleutils_print_line("assign [guest|user|admin] [name] -Assign a policy to a privilege level.");
	qsc_consoleutils_print_line("show [name] -Show a command policy.");
	qsc_consoleutils_print_line("help -Show this help.");
	qsc_consoleutils_print_line("detail -Show detailed setup and operations help.");
	qsc_consoleutils_print_line("exit -Return to server mode.");
}

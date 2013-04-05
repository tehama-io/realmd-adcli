/*
 * adcli
 *
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EFAIL  (-ADCLI_ERR_FAIL)
#define EUSAGE (-ADCLI_ERR_CONFIG)

static char *adcli_temp_directory = NULL;
static char *adcli_krb5_conf_filename = NULL;
static char *adcli_krb5_d_directory = NULL;

static char *
prompt_password_func (adcli_login_type login_type,
                      const char *name,
                      int flags,
                      void *unused_data)
{
	char *prompt;
	char *password;
	char *result;

	if (asprintf (&prompt, "Password for %s: ", name) < 0)
		return_val_if_reached (NULL);

	password = getpass (prompt);
	free (prompt);

	if (password == NULL)
		return NULL;

	result = strdup (password);
	adcli_mem_clear (password, strlen (password));

	return result;
}

static char *
read_password_func (adcli_login_type login_type,
                    const char *name,
                    int flags,
                    void *unused_data)
{
	char *buffer = NULL;
	size_t length = 0;
	size_t offset = 0;
	ssize_t res;

	for (;;) {
		if (offset >= length) {
			length += 4096;
			buffer = realloc (buffer, length + 1);
			return_val_if_fail (buffer != NULL, NULL);
		}

		res = read (0, buffer + offset, length - offset);
		if (res < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			err (EFAIL, "couldn't read password from stdin");

		} else if (res == 0) {
			buffer[offset] = '\0';
			return buffer;

		} else {
			if (memchr (buffer + offset, 0, res))
				errx (EUSAGE, "unsupported null character present in password");
			offset += res;
		}
	}
}

static void
cleanup_krb5_conf_directory (void)
{
	if (adcli_krb5_d_directory) {
		rmdir (adcli_krb5_d_directory);
		free (adcli_krb5_d_directory);
		adcli_krb5_d_directory = NULL;
	}

	if (adcli_krb5_conf_filename) {
		unlink (adcli_krb5_conf_filename);
		free (adcli_krb5_conf_filename);
		adcli_krb5_conf_filename = NULL;
	}

	if (adcli_temp_directory) {
		rmdir (adcli_temp_directory);
		free (adcli_temp_directory);
		adcli_temp_directory = NULL;
	}

	unsetenv ("KRB5_CONFIG");
}

static void
setup_krb5_conf_directory (adcli_conn *conn)
{
	const char *parent;
	const char *krb5_conf;
	char *filename = NULL;
	char *snippets = NULL;
	char *contents = NULL;
	char *directory = NULL;
	struct stat sb;
	int errn = 0;
	FILE *fo;

	krb5_conf = getenv ("KRB5_CONFIG");
	if (!krb5_conf || !krb5_conf[0])
		krb5_conf = KRB5_CONFIG;

	parent = getenv ("TMPDIR");
	if (!parent || !*parent)
		parent = _PATH_TMP;

	/* Check that the config file exists, don't include if not */
	if (stat (krb5_conf, &sb) < 0) {
		if (errno != ENOENT)
			warn ("couldn't access file: %s", krb5_conf);
		krb5_conf = NULL;
	}

	if (asprintf (&directory, "%s%sadcli-krb5-XXXXXX", parent,
	              (parent[0] && parent[strlen(parent) - 1]) == '/' ? "" : "/") < 0)
		errx (1, "unexpected: out of memory");

	if (mkdtemp (directory) == NULL) {
		errn = errno;
		warnx ("couldn't create temporary directory in: %s: %s",
		       parent, strerror (errn));
	} else {
		if (asprintf (&filename, "%s/krb5.conf", directory) < 0 ||
		    asprintf (&snippets, "%s/krb5.d", directory) < 0 ||
		    asprintf (&contents, "%s%s\nincludedir %s\n",
		              krb5_conf ? "include " : "",
		              krb5_conf ? krb5_conf : "", snippets) < 0)
			errx (1, "unexpected: out of memory");
	}

	if (errn == 0) {
		fo = fopen (filename, "wb");
		if (fo == NULL) {
			errn = errno;
		} else {
			fwrite (contents, 1, strlen (contents), fo);
			if (ferror (fo))
				errn = errno;
			fclose (fo);
			if (!errn && ferror (fo))
				errn = errno;
		}

		if (errn) {
			warnx ("couldn't write new krb5.conf file: %s: %s",
			       filename, strerror (errn));
		}
	}


	if (errn == 0 && mkdir (snippets, 0700) < 0) {
		errn = errno;
		warnx ("couldn't write new krb5.d directory: %s: %s",
		       snippets, strerror (errn));
	}

	if (errn == 0) {
		adcli_conn_set_krb5_conf_dir (conn, snippets);
		adcli_temp_directory = directory;
		adcli_krb5_conf_filename = filename;
		adcli_krb5_d_directory = snippets;
		setenv ("KRB5_CONFIG", adcli_krb5_conf_filename, 1);

	} else {
		free (filename);
		free (snippets);
		free (directory);
	}

	free (contents);
	atexit (cleanup_krb5_conf_directory);
}

static void
message_func (adcli_message_type type,
              const char *message,
              void *unused_data)
{
	const char *prefix = "";

	switch (type) {
	case ADCLI_MESSAGE_INFO:
		prefix = " * ";
		break;
	case ADCLI_MESSAGE_WARNING:
	case ADCLI_MESSAGE_ERROR:
		prefix = " ! ";
		break;
	}

	fprintf (stderr, "%s%s\n", prefix, message);
}

static void
dump_details (adcli_conn *conn,
              adcli_enroll *enroll)
{
	printf ("[domain]\n");
	printf ("domain-name = %s\n", adcli_conn_get_domain_name (conn));
	printf ("domain-realm = %s\n", adcli_conn_get_domain_realm (conn));
	printf ("domain-server = %s\n", adcli_conn_get_domain_server (conn));
	printf ("domain-short = %s\n", adcli_conn_get_domain_short (conn));
	printf ("naming-context = %s\n", adcli_conn_get_default_naming_context (conn));

	printf ("[computer]\n");
	printf ("host-fqdn = %s\n", adcli_conn_get_host_fqdn (conn));
	printf ("computer-name = %s\n", adcli_conn_get_computer_name (conn));
	printf ("computer-dn = %s\n", adcli_enroll_get_computer_dn (enroll));
	printf ("computer-ou = %s\n", adcli_enroll_get_computer_ou (enroll));

	printf ("[keytab]\n");
	printf ("kvno = %d\n", adcli_enroll_get_kvno (enroll));
	printf ("keytab = %s\n", adcli_enroll_get_keytab_name (enroll));
}

typedef enum {
	/* Have short equivalents */
	opt_domain = 'D',
	opt_domain_realm = 'R',
	opt_domain_server = 'S',
	opt_host_fqdn = 'H',
	opt_host_netbios = 'N',
	opt_host_keytab = 'K',
	opt_user = 'U',
	opt_login_ccache = 'C',
	opt_computer_ou = 'O',
	opt_service_name = 'V',
	opt_prompt_password = 'W',
	opt_verbose = 'v',

	/* Don't have short equivalents */
	opt_login_type = 1000,
	opt_ldap_url,
	opt_no_password,
	opt_stdin_password,
	opt_one_time_password,
	opt_show_details,
} Option;

static char
short_option (Option opt)
{
	if (isalpha (opt) || isdigit (opt))
		return (char)opt;
	return 0;
}

static void
usage_option (Option opt,
              const struct option *longopt,
              FILE *file)
{
	const char *long_name;
	char short_name;
	const char *description;
	const char *next;
	int spaces;
	int len;

	const int indent = 30;
	long_name = longopt->name;
	short_name = short_option (opt);
	description = NULL;

	switch (opt) {
	case opt_domain:
		description = "The active directory domain name.";
		break;
	case opt_domain_realm:
		description = "The kerberos realm for the domain.";
		break;
	case opt_domain_server:
		description = "The domain directory server to connect to.";
		break;
	case opt_host_fqdn:
		description = "Override the fully qualified domain name of the\n"
		              "local machine.";
		break;
	case opt_host_keytab:
		description = "The filename for the host kerberos keytab";
		break;
	case opt_host_netbios:
		description = "Override the netbios short name of the local\n"
		              "machine.";
		break;
	case opt_login_ccache:
		description = "Kerberos credential cache file which contains\n"
		              "ticket to used to connect to the domain.";
		break;
	case opt_user:
		description = "The user (usually administrative) login name of\n"
		              "the account to log into the domain as.";
		break;
	case opt_login_type:
		description = "Type of login allowed when connecting to the \n"
		              "domain. Should be either 'computer' or 'user'.\n"
		              "By default any type is allowed";
		break;
	case opt_ldap_url:
		description = "Full LDAP URL of the domain directory server\n"
		              "which to connect to.";
		break;
	case opt_computer_ou:
		description = "A LDAP DN representing an organizational unit in\n"
		              "which the computer account should be placed.";
		break;
	case opt_service_name:
		description = "An additional service name for a kerberos\n"
		              "service principal to be created on the account.";
		break;
	case opt_no_password:
		description = "Don't prompt for or read a password.";
		break;
	case opt_prompt_password:
		description = "Prompt for a password if necessary.";
		break;
	case opt_stdin_password:
		description = "Read a password from stdin if neccessary. Reads\n"
		              "until EOF and includes new lines.";
		break;
	case opt_one_time_password:
		description = "A password to use for the preset computer\n"
		              "accounts. If not specified this will default to\n"
		              "the default reset password for the account";
		break;
	case opt_verbose:
		description = "Show verbose progress and failure messages.";
		break;
	case opt_show_details:
		description = "Show information about joining the domain after\n"
		              "a successful join.";
		break;
	}

	if (short_name)
		len = fprintf (file, "  -%c, --%s", (int)short_name, long_name);
	else
		len = fprintf (file, "      --%s", long_name);

	if (len < indent)
		spaces = indent - len;
	else
		spaces = 1;

	if (!description)
		fprintf (file, "\n");
	while (description) {
		while (spaces-- > 0)
			fputc (' ', file);
		next = strchr (description, '\n');
		if (next) {
			next += 1;
			fprintf (file, "%.*s", (int)(next - description), description);
			description = next;
			spaces = indent;
		} else {
			fprintf (file, "%s\n", description);
			break;
		}
	}
}

static int
usage (int code,
       const char *command,
       const struct option *longopts,
       const char *arguments)
{
	FILE *file;
	int i;

	file = (code == 0) ? stdout : stderr;
	fprintf (file, "usage: adcli %s [options] %s\n",
	         command, arguments ? arguments : "");
	fprintf (file, "\nOptions:\n");

	for (i = 0; longopts[i].name != NULL; i++)
		usage_option ((Option)longopts[i].val, longopts + i, file);

	exit (code);
}

static char *
build_short_options (const struct option *longopts)
{
	char *options;
	char *p;
	char opt;
	int count = 0;
	int i;

	/* Number of characters */
	for (i = 0; longopts[i].name != NULL; i++)
		count++;

	p = options = malloc ((count * 2) + 1);
	return_val_if_fail (options != NULL, NULL);

	for (i = 0; i < count; i++) {
		opt = short_option (longopts[i].val);
		if (opt != 0) {
			*(p++) = (char)longopts[i].val;
			assert (longopts[i].has_arg != optional_argument);
			if (longopts[i].has_arg == required_argument)
				*(p++) = ':';
		}
	}

	*(p++) = '\0';
	return options;
}

static void
parse_option (Option opt,
              const char *optarg,
              adcli_conn *conn,
              adcli_enroll *enroll)
{
	static int no_password = 0;
	static int prompt_password = 0;
	static int stdin_password = 0;

	switch (opt) {
	case opt_login_ccache:
		adcli_conn_set_login_ccache_name (conn, optarg);
		return;
	case opt_user:
		if (adcli_conn_get_allowed_login_types (conn) & ADCLI_LOGIN_USER_ACCOUNT) {
			adcli_conn_set_user_name (conn, optarg);
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);
		} else {
			errx (EUSAGE, "cannot set --user if --login-type not set to 'user'");
		}
		return;
	case opt_login_type:
		if (strcmp (optarg, "computer") == 0) {
			if (adcli_conn_get_user_name (conn) != NULL)
				errx (EUSAGE, "cannot set --login-type to 'computer' if --user is set");
			else
				adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_COMPUTER_ACCOUNT);
		} else if (strcmp (optarg, "user") == 0) {
			adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

		} else {
			errx (EUSAGE, "unknown login type '%s'", optarg);
		}
		return;
	case opt_host_fqdn:
		adcli_conn_set_host_fqdn (conn, optarg);
		return;
	case opt_host_keytab:
		adcli_enroll_set_keytab_name (enroll, optarg);
		return;
	case opt_host_netbios:
		adcli_conn_set_computer_name (conn, optarg);
		adcli_enroll_set_computer_name (enroll, optarg);
		return;
	case opt_domain:
		adcli_conn_set_domain_name (conn, optarg);
		return;
	case opt_domain_realm:
		adcli_conn_set_domain_realm (conn, optarg);
		return;
	case opt_domain_server:
		adcli_conn_set_domain_server (conn, optarg);
		return;
	case opt_ldap_url:
		adcli_conn_add_ldap_url (conn, optarg);
		return;
	case opt_computer_ou:
		adcli_enroll_set_computer_ou (enroll, optarg);
		return;
	case opt_service_name:
		adcli_enroll_add_service_name (enroll, optarg);
		return;
	case opt_no_password:
		if (stdin_password || prompt_password) {
			errx (EUSAGE, "cannot use --no-password argument with %s",
			      stdin_password ? "--stdin-password" : "--prompt-password");
		} else {
			adcli_conn_set_password_func (conn, NULL, NULL, NULL);
			no_password = 1;
		}
		return;
	case opt_prompt_password:
		if (stdin_password || no_password) {
			errx (EUSAGE, "cannot use --prompt-password argument with %s",
			      stdin_password ? "--stdin-password" : "--no-password");
		} else {
			adcli_conn_set_password_func (conn, prompt_password_func, NULL, NULL);
			prompt_password = 1;
		}
		return;
	case opt_stdin_password:
		if (prompt_password || no_password) {
			errx (EUSAGE, "cannot use --stdin-password argument with %s",
			      prompt_password ? "--prompt-password" : "--no-password");
		} else {
			adcli_conn_set_password_func (conn, read_password_func, NULL, NULL);
			stdin_password = 1;
		}
		return;
	case opt_one_time_password:
		adcli_enroll_set_computer_password (enroll, optarg);
		return;
	case opt_verbose:
		adcli_conn_set_message_func (conn, message_func, NULL, NULL);
		return;

	/* Should be handled by caller */
	case opt_show_details:
		return_if_reached();
		break;
	}

	errx (EUSAGE, "failure to parse option '%c'", opt);
}

static int
adcli_join (int argc,
            char *argv[])
{
	adcli_enroll_flags flags = ADCLI_ENROLL_ALLOW_OVERWRITE;
	char *options;
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	int details = 0;
	int opt;

	struct option long_options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
		{ "user", required_argument, NULL, opt_user },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "login-type", required_argument, NULL, opt_login_type },
		{ "host-fqdn", required_argument, 0, opt_host_fqdn },
		{ "host-netbios", required_argument, 0, opt_host_netbios },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "computer-ou", required_argument, NULL, opt_computer_ou },
		{ "ldap-url", required_argument, NULL, opt_ldap_url },
		{ "service-name", required_argument, NULL, opt_service_name },
		{ "show-details", no_argument, NULL, opt_show_details },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	conn = adcli_conn_new (NULL);
	enroll = adcli_enroll_new (conn);
	if (conn == NULL || enroll == NULL)
		errx (-1, "unexpected memory problems");
	adcli_conn_set_password_func (conn, prompt_password_func, NULL, NULL);

	options = build_short_options (long_options);
	while ((opt = getopt_long (argc, argv, options, long_options, NULL)) != -1) {
		switch (opt) {
		case opt_show_details:
			details = 1;
			break;
		case 'h':
			usage (0, "join", long_options, NULL);
			break;
		case '?':
		case ':':
			usage (EUSAGE, "join", long_options, NULL);
			break;
		default:
			parse_option ((Option)opt, optarg, conn, enroll);
			break;
		}
	}

	free (options);
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage (EUSAGE, "join", long_options, NULL);

	setup_krb5_conf_directory (conn);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "couldn't connect to %s domain: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	res = adcli_enroll_join (enroll, flags);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "enroll in %s domain failed: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	if (details)
		dump_details (conn, enroll);

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);

	return 0;
}

static int
adcli_preset (int argc,
              char *argv[])
{
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	char *generated = NULL;
	char *options;
	adcli_enroll_flags flags;
	int reset_password = 1;
	int opt;
	int i;

	struct option long_options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
		{ "user", required_argument, NULL, opt_user },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "one-time-password", required_argument, 0, opt_one_time_password },
		{ "computer-ou", required_argument, NULL, opt_computer_ou },
		{ "ldap-url", required_argument, NULL, opt_ldap_url },
		{ "service-name", required_argument, NULL, opt_service_name },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	conn = adcli_conn_new (NULL);
	enroll = adcli_enroll_new (conn);
	if (conn == NULL || enroll == NULL)
		errx (-1, "unexpected memory problems");
	adcli_conn_set_password_func (conn, prompt_password_func, NULL, NULL);
	flags = ADCLI_ENROLL_NO_KEYTAB | ADCLI_ENROLL_ALLOW_OVERWRITE;

	options = build_short_options (long_options);

	while ((opt = getopt_long (argc, argv, options, long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage (0, "preset", long_options, "host.example.com ...");
			break;
		case '?':
		case ':':
			usage (EUSAGE, "preset", long_options, "host.example.com ...");
			break;
		default:
			parse_option ((Option)opt, optarg, conn, enroll);
			break;
		}
	}

	free (options);
	argc -= optind;
	argv += optind;

	if (argc < 1)
		errx (EUSAGE, "specify one or more host names of computer accounts to preset");

	setup_krb5_conf_directory (conn);

	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);
	reset_password = (adcli_enroll_get_computer_password (enroll) == NULL);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "couldn't connect to %s domain: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	for (i = 0; i < argc; i++) {
		if (strchr (argv[i], '.') != NULL) {
			adcli_enroll_set_host_fqdn (enroll, argv[i]);
			adcli_enroll_set_computer_name (enroll, NULL);
		} else {
			adcli_enroll_set_computer_name (enroll, argv[i]);
			adcli_enroll_set_host_fqdn (enroll, NULL);
		}

		if (reset_password)
			adcli_enroll_reset_computer_password (enroll);

		res = adcli_enroll_join (enroll, flags);
		if (res != ADCLI_SUCCESS) {
			errx (-res, "joining %s in %s domain failed: %s", argv[i],
			      adcli_conn_get_domain_name (conn),
			      adcli_conn_get_last_error (conn));
		}

		printf ("computer-name: %s\n", adcli_conn_get_computer_name (conn));
	}

	/* Print out the password */
	if (generated != NULL) {
		printf ("one-time-password: %s\n", generated);
		free (generated);
	}

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);

	return 0;
}

typedef struct {
	const char *name;
	int (* function) (int argc, char *argv[]);
	const char *description;
} Command;

static Command commands[] = {
	{ "join", adcli_join, "Join this machine to a domain", },
	{ "preset", adcli_preset, "Pre setup accounts in the domain", },
	{ 0, }
};

int
main (int argc,
      char *argv[])
{
	const char *command = NULL;
	int i;

	/* Find/remove the first non-flag argument: the command */
	for (i = 1; i < argc; i++) {
		if (command == NULL) {
			if (argv[i][0] != '-') {
				command = argv[i];
				argc--;
			}
		}
		if (command != NULL)
			argv[i] = argv[i + 1];
	}

	for (i = 0; command && commands[i].name != NULL; i++) {
		if (strcmp (command, commands[i].name) == 0)
			return (commands[i].function) (argc, argv);
	}

	fprintf (stderr, "usage: adcli command [options] ...\n");
	fprintf (stderr, "\nCommands:\n");

	for (i = 0; commands[i].name != NULL; i++)
		fprintf (stderr, "  %-15s%s\n", commands[i].name, commands[i].description);
	return EUSAGE;
}


#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <assert.h>
#include <err.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EFAIL  (-ADCLI_ERR_FAIL)
#define EUSAGE (-ADCLI_ERR_CONFIG)

static char *
password_func (const char *prompt,
               void *unused_data)
{
	char *password;
	char *result;

	password = getpass (prompt);

	if (password == NULL)
		return NULL;

	result = strdup (password);

	/* TODO: Clear the password properly */

	return result;
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
dump_variables (adcli_conn *conn,
                adcli_enroll *enroll)
{
	const char **urls;

	printf ("domain-name: %s\n", adcli_conn_get_domain_name (conn));
	printf ("domain-realm: %s\n", adcli_conn_get_domain_realm (conn));
	printf ("domain-server: %s\n", adcli_conn_get_domain_server (conn));
	printf ("ldap-urls: ");
	for (urls = adcli_conn_get_ldap_urls (conn); *urls != NULL; urls++)
		printf ("%s ", *urls);
	printf ("\n");
	printf ("naming-context: %s\n", adcli_conn_get_naming_context (conn));
	printf ("preferred-ou: %s\n", adcli_enroll_get_preferred_ou (enroll));
	printf ("computer-container: %s\n", adcli_enroll_get_computer_container (enroll));

	printf ("user-name: %s\n", adcli_conn_get_user_name (conn));
	printf ("login-ccache: %s\n", adcli_conn_get_login_ccache_name (conn));

	printf ("host-fqdn: %s\n", adcli_conn_get_host_fqdn (conn));
	printf ("computer-name: %s\n", adcli_conn_get_computer_name (conn));
	printf ("computer-dn: %s\n", adcli_enroll_get_computer_dn (enroll));
	printf ("kvno: %d\n", adcli_enroll_get_kvno (enroll));
	printf ("keytab: %s\n", adcli_enroll_get_keytab_name (enroll));
}

typedef enum {
	/* Have short equivalents */
	opt_domain_realm = 'R',
	opt_domain_server = 'S',
	opt_host_fqdn = 'H',
	opt_host_netbios = 'N',
	opt_host_keytab = 'K',
	opt_login_name = 'U',
	opt_login_ccache = 'C',
	opt_computer_ou = 'O',
	opt_service_name = 'V',
	opt_verbose = 'v',

	/* Don't have short equivalents */
	opt_ldap_url = 129,
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
	case opt_login_name:
		description = "The login name (usually administrative) of the\n"
		              "account to log into the domain as.";
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
	case opt_verbose:
		description = "Show verbose progress and failure messages.";
		break;
	}

	if (short_name)
		len = fprintf (file, "  -%c, --%s", (int)short_name, long_name);
	else
		len = fprintf (file, "  --%s", long_name);

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
	int count;
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
	switch (opt) {
	case opt_login_ccache:
		adcli_conn_set_login_ccache_name (conn, optarg);
		return;
	case opt_login_name:
		adcli_conn_set_user_name (conn, optarg);
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
		adcli_enroll_set_preferred_ou (enroll, optarg);
		return;
	case opt_service_name:
		adcli_enroll_add_service_name (enroll, optarg);
		return;
	case opt_verbose:
		adcli_conn_set_message_func (conn, message_func, NULL, NULL);
		return;
	}

	errx (EUSAGE, "failure to parse option '%c'", opt);
}

static int
adcli_join (int argc,
            char *argv[])
{
	adcli_enroll_flags flags = ADCLI_ENROLL_ALLOW_OVERWRITE;
	const char *domain;
	char *options;
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	int opt;

	struct option long_options[] = {
		{ "login-name", required_argument, NULL, opt_login_name },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "host-fqdn", required_argument, 0, opt_host_fqdn },
		{ "host-netbios", required_argument, 0, opt_host_netbios },
		{ "host-keytab", required_argument, 0, opt_host_keytab },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
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
	adcli_conn_set_password_func (conn, password_func, NULL, NULL);

	options = build_short_options (long_options);
	while ((opt = getopt_long (argc, argv, options, long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage (0, "join", long_options, "domain");
			break;
		case '?':
		case ':':
			usage (EUSAGE, "join", long_options, "domain");
			break;
		default:
			parse_option ((Option)opt, optarg, conn, enroll);
			break;
		}
	}

	free (options);
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage (EUSAGE, "join", long_options, "domain");

	domain = argv[0];
	adcli_conn_set_domain_name (conn, domain);

	res = adcli_enroll_join (enroll, flags);
	if (res != ADCLI_SUCCESS) {
		errx (1, "enroll in %s domain failed: %s",
		      domain ? domain : "default",
		      adcli_conn_get_last_error (conn));
	}

	dump_variables (conn, enroll);

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
	const char *domain;
	char *generated = NULL;
	char *options;
	adcli_enroll_flags flags;
	int opt;
	int i;

	struct option long_options[] = {
		{ "login-name", required_argument, NULL, opt_login_name },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
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
	adcli_conn_set_password_func (conn, password_func, NULL, NULL);
	flags = ADCLI_ENROLL_NO_KEYTAB | ADCLI_ENROLL_ALLOW_OVERWRITE;

	options = build_short_options (long_options);

	while ((opt = getopt_long (argc, argv, options, long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage (0, "preset", long_options, "domain host.example.com ...");
			break;
		case '?':
		case ':':
			usage (EUSAGE, "preset", long_options, "domain host.example.com ...");
			break;
		default:
			parse_option ((Option)opt, optarg, conn, enroll);
			break;
		}
	}

	free (options);
	argc -= optind;
	argv += optind;

	if (argc == 1)
		usage (EUSAGE, "preset", long_options, "host.example.com ...");

	domain = argv[0];
	adcli_conn_set_domain_name (conn, domain);
	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (1, "couldn't connect to %s domain %s",
		      domain, adcli_conn_get_last_error (conn));
	}

	for (i = 1; i < argc; i++) {
		if (strchr (argv[i], '.') != NULL) {
			adcli_enroll_set_host_fqdn (enroll, argv[i]);
			adcli_enroll_set_computer_name (enroll, NULL);
		} else {
			adcli_enroll_set_computer_name (enroll, argv[i]);
			adcli_enroll_set_host_fqdn (enroll, NULL);
		}

		adcli_enroll_reset_computer_password (enroll);

		res = adcli_enroll_join (enroll, flags);
		if (res != ADCLI_SUCCESS) {
			errx (1, "enroll of %s in %s domain failed: %s",
			      argv[i], domain, adcli_conn_get_last_error (conn));
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

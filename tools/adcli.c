
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

	printf ("admin-name: %s\n", adcli_conn_get_admin_name (conn));
	printf ("admin-ccache: %s\n", adcli_conn_get_admin_ccache_name (conn));

	printf ("host-fqdn: %s\n", adcli_enroll_get_host_fqdn (enroll));
	printf ("computer-name: %s\n", adcli_enroll_get_host_netbios (enroll));
	printf ("computer-account: %s\n", adcli_enroll_get_computer_account (enroll));
	printf ("kvno: %d\n", adcli_enroll_get_kvno (enroll));
	printf ("keytab: %s\n", adcli_enroll_get_keytab_name (enroll));
}

static int
usage (int code)
{
	fprintf (stderr, "usage: ad-enroll [-v] {args} domain.name\n");
	return code;
}

#define JOIN_LONG_OPTIONS \
	{ "admin-name", required_argument, 0, 'U' }, \
	{ "credential-cache", required_argument, 0, 'C' }, \
	{ "computer-ou", required_argument, 0, 'O' }, \
	{ "domain-realm", required_argument, 0, 'R' }, \
	{ "domain-server", required_argument, 0, 'S' }, \
	{ "ldap-url", required_argument, 0, 'L' }, \
	{ "service-name", required_argument, 0, 'V' }, \
	{ "verbose", no_argument, 0, 'v' }

#define JOIN_SHORT_OPTIONS \
	"vC:L:O:R:S:U:V:"

static int
parse_join_options (int opt,
                    const char *optarg,
                    adcli_conn *conn,
                    adcli_enroll *enroll)
{
	switch (opt) {
	case 'C':
		adcli_conn_set_admin_ccache_name (conn, optarg);
		return 1;
	case 'L':
		adcli_conn_add_ldap_url (conn, optarg);
		return 1;
	case 'O':
		adcli_enroll_set_preferred_ou (enroll, optarg);
		return 1;
	case 'R':
		adcli_conn_set_domain_realm (conn, optarg);
		return 1;
	case 'S':
		adcli_conn_set_domain_server (conn, optarg);
		return 1;
	case 'U':
		adcli_conn_set_admin_name (conn, optarg);
		return 1;
	case 'V':
		adcli_enroll_add_service_name (enroll, optarg);
		return 1;
	case 'v':
		adcli_conn_set_message_func (conn, message_func, NULL, NULL);
		return 1;
	default:
		return 0;
	}
}

static int
adcli_join (int argc,
            char *argv[])
{
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	int long_index;
	int opt;

	static struct option long_options[] = {
		{ "host-fqdn", required_argument, 0, 'H' },
		{ "host-netbios", required_argument, 0, 'N' },
		{ "keytab", required_argument, 0, 'K' },
		JOIN_LONG_OPTIONS,
		{ 0 },
	};

	conn = adcli_conn_new (NULL);
	enroll = adcli_enroll_new (conn);
	if (conn == NULL || enroll == NULL)
		errx (-1, "unexpected memory problems");

	while ((opt = getopt_long (argc, argv, "hK:H:N:" JOIN_SHORT_OPTIONS,
	                           long_options, &long_index)) != -1) {
		if (!parse_join_options (opt, optarg, conn, enroll)) {
			switch (opt) {
			case 'H':
				adcli_conn_set_host_fqdn (conn, optarg);
				break;
			case 'K':
				adcli_enroll_set_keytab_name (enroll, optarg);
				break;
			case 'N':
				adcli_enroll_set_host_netbios (enroll, optarg);
				break;
			case 'h':
			case '?':
				usage (0);
				break;
			case ':':
				usage (2);
				break;
			}
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage (2);

	adcli_conn_set_domain_name (conn, argv[0]);

	res = adcli_enroll_join (enroll, ADCLI_ENROLL_ALLOW_OVERWRITE);
	if (res != ADCLI_SUCCESS) {
		errx (1, "enroll in %s domain failed: %s", argv[0],
		      adcli_conn_get_last_error (conn));
	}

	dump_variables (conn, enroll);

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);

	return 0;
}

static int
adcli_prejoin (int argc,
               char *argv[])
{
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	const char *domain;
	const char *password;
	char *generated = NULL;
	size_t password_length;
	int long_index;
	adcli_enroll_flags flags;
	int opt;
	int i;

	static struct option long_options[] = {
		JOIN_LONG_OPTIONS,
		{ "one-time-password", required_argument, 0, 'P' },
		{ "overwrite", no_argument, 0, 'o' },
		{ 0 },
	};

	conn = adcli_conn_new (NULL);
	enroll = adcli_enroll_new (conn);
	if (conn == NULL || enroll == NULL)
		errx (-1, "unexpected memory problems");
	adcli_conn_set_password_func (conn, password_func, NULL, NULL);
	flags = ADCLI_ENROLL_NO_KEYTAB;

	while ((opt = getopt_long (argc, argv, "hoP:" JOIN_SHORT_OPTIONS,
	                           long_options, &long_index)) != -1) {
		if (!parse_join_options (opt, optarg, conn, enroll)) {
			switch (opt) {
			case 'o':
				flags |= ADCLI_ENROLL_ALLOW_OVERWRITE;
				break;
			case 'P':
				adcli_enroll_set_host_password (enroll, optarg, strlen (optarg));
				break;
			case 'h':
			case '?':
				usage (0);
				break;
			case ':':
				usage (2);
				break;
			}
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		usage (2);

	domain = argv[0];
	adcli_conn_set_domain_name (conn, domain);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (1, "couldn't connect to %s domain %s",
		      domain, adcli_conn_get_last_error (conn));
	}

	/* A new alpha-numeric one time password */
	password = adcli_enroll_get_host_password (enroll, &password_length);
	if (password == NULL) {
		password_length = 60;
		password = generated = adcli_enroll_generate_host_password (enroll, password_length, 1);
	}

	for (i = 1; i < argc; i++) {
		if (strchr (argv[i], '.') != NULL) {
			adcli_enroll_set_host_fqdn (enroll, argv[i]);
			adcli_enroll_set_host_netbios (enroll, NULL);
		} else {
			adcli_enroll_set_host_netbios (enroll, argv[i]);
			adcli_enroll_set_host_fqdn (enroll, NULL);
		}

		res = adcli_enroll_join (enroll, flags);
		if (res != ADCLI_SUCCESS) {
			errx (1, "enroll of %s in %s domain failed: %s",
			      argv[i], domain, adcli_conn_get_last_error (conn));
		}

		printf ("computer-name: %s\n", adcli_enroll_get_host_netbios (enroll));
	}

	/* Print out the password */
	if (generated != NULL) {
		printf ("one-time-password: %*s\n", (int)password_length, generated);
		free (generated);
	}

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);

	return 0;
}

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

	if (command == NULL)
		return usage (2);

	if (strcmp (command, "join") == 0)
		return adcli_join (argc, argv);
	else if (strcmp (command, "prejoin") == 0)
		return adcli_prejoin (argc, argv);
	else
		return usage(2);
}

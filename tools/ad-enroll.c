
#include "config.h"

#include "adcli.h"

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
	printf ("ldap-urls: ");
	for (urls = adcli_conn_get_ldap_urls (conn); *urls != NULL; urls++)
		printf ("%s ", *urls);
	printf ("\n");
	printf ("naming-context: %s\n", adcli_conn_get_naming_context (conn));
	printf ("computer-ou: %s\n", adcli_enroll_get_computer_ou (enroll));

	printf ("admin-name: %s\n", adcli_conn_get_admin_name (conn));
	printf ("admin-ccache: %s\n", adcli_conn_get_admin_ccache_name (conn));

	printf ("host-fqdn: %s\n", adcli_enroll_get_host_fqdn (enroll));
	printf ("host-netbios: %s\n", adcli_enroll_get_host_netbios (enroll));
}

static void
usage (int code)
{
	fprintf (stderr, "usage: ad-enroll [-v] {args} domain.name\n");
	exit (code);
}

int
main (int argc,
      char *argv[])
{
	adcli_conn *conn;
	adcli_enroll *enroll;
	adcli_result res;
	int long_index;
	int verbose = 0;
	int opt;

	static struct option long_options[] = {
		{ "admin-name", required_argument, 0, 'U' },
		{ "credential-cache", required_argument, 0, 'K' },
		{ "computer-ou", required_argument, 0, 'O' },
		{ "domain-realm", required_argument, 0, 'R' },
		{ "host-fqdn", required_argument, 0, 'H' },
		{ "host-netbios", required_argument, 0, 'N' },
		{ "ldap-url", required_argument, 0, 'L' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0 },
	};

	conn = adcli_conn_new (NULL);
	if (conn == NULL)
		errx (1, "out of memory");

	enroll = adcli_enroll_new (conn);
	if (enroll == NULL)
		errx (1, "out of memory");

	while ((opt = getopt_long (argc, argv, "vhK:H:L:N:O:R:U:",
	                           long_options, &long_index)) != -1) {
		switch (opt) {
		case 'H':
			res = adcli_conn_set_host_fqdn (conn, optarg);
			break;
		case 'K':
			res = adcli_conn_set_admin_ccache_name (conn, optarg);
			break;
		case 'L':
			res = adcli_conn_add_ldap_url (conn, optarg);
			break;
		case 'N':
			res = adcli_enroll_set_host_netbios (enroll, optarg);
			break;
		case 'O':
			res = adcli_enroll_set_computer_ou (enroll, optarg);
			break;
		case 'R':
			res = adcli_conn_set_domain_realm (conn, optarg);
			break;
		case 'U':
			res = adcli_conn_set_admin_name (conn, optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		case '?':
			usage (0);
			break;
		case ':':
			usage (2);
			break;
		}

		if (res != ADCLI_SUCCESS) {
			errx (2, "invalid option: %s: %s",
			      long_options[long_index].name, optarg);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage (2);

	if (verbose)
		adcli_conn_set_message_func (conn, message_func, NULL, NULL);
	adcli_conn_set_password_func (conn, password_func, NULL, NULL);

	adcli_conn_set_domain_name (conn, argv[0]);
	res = adcli_enroll_join (enroll);
	if (res != ADCLI_SUCCESS) {
		errx (1, "enroll in %s domain failed: %s", argv[0],
		      adcli_result_to_string (res));
	}

	dump_variables (conn, enroll);

	adcli_enroll_unref (enroll);
	adcli_conn_unref (conn);

	return 0;
}

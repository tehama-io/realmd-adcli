
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
dump_enroll_ctx (adcli_enroll_ctx *enroll)
{
	const char **urls;

	printf ("domain-name: %s\n", adcli_enroll_get_domain_name (enroll));
	printf ("domain-realm: %s\n", adcli_enroll_get_domain_realm (enroll));
	printf ("host-fqdn: %s\n", adcli_enroll_get_host_fqdn (enroll));
	printf ("host-netbios: %s\n", adcli_enroll_get_host_netbios (enroll));

	printf ("ldap-urls: ");
	for (urls = adcli_enroll_get_ldap_urls (enroll); *urls != NULL; urls++)
		printf ("%s ", *urls);
	printf ("\n");

	printf ("admin-name: %s\n", adcli_enroll_get_admin_name (enroll));
	printf ("admin-ccache: %s\n", adcli_enroll_get_admin_ccache_name (enroll));
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
	adcli_enroll_ctx *enroll;
	adcli_result res;
	int long_index;
	int verbose = 0;
	int opt;

	static struct option long_options[] = {
		{ "admin-name", required_argument, 0, 'U' },
		{ "credential-cache", required_argument, 0, 'K' },
		{ "domain-realm", required_argument, 0, 'R' },
		{ "host-fqdn", required_argument, 0, 'H' },
		{ "host-netbios", required_argument, 0, 'N' },
		{ "ldap-url", required_argument, 0, 'L' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0 },
	};

	enroll = adcli_enroll_ctx_new ();
	if (enroll == NULL)
		errx (1, "out of memory");

	while ((opt = getopt_long (argc, argv, "vhK:H:L:N:R:U:",
	                           long_options, &long_index)) != -1) {
		switch (opt) {
		case 'H':
			res = adcli_enroll_set_host_fqdn (enroll, optarg);
			break;
		case 'K':
			res = adcli_enroll_set_admin_ccache_name (enroll, optarg);
			break;
		case 'L':
			res = adcli_enroll_add_ldap_url (enroll, optarg);
			break;
		case 'N':
			res = adcli_enroll_set_host_netbios (enroll, optarg);
			break;
		case 'R':
			res = adcli_enroll_set_domain_realm (enroll, optarg);
			break;
		case 'U':
			res = adcli_enroll_set_admin_name (enroll, optarg);
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
		adcli_enroll_set_message_func (enroll, message_func, NULL, NULL);
	adcli_enroll_set_admin_password_func (enroll, password_func, NULL, NULL);

	res = adcli_enroll (argv[0], enroll);
	if (res != ADCLI_SUCCESS) {
		errx (1, "enroll in %s domain failed: %s", argv[0],
		      adcli_result_to_string (res));
	}

	dump_enroll_ctx (enroll);
	adcli_enroll_ctx_free (enroll);

	return 0;
}

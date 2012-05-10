
#include "config.h"

#include "adcli.h"

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void
message_func (adcli_message_type type,
              const char *message)
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
	int verbose = 0;
	int opt;

	static struct option long_options[] = {
		{ "host-fqdn", required_argument, 0, 'H' },
		{ "host-netbios", required_argument, 0, 'N' },
		{ "verbose", no_argument, 0, 'v' },
		{ 0 },
	};

	enroll = adcli_enroll_ctx_new ();
	if (enroll == NULL)
		errx (1, "out of memory");

	while ((opt = getopt_long (argc, argv, "vhH:N:",
	                           long_options, NULL)) != -1) {
		switch (opt) {
		case 'H':
			adcli_enroll_set_host_fqdn (enroll, optarg);
			break;
		case 'N':
			adcli_enroll_set_host_netbios (enroll, optarg);
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
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage (2);

	if (verbose)
		adcli_enroll_set_message_func (enroll, message_func);

	res = adcli_enroll (argv[0], enroll);
	if (res != ADCLI_SUCCESS) {
		errx (1, "enroll in %s domain failed: %s", argv[0],
		      adcli_result_to_string (res));
	}

	printf ("domain-name: %s\n", adcli_enroll_get_domain_name (enroll));
	printf ("host-fqdn: %s\n", adcli_enroll_get_host_fqdn (enroll));
	printf ("host-netbios: %s\n", adcli_enroll_get_host_netbios (enroll));

	adcli_enroll_ctx_free (enroll);
	return 0;
}

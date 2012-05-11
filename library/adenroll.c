
#include "config.h"

#include "adenroll.h"
#include "adprivate.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

struct _adcli_enroll {
	int refs;
	adcli_conn *conn;

	char *host_fqdn;
	char *host_netbios;
#if 0
	char *computer_ou;
	char *host_password;
	krb5_keytab host_keytab;
#endif
};

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_enroll *enroll)
{
	const char *fqdn;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		_adcli_err (enroll->conn, "Using fully qualified name: %s",
		            enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	/* By default use our actual host name discovered during connecting */
	fqdn = adcli_conn_get_host_fqdn (enroll->conn);
	return adcli_enroll_set_host_fqdn (enroll, fqdn);
}

static adcli_result
ensure_host_netbios (adcli_result res,
                     adcli_enroll *enroll)
{
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_netbios) {
		_adcli_info (enroll->conn, "Using host netbios name: %s",
		             enroll->host_netbios);
		return ADCLI_SUCCESS;
	}

	assert (enroll->host_fqdn != NULL);

	/* Use the FQDN minus the last part */
	dom = strchr (enroll->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == enroll->host_fqdn || dom[1] == '\0') {
		_adcli_err (enroll->conn,
		            "Couldn't determine the netbios name from host name: %s",
		            enroll->host_fqdn);
		return ADCLI_ERR_DNS;
	}

	enroll->host_netbios = strndup (enroll->host_fqdn,
	                                dom - enroll->host_fqdn);
	if (enroll->host_netbios) {
		_adcli_strup (enroll->host_netbios);
		_adcli_info (enroll->conn, "Calculated host netbios name from fqdn: %s",
		             enroll->host_netbios);
	}

	return enroll->host_netbios ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;
}

static void
enroll_clear_state (adcli_enroll *enroll)
{

}

adcli_result
adcli_enroll_join (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;

	res = adcli_conn_connect (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_host_netbios (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	/* TODO: Create a valid password */

	/* - Figure out the naming context */

	/* - Figure out the domain short name */

	/* - Search for computer account */

	/* - Update computer account or create */

	/* - Write out password to host keytab */

	return res;
}

adcli_enroll *
adcli_enroll_new (adcli_conn *conn)
{
	adcli_enroll *enroll;

	enroll = calloc (1, sizeof (adcli_enroll));
	if (enroll == NULL)
		return NULL;

	enroll->conn = adcli_conn_ref (conn);
	enroll->refs = 1;
	return enroll;
}

adcli_enroll *
adcli_enroll_ref (adcli_enroll *enroll)
{
	enroll->refs++;
	return enroll;
}

static void
enroll_free (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	free (enroll->host_fqdn);
	free (enroll->host_netbios);

	enroll_clear_state (enroll);
	adcli_conn_unref (enroll->conn);
	free (enroll);
}

void
adcli_enroll_unref (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	if (--(enroll->refs) > 0)
		return;

	enroll_free (enroll);
}

const char *
adcli_enroll_get_host_fqdn (adcli_enroll *enroll)
{
	return enroll->host_fqdn;
}

adcli_result
adcli_enroll_set_host_fqdn (adcli_enroll *enroll,
                            const char *value)
{
	return _adcli_set_str_field (&enroll->host_fqdn, value);
}

const char *
adcli_enroll_get_host_netbios (adcli_enroll *enroll)
{
	return enroll->host_netbios;
}

adcli_result
adcli_enroll_set_host_netbios (adcli_enroll *enroll,
                               const char *value)
{
	return _adcli_set_str_field (&enroll->host_netbios, value);
}

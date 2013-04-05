/*
 * adcli
 *
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "adcli.h"
#include "adattrs.h"
#include "tools.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>

typedef enum {
	/* Have short equivalents */
	opt_domain = 'D',
	opt_domain_realm = 'R',
	opt_domain_server = 'S',
	opt_login_user = 'U',
	opt_login_ccache = 'C',
	opt_user_ou = 'O',
	opt_prompt_password = 'W',
	opt_verbose = 'v',

	/* Don't have short equivalents */
	opt_no_password,
	opt_stdin_password,
	opt_display_name,
	opt_account_name,
	opt_mail,
	opt_unix_home,
	opt_unix_uid,
	opt_unix_gid,
	opt_unix_shell,
} Option;

static adcli_tool_desc common_usages[] = {
	{ opt_account_name, "unique security account name" },
	{ opt_display_name, "display name" },
	{ opt_mail, "email address" },
	{ opt_unix_home, "unix home directory" },
	{ opt_unix_uid, "unix uid number" },
	{ opt_unix_gid, "unix gid number" },
	{ opt_unix_shell, "unix shell" },
	{ opt_domain, "active directory domain name" },
	{ opt_domain_realm, "kerberos realm for the domain" },
	{ opt_domain_server, "domain directory server to connect to" },
	{ opt_login_ccache, "kerberos credential cache file which contains\n"
	                    "ticket to used to connect to the domain" },
	{ opt_login_user, "user (usually administrative) login name of\n"
	                  "the account to log into the domain as" },
	{ opt_user_ou, "a LDAP DN representing an organizational unit in\n"
	               "which the user account should be placed." },
	{ opt_no_password, "don't prompt for or read a password" },
	{ opt_prompt_password, "prompt for a login password if necessary" },
	{ opt_stdin_password, "read a login password from stdin (until EOF) if\n"
	                      "neccessary" },
	{ opt_verbose, "show verbose progress and failure messages", },
	{ 0 },
};

static void
parse_option (Option opt,
              const char *optarg,
              adcli_conn *conn)
{
	static int no_password = 0;
	static int prompt_password = 0;
	static int stdin_password = 0;

	switch (opt) {
	case opt_login_ccache:
		adcli_conn_set_login_ccache_name (conn, optarg);
		return;
	case opt_login_user:
		adcli_conn_set_user_name (conn, optarg);
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
			adcli_conn_set_password_func (conn, adcli_prompt_password_func, NULL, NULL);
			prompt_password = 1;
		}
		return;
	case opt_stdin_password:
		if (prompt_password || no_password) {
			errx (EUSAGE, "cannot use --stdin-password argument with %s",
			      prompt_password ? "--prompt-password" : "--no-password");
		} else {
			adcli_conn_set_password_func (conn, adcli_read_password_func, NULL, NULL);
			stdin_password = 1;
		}
		return;
	case opt_verbose:
		return;
	default:
		assert (0 && "not reached");
		break;
	}

	errx (EUSAGE, "failure to parse option '%c'", opt);
}

int
adcli_tool_user_create (adcli_conn *conn,
                        int argc,
                        char *argv[])
{
	adcli_user *user;
	adcli_result res;
	adcli_attrs *attrs;
	const char *ou = NULL;
	int opt;

	struct option options[] = {
		{ "account-name", required_argument, NULL, opt_account_name },
		{ "display-name", required_argument, NULL, opt_display_name },
		{ "mail", required_argument, NULL, opt_mail },
		{ "unix-home", required_argument, NULL, opt_unix_home },
		{ "unix-uid", required_argument, NULL, opt_unix_uid },
		{ "unix-gid", required_argument, NULL, opt_unix_gid },
		{ "unix-shell", required_argument, NULL, opt_unix_shell },
		{ "user-ou", required_argument, NULL, opt_user_ou },
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli create-user --domain=xxxx user" },
		{ 0 },
	};

	attrs = adcli_attrs_new ();

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_account_name:
			adcli_attrs_add (attrs, "sAMAccountName", optarg);
			break;
		case opt_display_name:
			adcli_attrs_add (attrs, "displayName", optarg);
			break;
		case opt_mail:
			adcli_attrs_add (attrs, "mail", optarg);
			break;
		case opt_unix_home:
			adcli_attrs_add (attrs, "unixHomeDirectory", optarg);
			break;
		case opt_unix_uid:
			adcli_attrs_add (attrs, "uidNumber", optarg);
			break;
		case opt_unix_gid:
			adcli_attrs_add (attrs, "gidNumber", optarg);
			break;
		case opt_unix_shell:
			adcli_attrs_add (attrs, "loginShell", optarg);
			break;
		case opt_user_ou:
			ou = optarg;
			break;
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			return opt == 'h' ? 0 : 2;
		default:
			parse_option ((Option)opt, optarg, conn);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		errx (2, "specify one user name to create");

	user = adcli_user_new (conn, argv[0]);
	if (user == NULL)
		errx (-1, "unexpected memory problems");
	adcli_user_set_ou (user, ou);

	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "couldn't connect to %s domain: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	res = adcli_user_create (user, attrs);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "creating user %s in domain failed: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	adcli_user_unref (user);
	adcli_attrs_free (attrs);

	return 0;
}

int
adcli_tool_user_delete (adcli_conn *conn,
                        int argc,
                        char *argv[])
{
	adcli_result res;
	adcli_user *user;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-realm", required_argument, NULL, opt_domain_realm },
		{ "domain-server", required_argument, NULL, opt_domain_server },
		{ "login-user", required_argument, NULL, opt_login_user },
		{ "login-ccache", required_argument, NULL, opt_login_ccache },
		{ "no-password", no_argument, 0, opt_no_password },
		{ "stdin-password", no_argument, 0, opt_stdin_password },
		{ "prompt-password", no_argument, 0, opt_prompt_password },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli delete-user --domain=xxxx user" },
		{ 0 },
	};

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			return opt == 'h' ? 0 : 2;
		default:
			parse_option ((Option)opt, optarg, conn);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		errx (2, "specify one user name to delete");

	user = adcli_user_new (conn, argv[0]);
	if (user == NULL)
		errx (-1, "unexpected memory problems");

	adcli_conn_set_allowed_login_types (conn, ADCLI_LOGIN_USER_ACCOUNT);

	res = adcli_conn_connect (conn);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "couldn't connect to %s domain: %s",
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	res = adcli_user_delete (user);
	if (res != ADCLI_SUCCESS) {
		errx (-res, "deleting user %s in domain %s failed: %s", argv[0],
		      adcli_conn_get_domain_name (conn),
		      adcli_conn_get_last_error (conn));
	}

	adcli_user_unref (user);

	return 0;
}

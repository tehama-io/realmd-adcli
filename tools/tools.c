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
#include "tools.h"

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <unistd.h>


static char *adcli_temp_directory = NULL;
static char *adcli_krb5_conf_filename = NULL;
static char *adcli_krb5_d_directory = NULL;

enum {
	CONNECTION_LESS = 1<<0,
};

struct {
	const char *name;
	int (*function) (adcli_conn *, int, char *[]);
	const char *text;
	int flags;
} commands[] = {
	{ "info", adcli_tool_info, "Print information about a domain", CONNECTION_LESS },
	{ "join", adcli_tool_computer_join, "Join this machine to a domain", },
	{ "update", adcli_tool_computer_update, "Update machine membership in a domain", },
	{ "preset-computer", adcli_tool_computer_preset, "Pre setup computers accounts", },
	{ "reset-computer", adcli_tool_computer_reset, "Reset a computer account", },
	{ "delete-computer", adcli_tool_computer_delete, "Delete a computer acocunt", },
	{ "create-user", adcli_tool_user_create, "Create a user account", },
	{ "delete-user", adcli_tool_user_delete, "Delete a user account", },
	{ "create-group", adcli_tool_group_create, "Create a group", },
	{ "delete-group", adcli_tool_group_delete, "Delete a group", },
	{ "add-member", adcli_tool_member_add, "Add users to a group", },
	{ "remove-member", adcli_tool_member_remove, "Remove users from a group", },
	{ 0, }
};

static char
short_option (int opt)
{
	if (isalpha (opt) || isdigit (opt))
		return (char)opt;
	return 0;
}

static const struct option *
find_option (const struct option *longopts,
             int opt)
{
	int i;

	for (i = 0; longopts[i].name != NULL; i++) {
		if (longopts[i].val == opt)
			return longopts + i;
	}

	return NULL;
}

void
adcli_tool_usage (const struct option *longopts,
                  const adcli_tool_desc *usages)
{
	const struct option *longopt;
	const int indent = 28;
	const char *description;
	const char *next;
	char short_name;
	int spaces;
	int len;
	int i;

	for (i = 0; usages[i].text != NULL; i++) {

		/* If no option, then this is a heading */
		if (!usages[i].option) {
			printf ("%s\n\n", usages[i].text);
			continue;
		}

		/* Only print out options we can actually parse */
		longopt = find_option (longopts, usages[i].option);
		if (!longopt)
			continue;

		short_name = short_option (usages[i].option);
		if (short_name && longopt->name)
			len = printf ("  -%c, --%s", (int)short_name, longopt->name);
		else if (longopt->name)
			len = printf ("  --%s", longopt->name);
		else
			len = printf ("  -%c", (int)short_name);
		if (longopt->has_arg)
			len += printf ("%s<%s>",
			               longopt->name ? "=" : " ",
			               usages[i].arg ? usages[i].arg : "...");
		if (len < indent) {
			spaces = indent - len;
		} else {
			printf ("\n");
			spaces = indent;
		}
		description = usages[i].text;
		while (description) {
			while (spaces-- > 0)
				fputc (' ', stdout);
			next = strchr (description, '\n');
			if (next) {
				next += 1;
				printf ("%.*s", (int)(next - description), description);
				description = next;
				spaces = indent;
			} else {
				printf ("%s\n", description);
				break;
			}
		}

	}
}

int
adcli_tool_getopt (int argc,
                   char *argv[],
                   const struct option *options)
{
	int count = 0;
	char *shorts;
	char *p;
	int ret;
	char opt;
	int i;

	/* Number of characters */
	for (i = 0; options[i].name != NULL; i++)
		count++;

	p = shorts = malloc ((count * 2) + 1);
	return_val_if_fail (shorts != NULL, -1);

	for (i = 0; i < count; i++) {
		opt = short_option (options[i].val);
		if (opt != 0) {
			*(p++) = (char)options[i].val;
			if (options[i].has_arg == required_argument)
				*(p++) = ':';
		}
	}

	*(p++) = '\0';

	ret = getopt_long (argc, argv, shorts, options, NULL);
	free (shorts);

	return ret;
}

static void
command_usage (void)
{
	int i;

	printf ("usage: adcli command <args>...\n");
	printf ("\nCommon adcli commands are:\n");
	for (i = 0; commands[i].name != NULL; i++)
		printf ("  %-15s  %s\n", commands[i].name, commands[i].text);
	printf ("\nSee 'adcli <command> --help' for more information\n");
}

char *
adcli_prompt_password_func (adcli_login_type login_type,
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

char *
adcli_read_password_func (adcli_login_type login_type,
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
	int failed = 0;
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
	              (parent[0] && parent[strlen(parent) - 1] == '/') ? "" : "/") < 0)
		errx (1, "unexpected: out of memory");

	if (mkdtemp (directory) == NULL) {
		errn = errno;
		failed = 1;
		warnx ("couldn't create temporary directory in: %s: %s",
		       parent, strerror (errn));
	} else {
		if (asprintf (&filename, "%s/krb5.conf", directory) < 0 ||
		    asprintf (&snippets, "%s/krb5.d", directory) < 0 ||
		    asprintf (&contents, "includedir %s\n%s%s\n", snippets,
		              krb5_conf ? "include " : "",
		              krb5_conf ? krb5_conf : "") < 0)
			errx (1, "unexpected: out of memory");
	}

	if (!failed) {
		fo = fopen (filename, "wb");
		if (fo == NULL) {
			errn = errno;
			failed = 1;
		} else {
			fwrite (contents, 1, strlen (contents), fo);
			if (ferror (fo)) {
				errn = errno;
				failed = 1;
				fclose (fo);
			} else {
				if (fclose (fo) != 0) {
					failed = 1;
					errn = errno;
				}
			}
		}

		if (failed) {
			warnx ("couldn't write new krb5.conf file: %s: %s",
			       filename, strerror (errn));
		}
	}


	if (!failed && mkdir (snippets, 0700) < 0) {
		errn = errno;
		failed = 1;
		warnx ("couldn't write new krb5.d directory: %s: %s",
		       snippets, strerror (errn));
	}

	if (!failed) {
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

int
main (int argc,
      char *argv[])
{
	adcli_conn *conn = NULL;
	char *command = NULL;
	int skip;
	int in, out;
	int ret;
	int i;

	/*
	 * Parse the global options. We rearrange the options as
	 * necessary, in order to pass relevant options through
	 * to the commands, but also have them take effect globally.
	 */

	for (in = 1, out = 1; in < argc; in++, out++) {
		skip = 0;

		/* The non-option is the command, take it out of the arguments */
		if (argv[in][0] != '-') {
			if (!command) {
				skip = 1;
				command = argv[in];
			}

		/* The global long options */
		} else if (argv[in][1] == '-') {
			skip = 0;

			if (strcmp (argv[in], "--") == 0) {
				if (!command)
					errx (2, "no command specified");

			} else if (strcmp (argv[in], "--verbose") == 0) {
				adcli_set_message_func (message_func);

			} else if (strcmp (argv[in], "--help") == 0) {
				if (!command) {
					command_usage ();
					return 0;
				}

			} else {
				if (!command)
					errx (2, "unknown option: %s", argv[in]);
			}

		/* The global short options */
		} else {
			skip = 0;

			for (i = 1; argv[in][i] != '\0'; i++) {
				switch (argv[in][i]) {
				case 'h':
					if (!command) {
						command_usage ();
						return 0;
					}
					break;

				case 'v':
					adcli_set_message_func (message_func);
					break;

				default:
					if (!command)
						errx (2, "unknown option: -%c", (int)argv[in][i]);
					break;
				}
			}
		}

		/* Skipping this argument? */
		if (skip)
			out--;
		else
			argv[out] = argv[in];
	}

	if (command == NULL) {
		/* As a special favor if someone just typed 'adcli', help them out */
		if (argc == 1)
			command_usage ();
		else
			warnx ("no command specified");
		return 2;
	}

	argc = out;
	conn = NULL;

	/* Look for the command */
	for (i = 0; commands[i].name != NULL; i++) {
		if (strcmp (commands[i].name, command) != 0)
			continue;

		if (!(commands[i].flags & CONNECTION_LESS)) {
			conn = adcli_conn_new (NULL);
			if (conn == NULL)
				errx (-1, "unexpected memory problems");
			adcli_conn_set_password_func (conn, adcli_prompt_password_func, NULL, NULL);
			setup_krb5_conf_directory (conn);
		}

		argv[0] = command;
		ret = (commands[i].function) (conn, argc, argv);

		if (conn)
			adcli_conn_unref (conn);
		return ret;
	}

	/* At this point we have no command */
	errx (2, "'%s' is not a valid adcli command. See 'adcli --help'", command);
}

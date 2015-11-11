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

#ifndef _ADCLI_TOOLS_H_
#define _ADCLI_TOOLS_H_

#include "adcli.h"

#include <getopt.h>

#define EFAIL  (-ADCLI_ERR_FAIL)
#define EUSAGE (-ADCLI_ERR_CONFIG)

typedef struct  {
	int option;
	const char *text;
	const char *arg;
} adcli_tool_desc;

int       adcli_tool_getopt            (int argc,
                                        char *argv[],
                                        const struct option *longopts);

void      adcli_tool_usage             (const struct option *longopts,
                                        const adcli_tool_desc *usages);

char *    adcli_prompt_password_func   (adcli_login_type login_type,
                                        const char *name,
                                        int flags,
                                        void *unused_data);

char *    adcli_read_password_func     (adcli_login_type login_type,
                                        const char *name,
                                        int flags,
                                        void *unused_data);

int       adcli_tool_computer_preset   (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_computer_reset    (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_computer_join     (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_computer_update   (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_computer_delete   (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_user_create       (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_user_delete       (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_group_create      (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_group_delete      (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_member_add        (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_member_remove     (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

int       adcli_tool_info              (adcli_conn *conn,
                                        int argc,
                                        char *argv[]);

#endif /* _ADCLI_TOOLS_H_ */

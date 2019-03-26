/*
 * Copyright (C) 2016-2018 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknet.h"

#include "internals.h"
#include "test-common.h"

static int private_data;

static void link_notify(void *priv_data,
			knet_node_id_t host_id,
			uint8_t link_id,
			uint8_t connected,
			uint8_t remote,
			uint8_t external)
{
	return;
}

static void test(void)
{
	knet_handle_t knet_h;
	int logfds[2];

	printf("Test knet_link_enable_status_change_notify incorrect knet_h\n");

	if ((!knet_link_enable_status_change_notify(NULL, NULL, link_notify)) || (errno != EINVAL)) {
		printf("knet_link_enable_status_change_notify accepted invalid knet_h or returned incorrect error: %s\n", strerror(errno));
		exit(FAIL);
	}

	setup_logpipes(logfds);

	knet_h = knet_handle_start(logfds, KNET_LOG_DEBUG);

	printf("Test knet_link_enable_status_change_notify with no private_data\n");

	if (knet_link_enable_status_change_notify(knet_h, NULL, link_notify) < 0) {
		printf("knet_link_enable_status_change_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->link_status_change_notify_fn_private_data != NULL) {
		printf("knet_link_enable_status_change_notify failed to unset private_data");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_enable_status_change_notify with private_data\n");

	if (knet_link_enable_status_change_notify(knet_h, &private_data, NULL) < 0) {
		printf("knet_link_enable_status_change_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->link_status_change_notify_fn_private_data != &private_data) {
		printf("knet_link_enable_status_change_notify failed to set private_data");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_enable_status_change_notify with no link_notify fn\n");

	if (knet_link_enable_status_change_notify(knet_h, NULL, NULL) < 0) {
		printf("knet_link_enable_status_change_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->link_status_change_notify_fn != NULL) {
		printf("knet_link_enable_status_change_notify failed to unset link_notify fn");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	printf("Test knet_link_enable_status_change_notify with link_notify fn\n");

	if (knet_link_enable_status_change_notify(knet_h, NULL, link_notify) < 0) {
		printf("knet_link_enable_status_change_notify failed: %s\n", strerror(errno));
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);
	}

	if (knet_h->link_status_change_notify_fn != &link_notify) {
		printf("knet_link_enable_status_change_notify failed to set link_notify fn");
		knet_handle_free(knet_h);
		flush_logs(logfds[0], stdout);
		close_logpipes(logfds);
		exit(FAIL);

	}

	flush_logs(logfds[0], stdout);

	knet_handle_free(knet_h);
	flush_logs(logfds[0], stdout);
	close_logpipes(logfds);
}

int main(int argc, char *argv[])
{
	test();

	return PASS;
}

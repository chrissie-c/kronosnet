/*
 * Copyright (C) 2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "test-common.h"

/*
 * use this one to randomize nozzle interface name
 * for named creation test
 */
uint8_t randombyte = 0;

static int test_iface(char *name, size_t size, const char *updownpath)
{
	nozzle_t nozzle;

	nozzle=nozzle_open(name, size, updownpath);
	if (!nozzle) {
		printf("Unable to open nozzle.\n");
		return -1;
	}
	printf("Created interface: %s\n", name);

	if (is_if_in_system(name) > 0) {
		printf("Found interface %s on the system\n", name);
	} else {
		printf("Unable to find interface %s on the system\n", name);
	}

	if (!nozzle_get_handle_by_name(name)) {
		printf("Unable to find interface %s in nozzle db\n", name);
	} else {
		printf("Found interface %s in nozzle db\n", name);
	}

	nozzle_close(nozzle);

	if (is_if_in_system(name) == 0)
		printf("Successfully removed interface %s from the system\n", name);

	return 0;
}

static int test(void)
{
	char device_name[2*IFNAMSIZ];
	char fakepath[PATH_MAX];
	size_t size = IFNAMSIZ;

	memset(device_name, 0, sizeof(device_name));

	printf("Creating random nozzle interface:\n");
	if (test_iface(device_name, size,  NULL) < 0) {
		printf("Unable to create random interface\n");
		return -1;
	}

#ifdef KNET_LINUX
	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create kronostest%u interface\n", randombyte);
		return -1;
	}
#endif
#ifdef KNET_BSD
	printf("Creating tap%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "tap%u", randombyte);
	if (test_iface(device_name, size, NULL) < 0) {
		printf("Unable to create tap%u interface\n", randombyte);
		return -1;
	}

	printf("Creating kronostest%u nozzle interface:\n", randombyte);
	snprintf(device_name, IFNAMSIZ, "kronostest%u", randombyte);
	if (test_iface(device_name, size, NULL) == 0) {
		printf("BSD should not accept kronostest%u interface\n", randombyte);
		return -1;
	}
#endif

	printf("Testing ERROR conditions\n");

	printf("Testing dev == NULL\n");
	errno=0;
	if ((test_iface(NULL, size, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing size < IFNAMSIZ\n");
	errno=0;
	if ((test_iface(device_name, 1, NULL) >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing device_name size > IFNAMSIZ\n");
	errno=0;
	strcpy(device_name, "abcdefghilmnopqrstuvwz");
	if ((test_iface(device_name, IFNAMSIZ, NULL) >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	printf("Testing updown path != abs\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, "foo")  >= 0) || (errno != EINVAL)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	memset(fakepath, 0, PATH_MAX);
	memset(fakepath, '/', PATH_MAX - 2);

	printf("Testing updown path > PATH_MAX\n");
	errno=0;

	memset(device_name, 0, IFNAMSIZ);
	if ((test_iface(device_name, IFNAMSIZ, fakepath)  >= 0) || (errno != E2BIG)) {
		printf("Something is wrong in nozzle_open sanity checks\n");
		return -1;
	}

	return 0;
}

int main(void)
{
	need_root();

	if (test() < 0)
		return FAIL;

	return PASS;
}

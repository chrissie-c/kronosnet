/*
 * Copyright (C) 2010-2018 Red Hat, Inc.  All rights reserved.
 *
 * Author: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#ifndef __KNETD_VTY_CLI_H__
#define __KNETD_VTY_CLI_H__

#include "vty.h"

static const char telnet_newline[] = { '\n', '\r', 0x0 };

void knet_vty_cli_bind(struct knet_vty *vty);

#endif

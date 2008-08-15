/*
 * eyefi-chdk.c
 *
 * Copyright (C) 2008 Dave Hansen <dave@sr71.net>
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 as published by the
 * Free Software Foundation.
 */

#include "eyefi-config.h"

int eyefi_printf(const char *fmt, ...)
{
        va_list args;
        int r;

        va_start(args, fmt);
        r = vprintf(fmt, args);
        va_end(args);

        return r;
}



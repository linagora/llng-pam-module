/*
 * str_utils.c - String utility functions for Open Bastion
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <ctype.h>
#include <string.h>

#include "str_utils.h"

char *str_trim(char *str)
{
    if (!str) return NULL;

    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') return str;

    /* Trim trailing whitespace */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

bool str_parse_bool(const char *value)
{
    if (!value) return false;

    if (strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "1") == 0 ||
        strcmp(value, "on") == 0) {
        return true;
    }

    return false;
}

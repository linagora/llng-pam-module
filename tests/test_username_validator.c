/*
 * test_username_validator.c - Unit tests for username validation
 *
 * Tests the username validation to prevent /etc/passwd injection attacks.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    tests_run++; \
    if (test_##name()) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

/*
 * Replicate validate_username from pam_llng.c for testing.
 * Returns 1 if valid, 0 if invalid.
 */
static int validate_username(const char *user)
{
    if (!user || !*user) return 0;

    size_t len = strlen(user);
    /* POSIX username max is typically 32, be conservative */
    if (len > 32) return 0;

    /* First character must be lowercase letter or underscore */
    if (!islower((unsigned char)user[0]) && user[0] != '_') return 0;

    for (size_t i = 0; i < len; i++) {
        char c = user[i];
        /* Allow lowercase, digits, underscore, hyphen */
        if (!islower((unsigned char)c) && !isdigit((unsigned char)c) &&
            c != '_' && c != '-') {
            return 0;
        }
    }

    return 1;
}

/* Test valid usernames are accepted */
static int test_valid_usernames(void)
{
    if (validate_username("alice") != 1) return 0;
    if (validate_username("bob_123") != 1) return 0;
    if (validate_username("user-name") != 1) return 0;
    if (validate_username("_service") != 1) return 0;
    if (validate_username("a") != 1) return 0;
    if (validate_username("user123") != 1) return 0;
    return 1;
}

/* Test usernames that are too long */
static int test_username_too_long(void)
{
    /* 33 characters - should fail */
    if (validate_username("abcdefghijklmnopqrstuvwxyz1234567") == 1) return 0;
    /* 32 characters - should pass */
    if (validate_username("abcdefghijklmnopqrstuvwxyz123456") != 1) return 0;
    return 1;
}

/* Test usernames with bad first character */
static int test_username_bad_start(void)
{
    /* Cannot start with digit */
    if (validate_username("1alice") == 1) return 0;
    /* Cannot start with hyphen */
    if (validate_username("-bob") == 1) return 0;
    /* Cannot start with uppercase */
    if (validate_username("Alice") == 1) return 0;
    return 1;
}

/* Test usernames with invalid characters */
static int test_username_bad_chars(void)
{
    /* Colon would corrupt /etc/passwd format */
    if (validate_username("alice:bob") == 1) return 0;
    /* Newline would add extra line */
    if (validate_username("alice\nroot:0:0") == 1) return 0;
    /* Carriage return */
    if (validate_username("alice\rroot") == 1) return 0;
    /* Slash could be path traversal */
    if (validate_username("alice/bob") == 1) return 0;
    /* Space not allowed */
    if (validate_username("alice bob") == 1) return 0;
    /* Uppercase not allowed */
    if (validate_username("aliceB") == 1) return 0;
    return 1;
}

/* Test shell metacharacters are rejected */
static int test_username_shell_injection(void)
{
    if (validate_username("alice;id") == 1) return 0;
    if (validate_username("bob|cat") == 1) return 0;
    if (validate_username("user`whoami`") == 1) return 0;
    if (validate_username("test$(id)") == 1) return 0;
    if (validate_username("u&ser") == 1) return 0;
    if (validate_username("user>file") == 1) return 0;
    return 1;
}

/* Test null and empty inputs */
static int test_username_null_empty(void)
{
    if (validate_username(NULL) == 1) return 0;
    if (validate_username("") == 1) return 0;
    return 1;
}

/* Test common service accounts are valid */
static int test_service_accounts(void)
{
    if (validate_username("www-data") != 1) return 0;
    if (validate_username("_apt") != 1) return 0;
    if (validate_username("nobody") != 1) return 0;
    if (validate_username("systemd-network") != 1) return 0;
    return 1;
}

int main(void)
{
    printf("Username Validator Tests\n");
    printf("========================\n\n");

    printf("Valid usernames:\n");
    TEST(valid_usernames);
    TEST(service_accounts);

    printf("\nInvalid usernames:\n");
    TEST(username_too_long);
    TEST(username_bad_start);
    TEST(username_bad_chars);
    TEST(username_shell_injection);
    TEST(username_null_empty);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}

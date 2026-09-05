/*
 * test_nss_config.c - Fail-closed boolean parsing in the NSS config loader
 * (issue #183, follow-up to the PAM-side fix).
 *
 * nss_openbastion.conf used to be parsed with
 *
 *     config->verify_ssl = (strcmp(value, "true") == 0 ||
 *                           strcmp(value, "1") == 0);
 *
 * so `verify_ssl = TRUE`, `verify_ssl = yes` or a stray trailing character
 * silently produced 0 and disabled TLS certificate verification on every NSS
 * call to the portal. This is the same defect class the PAM parser fixed; the
 * NSS module had its own parser and kept it.
 *
 * The NSS module cannot refuse to start the way pam_openbastion can — it is
 * loaded into every process doing a name lookup, and failing the load would
 * make every SSO user unresolvable host-wide. So it fails closed on the
 * security property instead: an unrecognised value is logged to syslog and the
 * SAFE value is used. These tests pin that contract.
 *
 * We include the module source directly to reach the static helper, the same
 * pattern as test_nss_cache.c.
 */

#include "../nss/libnss_openbastion.c"

#include <assert.h>

static int failures = 0;

static void check(const char *what, int got, int expected)
{
    if (got == expected) {
        printf("  ok   %-52s -> %d\n", what, got);
    } else {
        printf("  FAIL %-52s -> %d (expected %d)\n", what, got, expected);
        failures++;
    }
}

/* All eight documented tokens must be recognised, whatever the safe value. */
static void test_recognised_values(void)
{
    printf("Recognised boolean tokens:\n");

    const char *true_tokens[]  = { "true", "yes", "1", "on" };
    const char *false_tokens[] = { "false", "no", "0", "off" };

    for (size_t i = 0; i < sizeof(true_tokens) / sizeof(true_tokens[0]); i++) {
        check(true_tokens[i], nss_parse_bool_or_safe("verify_ssl", true_tokens[i], 1), 1);
        /* The safe value must not override an explicit, recognised value. */
        check(true_tokens[i], nss_parse_bool_or_safe("verify_ssl", true_tokens[i], 0), 1);
    }

    for (size_t i = 0; i < sizeof(false_tokens) / sizeof(false_tokens[0]); i++) {
        check(false_tokens[i], nss_parse_bool_or_safe("verify_ssl", false_tokens[i], 1), 0);
        check(false_tokens[i], nss_parse_bool_or_safe("verify_ssl", false_tokens[i], 0), 0);
    }
}

/*
 * The regression itself: every one of these used to yield 0, i.e. verify_ssl
 * OFF. They must now yield the safe value (1 for verify_ssl).
 */
static void test_unrecognised_values_keep_the_safe_value(void)
{
    printf("Unrecognised values fall back to the SAFE value (not to 0):\n");

    const char *bad[] = {
        "TRUE", "True", "tru", "trueish", "true ", " true",
        "YES", "Yes", "enabled", "enable", "y", "Y",
        "FALSE", "False", "no ", "2", "-1", "01",
        "", "  ", "#", "true#prod", "verify",
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        check(bad[i], nss_parse_bool_or_safe("verify_ssl", bad[i], 1), 1);
    }

    /* NULL must not crash and must yield the safe value either. */
    check("(NULL)", nss_parse_bool_or_safe("verify_ssl", NULL, 1), 1);

    /*
     * The helper is generic: when a key's safe value is 0, an unrecognised
     * value must resolve to 0 rather than to a hardcoded 1.
     */
    check("TRUE with safe_value=0", nss_parse_bool_or_safe("some_key", "TRUE", 0), 0);
    check("(NULL) with safe_value=0", nss_parse_bool_or_safe("some_key", NULL, 0), 0);
}

/*
 * Documents the exact bug: the old expression and the new helper disagree on
 * every unrecognised value, and the old one always chose the unsafe answer.
 */
static void test_old_expression_was_fail_open(void)
{
    printf("Old expression vs new helper on the reported typos:\n");

    const char *typos[] = { "TRUE", "tru", "yes", "on", "" };

    for (size_t i = 0; i < sizeof(typos) / sizeof(typos[0]); i++) {
        int old_result = (strcmp(typos[i], "true") == 0 ||
                          strcmp(typos[i], "1") == 0);
        int new_result = nss_parse_bool_or_safe("verify_ssl", typos[i], 1);

        if (old_result == 0 && new_result == 1) {
            printf("  ok   %-52s old=0 (TLS off) new=1 (TLS on)\n", typos[i]);
        } else {
            printf("  FAIL %-52s old=%d new=%d\n", typos[i], old_result, new_result);
            failures++;
        }
    }
}

int main(void)
{
    printf("=== NSS config: fail-closed boolean parsing (#183) ===\n\n");

    test_recognised_values();
    printf("\n");
    test_unrecognised_values_keep_the_safe_value();
    printf("\n");
    test_old_expression_was_fail_open();

    printf("\n%s\n", failures == 0 ? "All tests passed" : "FAILURES");
    return failures == 0 ? 0 : 1;
}

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/auth_session.h"

AuthSession *session_create(const char *username, long token) {
    AuthSession *s = malloc(sizeof(AuthSession));
    if (!s) return NULL;
    strncpy(s->username, username, sizeof(s->username) - 1);
    s->username[sizeof(s->username) - 1] = '\0';
    s->authenticated = 1;
    s->token = token;
    return s;
}

/*
 * VULNERABLE (CWE-416): frees the session object but leaves the caller's
 * pointer dangling. Any subsequent call into session_touch() (or any other
 * consumer holding the same pointer, e.g. a background heartbeat thread)
 * reads/writes freed memory.
 */
void session_logout(AuthSession *session) {
    if (!session) return;
    free(session);
    /* BUG: no `session = NULL;`-equivalent contract — callers keep the
       dangling pointer and nothing here invalidates it. */
}

int session_touch(AuthSession *session) {
    if (!session) return -1;
    /* dangling read/write if called after session_logout() on the same ptr */
    session->authenticated = 1;
    return 0;
}

#ifdef AUTH_SESSION_STANDALONE
int main(void) {
    AuthSession *s = session_create("operator1", 0xC0FFEE);
    printf("session created, authenticated=%d\n", s->authenticated);
    session_logout(s);
    /* Use-after-free trigger: touching the session after logout */
    int rc = session_touch(s);
    printf("post-logout touch rc=%d\n", rc);
    return 0;
}
#endif

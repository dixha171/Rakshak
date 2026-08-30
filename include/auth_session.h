#ifndef AUTH_SESSION_H
#define AUTH_SESSION_H

typedef struct {
    char username[64];
    int authenticated;
    long token;
} AuthSession;

/* Creates a new authenticated session for `username`. Caller owns the pointer. */
AuthSession *session_create(const char *username, long token);

/*
 * Logs a session out.
 *
 * NOTE (CWE-416): the reference implementation frees the session but does
 * not clear the caller's pointer, and other code paths continue to read
 * from / write to the session after logout, producing a use-after-free.
 */
void session_logout(AuthSession *session);

/* Touches a session (e.g. refresh last-seen timestamp). */
int session_touch(AuthSession *session);

#endif /* AUTH_SESSION_H */

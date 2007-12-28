/*
 * pam_xauthority.c
 * PAM session management functions for pam_xauthority.so
 *
 * Copyright © 2007 Tim Abbott <tabbott@mit.edu> and Anders Kaseorg
 * <andersk@mit.edu>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>

#define XAUTH "XAUTHORITY"

#define MAXBUF 256

void xauth_cleanup(pam_handle_t *pamh, void *data, int pam_end_status);

/* Initiate session management by creating Xauthority file. */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int i;
    int debug = 0;
    int pamret;
    int n;
    const char *user;
    struct passwd *pw;
    char xauth[MAXBUF];
    char envput[MAXBUF];
    const char *dir = "/tmp";
    int xauth_fd;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
	else if (strncmp(argv[i], "dir=", 4) == 0)
	    dir = argv[i] + 4;
    }

    if ((pamret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_athena-locker: pam_get_user: %s", pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    errno = 0;
    pw = getpwnam(user);
    if (pw == NULL) {
	if (errno != 0)
	    syslog(LOG_ERR, "pam_xauthority: getpwnam: %s", strerror(errno));
	else
	    syslog(LOG_ERR, "pam_xauthority: no such user: %s", user);
	return PAM_SESSION_ERR;
    }

    n = snprintf(xauth, MAXBUF, "%s/xauth-%d-XXXXXX", dir, pw->pw_uid);
    if (n < 0 || n >= MAXBUF) {
	syslog(LOG_ERR, "pam_xauthority: snprintf failed");
	return PAM_SESSION_ERR;
    }
    xauth_fd = mkstemp(xauth);
    if (xauth_fd == -1) {
	syslog(LOG_ERR, "pam_xauthority: mkstemp: %s", strerror(errno));
	return PAM_SESSION_ERR;
    }
    if (fchown(xauth_fd, pw->pw_uid, -1) != 0) {
	syslog(LOG_ERR, "pam_xauthority: fchown: %s", strerror(errno));
	return PAM_SESSION_ERR;
    }
    if (close(xauth_fd) != 0) {
	syslog(LOG_ERR, "pam_xauthority: close: %s", strerror(errno));
	return PAM_SESSION_ERR;
    }
    if (debug)
	syslog(LOG_DEBUG, "pam_xauthority: using Xauthority file %s", xauth);

    n = snprintf(envput, MAXBUF, "%s=%s", XAUTH, xauth);
    if (n < 0 || n >= MAXBUF) {
	syslog(LOG_ERR, "pam_xauthority: snprintf failed");
	return PAM_SESSION_ERR;
    }
    pamret = pam_putenv(pamh, envput);
    if (pamret != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_xauthority: pam_putenv: %s",
	       pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    pamret = pam_set_data(pamh, XAUTH, xauth, xauth_cleanup);
    if (pamret != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_xauthority: pam_set_data: %s",
	       pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

void
xauth_cleanup(pam_handle_t *pamh, void *data, int pam_end_status) 
{
    return;
}

/* Terminate session management by destroying old xauthority file. */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int i;
    int debug = 0;
    const char *xauth;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
    }

    xauth = pam_getenv(pamh, XAUTH);
    if (xauth == NULL) {
	syslog(LOG_ERR, "pam_xauthority: cannot get %s environment variable",
	       XAUTH);
	return PAM_SESSION_ERR;
    }

    if (debug)
	syslog(LOG_DEBUG, "pam_xauthority: unlinking Xauthority file %s",
	       xauth);
    if (unlink(xauth) != 0) {
	syslog(LOG_ERR, "pam_xauthority: unlink: %s", strerror(errno));
	return PAM_SESSION_ERR;
    }

    return PAM_SUCCESS;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (flags == PAM_ESTABLISH_CRED)
	return pam_sm_open_session(pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}


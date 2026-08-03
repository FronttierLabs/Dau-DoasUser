package main

/*
#cgo LDFLAGS: -lpam

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

static int g_verbose = 0;
static void dau_set_verbose(int v) { g_verbose = v; }

static void free_reply_upto(struct pam_response *reply, int upto) {
    if (!reply) return;
    for (int j = 0; j < upto; j++) {
        if (reply[j].resp) { free(reply[j].resp); reply[j].resp = NULL; }
    }
    free(reply);
}

static int dau_conv(int num_msg,
                    const struct pam_message **msg,
                    struct pam_response **resp,
                    void *appdata_ptr)
{
    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
        return PAM_CONV_ERR;

    struct pam_response *reply =
        (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
    if (!reply)
        return PAM_BUF_ERR;
    *resp = reply;

    for (int i = 0; i < num_msg; i++) {
        const struct pam_message *m = msg[i];
        if (!m) continue;

        if (g_verbose)
            fprintf(stderr, "dau-verbose: PAM conv msg_style=%d\n", m->msg_style);

        switch (m->msg_style) {

        case PAM_PROMPT_ECHO_OFF: {
            fprintf(stderr, "%s", m->msg);
            fflush(stderr);

            struct termios oldt, rawt;
            int raw_ok = 0;
            if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldt) == 0) {
                rawt = oldt;
                rawt.c_lflag &= ~(tcflag_t)(ECHO | ICANON | ISIG);
                rawt.c_cc[VMIN]  = 1;
                rawt.c_cc[VTIME] = 0;
                if (tcsetattr(STDIN_FILENO, TCSANOW, &rawt) == 0)
                    raw_ok = 1;
            }

            char buf[1024];
            int  len = 0;

            if (!raw_ok) {
                if (!fgets(buf, sizeof(buf), stdin)) {
                    free_reply_upto(reply, i);
                    *resp = NULL;
                    return PAM_CONV_ERR;
                }
                buf[strcspn(buf, "\r\n")] = '\0';
                len = (int)strlen(buf);
            } else {
                int done = 0;
                while (!done && len < (int)sizeof(buf) - 1) {
                    unsigned char c;
                    ssize_t r = read(STDIN_FILENO, &c, 1);
                    if (r != 1) {
                        if (r < 0 && errno == EINTR) continue;
                        break;
                    }
                    if (c == '\n' || c == '\r') {
                        done = 1;
                    } else if (c == 3) {
                        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                        fprintf(stderr, "\n");
                        memset(buf, 0, sizeof(buf));
                        free_reply_upto(reply, i);
                        *resp = NULL;
                        return PAM_CONV_ERR;
                    } else if (c == 127 || c == 8) {
                        if (len > 0) { len--; fprintf(stderr, "\b \b"); }
                    } else if (c >= 32) {
                        buf[len++] = (char)c;
                        fputc('*', stderr);
                    }
                }
                buf[len] = '\0';
                // Drain remaining stdin if buffer maxed to prevent password leak to child shell
                if (len == (int)sizeof(buf) - 1) {
                    unsigned char drain;
                    while (read(STDIN_FILENO, &drain, 1) == 1) {
                        if (drain == '\n' || drain == '\r') break;
                    }
                }
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                fprintf(stderr, "\n");
                fflush(stderr);
                if (g_verbose)
                    fprintf(stderr, "dau-verbose: tty restored, read %d chars\n", len);
            }

            reply[i].resp = strdup(buf);
            { volatile char *p = buf; while (*p) *p++ = 0; }
            if (!reply[i].resp) {
                free_reply_upto(reply, i);
                *resp = NULL;
                return PAM_BUF_ERR;
            }
            break;
        }

        case PAM_PROMPT_ECHO_ON: {
            fprintf(stderr, "%s", m->msg);
            fflush(stderr);
            char buf[1024];
            if (!fgets(buf, sizeof(buf), stdin)) {
                free_reply_upto(reply, i);
                *resp = NULL;
                return PAM_CONV_ERR;
            }
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n') {
                buf[len-1] = '\0';
            } else {
                // Drain truncated input so it doesn't leak to the shell
                int c;
                while ((c = fgetc(stdin)) != '\n' && c != EOF) {}
            }
            reply[i].resp = strdup(buf);
            if (!reply[i].resp) {
                free_reply_upto(reply, i);
                *resp = NULL;
                return PAM_BUF_ERR;
            }
            break;
        }

        case PAM_ERROR_MSG:
            fprintf(stderr, "dau: PAM error: %s\n", m->msg);
            break;

        case PAM_TEXT_INFO:
            fprintf(stderr, "dau: PAM info: %s\n", m->msg);
            break;

        default:
            break;
        }
    }
    return PAM_SUCCESS;
}

static struct pam_conv make_conv(void) {
    struct pam_conv c;
    c.conv        = dau_conv;
    c.appdata_ptr = NULL;
    return c;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
	"unsafe"
)

type pamHandle struct{ h *C.pam_handle_t }

func setPamVerbose(on bool) {
	if on {
		C.dau_set_verbose(1)
	} else {
		C.dau_set_verbose(0)
	}
}

func pamStart(service, username string) (*pamHandle, error) {
	cSvc := C.CString(service)
	cUsr := C.CString(username)
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cUsr))

	conv := C.make_conv()
	var ph *C.pam_handle_t
	rc := C.pam_start(cSvc, cUsr, &conv, &ph)
	if rc != C.PAM_SUCCESS {
		return nil, fmt.Errorf("pam_start(%s): %s",
			service, C.GoString(C.pam_strerror(nil, rc)))
	}
	vlogf("pam_start(%s, %s) ok", service, username)
	return &pamHandle{h: ph}, nil
}

func (p *pamHandle) setItem(itemType C.int, value string) error {
	cVal := C.CString(value)
	defer C.free(unsafe.Pointer(cVal))
	rc := C.pam_set_item(p.h, itemType, unsafe.Pointer(cVal))
	if rc != C.PAM_SUCCESS {
		return fmt.Errorf("%s", C.GoString(C.pam_strerror(nil, rc)))
	}
	return nil
}

func (p *pamHandle) setPamContext() {
	tty := ""
	link, err := os.Readlink("/proc/self/fd/0")
	if err == nil && len(link) > 5 && link[:5] == "/dev/" {
		tty = link
	}
	if err := p.setItem(C.PAM_TTY, tty); err != nil {
		vlogf("pam_set_item(PAM_TTY) failed: %v (non-fatal)", err)
	}
	if err := p.setItem(C.PAM_RHOST, "localhost"); err != nil {
		vlogf("pam_set_item(PAM_RHOST) failed: %v (non-fatal)", err)
	}
	vlogf("PAM context: tty=%q rhost=%q", tty, "localhost")
}

func (p *pamHandle) authenticate() error {
	rc := C.pam_authenticate(p.h, 0)
	if rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam_authenticate: %s", C.GoString(C.pam_strerror(nil, rc)))
	}
	vlogf("pam_authenticate ok")
	return nil
}

func (p *pamHandle) acctMgmt() error {
	rc := C.pam_acct_mgmt(p.h, 0)
	if rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam_acct_mgmt: %s", C.GoString(C.pam_strerror(nil, rc)))
	}
	vlogf("pam_acct_mgmt ok")
	return nil
}

func (p *pamHandle) setCred() error {
	rc := C.pam_setcred(p.h, C.PAM_ESTABLISH_CRED)
	if rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam_setcred: %s", C.GoString(C.pam_strerror(nil, rc)))
	}
	vlogf("pam_setcred ok")
	return nil
}

func (p *pamHandle) end() { C.pam_end(p.h, C.PAM_SUCCESS) }

func authenticateUser(invoker string) error {
	service := "dau"
	pamPath := "/etc/pam.d/" + service
	fi, err := os.Stat(pamPath)
	if err != nil {
		auditLog("AUTH_FAIL", fmt.Sprintf("no PAM service found (invoker=%s)", invoker))
		return fmt.Errorf("no usable PAM service %s present (fail-closed)", service)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot stat PAM service")
	}
	if st.Uid != 0 || st.Gid != 0 {
		return fmt.Errorf("PAM service %s must be root-owned", pamPath)
	}
	if fi.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("PAM service %s must not be group/other-writable", pamPath)
	}

	auditLog("AUTH", fmt.Sprintf("service=%s invoker=%s", service, invoker))

	ph, err := pamStart(service, invoker)
	if err != nil {
		return err
	}
	defer ph.end()

	ph.setPamContext()
	if err := ph.authenticate(); err != nil {
		auditLog("AUTH_FAIL", fmt.Sprintf("invoker=%s: %v", invoker, err))
		return err
	}
	if err := ph.acctMgmt(); err != nil {
		auditLog("ACCT_FAIL", fmt.Sprintf("invoker=%s: %v", invoker, err))
		return err
	}
	if err := ph.setCred(); err != nil {
		auditLog("CRED_FAIL", fmt.Sprintf("invoker=%s: %v", invoker, err))
		return err
	}
	return nil
}

func whoami() string {
	u, err := user.LookupId(fmt.Sprintf("%d", syscall.Getuid()))
	if err != nil {
		return fmt.Sprintf("uid=%d", syscall.Getuid())
	}
	return u.Username
}

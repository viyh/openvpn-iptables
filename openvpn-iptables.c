/*
 * openvpn-iptables - OpenVPN plugin for per group iptables rules
 *
 * Install openvpn-dev
 * Compile with "gcc -fPIC -shared -Wall openvpn-iptables.c -o openvpn-iptables.so"
 *
 * Copyright (C) 2014 Joe Richards <nospam-github@disconformity.net>
 */

#include <stdio.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <openvpn/openvpn-plugin.h>

struct plugin_context {
    const char *script_path;
};

void handle_sigchld(int sig)
{
    while(waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
}

static int
generic_deferred_handler(const char *script_path, const char * argv[], const char * envp[])
{
    int pid;
    struct sigaction sa;
    const char *sc_argv[] = {script_path, 0};

    sa.sa_handler = &handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;

    if (!argv[1] || !argv[2])
        return OPENVPN_PLUGIN_FUNC_ERROR;

    if (sigaction(SIGCHLD, &sa, 0) == -1)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    pid = fork();

    if (pid < 0)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    if (pid > 0)
        return OPENVPN_PLUGIN_FUNC_DEFERRED;

    execve(sc_argv[0], (char *const*)argv, (char *const*)envp);
    exit(127);
}


OPENVPN_EXPORT int
openvpn_plugin_open_v3 (const int v3structver,
                        struct openvpn_plugin_args_open_in const *args,
                        struct openvpn_plugin_args_open_return *ret)
{
    struct plugin_context *context = NULL;

    /*  Which callbacks to intercept.  */
    ret->type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_LEARN_ADDRESS);

    /* Allocate our context */
    context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

    if (args->argv[1])
        context->script_path = strdup(args->argv[1]);

    printf("openvpn-netfilter: script_path=%s\n", context->script_path);

    /* Point the global context handle to our newly created context */
    ret->handle = (void *) context;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3 (const int version,
                        struct openvpn_plugin_args_func_in const *args,
                        struct openvpn_plugin_args_func_return *retptr)
{
    struct plugin_context *context = (struct plugin_context *) args->handle;

    if (args->type == OPENVPN_PLUGIN_LEARN_ADDRESS)
        return generic_deferred_handler(context->script_path, args->argv, args->envp);
    else
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free (context);
}

/*
 * openvpn-iptables - OpenVPN plugin for per group iptables rules
 *
 * depends: openvpn-dev iptables-dev libyajl-dev
 *    iptables-devel
      git clone git://github.com/lloyd/yajl
 * Copyright (C) 2014 Joe Richards <nospam-github@disconformity.net>
 */

#define DEBUG 0
#define FILTER_GROUPS_FILE "/etc/openvpn/filter_groups.json"
#define TABLE "filter"

#include "openvpn-iptables.h"

static int
do_tables(char *const argv[], char *const envp[])
{
    struct plugin_context pc;

    pc.operation = argv[1];
    pc.client_ip = argv[2];

    if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "update") == 0)
    {
        pc.client_name = argv[3];
        printf("openvpn-iptables: operation[%s], client_ip[%s], client_name[%s]\n",
               pc.operation, pc.client_ip, pc.client_name);
        delete_iptables_client(pc);
        add_iptables_client(pc);
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
        printf("openvpn-iptables: operation[%s], client_ip[%s]\n",
               pc.operation, pc.client_ip);
        delete_iptables_client(pc);
    }
    else
    {
        printf("openvpn-iptables: unknown operation [%s]\n", argv[1]);
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
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
    context = (struct plugin_context *) safe_calloc (1, sizeof (struct plugin_context));

    /* Point the global context handle to our newly created context */
    ret->handle = (void **) context;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3 (const int version,
                        struct openvpn_plugin_args_func_in const *args,
                        struct openvpn_plugin_args_func_return *retptr)
{
    if (args->type == OPENVPN_PLUGIN_LEARN_ADDRESS)
        return do_tables((char *const *)args->argv, (char *const *)args->envp);
    /*        return generic_deferred_handler(context->script_path, args->argv, args->envp); */
    else
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free (context);
}


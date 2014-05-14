/*
 * openvpn-iptables - OpenVPN plugin for per group iptables rules
 *
 * depends: openvpn-dev libjson-c-dev
 *
 * Copyright (C) 2014 Joe Richards <nospam-github@disconformity.net>
 */

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <yajl/yajl_tree.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <openvpn/openvpn-plugin.h>

struct plugin_context
{
    char *operation;
    char *client_ip;
    char *client_name;
};

struct netaddr
{
    struct in_addr network;
    struct in_addr netmask;
};

struct rule
{
    char *comment;
    struct netaddr dst_net;
    int dst_port;
    int proto;
};

struct entry
{
    struct ipt_entry e;
    struct xt_standard_target t;
};

void *
safe_malloc (size_t size)
{
    register void *value = malloc (size);
    if (value == 0)
        perror("virtual memory exhausted");
    return value;
}

void *
safe_realloc (void *ptr, size_t size)
{
    register void *value = realloc (ptr, size);
    if (value == 0)
        perror("Virtual memory exhausted");
    return value;
}

struct netaddr
str_to_netaddr(char *ipstr, struct rule *r)
{
    struct netaddr netaddr;
    unsigned int prefix = 32;
    unsigned long mask = 0xffffffff, val = 0x0, ip;
    char *maskstr = (char *)NULL;

    if ( (maskstr = strchr(ipstr, '/')) )
    {
        *maskstr = 0;
        maskstr++;
    }

    if ( ( ip = (unsigned long)(inet_addr(ipstr)) ) == 0xffffffff )
    {
        printf("openvpn-iptables: must specify a valid ip\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    if ( maskstr )
        prefix = (unsigned long)atol(maskstr);

    if ( prefix < 0 || (prefix > 32) )
    {
        printf("openvpn-iptables: cidr must be in 1-32 range\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    mask = (mask << ((unsigned long)(32 - prefix)));

    ip = ntohl(ip) & mask;

    netaddr.network.s_addr = ntohl(ip | val);
    netaddr.netmask.s_addr = ntohl(mask);

    return netaddr;
}

int
add_iptables_rule(const struct rule *r, const char *table, const struct plugin_context pc)
{

    struct entry entry;
    struct xtc_handle *h;
    // struct ipt_tcp tcpinfo;

    h = iptc_init(table);
    if (!h)
    {
        printf("Could not init IPTC library: %s\n", iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    memset (&entry, 0, sizeof (entry));

    entry.t.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
    strncpy (entry.t.target.u.user.name, "ACCEPT", sizeof (entry.t.target.u.user.name));
    entry.e.target_offset = sizeof (struct ipt_entry);
    entry.e.next_offset = entry.e.target_offset + entry.t.target.u.user.target_size;
    entry.e.ip.src.s_addr = inet_addr(pc.client_ip);
    entry.e.ip.smsk.s_addr = inet_addr("255.255.255.255");
    entry.e.ip.dst.s_addr = r->dst_net.network.s_addr;
    entry.e.ip.dmsk.s_addr = r->dst_net.netmask.s_addr;
    entry.e.ip.proto = r->proto;

    printf("DEBUG: adding rule for %s\n", inet_ntoa(entry.e.ip.dst));
    fflush(stdout);

    if (!iptc_is_chain(pc.client_ip, h))
    {
        printf("Could not find chain!\n");
        iptc_create_chain(pc.client_ip, h);
    }

    if (!iptc_append_entry (pc.client_ip, (struct ipt_entry *) &entry, h))
    {
        printf("Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (!iptc_commit (h))
    {
        printf("Could not commit changes in iptables (table %s, chain: %s, target: %s): %s\n",
               table, pc.client_ip, entry.t.target.u.user.name, iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (h)
        iptc_free (h);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

yajl_val
read_json_file(const char *file)
{
    FILE *fp;
    yajl_val json;
    size_t rd;
    char errbuf[1024];
    static unsigned char fileData[65536];
    fileData[0] = errbuf[0] = 0;

    fp = fopen(file, "r");
    rd = fread((void *) fileData, 1, sizeof(fileData) - 1, fp);
    if (rd == 0 && !feof(stdin))
    {
        printf("openvpn-iptables: error encountered on file read\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    else if (rd >= sizeof(fileData) - 1)
    {
        printf("openvpn-iptables: config file too big\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    json = yajl_tree_parse((const char *) fileData, errbuf, sizeof(errbuf));

    if (json == NULL)
    {
        printf("openvpn-iptables: parse_error: ");
        if (strlen(errbuf))
            printf(" %s\n", errbuf);
        else
            printf("unknown error\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    return json;
}

struct rule *
parse_rule_param(struct rule *r, const char *key, yajl_val val)
{
    char *proto;

    printf( "\t%s: %s \n", key, YAJL_GET_STRING(val) );

    if (strcmp(key, "dst_ip") == 0)
    {
        r->dst_net = str_to_netaddr(YAJL_GET_STRING(val), r);
    }
    else if (strcmp(key, "dst_port") == 0)
    {
        r->dst_port = YAJL_GET_INTEGER(val);
    }
    else if (strcmp(key, "proto") == 0)
    {
        proto = YAJL_GET_STRING(val);
        if (strcmp(proto, "tcp") == 0)
            r->proto   = IPPROTO_TCP;
        else if (strcmp(proto, "udp") == 0)
            r->proto   = IPPROTO_UDP;
        else
            printf("Invalid protocol %s!\n", YAJL_GET_STRING(val));
    }
    else if (strcmp(key, "comment") == 0)
    {
        r->comment     = YAJL_GET_STRING(val);
    }
    else
        printf("Unknown rule parameter: %s\n", key);

    return r;
}

int
get_group_rules (const yajl_val json, const char *group, const struct plugin_context pc, const char *table)
{
    const char *path[] = { group, "rules", (const char *) 0 };
    yajl_val group_rules = yajl_tree_get(json, path, yajl_t_array);
    size_t len, rule_len;
    int i, j;
    const char *key;
    yajl_val val;
    struct rule *r = calloc(1, sizeof(struct rule));

    if (r == NULL)
    {
        printf("openvpn-iptables: rule malloc failure\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if ( !group_rules || !YAJL_IS_ARRAY(group_rules) )
    {
        printf("openvpn-iptables: no rules found for %s\n", group);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    printf( "openvpn-iptables: rules found for %s\n", group);

    len = group_rules->u.array.len;
    for (i = 0; i < len; ++i)
    {
        yajl_val rule = group_rules->u.array.values[i];
        rule_len = rule->u.object.len;
        for (j = 0; j < rule_len; ++j)
        {
            key = rule->u.object.keys[j];
            val = rule->u.object.values[j];
            parse_rule_param(r, key, val);
        }
        add_iptables_rule(r, table, pc);
    }
    yajl_tree_free(group_rules);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

gid_t *
add_group_rules (const struct plugin_context pc, const char *table)
{
    int i = 0;
    int ngroups = 128;
    gid_t *groups = (gid_t *) safe_malloc (ngroups * sizeof (gid_t));
    struct passwd *pw = getpwnam (pc.client_name);
    struct group *g;
    yajl_val json;

    static const char filename[] = "filter_groups.json";

    if (pw == NULL)
        return NULL;

    if (getgrouplist (pw->pw_name, pw->pw_gid, groups, &ngroups) < 0)
    {
        safe_realloc (groups, ngroups * sizeof (gid_t));
        getgrouplist (pw->pw_name, pw->pw_gid, groups, &ngroups);
    }

    json = read_json_file(filename);

    printf("groups found: %d\n", ngroups);
    while (i < ngroups)
    {
        g = getgrgid(groups[i]);
        if (g == NULL)
        {
            printf("gid %d not found\n", groups[i]);
            continue;
        }
        get_group_rules(json, g->gr_name, pc, table);
        i++;
    }
    return (gid_t *)groups;
}

static int
add_table_entries(const struct plugin_context pc, const char *table)
{
    printf("openvpn-iptables: table[%s], operation[add], client_ip[%s], client_name[%s]\n",
           table, pc.client_ip, pc.client_name);
    add_group_rules(pc, table);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
delete_table_entries(const struct plugin_context pc, const char *table)
{
    // struct ipt_entry *e;

    printf("openvpn-iptables: table[%s], operation[delete], client_ip[%s]\n",
           table, pc.client_ip);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
update_table_entries(const struct plugin_context pc, const char *table)
{
    // struct ipt_entry *e;

    printf("openvpn-iptables: table[%s], operation[update], client_ip[%s], client_name[%s]\n",
           table, pc.client_ip, pc.client_name);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
do_tables(char *const argv[], char *const envp[])
{
    const char *table = "filter";
    struct plugin_context pc;

    pc.operation = argv[1];
    pc.client_ip = argv[2];

    if (strcmp(argv[1], "add") == 0)
    {
        pc.client_name = argv[3];
        add_table_entries(pc, table);
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
        delete_table_entries(pc, table);
    }
    else if (strcmp(argv[1], "update") == 0)
    {
        pc.client_name = argv[3];
        update_table_entries(pc, table);
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
    context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

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

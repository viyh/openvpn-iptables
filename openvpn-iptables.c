/*
 * openvpn-iptables - OpenVPN plugin for per group iptables rules
 *
 * depends: openvpn-dev iptables-dev libyajl-dev
 *    iptables-devel
      git clone git://github.com/lloyd/yajl
 * Copyright (C) 2014 Joe Richards <nospam-github@disconformity.net>
 */

#define FILTER_GROUPS_FILE "/etc/openvpn/filter_groups.json"

#include <stdio.h>
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
#include <linux/netfilter/xt_comment.h>
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
    struct ipt_entry entry;
    struct xt_standard_target target;
};

void *
safe_calloc (int mult, size_t size)
{
    register void *value = calloc (mult, size);
    if (value == 0)
        perror("Virtual memory exhausted");
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

/* We want this to be readable, so only print out neccessary fields.
 * Because that's the kind of world I want to live in.  */
static void print_rule(const struct ipt_entry *e,
                       struct xtc_handle *h, const char *chain)
{
    const char *target_name;

    printf("openvpn-iptables: \t");

    /* print chain name */
    printf(" -A %s", chain);

    /* Print IP part. */
    printf(" -s %s %s", inet_ntoa(e->ip.src), inet_ntoa(e->ip.smsk));
    printf(" -d %s %s", inet_ntoa(e->ip.dst), inet_ntoa(e->ip.dmsk));

    //    print_proto(e->ip.proto, e->ip.invflags & IPT_INV_PROTO);

    if (e->ip.flags & IPT_F_FRAG)
        printf(" %s-f ",
               e->ip.invflags & IPT_INV_FRAG ? "! " : "");

    /* Print target name */
    target_name = iptc_get_target(e, h);
    if (target_name && (*target_name != '\0'))
        printf(" -j %s ", target_name);

    printf("\n");
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

struct ipt_entry *
create_iptables_entry(const char *table, struct xtc_handle *h,
                      const char *src_ip, const char *src_mask,
                      const char *dst_ip, const char *dst_mask,
                      const char *target, const char *comment)
{
    struct entry entry;
    int ret;

    memset (&entry, 0, sizeof (struct entry));

    printf("DEBUG entry:\n\ttable: %s\n\tsrc_ip: %s\n\tsrc_mask: %s\n\t", table, src_ip, src_mask);
    printf("dst_ip: %s\tdst_mask: %s\n\ttarget: %s\n", dst_ip, dst_mask, target);

    /* target */
    entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
    strncpy (entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));

    /* entry */
    entry.entry.target_offset = sizeof (struct ipt_entry);
    entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;

    entry.entry.ip.src.s_addr = inet_addr(src_ip);
    entry.entry.ip.smsk.s_addr = inet_addr(src_mask);
    entry.entry.ip.dst.s_addr = inet_addr(dst_ip);
    entry.entry.ip.dmsk.s_addr = inet_addr(dst_mask);
    // entry.entry.ip.proto = r->proto;

    printf("DEBUG: adding rule for %s\n", inet_ntoa(entry.entry.ip.dst));
    fflush(stdout);

    ret = iptc_append_entry(table, (struct ipt_entry *) &entry, h);
    if (!ret)
    {
        printf("Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

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

    if (!(fp = fopen(file, "r")))
    {
        printf("openvpn-iptables: could not open filter_groups file: %s\n", file);
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

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
            r->proto = IPPROTO_TCP;
        else if (strcmp(proto, "udp") == 0)
            r->proto = IPPROTO_UDP;
        else
            printf("Invalid protocol %s!\n", YAJL_GET_STRING(val));
    }
    else if (strcmp(key, "comment") == 0)
    {
        r->comment = YAJL_GET_STRING(val);
    }
    else
        printf("Unknown rule parameter: %s\n", key);

    return r;
}

struct rule *
process_group_rules (const yajl_val json, const char *group)
{
    const char *path[] = { group, "rules", (const char *) 0 };
    yajl_val group_rules = yajl_tree_get(json, path, yajl_t_array), val;
    size_t len, rule_len;
    int i, j;
    const char *key;
    struct rule *r = (struct rule *) safe_calloc(1, sizeof(struct rule));

    if ( !group_rules || !YAJL_IS_ARRAY(group_rules) )
    {
        printf("openvpn-iptables: no rules found for %s\n", group);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    printf( "openvpn-iptables: rules found for %s\n", group);

    len = group_rules->u.array.len;
    for (i = 0; i < len; ++i)
    {
        r = (struct rule *) safe_realloc(r, sizeof(struct rule) * i + 1);
        yajl_val rule = group_rules->u.array.values[i];
        rule_len = rule->u.object.len;
        for (j = 0; j < rule_len; ++j)
        {
            key = rule->u.object.keys[j];
            val = rule->u.object.values[j];
            parse_rule_param(&r[i], key, val);
        }
    }
    yajl_tree_free(group_rules);

    return r;
}

static int
add_group_rules (const struct plugin_context pc, const char *table)
{
    int i = 0;
    int ngroups = 128;
    gid_t *groups = (gid_t *) safe_calloc (ngroups, sizeof (gid_t));
    struct passwd *pw = getpwnam (pc.client_name);
    struct group *g;
    yajl_val json;
    struct rule *r;

    if (pw == NULL)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    if (getgrouplist (pw->pw_name, pw->pw_gid, groups, &ngroups) < 0)
    {
        safe_realloc (groups, ngroups * sizeof (gid_t));
        getgrouplist (pw->pw_name, pw->pw_gid, groups, &ngroups);
    }

    json = read_json_file(FILTER_GROUPS_FILE);

    printf("groups found: %d\n", ngroups);
    while (i < ngroups)
    {
        g = getgrgid(groups[i]);
        if (g == NULL)
        {
            printf("gid %d not found\n", groups[i]);
            continue;
        }
        r = process_group_rules(json, g->gr_name);

        i++;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
create_iptables_base_rules(struct xtc_handle *h, const char *table, const struct plugin_context pc)
{
    if (!iptc_is_chain(pc.client_ip, h))
    {
        printf("Creating new chain...\n");
        iptc_create_chain(pc.client_ip, h);
    }

    create_iptables_entry("OUTPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", pc.client_ip, pc.client_name);

    create_iptables_entry("INPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", pc.client_ip, pc.client_name);

    create_iptables_entry("FORWARD", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", pc.client_ip, pc.client_name);

    fflush(stdout);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
delete_iptables_client(struct xtc_handle *h, const char *table, const struct plugin_context pc)
{
    int ret, rulenum = 1, chainnum = 0;
    const struct ipt_entry *e;
    const char *chains[] = { "OUTPUT", "INPUT", "FORWARD", NULL };
    errno = 0;

    while (chains[chainnum] != NULL)
    {
        for (e = iptc_first_rule(chains[chainnum], h), rulenum=1; e; e = iptc_next_rule(e, h), rulenum++)
        {
            print_rule(e, h, chains[chainnum]);
            if (e->ip.src.s_addr == inet_addr(pc.client_ip))
            {
                printf("openvpn-iptables: deleting rule number %d in %s.\n", rulenum, chains[chainnum]);
                ret = iptc_delete_num_entry(chains[chainnum], rulenum-1, h);
                if (!ret)
                {
                    printf("openvpn-iptables: could not delete rule: [%s, %s]\n",
                        (char*)strerror(errno), iptc_strerror (errno));
                    exit(OPENVPN_PLUGIN_FUNC_ERROR);
                }

                fflush(stdout);
            }
            break;
        }
        chainnum++;
    }

    if (iptc_is_chain(pc.client_ip, h))
    {
        iptc_flush_entries(pc.client_ip, h);
        ret = iptc_delete_chain(pc.client_ip, h);
        if (!ret)
        {
            printf("openvpn-iptables: could not delete chain!\n");
            exit(OPENVPN_PLUGIN_FUNC_ERROR);
        }
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
add_iptables_client(const struct plugin_context pc, const char *table)
{
    struct xtc_handle *h;

    h = iptc_init(table);
    if (!h)
    {
        printf("Could not init IPTC library: %s\n", iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    delete_iptables_client(h, table, pc);

    create_iptables_base_rules(h, table, pc);

    // add_group_rules(table, pc);

    if (!iptc_commit (h))
    {
        printf("Could not commit changes in iptables (table %s, chain: %s, target: %s): %s, %s\n",
               table, pc.client_ip, "ACCEPT", (char*)strerror(errno), iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (h)
        iptc_free (h);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
add_table_entries(const struct plugin_context pc, const char *table)
{
    printf("openvpn-iptables: table[%s], operation[add/update], client_ip[%s], client_name[%s]\n",
           table, pc.client_ip, pc.client_name);
    add_iptables_client(pc, table);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
delete_table_entries(const struct plugin_context pc, const char *table)
{
    printf("openvpn-iptables: table[%s], operation[delete], client_ip[%s]\n",
           table, pc.client_ip);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
do_tables(char *const argv[], char *const envp[])
{
    const char *table = "filter";
    struct plugin_context pc;

    pc.operation = argv[1];
    pc.client_ip = argv[2];

    if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "update") == 0)
    {
        pc.client_name = argv[3];
        add_table_entries(pc, table);
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
        delete_table_entries(pc, table);
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


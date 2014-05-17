/*
 * openvpn-iptables - OpenVPN plugin for per group iptables rules
 *
 * depends: openvpn-dev iptables-dev libyajl-dev
 *    iptables-devel
      git clone git://github.com/lloyd/yajl
 * Copyright (C) 2014 Joe Richards <nospam-github@disconformity.net>
 */

#define DEBUG 1
#define FILTER_GROUPS_FILE "/etc/openvpn/filter_groups.json"
#define TABLE "filter"

#include "openvpn-iptables.h"

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
    char *dst_ip;
    char *dst_mask;
    char *dst_port;
    char *proto;
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
    {
        perror("Virtual memory exhausted");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    return value;
}

void *
safe_realloc (void *ptr, size_t size)
{
    register void *value = realloc (ptr, size);
    if (value == 0)
    {
        perror("Virtual memory exhausted");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    return value;
}

struct netaddr *
str_to_netaddr(const char *ipstr)
{
    struct netaddr *netaddr = safe_calloc(1, sizeof(struct netaddr));
    unsigned int prefix = 32;
    int mask = 0xffffffff, val = 0x0, ip;
    char *maskstr = (char *)NULL;
    char *tmp_ipstr = strdup(ipstr);

    if ( (maskstr = strchr(tmp_ipstr, '/')) )
    {
        *maskstr = 0;
        maskstr++;
    }

    if ( ( ip = (unsigned long)(inet_addr(tmp_ipstr)) ) == 0xffffffff )
    {
        printf("openvpn-iptables: must specify a valid ip\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if ( maskstr )
        prefix = (unsigned long)atol(maskstr);

    if ( prefix > 32 )
    {
        printf("openvpn-iptables: cidr must be in 1-32 range\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    mask = ~(1 << (32 - prefix)) - 1;
    ip = ntohl(ip) & mask;

    if (prefix == 0)
        netaddr->netmask.s_addr = inet_addr("0.0.0.0");
    else
        netaddr->netmask.s_addr = ntohl(~((1 << (32 - prefix)) - 1));

    netaddr->network.s_addr = ntohl(ip | val);

    return netaddr;
}

int
create_iptables_entry(const char *chain, struct xtc_handle *h,
                      const char *src_ip, const char *src_mask,
                      const char *dst_ip, const char *dst_mask,
                      const char *proto, const char *dst_port,
                      const char *target, const char *comment,
                      const int append)
{
    struct ipt_entry *chain_entry = NULL;
    struct ipt_entry_match *entry_match = NULL;
    struct ipt_entry_target *entry_target = NULL;
    ipt_chainlabel labelit;
    long match_size;
    int result = 0;
    errno = 0;

    chain_entry = safe_calloc(1, sizeof(*chain_entry));

    if (!chain_entry)
        printf("Could not allocate memory!\n");

    if (DEBUG)
    {
        printf("\tchain: %s\n", chain);
        printf("\tsrc_ip: %s\n", src_ip);
        printf("\tsrc_mask: %s\n", src_mask);
        printf("\tdst_ip: %s\n", dst_ip);
        printf("\tdst_mask: %s\n", dst_mask);
        printf("\tproto: %s\n", proto);
        printf("\tdst_port: %s\n", dst_port);
        printf("\ttarget: %s\n", target);
        fflush(stdout);
    }

    if (src_ip && src_mask)
    {
        chain_entry->ip.src.s_addr = inet_addr(src_ip);
        chain_entry->ip.smsk.s_addr = inet_addr(src_mask);
    }
    if (dst_ip && dst_mask)
    {
        chain_entry->ip.dst.s_addr = inet_addr(dst_ip);
        chain_entry->ip.dmsk.s_addr = inet_addr(dst_mask);
    }

    if (proto && dst_port && strcmp(proto, "tcp") == 0)
    {
        chain_entry->ip.proto = IPPROTO_TCP;
        entry_match = get_tcp_match(NULL, dst_port, &chain_entry->nfcache);
    }
    else if (proto && dst_port && strcmp(proto, "udp") == 0)
    {
        chain_entry->ip.proto = IPPROTO_UDP;
        entry_match = get_udp_match(NULL, dst_port, &chain_entry->nfcache);
    }

    size_t size;

    size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(int));
    entry_target = calloc(1, size);
    entry_target->u.user.target_size = size;
    strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);

    if (entry_match)
        match_size = entry_match->u.match_size;
    else
        match_size = 0;

    fflush(stdout);
    chain_entry = safe_realloc(chain_entry, sizeof(*chain_entry) + match_size + entry_target->u.target_size);
    memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
    chain_entry->target_offset = sizeof(*chain_entry) + match_size;
    chain_entry->next_offset = sizeof(*chain_entry) + match_size + entry_target->u.target_size;

    if (entry_match)
        memcpy(chain_entry->elems, entry_match, match_size);

    strncpy(labelit, chain, sizeof(ipt_chainlabel));

    result = iptc_is_chain(chain, h);
    if (!result)
    {
        printf("libiptc error: Chain %s does not exist!\n", chain);
        return 0;
    }
    if (append)
        result = iptc_append_entry(labelit, chain_entry, h);
    else
        result = iptc_insert_entry(labelit, chain_entry, 0, h);

    if (!result)
    {
        printf("libiptc error: Can't add, %s\n", iptc_strerror(errno));
        return 0;
    }

    else
        printf("added new rule successfully\n");

    free(entry_match);
    free(entry_target);
    free(chain_entry);

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

void
parse_rule_param(struct rule *r, const char *key, yajl_val val)
{
    char *proto;
    char *ipstr;
    struct netaddr *netaddr;

    // if (DEBUG)
    //     printf( "\t%s: %s \n", key, YAJL_GET_STRING(val) );

    if (strcmp(key, "dst_ip") == 0)
    {
        ipstr = YAJL_GET_STRING(val);
        netaddr = str_to_netaddr(ipstr);
        r->dst_ip = strdup(inet_ntoa(netaddr->network));
        r->dst_mask = strdup(inet_ntoa(netaddr->netmask));
        // r->dst_mask = strdup("255.255.255.255");
    }
    else if (strcmp(key, "dst_port") == 0)
    {
        r->dst_port = YAJL_GET_STRING(val);
    }
    else if (strcmp(key, "proto") == 0)
    {
        proto = YAJL_GET_STRING(val);
        if (strcmp(proto, "tcp") == 0 || strcmp(proto, "udp") == 0)
            r->proto = proto;
        else
            printf("Invalid protocol %s!\n", proto);

    }
    else if (strcmp(key, "comment") == 0)
    {
        r->comment = YAJL_GET_STRING(val);
    }
    else
        printf("Unknown rule parameter: %s\n", key);

    if (!proto)
        r->proto = proto;
}

int
process_group_rules (struct xtc_handle *h, const struct plugin_context pc,
                     const yajl_val json, const char *group)
{
    const char *path[] = { group, "rules", (const char *) 0 };
    yajl_val group_rules = yajl_tree_get(json, path, yajl_t_array), val;
    size_t len, rule_len;
    int i, j;
    const char *key;

    fflush(stdout);
    if ( !group_rules || !YAJL_IS_ARRAY(group_rules) )
    {
        printf("openvpn-iptables: no rules found for %s\n", group);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    printf( "openvpn-iptables: rules found for %s\n", group);

    len = group_rules->u.array.len;
    for (i = 0; i < len; ++i)
    {
        struct rule r;
        // = (struct rule *) safe_calloc(1, sizeof(struct rule));
        yajl_val rule = group_rules->u.array.values[i];
        rule_len = rule->u.object.len;
        for (j = 0; j < rule_len; ++j)
        {
            key = rule->u.object.keys[j];
            val = rule->u.object.values[j];
            parse_rule_param(&r, key, val);
        }

        create_iptables_entry(pc.client_ip, h, pc.client_ip, "255.255.255.255",
                              r.dst_ip, r.dst_mask, r.proto, r.dst_port,
                              "ACCEPT", r.comment, 0);
    }
    yajl_tree_free(group_rules);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/*
create_iptables_entry(const char *chain, struct xtc_handle *h,
                      const char *src_ip, const char *src_mask,
                      const char *dst_ip, const char *dst_mask,
                      const char *proto, const char *dst_port,
                      const char *target, const char *comment,
                      const int append)
*/

static int
add_group_rules (struct xtc_handle *h, const struct plugin_context pc)
{
    int i = 0;
    int ngroups = 128;
    gid_t *groups = (gid_t *) safe_calloc (ngroups, sizeof (gid_t));
    struct passwd *pw = getpwnam (pc.client_name);
    struct group *g;
    yajl_val json;

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
        process_group_rules(h, pc, json, g->gr_name);
        i++;
        break;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
create_iptables_base_rules(struct xtc_handle *h, const struct plugin_context pc)
{
    errno = 0;

    if (!iptc_is_chain(pc.client_ip, h))
    {
        printf("Creating new chain...\n");
        iptc_create_chain(pc.client_ip, h);
    }

    create_iptables_entry("OUTPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", NULL, NULL, pc.client_ip, pc.client_name, 0);
    create_iptables_entry("INPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", pc.client_ip, pc.client_name, 0);
    create_iptables_entry("FORWARD", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", pc.client_ip, pc.client_name, 0);
    create_iptables_entry(pc.client_ip, h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", "ACCEPT", pc.client_name, 0);
    create_iptables_entry(pc.client_ip, h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", "DROP", pc.client_name, 1);

    fflush(stdout);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

const struct ipt_entry *
delete_iptables_rule(struct xtc_handle *h, const char *chain, const int rulenum)
{
    int ret;
    printf("openvpn-iptables: deleting rule number %d in %s.\n", rulenum, chain);

    ret = iptc_delete_num_entry(chain, rulenum, h);
    if (!ret)
    {
        printf("openvpn-iptables: could not delete rule: [%s, %s]\n",
               (char *)strerror(errno), iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    return iptc_first_rule(chain, h);
}

int
delete_chain(struct xtc_handle *h, const char *chain)
{
    int ret;
    if (!iptc_is_chain(chain, h))
        return 0;

    iptc_flush_entries(chain, h);
    ret = iptc_delete_chain(chain, h);
    if (!ret)
    {
        printf("openvpn-iptables: could not delete chain!\n");
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    return 0;
}

struct xtc_handle *
init_iptables(const char *table)
{
    struct xtc_handle *h;
    h = iptc_init(table);

    if (!h)
    {
        printf("Could not init IPTC library: %s\n", iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }
    return h;
}

void
close_iptables(struct xtc_handle *h, const struct plugin_context pc)
{
    errno = 0;
    if (!iptc_commit (h))
    {
        printf("Could not commit changes in iptables (client: %s): %s, %s\n",
               pc.client_ip, (char *)strerror(errno), iptc_strerror (errno));
        exit(OPENVPN_PLUGIN_FUNC_ERROR);
    }

    if (h)
        iptc_free (h);
}

int
delete_iptables_client(const struct plugin_context pc)
{
    const char *chain;
    int rulenum;

    struct xtc_handle *h;
    h = init_iptables(TABLE);

    printf("openvpn-iptables: operation[delete], client_ip[%s]\n", pc.client_ip);

    /* delete iptables rules matching client src from any chain */
    for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))
    {
        const struct ipt_entry *e;
        rulenum = 0;
        e = iptc_first_rule(chain, h);
        while (e)
        {
            if (e->ip.src.s_addr == inet_addr(pc.client_ip))
            {
                e = delete_iptables_rule(h, chain, rulenum);
                rulenum = 0;
            }
            else
            {
                e = iptc_next_rule(e, h);
                rulenum++;
            }
        }
    }

    delete_chain(h, pc.client_ip);

    close_iptables(h, pc);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
add_iptables_client(const struct plugin_context pc)
{
    errno = 0;
    struct xtc_handle *h;
    h = init_iptables(TABLE);

    printf("openvpn-iptables: operation[add/update], \
           client_ip[%s], client_name[%s]\n",
           pc.client_ip, pc.client_name);

    create_iptables_base_rules(h, pc);

    printf("DEBUG: Base rules/chain added.\n");

    add_group_rules(h, pc);

    close_iptables(h, pc);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

static int
do_tables(char *const argv[], char *const envp[])
{
    struct plugin_context pc;

    pc.operation = argv[1];
    pc.client_ip = argv[2];

    if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "update") == 0)
    {
        pc.client_name = argv[3];
        delete_iptables_client(pc);
        add_iptables_client(pc);
    }
    else if (strcmp(argv[1], "delete") == 0)
    {
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


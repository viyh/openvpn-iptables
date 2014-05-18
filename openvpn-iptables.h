#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <yajl/yajl_tree.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_comment.h>
#include <linux/netfilter/xt_state.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <openvpn/openvpn-plugin.h>

#define IPT_ALIGN(s) (((s) + (__alignof__(struct ipt_entry)-1)) & ~(__alignof__(struct ipt_entry)-1))

struct ipt_entry_match * get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache);
struct ipt_entry_match * get_udp_match(const char *sports, const char *dports, unsigned int *nfcache);
static u_int16_t ipt_parse_port(const char *port);
static void parse_ports(const char *portstring, u_int16_t *ports);
static int ipt_service_to_port(const char *name);

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

struct ipt_entry_match *
get_established_match(void)
{
    struct ipt_entry_match *match;
    struct xt_state_info *stateinfo;
    size_t size;

    size = IPT_ALIGN(sizeof(*match)) + IPT_ALIGN(sizeof(struct ipt_state_info *));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "state", IPT_FUNCTION_MAXNAMELEN);

    stateinfo = (struct xt_state_info *)match->data;
    stateinfo->statemask |= XT_STATE_BIT(IP_CT_ESTABLISHED);
    stateinfo->statemask |= XT_STATE_BIT(IP_CT_RELATED);

    return match;
}

struct ipt_entry_match *
get_tcp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_tcp *tcpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof(*match)) + IPT_ALIGN(sizeof(*tcpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);

    tcpinfo = (struct ipt_tcp *)match->data;
    tcpinfo->spts[1] = tcpinfo->dpts[1] = 0xFFFF;

    if (sports)
    {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, tcpinfo->spts);
    }
    if (dports)
    {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, tcpinfo->dpts);
    }

    return match;
}

struct ipt_entry_match *
get_udp_match(const char *sports, const char *dports, unsigned int *nfcache)
{
    struct ipt_entry_match *match;
    struct ipt_udp *udpinfo;
    size_t size;

    size = IPT_ALIGN(sizeof(*match)) + IPT_ALIGN(sizeof(*udpinfo));
    match = calloc(1, size);
    match->u.match_size = size;
    strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);

    udpinfo = (struct ipt_udp *)match->data;
    udpinfo->spts[1] = udpinfo->dpts[1] = 0xFFFF;

    if (sports)
    {
        *nfcache |= NFC_IP_SRC_PT;
        parse_ports(sports, udpinfo->spts);
    }
    if (dports)
    {
        *nfcache |= NFC_IP_DST_PT;
        parse_ports(dports, udpinfo->dpts);
    }

    return match;
}

static u_int16_t ipt_parse_port(const char *port)
{
    unsigned int portnum;

    if ((portnum = ipt_service_to_port(port)) != -1)
    {
        return (u_int16_t)portnum;
    }
    else
    {
        return atoi(port);
    }
}

static void
parse_ports(const char *portstring, u_int16_t *ports)
{
    char *buffer;
    char *cp;

    buffer = strdup(portstring);
    if ((cp = strchr(buffer, ':')) == NULL)
        ports[0] = ports[1] = ipt_parse_port(buffer);
    else
    {
        *cp = '\0';
        cp++;

        ports[0] = buffer[0] ? ipt_parse_port(buffer) : 0;
        ports[1] = cp[0] ? ipt_parse_port(cp) : 0xFFFF;
    }
    free(buffer);
}

static int ipt_service_to_port(const char *name)
{
    struct servent *service;

    if ((service = getservbyname(name, "tcp")) != NULL)
        return ntohs((unsigned short) service->s_port);

    return -1;
}

void *
safe_calloc (int mult, size_t size)
{
    register void *value = calloc (mult, size);
    if (value == 0)
    {
        perror("openvpn-iptables: memory exhausted");
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
        perror("openvpn-iptables: memory exhausted");
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
                      const char *state, const int append)
{
    struct ipt_entry *chain_entry = NULL;
    struct ipt_entry_match *entry_match = NULL;
    struct ipt_entry_target *entry_target = NULL;
    struct ipt_entry_match *entry_match_state = NULL;

    ipt_chainlabel labelit;
    long match_size = 0;
    int result = 0;
    errno = 0;

    chain_entry = safe_calloc(1, sizeof(*chain_entry));

    if (DEBUG)
    {
        printf("\tchain: %s\n", chain);
        printf("\tsrc_ip: %s\n", src_ip);
        printf("\tsrc_mask: %s\n", src_mask);
        printf("\tdst_ip: %s\n", dst_ip);
        printf("\tdst_mask: %s\n", dst_mask);
        if (proto != NULL)
            printf("\tproto: %s\n", proto);
        printf("\tdst_port: %s\n", dst_port);
        printf("\ttarget: %s\n", target);
        printf("\tstate: %s\n", state);
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

    if (state && strcmp(state, "ESTABLISHED,RELATED") == 0)
    {
        chain_entry->ip.proto = IPPROTO_TCP;
        entry_match_state = get_established_match();
    }

    size_t size;

    size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(int));
    entry_target = calloc(1, size);
    entry_target->u.user.target_size = size;
    strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);

    if (entry_match_state)
        match_size = entry_match_state->u.match_size;
    else if (entry_match)
        match_size = entry_match->u.match_size;

    fflush(stdout);
    chain_entry = safe_realloc(chain_entry, sizeof(*chain_entry) + match_size + entry_target->u.target_size);
    memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
    chain_entry->target_offset = sizeof(*chain_entry) + match_size;
    chain_entry->next_offset = sizeof(*chain_entry) + match_size + entry_target->u.target_size;

    if (entry_match_state)
        memcpy(chain_entry->elems, entry_match_state, entry_match_state->u.match_size);
    else if (entry_match)
        memcpy(chain_entry->elems, entry_match, entry_match->u.match_size);

    strncpy(labelit, chain, sizeof(ipt_chainlabel));

    result = iptc_is_chain(chain, h);
    if (!result)
    {
        printf("openvpn-iptables: chain %s does not exist!\n", chain);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (append)
        result = iptc_append_entry(labelit, chain_entry, h);
    else
        result = iptc_insert_entry(labelit, chain_entry, 0, h);

    if (!result)
    {
        printf("openvpn-iptables: can't add rule: %s\n", iptc_strerror(errno));
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    else if (DEBUG)
        printf("openvpn-iptables: added new rule successfully\n");

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
            printf("openvpn-iptables: invalid protocol %s!\n", proto);

    }
    else if (strcmp(key, "comment") == 0)
    {
        r->comment = YAJL_GET_STRING(val);
    }
    else
        printf("openvpn-iptables: unknown rule parameter: %s\n", key);

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
        if (DEBUG)
            printf("openvpn-iptables: no rules found for %s\n", group);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    if (DEBUG)
        printf("openvpn-iptables: rules found for %s\n", group);

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
                              "ACCEPT", r.comment, NULL, 0);
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

    if (DEBUG)
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
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int
create_iptables_base_rules(struct xtc_handle *h, const struct plugin_context pc)
{
    errno = 0;

    if (!iptc_is_chain(pc.client_ip, h))
    {
        if (DEBUG)
            printf("openvpn-iptables: creating new chain...\n");
        iptc_create_chain(pc.client_ip, h);
    }

    create_iptables_entry("OUTPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", NULL, NULL, pc.client_ip, pc.client_name, NULL, 0);
    create_iptables_entry("INPUT", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", pc.client_ip, pc.client_name, NULL, 0);
    create_iptables_entry("FORWARD", h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", pc.client_ip, pc.client_name, NULL, 0);
    create_iptables_entry(pc.client_ip, h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", "ACCEPT", pc.client_name, "ESTABLISHED,RELATED", 0);
    create_iptables_entry(pc.client_ip, h, pc.client_ip, "255.255.255.255",
                          "0.0.0.0", "0.0.0.0", "", "", "DROP", pc.client_name, NULL, 1);

    fflush(stdout);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

const struct ipt_entry *
delete_iptables_rule(struct xtc_handle *h, const char *chain, const int rulenum)
{
    int ret;

    if (DEBUG)
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
        printf("openvpn-iptables: could not init IPTC library: %s\n", iptc_strerror (errno));
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
        printf("openvpn-iptables: could not commit changes in iptables (client: %s): %s, %s\n",
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

    create_iptables_base_rules(h, pc);

    if (DEBUG)
        printf("openvpn-iptables: base rules/chain added.\n");

    add_group_rules(h, pc);

    close_iptables(h, pc);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

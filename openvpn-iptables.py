#!/usr/bin/python

import sys
import os
import json

config = {
    'iptables': 'sudo /sbin/iptables',
    'rule_file': 'filter_groups.json'
}

class IPTablesFailure (Exception):
    pass

def build_rule(chain, client_ip, dst_ip, dst_port=None, proto=None, comment=None):
    if comment:
        comment = ' -m comment --comment "%s"' % (comment,)
    if (dst_port and not proto) or (not dst_port and proto):
        sys.stderr.write("dst_port and proto must be defined together!\n")
        return False
    if dst_port and proto:
        dst_port = ' -m multiport --dports %s' % (dst_port,)
        proto = ' -p %s' % (proto,)
        rule = "-A %s -s %s -d %s %s%s%s -j ACCEPT" % \
            (chain, client_ip, dst_ip, proto, dst_port, comment)
    else:
        rule = "-A %s -s %s -d %s %s -j ACCEPT" % \
            (chain, client_ip, dst_ip, comment)
    iptables(rule)

def load_group_rules():
    json_data = open(config['rule_file'])
    group_rules = json.load(json_data)
    return group_rules

def get_unix_groups(client_name):
    import grp, pwd
    gids = [g.gr_gid for g in grp.getgrall() if client_name in g.gr_mem]
    gid = pwd.getpwnam(client_name).pw_gid
    gids.append(grp.getgrgid(gid).gr_gid)
    return [grp.getgrgid(gid).gr_name for gid in gids]

def load_rules(client_ip, client_name):
    unix_groups = get_unix_groups(client_name)
    matched_groups = []
    uniq_nets = list()
    group_rules = load_group_rules()
    for group in [group for group in group_rules if group in unix_groups]:
        matched_groups.append(group)
        rules = group_rules[group]['rules']
        for rule in rules:
            dst_ip = rule['dst_ip'] if rule.has_key('dst_ip') else None
            dst_port = rule['dst_port'] if rule.has_key('dst_port') else None
            proto = rule['proto'] if rule.has_key('proto') else None
            comment = rule['comment'] if rule.has_key('comment') else None
            build_rule(client_ip, client_ip, dst_ip, dst_port, proto, comment)

    # Support setting routes
    if "__EVERYONE__" in group_rules:
        for rule in group_rules["__EVERYONE__"]["rules"]:
            dst_ip = rule['dst_ip'] if rule.has_key('dst_ip') else None
            dst_port = rule['dst_port'] if rule.has_key('dst_port') else None
            proto = rule['proto'] if rule.has_key('proto') else None
            comment = rule['comment'] if rule.has_key('comment') else None
            build_rule(client_ip, client_ip, dst_ip, dst_port, proto, comment)
    return ';'.join(matched_groups)

def iptables(args, raiseEx=True):
    command = "%s %s" % (config['iptables'], args)
    print command
    status = os.system(command)
    if status == -1:
        raise IPTablesFailure("Could not run iptables: %s" % (command,))
    status = os.WEXITSTATUS(status)
    if raiseEx and (status != 0):
        raise IPTablesFailure("iptables exited with status %d (%s)" % (status, (config['iptables'], args)))
    if (status != 0):
        return False
    return True

def chain_exists(chain):
    return iptables('-n -L %s' % (chain,), False)

def add_chain(client_ip, client_name):
    del_chain(client_ip)
    usergroups = ""
    if chain_exists(client_ip):
        sys.stderr.write("Attempted to replace an existing chain, failing.\n")
        sys.stderr.write("\tclient_ip=%s, client_name=%s\n" % (client_ip, client_name) )
        return False
    iptables('-N %s' % (client_ip,))
    iptables('-A OUTPUT  -d %s -j %s' % (client_ip, client_ip), False)
    iptables('-A INPUT   -s %s -j %s' % (client_ip, client_ip), False)
    iptables('-A FORWARD -s %s -j %s' % (client_ip, client_ip), False)

    comment = client_name + ' groups: ' + usergroups
    if len(comment) > 254:
        comment = comment[:243] + '..truncated...'
    usergroups = load_rules(client_ip, client_name)

    iptables('-A %s -m conntrack --ctstate ESTABLISHED -j ACCEPT -m comment --comment "%s at %s"' % (client_ip, client_name, client_ip))
    iptables('-A %s -j LOG --log-prefix "DROP %s" -m comment --comment "%s at %s"' % (client_ip, client_name[:23], client_name, client_ip))
    iptables('-A %s -j DROP -m comment --comment "%s at %s"' % (client_ip, client_name, client_ip))
    return True

def del_chain(client_ip, client_name=None):
    iptables('-D OUTPUT  -d %s -j %s' % (client_ip, client_ip), False)
    iptables('-D INPUT   -s %s -j %s' % (client_ip, client_ip), False)
    iptables('-D FORWARD -s %s -j %s' % (client_ip, client_ip), False)
    iptables('-F %s' % (client_ip,), False)
    iptables('-X %s' % (client_ip,), False)
    return True

def update_chain(client_ip, client_name):
    return add_chain(client_ip, client_name)

def main():
    if len(sys.argv) < 2:
        print "USAGE: %s <operation>" % sys.argv[0]
        return False
    operation     = sys.argv[1]
    client_ip     = sys.argv[2]
    client_name   = sys.argv[3] if operation != 'delete' else 'none'

    if operation == "add":
        sys.stderr.write("change, [%s] %s@%s\n" % (operation, client_name, client_ip))
    else:
        sys.stderr.write("change, [%s] [%s]\n" % (operation, client_ip))

    chain_func = {
        'add':    add_chain,
        'update': update_chain,
        'delete': del_chain
    }
    try:
        chain_func[operation](client_ip, client_name)
        return True
    except Exception, e:
        sys.stderr.write("Bad operation! %s\n" % (e,))
    return False

def write_auth_control_file(control_status):
    auth_control_file = os.environ.get('auth_control_file', None)
    if auth_control_file:
        f = open(auth_control_file, 'w')
        f.write(control_status)
        f.close()

if __name__ == "__main__":
    if main():
        write_auth_control_file(1)
        sys.exit(0)
    write_auth_control_file(0)
    sys.exit(1)

openvpn-iptables
================

This is an OpenVPN plugin which implements per group IP tables rules. For now, it's a simple C plugin file that calls a python script to do the heavy lifting. For each user that logs in, an iptables chain is created with filter rules specified from a JSON file. If no rules are specified, all traffic for that user is dropped. The chain is removed once OpenVPN determines the user has logged off and the keepalive time expires.

Rules are specified on a per group basis. I may implement per user functionality in the future but didn't have a need for that for the first iteration of this code. Since the python code does a lookup based on unix system groups, it is compatible with LDAP or unix system users.

I'm working on getting a pure C implementation running and will hopefully post that soon.

## Installation ##

There are two ways to install the code. Either way requires the configuration lines at the top of the python script to be correct, and the filter_groups.json file exist somewhere with the rules for each group's access (more on that later).

### As a module ###

The first way to install this is to use it as an OpenVPN plugin.

Compile the C code with something like this:

```bash
gcc -fPIC -shared -Wall openvpn-iptables.c -o openvpn-iptables.so
```

Put the openvpn-iptables.so and openvpn-iptables.py script somewhere, make them executable, and set it up in the OpenVPN server config like so:

```
plugin <PATH TO .so MODULE> <PATH TO .py SCRIPT>
```

### Learn-Address script ###

The second way to use it is by having OpenVPN call the python code directly.

Put the python script somewhere and make it executable. Add a line to your OpenVPN server config such as:

```
learn-address <PATH TO .py SCRIPT>
```

## filter_rules.json ##

The filter_rules.json file specifies groups of network access rules for each group. Members of a group will be given access to all of the specified rules for all groups they are a member of. All other traffic is dropped.

An example would look like the following:

```json
{
    "dbagroup": {
        "rules": [
            {
                "dst_ip": "172.16.0.0/16",
                "dst_port": "1433",
                "proto": "tcp",
                "comment": "mssql"
            }
        ]
    },
    "admins": {
        "rules": [
            {
                "dst_ip": "10.0.0.0/8",
                "comment": "all traffic"
            }
        ]
    }
}
```

Any member of the dbagroup on your system would get access to any host in 172.16.0.0/16 on port 1433. Any member of admins have access to the 10.0.0.0/8 network. And any user that is a member of both groups would have access to both of those networks. If a dst_port is specified, a proto must also be specified. Another example of the filter_groups.json file is included in the source distribution.

## Credits ##

This module was inspired by the code here: https://github.com/gdestuynder/openvpn-netfilter
That implementation didn't work well for me so I decided to write my own with a simpler configuration.

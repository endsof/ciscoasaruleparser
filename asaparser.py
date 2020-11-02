import re
from colorama import init, Fore
from ipaddress import ip_address, ip_network, summarize_address_range

init(autoreset=True)

def extract_obj(obj_name, objs_dict):
    '''
    Searches ASA object/object-group by name recursively and returns object properties
    '''
    print(Fore.GREEN + 'Extract object:', obj_name)

    # Search object
    obj = objs_dict[obj_name]
    obj_type = obj[1]
    obj_body = obj[3]

    # ASA network objects
    if obj_type == 'network':
        if 'host' in obj_body:
            host = re.search(r'host (\d+\.\d+.\d+\.\d+)', obj_body)
            results = [(obj_name, host[1])]
        
        elif 'range' in obj_body:
            raw_range = re.search(r'range (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj_body)
            results = [('[RANGE]', raw_range[1].replace(' ', '-'))]
            # hosts = re.search(r'range (\d+\.\d+.\d+\.\d+) (\d+\.\d+.\d+\.\d+)', obj_body)
            # first = ip_address(hosts.group(1))
            # last = ip_address(hosts.group(2))
            # for network in summarize_address_range(first, last):
            #     for host in network:
            #         results.append(('[RANGE]', host.exploded))

        elif 'subnet' in obj_body:
            subnet = re.search(r'subnet (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj_body)
            results = [('[NETWORK]', ip_network(subnet[1].replace(' ', '/')).exploded)]

    elif obj_type == 'service':
        # Getting only destination ports, source ports will be ignored...
        # Regex groups: 1 - protocol, 2 - dst port, 3 - dst port-range
        raw_service = re.search(r'service ([\w\-\.]+) (?:source (?:eq [\w\-\.]+|range \d+ \d+) )?destination (?:eq ([\w\-\.]+)|range (\d+ \d+))', obj_body) 
        protocol = raw_service[1]
        if raw_service[2]:
            port = raw_service[2]
        elif raw_service[3]:
            port = raw_service[3].replace(' ', '-')
        
        results = [(protocol, port)]

    print(results)
    return results

def extract_grp(grp_name, objs_dict):
    '''
    Searches ASA object-group by name recursively and returns list of parsed objects
    '''
    results = []
    print(Fore.GREEN + 'Extract object-group:', grp_name)

    grp = objs_dict[grp_name]
    grp_type = grp[1]
    grp_body = grp[3]

    # network-object
    if grp_type == 'network':
        net_objs = re.findall(r'network-object (?:object ([\w\-\.]+)|(\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+))', grp_body)
        for net_obj in net_objs:
            if net_obj[0]:
                results.extend(extract_obj(net_obj[0], objs_dict))
            elif net_obj[1]:
                results.append(('[NETWORK]', ip_network(net_obj[1].replace(' ', '/')).exploded))
    
    # service-object
    elif raw_obj[1] == 'service':
        serv_objs = re.findall(r'service-object (?:object ([\w\-\.]+)|([\w\-\.]+))(?: source (?:eq [\w\-\.]+|range \d+ \d+))?(?: destination (?:eq ([\w\-\.]+)|range (\d+ \d+)))?', grp_body)
        # Regex groups: 0 - object name, 1 - protocol, 2 - dst port, 3 - dst port-range

        for serv_obj in serv_objs:
            if serv_obj[0]:
                results.extend(extract_obj(serv_obj[0], objs_dict))
            elif serv_obj[1]:
                protocol = serv_obj[1]
                if serv_obj[2]:
                    port = serv_obj[2]
                elif serv_obj[3]:
                    port = serv_obj[3].replace(' ', '-')
                else:
                    port = ''

                results.append((protocol, port))            

    # protocol-object
    elif raw_obj[1] == 'protocol':
        prot_objs = re.findall(r'protocol-object ([\w\-\.]+)', grp_body)
        results = prot_objs

    # group-object
    grp_objs = re.findall(r'group-object ([\w\-\.]+)', grp_body)
    for grp_obj in grp_objs:
        results.extend(extract_grp(grp_obj, objs_dict))

    print(results)
    return results


with open('config.cfg', 'r') as f:
    config = f.read()

# Getting full object/object-group, type, name and object body.
pattern = r'(object|object-group) (network|protocol|service) ([\w\-\.]+)((?:\n [^\n]+)+)'
# Regex groups: 0 - object/object-group, 1 - object type, 2 - object name, 3 - object body
raw_objs = re.findall(pattern, config)

objs_dict = dict()
for raw_obj in raw_objs:
    objs_dict[raw_obj[2]] = raw_obj

# CSV header
with open("rules.csv", "w") as f:
    f.write("Interface;Rule;SrcFQDN;SrcIP;DstFQDN;DstIP;Protocol;Port;Description;ACL\n")

# Access Lists
# ACL description
descr_pattern = re.compile(r'access-list [\w\-\.]+ remark (.+)')
# ACL rule
acl_pattern = re.compile('access-list {interface} extended {rule} {protocol} {hosts} {hosts}{port}{state}'.format(
    interface=r'([[\w\-\.]+)',
    rule=r'(permit|deny)',
    protocol=r'(object-group [[\w\-\.]+|object [[\w\-\.]+|[[\w\-\.]+)',
    hosts=r'(interface [\w\-\.]+|object-group [\w\-\.]+|object [\w\-\.]+|\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+|[\w\-\.]+)',
    port=r'(?: eq ([\w\-\.]+))?',
    state=r'( inactive)?'
))
# Regex groups: 1-interface, 2-rule, 3-protocol, 4-srcips, 5-dstips, 6-port, 7-state

# Config parse
descr = ''
for row in config.split('\n'):
    if row.startswith('access-list'):

        acl = acl_pattern.search(row)

        if acl:
            # skip inactive rules
            if acl.group(7):
                continue

            interface = acl.group(1)
            rule = acl.group(2)

            # Protocol & Ports
            services = acl.group(3)
            if services.startswith('object'):
                services = services.split(' ')
                if services[0] == 'object':
                    services = extract_obj(services[1], objs_dict)
                elif services[0] == 'object-group':
                    services = extract_grp(services[1], objs_dict)
            else:
                if acl.group(6):
                    services = [(services, acl.group(6))]
                else:
                    services = [(services, '')]
            
            # Src IP
            srcips = acl.group(4)
            if srcips.startswith('object'):
                srcips = srcips.split(' ')
                if srcips[0] == 'object':
                    srcips = extract_obj(srcips[1], objs_dict)
                elif srcips[0] == 'object-group':
                    srcips = extract_grp(srcips[1], objs_dict)     
            elif srcips.startswith('any'):
                srcips = [('[ANY]', srcips)]
            else:
                srcips = [('[NETWORK]', ip_network(srcips.replace(' ', '/')))]
            
            # Dst IP
            dstips = acl.group(5)
            if dstips.startswith('object'):
                dstips = dstips.split(' ')
                if dstips[0] == 'object':
                    dstips = extract_obj(dstips[1], objs_dict)
                elif dstips[0] == 'object-group':
                    dstips = extract_grp(dstips[1], objs_dict)
            elif dstips.startswith('any'):
                dstips = [('[ANY]', dstips)]
            else:
                dstips = [('[NETWORK]', ip_network(dstips.replace(' ', '/')))]
            
            # Iterate through the services/srcip/dstip and write to file
            for srcip in srcips:
                for dstip in dstips:
                    for service in services:
                        with open('rules.csv', 'a') as f:
                            f.write("{};{};{};{};{};{};{};{};{};{}\n".format(interface, rule, srcip[0], srcip[1], dstip[0], dstip[1], service[0], service[1], descr, row))
            
            # Remove old description
            descr = ''

        else:
            descr = descr_pattern.search(row).group(1)
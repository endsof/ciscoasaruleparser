import re
from colorama import init, Fore
from ipaddress import ip_address, ip_network, summarize_address_range

init(autoreset=True)

def extract_obj (obj_name, raw_objs):
    '''
    Searches ASA object/object-group by name recursively and returns list of parsed objects
    '''
    results = []

    #debug
    print(Fore.GREEN + obj_name)

    for raw_obj in raw_objs:
        obj = raw_obj[3]

        # Search by ASA ObjectName
        if obj_name == raw_obj[2]:

            # ASA OBJECTS
            if raw_obj[0] == 'object':
                if raw_obj[1] == 'network':
                    if 'host' in obj:
                        host = re.search(r'host (\d+\.\d+.\d+\.\d+)', obj)
                        results = [(obj_name, host.group(1))]
                    
                    elif 'range' in obj:
                        # hosts = re.search(r'range (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj)
                        # results = [hosts[1].replace(' ', '-')]
                        # print(hosts.group(0))
                        hosts = re.search(r'range (\d+\.\d+.\d+\.\d+) (\d+\.\d+.\d+\.\d+)', obj)
                        first = ip_address(hosts.group(1))
                        last = ip_address(hosts.group(2))
                        for network in summarize_address_range(first, last):
                            for host in network:
                                results.append(('[RANGE]', host.exploded))

                    elif 'subnet' in obj:
                        subnet = re.search(r'subnet (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj)
                        results = [('[NETWORK]', ip_network(subnet[1].replace(' ', '/')).exploded)]

                elif raw_obj[1] == 'service':
                    # Getting only destination ports, source ports will be ignored...
                    # Regex groups: 1 - protocol, 2 - dst port, 3 - dst port-range
                    raw_service = re.search(r'service ([\w\-\.]+) (?:source (?:eq [\w\-\.]+|range \d+ \d+) )?destination (?:eq ([\w\-\.]+)|range (\d+ \d+))', obj) 
                    protocol = raw_service[1]
                    if raw_service[2]:
                        port = raw_service[2]
                    elif raw_service[3]:
                        port = raw_service[3].replace(' ', '-')
                    
                    results = [(protocol, port)]
            
            # ASA OBJECT-GROUPS
            elif raw_obj[0] == 'object-group':

                if raw_obj[1] == 'network':
                    net_objs = re.findall(r'network-object (?:object ([\w\-\.]+)|(\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+))', obj)
                    for net_obj in net_objs:
                        if net_obj[0]:
                            results.extend(extract_obj(net_obj[0], raw_objs))
                        elif net_obj[1]:
                            results.append(('[NETWORK]', ip_network(net_obj[1].replace(' ', '/')).exploded))

                    group_objs = re.findall(r'group-object ([\w\-\.]+)', obj)
                    for group_obj in group_objs:
                        results.extend(extract_obj(group_obj, raw_objs))
                
                elif raw_obj[1] == 'service':
                    # Regex groups: 0 - object name, 1 - protocol, 2 - dst port, 3 - dst port-range
                    serv_objs = re.findall(r'service-object (?:object ([\w\-\.]+)|([\w\-\.]+))(?: source (?:eq [\w\-\.]+|range \d+ \d+))?(?: destination (?:eq ([\w\-\.]+)|range (\d+ \d+)))?', obj)
                    
                    for serv_obj in serv_objs:
                        if serv_obj[0]:
                            results.extend(extract_obj(serv_obj[0], raw_objs))
                        elif serv_obj[1]:
                            protocol = serv_obj[1]
                            if serv_obj[2]:
                                port = serv_obj[2]
                            elif serv_obj[3]:
                                port = serv_obj[3].replace(' ', '-')
                            else:
                                port = None
                        
                            results.append((protocol, port))

                elif raw_obj[1] == 'protocol':
                    prot_objs = re.findall(r'protocol-object ([\w\-\.]+)', obj)
                    results = [prot_objs]

            #debug
            print(results)

            break

    return results


# Access Lists
acl_pattern = re.compile('access-list {interface} extended {rule} {protocol} {srcip} {dstip}{service}{state}'.format(
    interface=r'([[\w\-\.]+)',
    rule=r'(permit|deny)',
    protocol=r'(object-group [[\w\-\.]+|object [[\w\-\.]+|[[\w\-\.]+)',
    srcip=r'(interface [\w\-\.]+|object-group [\w\-\.]+|object [\w\-\.]+|\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+|[\w\-\.]+)',
    dstip=r'(interface [\w\-\.]+|object-group [\w\-\.]+|object [\w\-\.]+|\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+|[\w\-\.]+)',
    service=r'(?: eq ([\w\-\.]+))?',
    state=r'( inactive)?'
))

with open('config.cfg', 'r') as f:
    config = f.read()

# Getting full object/object-group, type, name and object body.
pattern = r'(object|object-group) (network|protocol|service) ([\w\-\.]+)((?:\n [^\n]+)+)'
raw_objs = re.findall(pattern, config)

# CSV header
with open("rules.csv", "w") as f:
    f.write("Interface;Rule;SrcFQDN;SrcIP;DstFQDN;DstIP;Protocol;Port;ACL\n")

# Config parse
for row in config.split('\n'):
    if row.startswith('access-list'):
        
        acl = acl_pattern.search(row)
        if acl and (not acl[7]):
            interface = acl[1]
            rule = acl[2]

            # Protocol & Ports
            service_raw = acl[3]
            if service_raw.startswith('object'):
                services = extract_obj(service_raw.split(' ')[1], raw_objs)
            else:
                if acl[6]:
                    services = [(acl[3], acl[6])]
                else:
                    services = [(acl[3], None)]
            
            # Src IP
            srcips = acl[4]
            if srcips.startswith('object'):
                srcips = extract_obj(srcips.split(' ')[1], raw_objs)
            elif srcips.startswith('any'):
                srcips = [('[NETWORK]', srcips)]
            else:
                srcips = [('[NETWORK]', ip_network(srcips.replace(' ', '/')))]
            
            # Dst IP
            dstips = acl[5]
            if dstips.startswith('object'):
                dstips = extract_obj(dstips.split(' ')[1], raw_objs)
            elif dstips.startswith('any'):
                dstips = [('[NETWORK]', dstips)]
            else:
                dstips = [('[NETWORK]', ip_network(dstips.replace(' ', '/')))]


            
            # Iterate through the services/srcip/dstip and write to file
            for service in services:
                for srcip in srcips:
                    for dstip in dstips:
                        with open('rules.csv', 'a') as f:
                            f.write("{};{};{};{};{};{};{};{};{}\n".format(interface, rule, srcip[0], srcip[1], dstip[0], dstip[1], service[0], service[1], row))           
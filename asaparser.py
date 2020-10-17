import re
from colorama import init, Fore
from ipaddress import ip_address, ip_network, summarize_address_range

init(autoreset=True)

with open('config.cfg', 'r') as f:
    config = f.read()

# выхватываем полностью объект/группу, тип, имя и тело объекта.
pattern = r'(object|object-group) (network|protocol|service) ([\w\-]+)((?:\n [^\n]+)+)'
raw_objects = re.findall(pattern, config)

def extract_obj (obj_name):
    # ищем объекты по имени и распаковываем их
    results = []

    for raw_obj in raw_objects:
        obj = raw_obj[3]

        # ищем по имени
        if raw_obj[2] == obj_name:

            # вылавливаем объекты
            if raw_obj[0] == 'object':
                if raw_obj[1] == 'network':
                    if 'host' in obj:
                        host = re.search(r'host (\d+\.\d+.\d+\.\d+)', obj)
                        results = [host.group(1)]
                    
                    elif 'range' in obj:
                        hosts = re.search(r'range (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj)
                        results = [hosts[1].replace(' ', '-')]
                        # print(hosts.group(0))
                        # first = ip_address(hosts.group(1))
                        # last = ip_address(hosts.group(2))

                        # for network in summarize_address_range(first, last):
                        #     for host in network:
                        #         results.append(host.exploded)

                    elif 'subnet' in obj:
                        subnet = re.search(r'subnet (\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+)', obj)
                        results = [ip_network(subnet[1].replace(' ', '/')).exploded]

                elif raw_obj[1] == 'service':
                    # выхватываем только Destination порты, Source игнорим...
                    raw_service = re.search(r'service ([\w\-]+) (?:source (?:eq [\w\-]+|range \d+ \d+) )?destination (?:eq ([\w\-]+)|range (\d+ \d+))', obj)
                    # 1 - protocol
                    # 2 - dst port
                    # 3 - dst port-range
                    
                    protocol = raw_service[1]

                    if raw_service[2]:
                        port = raw_service[2]
                    elif raw_service[3]:
                        port = raw_service[3].replace(' ', '-')
                    
                    results = [(protocol, port)]
            
            # вылавливаем группы
            elif raw_obj[0] == 'object-group':
                if raw_obj[1] == 'network':

                    net_objs = re.findall(r'network-object (?:object ([\w\-]+)|(\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+))', obj)

                    for net_obj in net_objs:
                        if net_obj[0]:
                            results.extend(extract_obj(net_obj[0]))
                        elif net_obj[1]:
                            results.extend(ip_network(net_obj[1].replace(' ', '/')).exploded)

                    group_objs = re.findall(r'group-object ([\w\-]+)', obj)
                    for group_obj in group_objs:
                        results.extend(extract_obj(group_obj))
                
                elif raw_obj[1] == 'service':
                    serv_objs = re.findall(r'service-object (?:object ([\w\-]+)|([\w\-]+))(?: source (?:eq [\w\-]+|range \d+ \d+))?(?: destination (?:eq ([\w\-]+)|range (\d+ \d+)))?', obj)
                    # 0 - object name
                    # 1 - protocol
                    # 2 - dst port
                    # 3 - dst port-range
                    
                    for serv_obj in serv_objs:
                        if serv_obj[0]:
                            results.extend(extract_obj(serv_obj[0]))
                        elif serv_obj[1]:
                            protocol = serv_obj[1]
                            if serv_obj[2]:
                                port = serv_obj[2]
                            elif serv_obj[3]:
                                port = serv_obj[3].replace(' ', '-')
                            else:
                                port = ''
                        
                            results.append((protocol, port))

                elif raw_obj[1] == 'protocol':
                    prot_objs = re.findall(r'protocol-object ([\w\-]+)', obj)
                    results = prot_objs

            break
    return results


# Паттерн для ACL
acl_pattern = re.compile('access-list {interface} extended {rule} {protocol} {src} {dst}{service}'.format(
    interface=r'([[\w\-]+)',
    rule=r'(permit|deny)',
    protocol=r'(object-group [[\w\-]+|object [[\w\-]+|[[\w\-]+)',
    src=r'(object-group [\w\-]+|object [\w\-]+|\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+|host \d+\.\d+.\d+\.\d+|[\w\-]+)',
    dst=r'(object-group [\w\-]+|object [\w\-]+|\d+\.\d+.\d+\.\d+ \d+\.\d+.\d+\.\d+|host \d+\.\d+.\d+\.\d+|[\w\-]+)',
    service=r'(?: eq ([\w\-]+))?'
))
# 1 - interface
# 2 - rule
# 3 - 

for row in config.split('\n'):
    if row.startswith('access-list'):
        
        acl = acl_pattern.search(row)
        if acl:
            interface = acl[1]
            rule = acl[2]

            service_raw = acl[3]
            if service_raw.startswith('object'):
                service = extract_obj(service_raw.split(' ')[1])
            else:
                if acl[6]:
                    service = [(acl[3], acl[6])]
                else:
                    service = [(acl[3], None)]

            src = acl[4]
            if src.startswith('object'):
                src = extract_obj(src.split(' ')[1])

            dst = acl[5]
            if dst.startswith('object'):
                dst = extract_obj(dst.split(' ')[1])

            print(Fore.GREEN + 'ACCESS-LIST:', row)
            print(Fore.LIGHTYELLOW_EX + 'INTERFACE:', interface)
            print(Fore.LIGHTYELLOW_EX + 'RULE:', rule)
            print(Fore.LIGHTYELLOW_EX + 'SRC:', src)
            print(Fore.LIGHTYELLOW_EX + 'DST:', dst)
            print(Fore.LIGHTYELLOW_EX + 'SERVICE', service)
            input()
        
        else:
            if 'remark' not in row:
                raise Exception("ACL not found!\n", row)            
            
            #print('{}, {}, {}, {}, {}'.format(interface, rule, src, dst, protocol, service))
        
#!/usr/bin/env python3
'''Чтение правил межсетевого экрана из файла и загрузка их в NGFW Usergate'''

import os
import xlwt
import keyring
import xmlrpc.client
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.xlsread import ExcelToJson
from modules.fw_rules import FirewallRules
from modules.zones import Zones
from modules.addr_list import AddressList
from modules.services import Services


def zone_add(zones, item, zone_list, newrule, all_zones_name):
    '''zone_list - src_zones or dst_zones'''
    for zone in item.get(zone_list):
        if zone == 'any':
            newrule[zone_list] = []
        elif all_zones_name.get(zone):
            newrule[zone_list].append(zones.get_by_key(all_zones_name, zone))
        else:
            newrule[zone_list].append(zones.create_zone(all_zones_name, zone))
            all_zones_name = zones.get_all_zones('name')
    return newrule, all_zones_name

def addr_list_add(addr_lists, item, addr_list, newrule, all_addr_lists_name):
    '''addr_list - src_ips or dst_ips'''
    create_items = False
    for ip_list in item.get(addr_list):
        ip_list_name = ip_list.get('name')
        new_ip_list = ['list_id']
        if ip_list_name == 'any' or ip_list_name == []:
            newrule[addr_list] = []
        elif all_addr_lists_name.get(ip_list_name):
            new_ip_list.append(addr_lists.get_by_key(all_addr_lists_name, ip_list_name))
            newrule[addr_list].append(new_ip_list)
        else:
            new_ip_list_item = {'type': 'network', 'name': ip_list_name}
            new_ip_list.append(addr_lists.create_list(all_addr_lists_name, new_ip_list_item))
            newrule[addr_list].append(new_ip_list)
            all_addr_lists_name = addr_lists.get_all_address_lists('name')
            create_items = True
    return newrule, all_addr_lists_name, create_items


def main():
    
    load_dotenv()

    UGUSER = os.getenv('TESTUGUSER')
    # UGPASS = os.getenv('TESTUGPASS')
    UGPASS = keyring.get_password('usergate-api', 's.kotelnikov')
    UGSERVER = os.getenv('TESTUGSERVER')
    
    with UsergateClient(
        host=UGSERVER,
        username=UGUSER,
        password=UGPASS
    ) as client:
    
        e2j = ExcelToJson('all_staff3_normalized_2.xls') # Input file
        rules = FirewallRules(client)
        zones = Zones(client)
        addr_lists = AddressList(client)
        services = Services(client)
        
        all_zones_name = zones.get_all_zones('name') # Кэш зон для поиска по name
        all_addr_lists_name = addr_lists.get_all_address_lists('name') # Кэш списков адресов для поиска по name
        all_services = services.get_all_services('name')
        
        newrules = e2j.convert_values()
        for item in newrules:
            newrule = {}
            newrule['name'] = item.get('name')
            newrule['action'] = item.get('action')[0]
            newrule['src_zones'] = []
            newrule['dst_zones'] = []
            newrule['src_ips'] = []
            newrule['dst_ips'] = []
            newrule['services'] = []
            newrule['log'] = True
            newrule['log_session_start'] = True
            
            for zone_list in ['src_zones', 'dst_zones']:
                newrule, all_zones_name = zone_add(zones, item, zone_list, newrule, all_zones_name)
            
            for addr_list in ['src_ips', 'dst_ips']:
                newrule, all_addr_lists_name, create_items = addr_list_add(addr_lists, item, addr_list, newrule, all_addr_lists_name)
                if create_items == True:
                    for ip_list in item[addr_list]:
                        ip_list_name = ip_list.get('name')
                        ip_list_id = all_addr_lists_name.get(ip_list_name).get('id')
                        new_values = ip_list.get('items')
                        for value in new_values:
                            new_list_value = {'value': value}
                            addr_lists.create_list_item(ip_list_id, new_list_value)
            
            if item.get('enabled')[0] == 'enabled':
                newrule['enabled'] = True
            else:
                newrule['enabled'] = False
            
            for service_list in item['services']:
                service_list_name = service_list.get('name')
                new_service_list = ['service']
                if service_list == []:
                    newrule['services'] = []
                elif all_services.get(service_list_name):
                    service_id = all_services.get(service_list_name).get('id')
                    new_service_list.append(service_id)
                    newrule['services'].append(new_service_list)
                else:
                    new_protocol_list = []
                    item_protocol_list = item.get('services')
                    for protocol_list in item_protocol_list:
                        new_protocol_list_name = protocol_list.get('name')
                        new_protocol_list_item = {}
                        for item in protocol_list.get('protocols'):
                            proto_list = item.split(':')
                            new_protocol_list_item['proto'] = proto_list[0]
                            new_protocol_list_item['port'] = proto_list[1].strip()
                            new_protocol_list.append(new_protocol_list_item)
                        new_service_item = {'name': new_protocol_list_name, 'protocols': new_protocol_list}
                        services.create_service(all_services, new_service_item)
                        all_services = services.get_all_services('name')
                        # print(new_service_item)
                    
                
            rules.create_rule(newrule)
            print(newrule)

if __name__ == '__main__':
    main()
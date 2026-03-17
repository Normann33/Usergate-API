#!/usr/bin/env python3
'''Чтение и правил межсетевого экрана из файла и загрузка их в NGFW Usergate'''

import os
import xlwt
import xmlrpc.client
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.xlsread import ExcelToJson
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
    for ip_list in item.get(addr_list):
        ip_list_name = ip_list.get('name')
        new_ip_list = ['list_id']
        if ip_list_name == 'any':
            newrule[addr_list] = []
        elif all_addr_lists_name.get(ip_list_name):
            new_ip_list.append(addr_lists.get_by_key(all_addr_lists_name, ip_list_name))
            newrule[addr_list].append(new_ip_list)
        else:
            new_ip_list_item = {'type': 'network', 'name': ip_list_name}
            new_ip_list.append(addr_lists.create_list(all_addr_lists_name, new_ip_list_item))
            newrule[addr_list].append(new_ip_list)
            all_addr_lists_name = addr_lists.get_all_address_lists('name')
    return newrule, all_addr_lists_name


def main():
    
    load_dotenv()

    UGUSER = os.getenv('TESTUGUSER')
    UGPASS = os.getenv('TESTUGPASS')
    UGSERVER = os.getenv('TESTUGSERVER')
    
    with UsergateClient(
        host=UGSERVER,
        username=UGUSER,
        password=UGPASS
    ) as client:
    
        e2j = ExcelToJson('test_zone.xls') # Input file
        zones = Zones(client)
        addr_lists = AddressList(client)
        
        all_zones_name = zones.get_all_zones('name') # Кэш зон для поиска по name
        all_addr_lists_name = addr_lists.get_all_address_lists('name') # Кэш списков адресов для поиска по name
        
        newrules = e2j.convert_values()
        for item in newrules:
            newrule = {}
            newrule['name'] = item.get('name')
            newrule['action'] = item.get('action')
            newrule['src_zones'] = []
            newrule['dst_zones'] = []
            newrule['src_ips'] = []
            newrule['dst_ips'] = []
            
            for zone_list in ['src_zones', 'dst_zones']:
                newrule, all_zones_name = zone_add(zones, item, zone_list, newrule, all_zones_name)
            
            for addr_list in ['src_ips', 'dst_ips']:
                newrule, all_addr_lists_name = addr_list_add(addr_lists, item, addr_list, newrule, all_addr_lists_name)

            print(newrule)

if __name__ == '__main__':
    main()
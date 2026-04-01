#!/usr/bin/env python3
'''Получаем информацию из CBase и создаем правила на Usergate'''

import os
import sys
import xlwt
import keyring
import xmlrpc.client
import psycopg2
from keyrings.cryptfile.cryptfile import CryptFileKeyring
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.fw_rules import FirewallRules
from modules.zones import Zones
from modules.addr_list import AddressList
from modules.services import Services

@contextmanager
def get_db_cursor(host, port, database, user, password):
    """Контекстный менеджер для подключения к БД"""
    conn = psycopg2.connect(
        host=host, port=port, database=database,
        user=user, password=password
    )
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cur
        finally:
            cur.close()
    finally:
        conn.close()
# def zone_add(zones, item, zone_list, newrule, all_zones_name):
#     '''zone_list - src_zones or dst_zones'''
#     for zone in item.get(zone_list):
#         if zone == 'any':
#             newrule[zone_list] = []
#         elif all_zones_name.get(zone):
#             newrule[zone_list].append(zones.get_by_key(all_zones_name, zone))
#         else:
#             newrule[zone_list].append(zones.create_zone(all_zones_name, zone))
#             all_zones_name = zones.get_all_zones('name')
#     return newrule, all_zones_name

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
    
    kr = CryptFileKeyring()
    load_dotenv()

    KEYPATH = os.getenv("KEYPATH")
    
    with open(KEYPATH + '/keyring.pass', 'r') as f:
        kr.keyring_key = f.read().strip()
    
    keyring.set_keyring(kr)
    UGUSER = os.getenv('UGUSER')
    UGPASS = keyring.get_password('usergate-api', UGUSER)
    UGSERVER = os.getenv('UGSERVER')
    DBUSER = os.getenv('DBUSER')
    DBPASSWORD = keyring.get_password('cbase-db', DBUSER)
    DBNAME = os.getenv('DBNAME')
    
    vpnlogin = sys.argv[1]
    
    with UsergateClient(
        host=UGSERVER,
        username=UGUSER,
        password=UGPASS
    ) as client:
    
        rules = FirewallRules(client)
        zones = Zones(client)
        addr_lists = AddressList(client)
        services = Services(client)
        
        all_zones_name = zones.get_all_zones('name') # Кэш зон для поиска по name
        all_addr_lists_name = addr_lists.get_all_address_lists('name') # Кэш списков адресов для поиска по name
        all_services = services.get_all_services('name')
        
        with get_db_cursor('localhost', 5432, DBNAME, DBUSER, DBPASSWORD) as cur:
            cur.execute("SELECT \"UserName\", ip, iplist FROM vpn_clients WHERE \"UserName\" = %s", (vpnlogin,))
            db_data = cur.fetchone()
        
        db_ip_list = db_data.get('iplist').split('<br>')
        print(db_ip_list)
        
        item = {
            'name': vpnlogin,
            'src_zones': ["gDMZ VPN"],
            "dst_zones": ["Trusted VPN"],
            "src_ips": [{"name": db_data.get('ip'),"items": db_data.get('ip')}], # Тут адрес который выдается пользователю при подключении по впн, читаем из базы
            "dst_ips": [{"name": vpnlogin,"items": db_ip_list}], # Тут читаем разрешенные имена из базы, если адрес один - именуем список по адресу, если несколько - по впн логину
            "services": [{"name": "RDP", "protocols": ["tcp: 3389"]}, {"name": "SSH", "protocols": ["tcp: 22"]}] # Пока хардкодим RDP и SSH
            }
        
        print(item)
        exit()
        
        newrule = {}
        newrule['name'] = item.get('name') # Тут получаем VPN логин из аргумента командной строки
        newrule['action'] = 'accept'
        newrule['enabled'] = True
        newrule['src_zones'] = []
        newrule['dst_zones'] = []
        newrule['src_ips'] = [] # Получаем значение из базы CBase
        newrule['dst_ips'] = [] # Получаем значение из базы CBase
        newrule['services'] = []
        newrule['log'] = True
        newrule['log_session_start'] = True
        
        for zone_list in ['src_zones', 'dst_zones']:
            newrule, all_zones_name = Zones.zone_add(zones, item, zone_list, newrule, all_zones_name)
        
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
                
            
        # rules.create_rule(newrule)
        print(newrule)

if __name__ == '__main__':
    main()
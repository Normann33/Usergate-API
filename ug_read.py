#!/usr/bin/env python3

import os
import xmlrpc.client
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.fw_rules import FirewallRules
from modules.zones import Zones
from modules.addr_list import AddressList



def get_item_names(item_list, all_item_ids, item_ids):
    item_names = []
    if len(item_ids) > 0:
        for item_id in item_ids:
            item_name = item_list.get_by_key(all_item_ids, item_id)
            item_names.append(item_name)
    else:
        item_names.append('any')
    # item_names = ', '.join(item_names)
    return item_names



def main():
    
    load_dotenv()

    TESTUGUSER = os.getenv('TESTUGUSER')
    TESTUGPASS = os.getenv('TESTUGPASS')
    TESTUGSERVER = os.getenv('TESTUGSERVER')
    
    with UsergateClient(
        host=TESTUGSERVER,
        username=TESTUGUSER,
        password=TESTUGPASS
    ) as client:
        rules = FirewallRules(client)
        zones = Zones(client)
        addr_lists = AddressList(client)
        
        all_rules = rules.get_all_rules()
                
        # В зависимости от ключа .get_all_zones возвращает нам кэш словарей, где ключ или id, или name
        # Нужно это для того, чтобы получить нужный объект или по id, или по имени
        
        all_zones_id = zones.get_all_zones('id') # Кэш зон для поиска по id
        all_zones_name = zones.get_all_zones('name') # Кэш зон для поиска по name
        all_addr_lists_id = addr_lists.get_all_address_lists('id') # Кэш списков адресов для поиска по id
        all_addr_lists_name = addr_lists.get_all_address_lists('name') # Кэш списков адресов для поиска по name
        
        for rule in all_rules.get('items', []):
            rule_name = rule.get('name', 'Без имени')
            print('=====================RULE===================')
            print(rule_name)
            rule_position = rule.get('position', '0')
            rule_action = rule.get('action', '-')
            
            src_zone_ids = rule.get('src_zones', [])
            src_zone_names = get_item_names(zones, all_zones_id, src_zone_ids)
            print(f'Зоны источника {src_zone_names}')
            
            
            src_addr_list = rule.get('src_ips')
            src_addr_ids = addr_lists.get_addr_list_id(src_addr_list)
            src_addr_list_names = get_item_names(addr_lists, all_addr_lists_id, src_addr_ids)

            src_addr_dict = addr_lists.get_address_list_dict(src_addr_ids, addr_lists, src_addr_list_names)
            if src_addr_dict:
                for i in src_addr_dict:
                    print(f'{i.get('name')}: {i.get('value')} ')
            else:
                print('any')
            
            dst_zone_ids = rule.get('dst_zones', [])
            dst_zone_names = get_item_names(zones, all_zones_id, dst_zone_ids)
            print(f'Зоны назначения {dst_zone_names}')
            
            dst_addr_list = rule.get('dst_ips')
            dst_addr_ids = addr_lists.get_addr_list_id(dst_addr_list)
            dst_addr_list_names = get_item_names(addr_lists, all_addr_lists_id, dst_addr_ids)
            
            dst_addr_dict = addr_lists.get_address_list_dict(dst_addr_ids, addr_lists, dst_addr_list_names)
            if dst_addr_dict:
                for i in dst_addr_dict:
                    print(f'{i.get('name')}: {i.get('value')} ')
            else:
                print('any')
        
        # print(zones.get_by_key(all_zones_id, 9))
        # print(zones.get_by_key(all_zones_name, 'gDMZ VPN'))
        # print(zones.create_zone(all_zones_name, 'gDMZ VPN'))
        

if __name__ == '__main__':
    main()
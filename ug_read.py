#!/usr/bin/env python3

import os
import xmlrpc.client
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.fw_rules import FirewallRules
from modules.zones import Zones



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
        #  rules = FirewallRules(client)
        #  all_rules = rules.get_all_rules()
        #  print(all_rules)
        zones = Zones(client)
        
        # В зависимости от ключа .get_all_zones возвращает нам кэш словарей, где ключ или id, или name
        # Нужно это для того, чтобы получить нужный объект или по id, или по имени
        all_zones_id = zones.get_all_zones('id')
        all_zones_name = zones.get_all_zones('name')
        print(zones.get_by_key(all_zones_id, 9))
        print(zones.get_by_key(all_zones_name, 'gDMZ VPN'))
        # print(zones.create_zone(all_zones_name, 'gDMZ VPN'))
        

if __name__ == '__main__':
    main()
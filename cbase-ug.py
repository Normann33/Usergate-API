#!/usr/bin/env python3
'''Получаем информацию из CBase и создаем правила на Usergate'''

import os
import keyring
import xmlrpc.client
import psycopg2
import argparse
import logging
from keyrings.cryptfile.cryptfile import CryptFileKeyring
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
from dotenv import load_dotenv
from pathlib import Path
from logging_config import setup_logging
from modules.ug_client import UsergateClient
from modules.fw_rules import FirewallRules
from modules.zones import Zones
from modules.addr_list import AddressList
from modules.services import Services
from modules.asa import AsaACL
from modules.asa_client import ASAConnection


# log_file = 'app.log'
# # log_file.parent.mkdir(exist_ok=True)
# logging.basicConfig(filename=log_file, level=logging.INFO, 
#                    format='%(asctime)s - %(levelname)s - %(message)s')

setup_logging('app.log', level=logging.INFO)
logger = logging.getLogger(__name__)

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

def parse_arguments():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description='Управление пользователями в базе данных',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Примеры использования:
        %(prog)s -l j.smith --create
        %(prog)s -l j.smith --update
        %(prog)s -l j.smith --delete
        %(prog)s -l j.smith --deactivate
                """
    )
    
    # Обязательный параметр: имя пользователя
    parser.add_argument(
        '-l', '--login',
        type=str,
        required=True,
        metavar='USERNAME',
        help='Имя пользователя (обязательно)'
    )
    
    # Взаимоисключающая группа для действий
    action_group = parser.add_mutually_exclusive_group(required=True)
    
    action_group.add_argument(
        '--create',
        action='store_true',
        help='Создать новое правило доступа'
    )
    
    action_group.add_argument(
        '--update',
        action='store_true',
        help='Изменить правило доступа'
    )
    
    action_group.add_argument(
        '--delete',
        action='store_true',
        help='Удалить правило доступа'
    )
    
    action_group.add_argument(
        '--deactivate',
        action='store_true',
        help='Деактивировать правило доступа'
    )
    
    action_group.add_argument(
        '--activate',
        action='store_true',
        help='Активировать правило доступа'
    )
            
    return parser.parse_args()

def main():
    
    args = parse_arguments()
    kr = CryptFileKeyring()
    load_dotenv()

    KEYPATH = os.getenv('KEYPATH')
    
    with open(KEYPATH + '/keyring.pass', 'r') as f:
        kr.keyring_key = f.read().strip()
    
    keyring.set_keyring(kr)
    UGUSER = os.getenv('UGUSER')
    UGPASS = keyring.get_password('usergate-api', UGUSER)
    UGSERVERS = os.getenv('UGSERVERS')
    
    DBUSER = os.getenv('DBUSER')
    DBPASSWORD = keyring.get_password('cbase-db', DBUSER)
    DBNAME = os.getenv('DBNAME')
    
    CISCOUSER = os.getenv('CISCOUSER')
    CISCOPASS = keyring.get_password('cisco', CISCOUSER)
    ASALIST = os.getenv('ASALIST')
    
    vpnlogin = args.login
    
    action = 'create' if args.create else 'update' if args.update else 'delete' if args.delete else 'deactivate'

    logging.info(f'============================Запуск============================')
    logging.info(f"Пользователь: {args.login}, действие: {action}")
    
    if not args.delete:
        with get_db_cursor('localhost', 5432, DBNAME, DBUSER, DBPASSWORD) as cur:
            cur.execute("SELECT \"UserName\", ip, iplist FROM vpn_clients WHERE \"UserName\" = %s", (vpnlogin,))
            db_data = cur.fetchone()

            if not db_data:
                logging.info(f"{args.login}, No data in database")
                exit()
            
            if db_data.get('iplist'):
                db_iplist = db_data.get('iplist').split('\n')
            else:
                print('No ip list!')
                logging.info(f"{vpnlogin} No ip list, exiting")
                exit()
            # if len(db_iplist) == 1:
            #     db_iplist_name = db_iplist[0]
            # else:
            db_iplist_name = vpnlogin
    
    for UGSERVER in UGSERVERS.split(','):
        with UsergateClient(
            host=UGSERVER,
            username=UGUSER,
            password=UGPASS
        ) as client:
            
            # Version detect:
            result = client.server.v2.core.license.info(client.auth_token)
            version = result.get('version')
            if '6.1.9' in version:
                version_619 = True
            else:
                version_619 = False
        
            rule_manager = FirewallRules(client)
            zone_manager = Zones(client)
            addr_list_manager = AddressList(client)
            services_manager = Services(client)
            
            all_zones_name = zone_manager.get_all_zones('name') # Кэш зон для поиска по name
            all_addr_lists_name = addr_list_manager.get_all_address_lists('name') # Кэш списков адресов для поиска по name
            all_addr_lists_id = addr_list_manager.get_all_address_lists('id') # Кэш списков адресов для поиска по id
            all_services = services_manager.get_all_services('name')
            all_rules = rule_manager.get_all_rules_dict('name')
            
            if args.create or args.update:
                rule_item = {
                    'name': vpnlogin,
                    'src_zones': ['gDMZ VPN'],
                    'dst_zones': ['Trusted VPN'],
                    'src_ips': [{'name': db_data.get('ip'), 'items': db_data.get('ip')}], # Тут адрес который выдается пользователю при подключении по впн, читаем из базы
                    'dst_ips': [{'name': db_iplist_name, 'items': db_iplist}], # Тут читаем разрешенные имена из базы, если адрес один - именуем список по адресу, если несколько - по впн логину
                    'services': [{'name': 'RDP', 'protocols': ['tcp: 3389']}, {'name': 'SSH', 'protocols': ['tcp: 22']}] # Пока хардкодим RDP и SSH
                    }
                
                print(f'Item: {rule_item}')
            # logging.info(f"{vpnlogin} rule_item {rule_item}")
            
            current_rule = all_rules.get(vpnlogin)
            if current_rule:
                current_rule_id = current_rule.get('id')
            else:
                logging.info(f"{vpnlogin} Can't delete - Rule not found")
            
            if args.create:
                try:
            
                    newrule = {}
                    newrule['name'] = rule_item.get('name') # Тут получаем VPN логин из аргумента командной строки
                    newrule['action'] = 'accept'
                    newrule['enabled'] = True
                    newrule['src_zones'] = []
                    newrule['dst_zones'] = []
                    newrule['src_ips'] = [] # Получаем значение из базы CBase
                    newrule['dst_ips'] = [] # Получаем значение из базы CBase
                    newrule['services'] = []
                    newrule['log'] = True
                    newrule['log_session_start'] = True
                    
                    # logging.info(f"{vpnlogin} newrule creating {newrule}")
                    
                    for zone_list in ['src_zones', 'dst_zones']:
                        newrule, all_zones_name = Zones.zone_add(zone_manager, rule_item, zone_list, newrule, all_zones_name)
                    
                    logging.info(f"{vpnlogin} zone_add done")
                    
                    for addr_list_type in ['src_ips', 'dst_ips']:
                        new_addr_list, all_addr_lists_name, create_items = AddressList.addr_list_add(addr_list_manager, rule_item, addr_list_type, all_addr_lists_name)
                        newrule[addr_list_type] = new_addr_list
                        logging.info(f"{vpnlogin} new_addr_list {new_addr_list}")
                        if create_items == True:
                            AddressList.addr_list_add_items(rule_item, addr_list_type, all_addr_lists_name, addr_list_manager)
                            logging.info(f"{vpnlogin} new items created")
                    
                    logging.info(f"{vpnlogin} addr_list_add done")
                    
                    for service_list in rule_item['services']:
                        service_list_name = service_list.get('name')
                        new_service_list = ['service']
                        if service_list == []:
                            newrule['services'] = []
                        elif all_services.get(service_list_name):
                            service_id = all_services.get(service_list_name).get('id')
                            new_service_list.append(service_id)
                            if version_619 == True:
                                newrule['services'].append(service_id)
                            else:
                                newrule['services'].append(new_service_list)
                        else:
                            new_protocol_list = []
                            item_protocol_list = rule_item.get('services')
                            for protocol_list in item_protocol_list:
                                new_protocol_list_name = protocol_list.get('name')
                                new_protocol_list_item = {}
                                for rule_item in protocol_list.get('protocols'):
                                    proto_list = rule_item.split(':')
                                    new_protocol_list_item['proto'] = proto_list[0]
                                    new_protocol_list_item['port'] = proto_list[1].strip()
                                    new_protocol_list.append(new_protocol_list_item)
                                new_service_item = {'name': new_protocol_list_name, 'protocols': new_protocol_list}
                                services_manager.create_service(all_services, new_service_item)
                                all_services = services_manager.get_all_services('name')
                                # print(new_service_item)
                                
                
                    rule_manager.create_rule(newrule)
                    logging.info(f"{vpnlogin} Rule created")
                    print(newrule)
                except Exception as e:
                    logging.info(f"{vpnlogin} {e}")
            
            elif args.update:
                current_addr_list_id = current_rule.get('dst_ips')[0][1]
                current_addr_list_name = all_addr_lists_id.get(current_addr_list_id)
                print(current_addr_list_id)
                addr_list_type = 'dst_ips'
                if db_iplist_name != current_addr_list_name:
                    current_items = addr_list_manager.get_addr_list_items(current_addr_list_id, result_type='full')
                    for item in current_items.get('items'):
                        print(item.get('id'))
                        addr_list_manager.delete_list_items(current_addr_list_id, item.get('id'))
                    AddressList.addr_list_add_items(rule_item, addr_list_type, all_addr_lists_name, addr_list_manager)
                    logging.info(f"{vpnlogin} new items created")
            
            elif args.delete:
                current_addr_list_id = current_rule.get('dst_ips')[0][1]
                rule_manager.delete_rule(current_rule_id)
                addr_list_manager.delete_list(current_addr_list_id)
                logging.info(f"{vpnlogin} Rule deleted")
            
            elif args.deactivate or args.activate:
                if args.deactivate:
                    rule_info = {'enabled': False}
                elif args.activate:
                    rule_info = {'enabled': True}
                rule_manager.update_rule(current_rule_id, rule_info)
                logging.info(f"{vpnlogin} {rule_info}")  

    # for CISCOASA in ASALIST.split(','):
    #     try:
    #         with ASAConnection(host=CISCOASA, username=CISCOUSER, password=CISCOPASS, port='22') as connection:
    #             protocol = 'tcp'
    #             src_ip = db_data.get('ip')
    #             ip_list = db_data.get('iplist').split('<br>')
    #             acl_manager = AsaACL(connection, vpnlogin, protocol, src_ip)
    #             if args.create:
    #                 print(acl_manager.create_object_group(ip_list))
    #                 print(acl_manager.create_acl_rule())
    #             elif args.update:
    #                 print(acl_manager.delete_item('access-list'))
    #                 print(acl_manager.delete_item('object-group'))
    #                 print(acl_manager.create_object_group(ip_list))
    #                 print(acl_manager.create_acl_rule())
    #             elif args.delete:
    #                 print(acl_manager.delete_item('access-list'))
    #                 print(acl_manager.delete_item('object-group'))
    #     except Exception as e:
    #         logging.error(f'ASA {CISCOASA} недоступна')

if __name__ == '__main__':
    main()
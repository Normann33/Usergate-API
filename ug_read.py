#!/usr/bin/env python3

import os
import xlwt
import xmlrpc.client
from dotenv import load_dotenv
from modules.ug_client import UsergateClient
from modules.fw_rules import FirewallRules
from modules.zones import Zones
from modules.addr_list import AddressList
from modules.services import Services



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

def addr_output(addr_dict, sheet1, text_style, excel_counter, column_n):
    if addr_dict:
        for i in addr_dict:
            sheet1.write(excel_counter, column_n, i.get('name'), text_style)
            sheet1.write(excel_counter, column_n + 1, i.get('value'), text_style)
            print(f'{i.get('name')}: {i.get('value')} ')
            excel_counter += 1
    else:
        sheet1.write(excel_counter, column_n, 'any', text_style)
        excel_counter += 1
        print('any')
    return excel_counter

def main():
    
    load_dotenv()

    # UGUSER = os.getenv('TESTUGUSER')
    # UGPASS = os.getenv('TESTUGPASS')
    # UGSERVER = os.getenv('TESTUGSERVER')
    
    UGUSER = os.getenv('UGUSER')
    UGPASS = os.getenv('UGPASS')
    UGSERVER = os.getenv('UGSERVER')
    
    with UsergateClient(
        host=UGSERVER,
        username=UGUSER,
        password=UGPASS
    ) as client:
        rules = FirewallRules(client)
        zones = Zones(client)
        addr_lists = AddressList(client)
        services = Services(client)
        
        all_rules = rules.get_all_rules()
        
        #====================== Excel part =========================
        wb = xlwt.Workbook()
        bold = xlwt.easyxf(
            'font: bold 1, height 240;'
            'alignment: horizontal center, vertical center;')
        
        text_style = xlwt.easyxf(
            'font: height 240; '  # 12 пунктов
            'alignment: wrap on'
        )
        
        sheet1 = wb.add_sheet('Sheet 1')

        sheet1.col(0).width = 1000   # № - узкий
        sheet1.col(1).width = 12000  # Правило - широкий
        sheet1.col(2).width = 2000   # Enabled
        sheet1.col(3).width = 2000   # Тэги
        sheet1.col(4).width = 4000   # Действие - средний
        sheet1.col(5).width = 5000   # Зона источника
        sheet1.col(6).width = 5000   # Список адресов источника
        sheet1.col(7).width = 7000   # Адреса источника
        sheet1.col(8).width = 5000   # Зона назначения
        sheet1.col(9).width = 5000   # Список адресов назначения
        sheet1.col(10).width = 7000   # Адреса назначения
        sheet1.col(11).width = 5000   # Список портов
        sheet1.col(12).width = 4000   # Порты
        
        sheet1.write(0, 0, 'position',bold)
        sheet1.write(0, 1, 'name',bold)
        sheet1.write(0, 2, 'enabled',bold)
        sheet1.write(0, 3, 'tags',bold)
        sheet1.write(0, 4, 'action', bold)
        sheet1.write(0, 5, 'src_zones',bold)
        sheet1.write(0, 6, 'src_ips_list',bold)
        sheet1.write(0, 7, 'src_ips',bold)
        sheet1.write(0, 8, 'dst_zones',bold)
        sheet1.write(0, 9, 'dst_ips_list',bold)
        sheet1.write(0, 10, 'dst_ips',bold)
        sheet1.write(0, 11, 'services',bold)
        sheet1.write(0, 12, 'protocols',bold)
        
        excel_counter = 1
        # ====================== /Excel part =========================
        
                
        # В зависимости от ключа .get_all_zones возвращает нам кэш словарей, где ключ или id, или name
        # Нужно это для того, чтобы получить нужный объект или по id, или по имени
        
        all_zones_id = zones.get_all_zones('id') # Кэш зон для поиска по id
        all_zones_name = zones.get_all_zones('name') # Кэш зон для поиска по name
        all_addr_lists_id = addr_lists.get_all_address_lists('id') # Кэш списков адресов для поиска по id
        all_addr_lists_name = addr_lists.get_all_address_lists('name') # Кэш списков адресов для поиска по name
        
        for rule in all_rules.get('items', []):
            print('=====================RULE===================')
            rule_position = rule.get('position', '0')
            sheet1.write(excel_counter, 0, rule_position, text_style)
            
            rule_name = rule.get('name', 'Без имени')
            sheet1.write(excel_counter, 1, rule_name, text_style)
            print(rule_name)
            
            rule_status = rule.get('enabled')
            if rule_status == True:
                sheet1.write(excel_counter, 2, 'enabled', text_style)
            else:
                sheet1.write(excel_counter, 2, 'disabled', text_style)
            print(f'Rule is enabled: {rule_status}')
            
            rule_action = rule.get('action', '-')
            sheet1.write(excel_counter, 4, rule_action, text_style)
            
            src_zone_ids = rule.get('src_zones', [])
            src_zone_names = get_item_names(zones, all_zones_id, src_zone_ids)
            sheet1.write(excel_counter, 5, ', '.join(src_zone_names), text_style)
            print(f'Зоны источника {', '.join(src_zone_names)}')
            
            src_addr_list = rule.get('src_ips')
            src_addr_ids = addr_lists.get_addr_list_id(src_addr_list)
            src_addr_list_names = get_item_names(addr_lists, all_addr_lists_id, src_addr_ids)
            src_addr_dict = addr_lists.get_address_list_dict(src_addr_ids, addr_lists, src_addr_list_names)
            src_excel_counter = addr_output(src_addr_dict, sheet1, text_style, excel_counter, 6)
            
            dst_zone_ids = rule.get('dst_zones', [])
            dst_zone_names = get_item_names(zones, all_zones_id, dst_zone_ids)
            sheet1.write(excel_counter, 8, ', '.join(dst_zone_names), text_style)
            print(f'Зоны назначения {', '.join(dst_zone_names)}')
            
            dst_addr_list = rule.get('dst_ips')
            dst_addr_ids = addr_lists.get_addr_list_id(dst_addr_list)
            dst_addr_list_names = get_item_names(addr_lists, all_addr_lists_id, dst_addr_ids)
            dst_addr_dict = addr_lists.get_address_list_dict(dst_addr_ids, addr_lists, dst_addr_list_names)
            dst_excel_counter = addr_output(dst_addr_dict, sheet1, text_style, excel_counter, 9)
            
            service_ids = rule.get('services')
            service_info = services.get_service_info(service_ids)
            ports_excel_counter = excel_counter
            if service_info:
                for item in service_info:
                    protocol_list_name = item.get('name')
                    print(protocol_list_name)
                    protocols = item.get('protocols')
                    sheet1.write(ports_excel_counter, 11, protocol_list_name, text_style)
                    for protocol in protocols:
                        ports = f"{protocol.get('proto')}: {protocol.get('port')}"
                        print(ports)
                        sheet1.write(ports_excel_counter, 12, ports, text_style)
                        ports_excel_counter += 1
            excel_counter = max(src_excel_counter, dst_excel_counter, ports_excel_counter)
            excel_counter += 1
    wb.save('Usergate35.xls')
        # print(zones.get_by_key(all_zones_id, 9))
        # print(zones.get_by_key(all_zones_name, 'gDMZ VPN'))
        # print(zones.create_zone(all_zones_name, 'gDMZ VPN'))
        

if __name__ == '__main__':
    main()
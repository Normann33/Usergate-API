
#!/usr/bin/env python3

import xmlrpc.client
from modules.ug_client import UsergateClient

class AddressList:
    
    def __init__(self, client: UsergateClient):
        self.client = client

    def get_all_address_lists(self, addr_list_key):
        ''' addr_list_key должен быть 'id' или 'name' '''
        address_lists = self.client.server.v2.nlists.list(self.client.auth_token, 'network', 0, 10000, {})
        address_lists_dict = {item[addr_list_key]: item for item in address_lists.get('items', [])}
        return address_lists_dict
    
    def get_addr_list_id(self, addr_list_list):
        addr_list_ids = []
        for addr_list in addr_list_list:
            if addr_list[0] == 'list_id':
                    addr_list_ids.append(addr_list[1])
        return addr_list_ids
                
                
    def get_by_key(self, addr_list_dict, addr_list_key):
        try:
            if type(addr_list_key) == int:
                addr_list_name = addr_list_dict.get(addr_list_key, {}).get('name')
                return addr_list_name
            else:
                addr_list_id = addr_list_dict.get(addr_list_key).get('id')
                return addr_list_id
        except AttributeError as e:
            print(e, addr_list_key)
        
    
    def get_addr_list_items(self, addr_list_id):
        addr_list_values = []
        try:
            addr_list_items = self.client.server.v2.nlists.list.list(self.client.auth_token, int(addr_list_id), 0, 1000, {}, [])
            for item in addr_list_items.get('items', []):
                        item_value = item.get('value', '—')
                        addr_list_values.append(item_value)
        except xmlrpc.client.Fault as e:
            if e.faultCode == 2010 and 'List content is not available' in e.faultString:
                return 'List content is not available'
            else:
                raise
        addr_list_values = ', '.join(addr_list_values)
        return addr_list_values
    
    def get_address_list_dict(self, addr_ids, addr_lists, addr_list_names):
        '''Возвращаем словарь ip адресов, где name - имя списка, value - сами ip адреса'''
        addr_list_items = []
        if len(addr_ids) > 0:
            for id in addr_ids:
                addr_list_items.append(addr_lists.get_addr_list_items(id))
                # print(f'Ip адреса источника: {src_addr_list_items}')
        
        src_ip_dict = [
            {'name': name, 'value': value}
            for name, value in zip(addr_list_names, addr_list_items)
        ]
        return src_ip_dict
    
    def create_list(self, addr_list_dict, new_list):
        '''Тут или создаем список ip, и возвращаем его id, или, если такой список уже есть,
           определяем и возвращаем его id'''
        
        try:
            result = self.client.server.v2.nlists.add(self.client.auth_token, new_list)
        except xmlrpc.client.Fault as e:
            if e.faultCode == 409 and 'Object with the same name already exists' in e.faultString:
                result = self.get_by_key(addr_list_dict, new_list.get('name'))
            else:
                # Другая ошибка - пробрасываем дальше
                raise
        return result
        
    def create_list_item(self, list_id, new_item):
        try:
            self.client.server.v2.nlists.list.add(self.client.auth_token, list_id, new_item)
        except xmlrpc.client.Fault as e:
            if e.faultCode == 2001 and 'Item duplicate' in e.faultString:
                print('Item already exists')
                pass
            else:
                # Другая ошибка - пробрасываем дальше
                raise
    
    def delete_list(self, list_id):
        try:
            self.client.server.v2.nlists.delete(self.client.auth_token, list_id)
        except Exception as e:
            print(e)
            
    def update_list(self, list_id, list_info):
        try:
            result = self.client.server.v2.nlists.update(self.client.auth_token, list_id, list_info)
            return result
        except Exception as e:
            return e
        
    def delete_list_items(self, list_id, item_id):
        try:
            result = self.client.server.v2.nlists.list.delete(self.client.auth_token, list_id, item_id)
            return result
        except Exception as e:
            return e
    
    @staticmethod
    def addr_list_add(addr_list_manager, rule_item, addr_list_type, all_addr_lists_name):
        '''addr_list - src_ips or dst_ips'''
        create_items = False
        for ip_list in rule_item.get(addr_list_type):
            ip_list_name = ip_list.get('name')
            new_addr_list = []
            new_ip_list = ['list_id']
            if ip_list_name == 'any' or ip_list_name == []:
                new_addr_list = []
            elif all_addr_lists_name.get(ip_list_name):
                new_ip_list.append(addr_list_manager.get_by_key(all_addr_lists_name, ip_list_name))
                new_addr_list.append(new_ip_list)
            else:
                new_ip_list_item = {'type': 'network', 'name': ip_list_name}
                new_ip_list.append(addr_list_manager.create_list(all_addr_lists_name, new_ip_list_item))
                new_addr_list.append(new_ip_list)
                all_addr_lists_name = addr_list_manager.get_all_address_lists('name')
                create_items = True
        return new_addr_list, all_addr_lists_name, create_items
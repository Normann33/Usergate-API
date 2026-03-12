
#!/usr/bin/env python3

import xmlrpc.client
from modules.ug_client import UsergateClient

class AddressList:
    
    def __init__(self, client: UsergateClient):
        self.client = client

    def get_all_address_lists(self, addr_list_key):
        ''' addr_list_key должен быть 'id' или 'name' '''
        address_lists = self.client.server.v2.nlists.list(self.client.auth_token, 'network', 0, 1000, {})
        address_lists_dict = {item[addr_list_key]: item for item in address_lists.get('items', [])}
        return address_lists_dict
    
    def get_addr_list_id(self, addr_list_list):
        addr_list_ids = []
        for addr_list in addr_list_list:
            if addr_list[0] == 'list_id':
                    addr_list_ids.append(addr_list[1])
        return addr_list_ids
                
                
    def get_by_key(self, addr_list_dict, addr_list_key):
        if type(addr_list_key) == int:
            addr_list_name = addr_list_dict.get(addr_list_key, {}).get('name')
            return addr_list_name
        else:
            addr_list_id = addr_list_dict.get(addr_list_key, {}).get('id')
            return addr_list_id
        
    
    def get_addr_list_items(self, addr_list_ids):
        addr_list_values = []
        for addr_list_id in addr_list_ids:
            try:
                addr_list_items = self.client.server.v2.nlists.list.list(self.client.auth_token, addr_list_id, 0, 1000, {}, [])
                for item in addr_list_items.get('items', []):
                            item_value = item.get('value', '—')
                            addr_list_values.append(item_value)
            except Exception as e:
                return "Нельзя просмотреть список"
            addr_list_values = ', '.join(addr_list_values)
        return addr_list_values
    
    def create_list(self, new_list):
        result = self.client.server.v2.nlists.add(self.client.auth_token, new_list)
        return result
        
    def create_list_item(self, list_id, new_item):
        self.client.server.v2.nlists.list.add(self.client.auth_token, list_id, new_item)
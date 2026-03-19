#!/usr/bin/env python3

import xmlrpc.client
from modules.ug_client import UsergateClient

class Services:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_services(self, service_key):
        ''' service_key должен быть 'id' или 'name' '''
        services = self.client.server.v1.libraries.services.list(self.client.auth_token, 0, 1000, {}, [])
        services_dict = {s[service_key]: s for s in services.get('items', [])}
        return services_dict
    
    def get_service_info(self, service_list):
        service_info_list = []
        services_dict = self.get_all_services('id')
        for service_ref in service_list:
            service_info = services_dict.get(service_ref[1])
            service_info_list.append(service_info)
        return service_info_list
    
    def create_service(self, service_dict, new_service):
        '''Тут или создаем сервис, и возвращаем его id, или, если такой сервис уже есть,
           определяем и возвращаем его id'''
        try:
            result = self.client.server.v1.libraries.service.add(self.client.auth_token, new_service)
        except xmlrpc.client.Fault as e:
            if e.faultCode == 409 and 'Object with the same name already exists' in e.faultString:
                pass
                # result = self.get_by_key(service_dict, new_service)
            else:
                # Другая ошибка - пробрасываем дальше
                raise
        # return result
    
   
    
    
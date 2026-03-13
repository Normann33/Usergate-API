#!/usr/bin/env python3

import xmlrpc.client
from modules.ug_client import UsergateClient

class Services:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_services(self):
        services = self.client.server.v1.libraries.services.list(self.client.auth_token, 0, 1000, {}, [])
        services_dict = {s['id']: s for s in services.get('items', [])}
        return services_dict
    
    def get_service_info(self, service_list):
        service_info_list = []
        services_dict = self.get_all_services()
        for service_ref in service_list:
            service_info = services_dict.get(service_ref[1])
            service_info_list.append(service_info)
        return service_info_list
    
    def create_service(self):
        pass
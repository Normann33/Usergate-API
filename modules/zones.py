#!/usr/bin/env python3

import xmlrpc.client
from modules.ug_client import UsergateClient


class Zones:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_zones(self, zone_key):
        ''' zone_key должен быть 'id' или 'name' '''
        zones_list = self.client.server.v1.netmanager.zones.list(self.client.auth_token)
        zones_dict = {z[zone_key]: z for z in zones_list}
        return zones_dict
    
    def get_by_key(self, zones_dict, zone_key):
        if type(zone_key) == int:
            zone_name = zones_dict.get(zone_key, {}).get('name')
            return zone_name
        else:
            zone_id = zones_dict.get(zone_key, {}).get('id')
            return zone_id
            
    def create_zone(self, zones_dict, zone_name):
        '''Тут или создаем зону, и возвращаем ее id, или, если такая зона уже есть,
           определяем и возвращаем ее id'''
        try:
            result = self.client.server.v1.netmanager.zone.add(self.client.auth_token, {'name': zone_name})
        except xmlrpc.client.Fault as e:
            if e.faultCode == 409 and 'Object with the same name already exists' in e.faultString:
                result = self.get_by_key(zones_dict, zone_name)
            else:
                # Другая ошибка - пробрасываем дальше
                raise
        return result
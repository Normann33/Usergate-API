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
            elif e.faultCode == 2 and 'Internal server error' in e.faultString:
                # Для версии 6.1.9
                zone_data_619 = {
                    'name': zone_name,         
                    'enable_antispoof': True,  
                    'networks': [],            
                    'dos_profiles': [],
                    'services_access': []
                }
                result = self.client.server.v1.netmanager.zone.add(self.client.auth_token, zone_data_619)
            else:
                # Другая ошибка - пробрасываем дальше
                raise
        return result
    
    @staticmethod
    def zone_add(zones, item, zone_list, newrule, all_zones_name):
        '''zone_list - src_zones or dst_zones'''
        for zone in item.get(zone_list):
            if zone == 'any':
                newrule[zone_list] = []
            elif all_zones_name.get(zone):
                newrule[zone_list].append(zones.get_by_key(all_zones_name, zone))
            else:
                newrule[zone_list].append(zones.create_zone(all_zones_name, zone))
                all_zones_name = zones.get_all_zones('name')
        return newrule, all_zones_name
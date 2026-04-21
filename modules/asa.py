#!/usr/bin/env python3

import ipaddress
from typing import Dict, List, Tuple, Any, Optional
from modules.asa_client import ASAConnection


class AsaACL:
    
    def __init__(self, conn: ASAConnection, vpnlogin: str, protocol: str, src_ip: str):
        self.conn = conn
        self.acl_name = vpnlogin
        self.protocol = protocol
        self.src_ip = src_ip
        
    def create_object_group(self, ip_list: List):
        commands = []
        commands.append(f'object-group network {self.acl_name}')
        for item in ip_list:
            commands.append(f'network-object {ipaddress.IPv4Network(item).network_address} {ipaddress.IPv4Network(item).netmask}')
        commands.append('exit')
        result = self.conn.send_config_set(commands)
        return result
        
    def create_acl_rule(self):
        acl_rule = f'access-list {self.acl_name} extended permit {self.protocol} host {self.src_ip} object-group {self.acl_name} object-group REMOTE'
        print(acl_rule)
        result = self.conn.send_config_set(acl_rule)
        return result
    
    def delete_item(self, item_type: str):
        if item_type == 'access-list':
            command = f'clear configure access-list {self.acl_name}'
        elif item_type == 'object-group':
            command = f'no object-group network {self.acl_name}'
        result = self.conn.send_config_set(command)
        return result
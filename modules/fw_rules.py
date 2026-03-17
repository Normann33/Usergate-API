#!/usr/bin/env python3

import xmlrpc
from modules.ug_client import UsergateClient

class FirewallRules:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_rules(self):
        fw_rules = self.client.server.v1.firewall.rules.list(self.client.auth_token, 0, 100, {})
        return fw_rules
    
    def create_rule(self, new_rule):
        try:
            self.client.server.v1.firewall.rule.add(self.client.auth_token, new_rule)
        except xmlrpc.client.Fault as e:
            if e.faultCode == 409 and 'Name already exist' in e.faultString:
                pass
            else:
                # Другая ошибка - пробрасываем дальше
                raise
    
    
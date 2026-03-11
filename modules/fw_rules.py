#!/usr/bin/env python3

from modules.ug_client import UsergateClient

class FirewallRules:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_rules(self):
        fw_rules = self.client.server.v1.firewall.rules.list(self.client.auth_token, 0, 100, {})
        return fw_rules
    
    def create_rule(self, new_rule):
        self.client.server.v1.firewall.rule.add(self.client.auth_token, new_rule)
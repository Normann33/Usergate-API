#!/usr/bin/env python3

import os
from dotenv import load_dotenv
from modules.ug_client import UsergateClient

class FirewallRules:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_rules(self):
        fw_rules = self.client.server.v1.firewall.rules.list(self.client.auth_token, 0, 100, {})
        return fw_rules

def main():
    
    load_dotenv()

    TESTUGUSER = os.getenv('TESTUGUSER')
    TESTUGPASS = os.getenv('TESTUGPASS')
    TESTUGSERVER = os.getenv('TESTUGSERVER')
    
    with UsergateClient(
        host=TESTUGSERVER,
        username=TESTUGUSER,
        password=TESTUGPASS
    ) as client:
         rules = FirewallRules(client)
         all_rules = rules.get_all_rules()
         print(all_rules)

if __name__ == '__main__':
    main()
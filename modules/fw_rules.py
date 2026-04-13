#!/usr/bin/env python3

import xmlrpc
import logging
from modules.ug_client import UsergateClient

logger = logging.getLogger(__name__)

class FirewallRules:
    
    def __init__(self, client: UsergateClient):
        self.client = client
    
    def get_all_rules(self):
        fw_rules = self.client.server.v1.firewall.rules.list(self.client.auth_token, 0, 10000, {})
        return fw_rules
    
    def get_all_rules_dict(self, rule_key):
        ''' rule_key должен быть 'id' или 'name' '''
        rules_list = self.client.server.v1.firewall.rules.list(self.client.auth_token, 0, 10000, {})
        rules_dict = {item[rule_key]: item for item in rules_list.get('items', [])}
        return rules_dict
    
    def create_rule(self, new_rule):
        try:
            result = self.client.server.v1.firewall.rule.add(self.client.auth_token, new_rule)
            logger.info(f'Правило {new_rule.get('name')} успешно создано (ID: {result})')
        except xmlrpc.client.Fault as e:
            if e.faultCode == 409 and 'Name already exist' in e.faultString:
                logger.error(f'Правило {new_rule.get('name')} уже существует')
                pass
            else:
                # Другая ошибка - пробрасываем дальше
                logger.error(f"Ошибка создания правила {new_rule.get('name')}: {e}", exc_info=True)
                raise
    
    def delete_rule(self, rule_id):
        try:
            result = self.client.server.v1.firewall.rule.delete(self.client.auth_token, rule_id)
            logger.info(f'Правило {rule_id} успешно удалено (ID: {result})')
            return result
        except Exception as e:
            logger.error(f"Ошибка удаления правила {rule_id}: {e}", exc_info=True)
            return e
        
    def update_rule(self, rule_id, rule_info):
        try:
            result = self.client.server.v1.firewall.rule.update(self.client.auth_token, rule_id, rule_info)
            logger.info(f'Правило {rule_id} успешно обновлено')
            return result
        except Exception as e:
            logger.error(f"Ошибка обновления правила {rule_id}: {e}", exc_info=True)
            return e
    
    
#!/usr/bin/env python3

import pandas as pd
import json

"""
Convert Excel file entries to new_rule json format
"""

class ExcelToJson:
    
    def __init__(self, excel_file):
        self.excel_file = excel_file
    
    def convert_values(self):
        # Чтение Excel файла
        df = pd.read_excel(self.excel_file)
        
        # Удаляем полностью пустые строки
        df = df.dropna(how='all')
        
        # Определяем поля, которые идентифицируют правило
        rule_identifiers = ['position', 'name']
        
        # Заполняем пустые значения в идентификаторах
        df[rule_identifiers] = df[rule_identifiers].ffill()
        
        # Группируем по идентификаторам
        rules = []
        
        for (position, name), group in df.groupby(rule_identifiers):
            rule = {
                'position': position,
                'name': name,
            }
            
            # Обработка обычных полей (без привязки)
            for col in ['enabled', 'action', 'src_zones', 'dst_zones', 'tags']:
                if col in group.columns:
                    values = group[col].dropna().tolist()
                    rule[col] = values if values else []
            
            # ============================================================
            # Обработка источников (src_ips_list + src_ips)
            # ============================================================
            src_ips_list = []
            current_src_list = None
            
            for _, row in group.iterrows():
                list_name = row.get('src_ips_list')
                ip_value = row.get('src_ips')
                
                # Если встретили новое имя списка
                if pd.notna(list_name):
                    # Добавляем предыдущий список в результат
                    if current_src_list is not None:
                        src_ips_list.append(current_src_list)
                    
                    # Создаём новый список
                    current_src_list = {
                        'name': list_name,
                        'items': []
                    }
                
                # Добавляем IP к текущему списку
                if pd.notna(ip_value) and current_src_list is not None:
                    current_src_list['items'].append(ip_value)
            
            # Не забываем добавить последний список
            if current_src_list is not None:
                src_ips_list.append(current_src_list)
            
            rule['src_ips'] = src_ips_list
            
            # ============================================================
            # Обработка назначений (dst_ips_list + dst_ips)
            # ============================================================
            dst_ips_list = []
            current_dst_list = None
            
            for _, row in group.iterrows():
                list_name = row.get('dst_ips_list')
                ip_value = row.get('dst_ips')
                
                if pd.notna(list_name):
                    if current_dst_list is not None:
                        dst_ips_list.append(current_dst_list)
                    
                    current_dst_list = {
                        'name': list_name,
                        'items': []
                    }
                
                if pd.notna(ip_value) and current_dst_list is not None:
                    current_dst_list['items'].append(ip_value)
            
            if current_dst_list is not None:
                dst_ips_list.append(current_dst_list)
            
            rule['dst_ips'] = dst_ips_list
            
            # ============================================================
            # Обработка сервисов (services + protocols)
            # ============================================================
            services_list = []
            current_service = None
            
            for _, row in group.iterrows():
                service_name = row.get('services')
                protocol = row.get('protocols')
                
                if pd.notna(service_name):
                    if current_service is not None:
                        services_list.append(current_service)
                    
                    current_service = {
                        'name': service_name,
                        'protocols': []
                    }
                
                if pd.notna(protocol) and current_service is not None:
                    current_service['protocols'].append(protocol)
            
            if current_service is not None:
                services_list.append(current_service)
            
            rule['services'] = services_list
            
            rules.append(rule)
        
        return json.dumps(rules, ensure_ascii=False, indent=2)
            

def main():
    e2j = ExcelToJson('Usergate35.xls')
    print(e2j.convert_values())

if __name__ == '__main__':
    main()
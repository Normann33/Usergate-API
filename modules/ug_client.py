#!/usr/bin/env python3
"""
Usergate NGFW API Client
"""

import xmlrpc.client
from typing import Optional

class UsergateClient:
    """Базовый клиент для работы с Usergate API"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 4040):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.server = xmlrpc.client.ServerProxy(f'http://{host}:{port}/rpc')
        self.auth_token: Optional[str] = None
    
    def login(self) -> None:
        """Авторизация в системе"""
        auth = self.server.v2.core.login(self.username, self.password, {})
        self.auth_token = auth['auth_token']
    
    def logout(self) -> None:
        """Завершение сессии"""
        if self.auth_token:
            self.server.v2.core.logout(self.auth_token)
            self.auth_token = None
    
    def __enter__(self):
        self.login()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
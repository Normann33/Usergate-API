"""
Модуль для SSH-подключения к Cisco ASA с использованием Netmiko.
Поддерживает контекстный менеджер, логирование и безопасную обработку ошибок.
"""

import logging
from typing import List, Optional, Union, Dict, Any

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger(__name__)


class ASAConnection:
    """Класс для управления SSH-подключением к Cisco ASA."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        secret: Optional[str] = None,
        port: int = 22,
        timeout: int = 10,
        **netmiko_kwargs: Any
    ):
        self.host = host
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.timeout = timeout
        self.netmiko_kwargs = netmiko_kwargs
        self._connection: Optional[ConnectHandler] = None

    @property
    def is_connected(self) -> bool:
        """Проверяет, существует ли активное подключение."""
        return self._connection is not None

    def connect(self) -> None:
        """Устанавливает SSH-подключение к устройству."""
        if self.is_connected:
            logger.info("Already connected to %s", self.host)
            return

        device_params: Dict[str, Any] = {
            "device_type": "cisco_asa",
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "timeout": self.timeout,
            **self.netmiko_kwargs,
        }
        if self.secret:
            device_params["secret"] = self.secret

        try:
            logger.info("Connecting to ASA %s...", self.host)
            self._connection = ConnectHandler(**device_params)
            logger.info("Successfully connected to %s", self.host)
        except NetmikoAuthenticationException as e:
            logger.error("Authentication failed for %s: %s", self.host, e)
            raise
        except NetmikoTimeoutException as e:
            logger.error("Connection timeout to %s: %s", self.host, e)
            raise
        except Exception as e:
            logger.error("Unexpected error connecting to %s: %s", self.host, e)
            raise

    def disconnect(self) -> None:
        """Закрывает SSH-подключение."""
        if self._connection:
            try:
                self._connection.disconnect()
                logger.info("Disconnected from %s", self.host)
            except Exception as e:
                logger.warning("Error disconnecting from %s: %s", self.host, e)
            finally:
                self._connection = None

    def send_command(self, command: str, **kwargs: Any) -> str:
        """Выполняет команду в operational/exec режиме (show, ping и т.д.)."""
        if not self.is_connected:
            raise RuntimeError("Not connected. Call connect() first.")
        logger.debug("Executing command: %s", command)
        return self._connection.send_command(command, **kwargs)

    def send_config_set(
        self,
        config_commands: Union[str, List[str]],
        **kwargs: Any
    ) -> str:
        """Отправляет набор конфигурационных команд в config-режиме."""
        if not self.is_connected:
            raise RuntimeError("Not connected. Call connect() first.")
        logger.debug("Sending config commands...")
        if isinstance(config_commands, str):
            config_commands = [config_commands]
        return self._connection.send_config_set(config_commands, **kwargs)

    def __enter__(self) -> "ASAConnection":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
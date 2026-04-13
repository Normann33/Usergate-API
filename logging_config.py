# logging_config.py

import logging
from pathlib import Path
from datetime import datetime

def setup_logging(log_file: str = 'app.log', level: int = logging.INFO):
    """
    Единая настройка логирования для всего проекта.
    Вызывается ОДИН раз в main.py
    """
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Формат с именем модуля (важно для отладки!)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Обработчик файла
    file_handler = logging.FileHandler(log_path, encoding='utf-8')
    file_handler.setFormatter(formatter)
    
    # Обработчик консоли
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Убираем дублирование логов от библиотек
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logging
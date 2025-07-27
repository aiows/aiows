#!/usr/bin/env python3
"""
Graceful Shutdown Example для aiows

Этот пример демонстрирует как использовать graceful shutdown механизм
в aiows WebSocket сервере.

Для запуска:
1. Запустите сервер: python examples/graceful_shutdown_example.py
2. Подключитесь WebSocket клиентом к ws://localhost:8000
3. Отправьте Ctrl+C или SIGTERM для graceful shutdown
4. Наблюдайте как сервер корректно закрывает все соединения

Features:
- Signal handlers для SIGTERM и SIGINT
- Graceful закрытие всех активных соединений 
- Timeout для shutdown процесса
- Programmatic shutdown API
- Proper cleanup ресурсов
"""

import asyncio
import logging
import signal
import time
from aiows import WebSocketServer, Router

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Создание роутера
router = Router()

# Статистика подключений
connections_stats = {
    'total_connected': 0,
    'currently_connected': 0,
    'active_connections': set()
}

@router.on_connect
async def handle_connect(ws):
    """Обработка подключения нового клиента"""
    connections_stats['total_connected'] += 1
    connections_stats['currently_connected'] += 1
    connections_stats['active_connections'].add(ws)
    
    logger.info(f"Новое подключение! Всего подключений: {connections_stats['currently_connected']}")
    
    # Отправляем приветственное сообщение
    await ws.send_json({
        "type": "welcome",
        "message": "Добро пожаловать! Сервер поддерживает graceful shutdown.",
        "connection_id": connections_stats['total_connected'],
        "server_info": {
            "shutdown_timeout": server._shutdown_timeout,
            "supports_graceful_shutdown": True
        }
    })

@router.on_disconnect
async def handle_disconnect(ws, reason):
    """Обработка отключения клиента"""
    if ws in connections_stats['active_connections']:
        connections_stats['active_connections'].remove(ws)
        connections_stats['currently_connected'] -= 1
    
    logger.info(f"Клиент отключился (причина: {reason}). Активных подключений: {connections_stats['currently_connected']}")

@router.message("ping")
async def handle_ping(ws, message_data):
    """Обработка ping сообщений"""
    await ws.send_json({
        "type": "pong",
        "timestamp": time.time(),
        "server_status": "running" if not server.is_shutting_down else "shutting_down"
    })

@router.message("echo")
async def handle_echo(ws, message_data):
    """Эхо сообщения обратно клиенту"""
    await ws.send_json({
        "type": "echo_response",
        "original_message": message_data,
        "timestamp": time.time()
    })

@router.message("status")
async def handle_status(ws, message_data):
    """Получение статуса сервера"""
    await ws.send_json({
        "type": "server_status",
        "connections": {
            "total_connected": connections_stats['total_connected'],
            "currently_connected": connections_stats['currently_connected']
        },
        "server": {
            "is_shutting_down": server.is_shutting_down,
            "shutdown_timeout": server._shutdown_timeout
        },
        "timestamp": time.time()
    })

@router.message("shutdown")
async def handle_shutdown_request(ws, message_data):
    """Обработка запроса на shutdown (только для демонстрации)"""
    logger.info("Получен запрос на programmatic shutdown от клиента")
    
    # Уведомляем клиента о начале shutdown
    await ws.send_json({
        "type": "shutdown_initiated",
        "message": "Сервер начинает graceful shutdown...",
        "timestamp": time.time()
    })
    
    # Запускаем shutdown в фоне
    asyncio.create_task(shutdown_server_gracefully())

async def shutdown_server_gracefully():
    """Graceful shutdown сервера с задержкой"""
    logger.info("Начинается programmatic shutdown через 2 секунды...")
    await asyncio.sleep(2)  # Даём время клиенту получить ответ
    await server.shutdown(timeout=10.0)

# Создание сервера
server = WebSocketServer()
server.include_router(router)

# Настройка graceful shutdown
server.set_shutdown_timeout(15.0)  # 15 секунд на graceful shutdown

def main():
    """Главная функция запуска сервера"""
    print("=" * 60)
    print("🚀 Graceful Shutdown Example для aiows")
    print("=" * 60)
    print("📡 Сервер запускается на ws://localhost:8000")
    print("🔧 Graceful shutdown timeout: 15 секунд")
    print("=" * 60)
    print("Команды для тестирования:")
    print("  💬 ping    - проверка связи")
    print("  🔄 echo    - эхо сообщения") 
    print("  📊 status  - статус сервера")
    print("  🛑 shutdown - programmatic shutdown")
    print("=" * 60)
    print("Для graceful shutdown:")
    print("  🔴 Нажмите Ctrl+C")
    print("  🔴 Или отправьте SIGTERM процессу")
    print("  🔴 Или отправьте сообщение 'shutdown'")
    print("=" * 60)
    
    try:
        # Запуск сервера (блокирующий вызов)
        server.run(host="localhost", port=8000)
    except KeyboardInterrupt:
        logger.info("Получен KeyboardInterrupt")
    except Exception as e:
        logger.error(f"Ошибка сервера: {e}")
    finally:
        logger.info("Сервер завершил работу")

if __name__ == "__main__":
    main() 
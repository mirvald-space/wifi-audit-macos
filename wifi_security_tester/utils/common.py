"""
Common utilities and helper functions for WiFi Security Tester

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import os
import sys
import subprocess
import platform
from typing import Optional, Dict, Any
from pathlib import Path

def display_legal_warning() -> bool:
    """Display legal warning and usage terms"""
    warning_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ПРАВОВОЕ ПРЕДУПРЕЖДЕНИЕ                           ║
║                              LEGAL WARNING                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║ РУССКИЙ:                                                                     ║
║ Этот инструмент предназначен ИСКЛЮЧИТЕЛЬНО для:                              ║
║ • Тестирования безопасности СОБСТВЕННЫХ сетей                                ║
║ • Образовательных целей в контролируемой среде                               ║
║ • Авторизованного пентестинга с письменным разрешением                       ║
║                                                                              ║
║ ЗАПРЕЩЕНО использовать для:                                                  ║
║ • Несанкционированного доступа к чужим сетям                                 ║
║ • Любых незаконных действий                                                  ║
║                                                                              ║
║ ENGLISH:                                                                     ║
║ This tool is intended EXCLUSIVELY for:                                      ║
║ • Testing security of YOUR OWN networks                                     ║
║ • Educational purposes in controlled environments                            ║
║ • Authorized penetration testing with written permission                     ║
║                                                                              ║
║ PROHIBITED for:                                                              ║
║ • Unauthorized access to networks you don't own                             ║
║ • Any illegal activities                                                     ║
║                                                                              ║
║ Пользователь несет полную ответственность за использование этого инструмента ║
║ User bears full responsibility for the use of this tool                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(warning_text)
    return True

def get_user_consent() -> bool:
    """Get explicit user consent for tool usage"""
    consent_prompt = """
Для продолжения вы должны подтвердить, что:
To continue, you must confirm that:

1. Вы будете использовать этот инструмент только для тестирования собственных сетей
   You will use this tool only for testing your own networks

2. У вас есть письменное разрешение на тестирование (если применимо)
   You have written permission for testing (if applicable)

3. Вы понимаете правовые последствия неправомерного использования
   You understand the legal consequences of improper use

Согласны ли вы с этими условиями? (да/yes/y для согласия)
Do you agree to these terms? (да/yes/y to agree): """
    
    try:
        response = input(consent_prompt).strip().lower()
        return response in ['да', 'yes', 'y']
    except (EOFError, KeyboardInterrupt):
        return False

def get_system_info() -> Dict[str, Any]:
    """Get system information for compatibility checks"""
    info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'machine': platform.machine(),
        'python_version': platform.python_version(),
        'is_macos': platform.system() == 'Darwin'
    }
    
    if info['is_macos']:
        try:
            # Get macOS version
            result = subprocess.run(['sw_vers', '-productVersion'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info['macos_version'] = result.stdout.strip()
        except Exception:
            info['macos_version'] = 'Unknown'
    
    return info

def check_admin_privileges() -> bool:
    """Check if running with administrator privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def run_command(command: list, timeout: int = 30, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run a system command with error handling"""
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            check=False
        )
        return result
    except subprocess.TimeoutExpired:
        raise Exception(f"Command timed out after {timeout} seconds: {' '.join(command)}")
    except FileNotFoundError:
        raise Exception(f"Command not found: {command[0]}")
    except Exception as e:
        raise Exception(f"Command execution failed: {e}")

def ensure_directory(path: Path) -> Path:
    """Ensure directory exists, create if necessary"""
    path.mkdir(parents=True, exist_ok=True)
    return path

def validate_file_path(file_path: str) -> bool:
    """Validate if file path exists and is readable"""
    try:
        path = Path(file_path)
        return path.exists() and path.is_file() and os.access(path, os.R_OK)
    except Exception:
        return False

def format_bytes(bytes_count: int) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"

def format_time_duration(seconds: int) -> str:
    """Format seconds into human readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

def safe_input(prompt: str, default: str = None) -> str:
    """Safe input with default value and interrupt handling"""
    try:
        if default:
            response = input(f"{prompt} [{default}]: ").strip()
            return response if response else default
        else:
            return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        if default:
            return default
        raise KeyboardInterrupt("User interrupted input")

def confirm_action(message: str, default: bool = False) -> bool:
    """Get user confirmation for an action"""
    default_text = "Y/n" if default else "y/N"
    try:
        response = input(f"{message} ({default_text}): ").strip().lower()
        if not response:
            return default
        return response in ['y', 'yes', 'да']
    except (EOFError, KeyboardInterrupt):
        return False
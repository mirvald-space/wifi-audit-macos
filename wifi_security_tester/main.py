#!/usr/bin/env python3
"""
WiFi Security Test Tool - Main Application Entry Point

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License

ВНИМАНИЕ: Этот инструмент предназначен ИСКЛЮЧИТЕЛЬНО для тестирования собственных сетей!
WARNING: This tool is intended EXCLUSIVELY for testing your own networks!
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.menu_system import MenuSystem
from core.logger import setup_logger
from utils.common import display_legal_warning, get_user_consent

def main():
    """Main application entry point"""
    try:
        # Setup logging
        logger = setup_logger()
        logger.info("WiFi Security Tester starting...")
        
        # Display legal warning and get consent
        if not display_legal_warning() or not get_user_consent():
            print("\nВыход из программы. Согласие на использование не получено.")
            print("Exiting. User consent not obtained.")
            sys.exit(0)
        
        # Initialize and run menu system
        menu = MenuSystem()
        menu.run()
        
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем.")
        print("Program interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        print(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
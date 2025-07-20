"""
Menu System - Interactive menu interface for WiFi Security Tester

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import os
import sys
from typing import Dict, Callable, Optional
from .logger import get_logger

# Import components with proper path handling
try:
    from ..components.interface_manager import InterfaceManager
    from ..components.wordlist_manager import WordlistManager
    from ..components.dependency_manager import DependencyManager
    from ..components.network_scanner import NetworkScanner
    from ..components.capture_engine import CaptureEngine
    from ..components.password_cracker import PasswordCracker
    from ..components.security_manager import SecurityManager
    from ..core.performance_optimizer import get_performance_optimizer
    from ..core.error_handler import get_error_handler
except ImportError:
    # Fallback for direct execution
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from components.interface_manager import InterfaceManager
    from components.wordlist_manager import WordlistManager
    from components.dependency_manager import DependencyManager
    from components.network_scanner import NetworkScanner
    from components.capture_engine import CaptureEngine
    from components.password_cracker import PasswordCracker
    from components.security_manager import SecurityManager
    from core.performance_optimizer import get_performance_optimizer
    from core.error_handler import get_error_handler

class MenuSystem:
    """Interactive menu system for the WiFi Security Tester"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.running = True
        
        # Initialize all components
        self.interface_manager = InterfaceManager()
        self.wordlist_manager = WordlistManager()
        self.dependency_manager = DependencyManager()
        self.network_scanner = NetworkScanner()
        self.capture_engine = CaptureEngine()
        self.password_cracker = PasswordCracker(self.wordlist_manager)
        self.security_manager = SecurityManager()
        self.performance_optimizer = get_performance_optimizer()
        self.error_handler = get_error_handler()
        
        self.menu_items = self._initialize_menu_items()
    
    def _initialize_menu_items(self) -> Dict[str, Dict]:
        """Initialize menu items with their handlers"""
        return {
            "1": {
                "title": "Проверить зависимости / Check Dependencies",
                "handler": self._dependency_management_handler,
                "description": "Проверить и установить необходимые инструменты"
            },
            "2": {
                "title": "Сканировать сети / Scan Networks", 
                "handler": self._network_scanning_handler,
                "description": "Найти доступные WiFi сети"
            },
            "3": {
                "title": "Управление интерфейсами / Interface Management",
                "handler": self._interface_management_handler,
                "description": "Настроить WiFi интерфейсы"
            },
            "4": {
                "title": "Захват пакетов / Packet Capture",
                "handler": self._packet_capture_handler,
                "description": "Захватить handshake пакеты"
            },
            "5": {
                "title": "Взлом паролей / Password Cracking",
                "handler": self._password_cracking_handler,
                "description": "Тестировать стойкость паролей"
            },
            "6": {
                "title": "Управление словарями / Wordlist Management",
                "handler": self._wordlist_management_handler,
                "description": "Создать и управлять списками паролей"
            },
            "7": {
                "title": "Настройки безопасности / Security Settings",
                "handler": self._security_settings_handler,
                "description": "Проверить SIP и права доступа"
            },
            "8": {
                "title": "Производительность / Performance",
                "handler": self._performance_management_handler,
                "description": "Мониторинг и оптимизация производительности"
            },
            "9": {
                "title": "Отчеты / Reports",
                "handler": self._reports_handler,
                "description": "Просмотр отчетов и статистики"
            },
            "0": {
                "title": "Выход / Exit",
                "handler": self._exit_handler,
                "description": "Завершить работу программы"
            }
        }
    
    def _placeholder_handler(self):
        """Placeholder handler for menu items not yet implemented"""
        print("\n" + "="*60)
        print("Эта функция будет реализована в следующих задачах.")
        print("This feature will be implemented in upcoming tasks.")
        print("="*60)
        input("\nНажмите Enter для продолжения / Press Enter to continue...")
    
    def _interface_management_handler(self):
        """Handle interface management menu option"""
        print("\n" + "="*60)
        print("           Управление интерфейсами / Interface Management")
        print("="*60)
        
        try:
            # Discover interfaces
            print("Поиск WiFi интерфейсов... / Discovering WiFi interfaces...")
            interfaces = self.interface_manager.discover_wifi_interfaces()
            
            if not interfaces:
                print("WiFi интерфейсы не найдены / No WiFi interfaces found")
                input("\nНажмите Enter для продолжения / Press Enter to continue...")
                return
            
            # Display discovered interfaces
            print(f"\nНайдено {len(interfaces)} интерфейс(ов) / Found {len(interfaces)} interface(s):")
            print("-" * 40)
            
            for i, iface in enumerate(interfaces, 1):
                print(f"{i}. {iface['name']} ({iface['device']})")
                print(f"   MAC: {iface['mac_address']}")
                print(f"   Статус / Status: {iface['status']}")
                
                # Get capabilities
                capabilities = self.interface_manager.get_interface_capabilities(iface['device'])
                print(f"   Возможности / Capabilities:")
                print(f"     Monitor Mode: {'✓' if capabilities['monitor_mode'] else '✗'}")
                print(f"     Active: {'✓' if capabilities['active'] else '✗'}")
                print()
            
            # Interface management submenu
            while True:
                print("\nОпции управления / Management Options:")
                print("1. Подробная информация об интерфейсе / Detailed interface info")
                print("2. Проверить статус интерфейса / Check interface status")
                print("3. Режим мониторинга (требует sudo) / Monitor mode (requires sudo)")
                print("4. Восстановить обычный режим / Restore managed mode")
                print("5. Очистить интерфейс / Cleanup interface")
                print("0. Назад / Back")
                
                choice = input("\nВыберите опцию / Select option: ").strip()
                
                if choice == "0":
                    break
                elif choice == "1":
                    self._show_interface_details(interfaces)
                elif choice == "2":
                    self._check_interface_status(interfaces)
                elif choice == "3":
                    self._set_monitor_mode(interfaces)
                elif choice == "4":
                    self._restore_managed_mode(interfaces)
                elif choice == "5":
                    self._cleanup_interface(interfaces)
                else:
                    print("Неверный выбор / Invalid choice")
                
                input("\nНажмите Enter для продолжения / Press Enter to continue...")
                
        except Exception as e:
            self.logger.error(f"Interface management error: {e}")
            print(f"Ошибка управления интерфейсами / Interface management error: {e}")
            input("\nНажмите Enter для продолжения / Press Enter to continue...")
    
    def _show_interface_details(self, interfaces):
        """Show detailed interface information"""
        if not interfaces:
            return
        
        print("\nВыберите интерфейс / Select interface:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface['device']}")
        
        try:
            choice = int(input("Номер интерфейса / Interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                device = interfaces[choice]['device']
                status = self.interface_manager.validate_interface_status(device)
                
                print(f"\nПодробная информация для {device} / Detailed info for {device}:")
                print("-" * 40)
                print(f"Существует / Exists: {status['exists']}")
                print(f"Активен / Active: {status['active']}")
                print(f"Подключен / Connected: {status['connected']}")
                print(f"Режим / Mode: {status['mode']}")
                
                if status['ssid']:
                    print(f"SSID: {status['ssid']}")
                if status['channel']:
                    print(f"Канал / Channel: {status['channel']}")
                if status['signal_strength']:
                    print(f"Сигнал / Signal: {status['signal_strength']} dBm")
                
                if status['issues']:
                    print("\nПроблемы / Issues:")
                    for issue in status['issues']:
                        print(f"  - {issue}")
                
                if status['recommendations']:
                    print("\nРекомендации / Recommendations:")
                    for rec in status['recommendations']:
                        print(f"  - {rec}")
            else:
                print("Неверный номер / Invalid number")
        except ValueError:
            print("Неверный ввод / Invalid input")
    
    def _check_interface_status(self, interfaces):
        """Check status of all interfaces"""
        print("\nСтатус всех интерфейсов / Status of all interfaces:")
        print("-" * 50)
        
        for iface in interfaces:
            device = iface['device']
            current_mode = self.interface_manager.get_current_mode(device)
            print(f"{device}: {current_mode}")
    
    def _set_monitor_mode(self, interfaces):
        """Set interface to monitor mode"""
        if not interfaces:
            return
        
        print("\nВНИМАНИЕ: Требуются права администратора!")
        print("WARNING: Administrator privileges required!")
        print("\nВыберите интерфейс / Select interface:")
        
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface['device']}")
        
        try:
            choice = int(input("Номер интерфейса / Interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                device = interfaces[choice]['device']
                
                confirm = input(f"Активировать режим мониторинга для {device}? (y/N): ")
                if confirm.lower() in ['y', 'yes', 'да']:
                    print("Активация режима мониторинга... / Activating monitor mode...")
                    success, message = self.interface_manager.set_monitor_mode(device)
                    
                    if success:
                        print(f"✓ {message}")
                    else:
                        print(f"✗ {message}")
                else:
                    print("Отменено / Cancelled")
            else:
                print("Неверный номер / Invalid number")
        except ValueError:
            print("Неверный ввод / Invalid input")
    
    def _restore_managed_mode(self, interfaces):
        """Restore interface to managed mode"""
        if not interfaces:
            return
        
        print("\nВыберите интерфейс / Select interface:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface['device']}")
        
        try:
            choice = int(input("Номер интерфейса / Interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                device = interfaces[choice]['device']
                
                print("Восстановление обычного режима... / Restoring managed mode...")
                success, message = self.interface_manager.restore_managed_mode(device)
                
                if success:
                    print(f"✓ {message}")
                else:
                    print(f"✗ {message}")
            else:
                print("Неверный номер / Invalid number")
        except ValueError:
            print("Неверный ввод / Invalid input")
    
    def _cleanup_interface(self, interfaces):
        """Cleanup interface"""
        if not interfaces:
            return
        
        print("\nВыберите интерфейс / Select interface:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface['device']}")
        
        try:
            choice = int(input("Номер интерфейса / Interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                device = interfaces[choice]['device']
                
                print("Очистка интерфейса... / Cleaning up interface...")
                success, message = self.interface_manager.cleanup_interface(device)
                
                if success:
                    print(f"✓ {message}")
                else:
                    print(f"✗ {message}")
            else:
                print("Неверный номер / Invalid number")
        except ValueError:
            print("Неверный ввод / Invalid input")
    
    def _wordlist_management_handler(self):
        """Handle wordlist management menu option"""
        print("\n" + "="*60)
        print("           Управление словарями / Wordlist Management")
        print("="*60)
        
        try:
            while True:
                print("\nОпции управления словарями / Wordlist Management Options:")
                print("1. Показать доступные словари / Show available wordlists")
                print("2. Создать встроенный словарь / Create built-in wordlist")
                print("3. Создать пользовательский словарь / Create custom wordlist")
                print("4. Импортировать словарь / Import wordlist")
                print("5. Объединить словари / Combine wordlists")
                print("6. Анализировать словарь / Analyze wordlist")
                print("7. Оптимизировать словарь / Optimize wordlist")
                print("0. Назад / Back")
                
                choice = input("\nВыберите опцию / Select option: ").strip()
                
                if choice == "0":
                    break
                elif choice == "1":
                    self._show_available_wordlists()
                elif choice == "2":
                    self._create_builtin_wordlist()
                elif choice == "3":
                    self._create_custom_wordlist()
                elif choice == "4":
                    self._import_wordlist()
                elif choice == "5":
                    self._combine_wordlists()
                elif choice == "6":
                    self._analyze_wordlist()
                elif choice == "7":
                    self._optimize_wordlist()
                else:
                    print("Неверный выбор / Invalid choice")
                
                input("\nНажмите Enter для продолжения / Press Enter to continue...")
                
        except Exception as e:
            self.logger.error(f"Wordlist management error: {e}")
            print(f"Ошибка управления словарями / Wordlist management error: {e}")
            input("\nНажмите Enter для продолжения / Press Enter to continue...")
    
    def _show_available_wordlists(self):
        """Show available wordlists"""
        print("\nДоступные словари / Available Wordlists:")
        print("-" * 50)
        
        try:
            wordlists = self.wordlist_manager.get_available_wordlists()
            
            if not wordlists:
                print("Словари не найдены / No wordlists found")
                return
            
            # Group by type
            builtin_wordlists = {k: v for k, v in wordlists.items() if v.get('type') == 'builtin'}
            custom_wordlists = {k: v for k, v in wordlists.items() if v.get('type') == 'custom'}
            
            # Show built-in wordlists
            if builtin_wordlists:
                print("\n📚 Встроенные словари / Built-in Wordlists:")
                for name, info in builtin_wordlists.items():
                    category = info.get('category', 'unknown')
                    description = info.get('description', 'No description')
                    estimated_size = info.get('estimated_size', 0)
                    print(f"  • {category}: {description}")
                    print(f"    Примерный размер / Estimated size: {estimated_size} паролей / passwords")
            
            # Show custom wordlists
            if custom_wordlists:
                print("\n📝 Пользовательские словари / Custom Wordlists:")
                for name, info in custom_wordlists.items():
                    path = info.get('path', 'Unknown path')
                    password_count = info.get('password_count', 0)
                    size_formatted = info.get('size_formatted', 'Unknown size')
                    modified = info.get('modified', 'Unknown date')
                    
                    print(f"  • {name}")
                    print(f"    Путь / Path: {path}")
                    print(f"    Паролей / Passwords: {password_count:,}")
                    print(f"    Размер / Size: {size_formatted}")
                    print(f"    Изменен / Modified: {modified}")
                    print()
            
            print(f"\nВсего словарей / Total wordlists: {len(wordlists)}")
            
        except Exception as e:
            self.logger.error(f"Error showing wordlists: {e}")
            print(f"Ошибка отображения словарей / Error showing wordlists: {e}")
    
    def _create_builtin_wordlist(self):
        """Create built-in wordlist"""
        print("\nСоздание встроенного словаря / Creating Built-in Wordlist")
        print("-" * 50)
        
        try:
            # Show available categories
            categories = self.wordlist_manager.builtin_categories
            print("\nДоступные категории / Available Categories:")
            
            category_list = list(categories.keys())
            for i, (category, description) in enumerate(categories.items(), 1):
                print(f"{i}. {category}: {description}")
            
            # Get user choice
            try:
                choice = int(input("\nВыберите категорию / Select category (number): ")) - 1
                if 0 <= choice < len(category_list):
                    selected_category = category_list[choice]
                    
                    # Generate wordlist
                    print(f"\nГенерация словаря для категории '{selected_category}'...")
                    print(f"Generating wordlist for category '{selected_category}'...")
                    
                    passwords = self.wordlist_manager.generate_builtin_wordlist(selected_category)
                    
                    if not passwords:
                        print("Не удалось сгенерировать пароли / Failed to generate passwords")
                        return
                    
                    # Create wordlist file
                    wordlist_name = f"builtin_{selected_category}"
                    description = f"Built-in {selected_category} passwords"
                    
                    success, result = self.wordlist_manager.create_custom_wordlist(
                        wordlist_name, passwords, description
                    )
                    
                    if success:
                        print(f"✓ Словарь создан / Wordlist created: {result}")
                        print(f"  Паролей / Passwords: {len(passwords):,}")
                    else:
                        print(f"✗ Ошибка создания словаря / Error creating wordlist: {result}")
                else:
                    print("Неверный номер / Invalid number")
            except ValueError:
                print("Неверный ввод / Invalid input")
                
        except Exception as e:
            self.logger.error(f"Error creating built-in wordlist: {e}")
            print(f"Ошибка создания встроенного словаря / Error creating built-in wordlist: {e}")
    
    def _create_custom_wordlist(self):
        """Create custom wordlist"""
        print("\nСоздание пользовательского словаря / Creating Custom Wordlist")
        print("-" * 50)
        
        try:
            # Get wordlist name
            name = input("Имя словаря / Wordlist name: ").strip()
            if not name:
                print("Имя обязательно / Name is required")
                return
            
            description = input("Описание (опционально) / Description (optional): ").strip()
            
            print("\nВведите пароли (по одному на строку, пустая строка для завершения):")
            print("Enter passwords (one per line, empty line to finish):")
            
            passwords = []
            while True:
                password = input("Пароль / Password: ").strip()
                if not password:
                    break
                passwords.append(password)
                print(f"  Добавлено / Added: {len(passwords)} паролей / passwords")
            
            if not passwords:
                print("Пароли не введены / No passwords entered")
                return
            
            # Create wordlist
            print(f"\nСоздание словаря с {len(passwords)} паролями...")
            print(f"Creating wordlist with {len(passwords)} passwords...")
            
            success, result = self.wordlist_manager.create_custom_wordlist(
                name, passwords, description
            )
            
            if success:
                print(f"✓ Пользовательский словарь создан / Custom wordlist created: {result}")
            else:
                print(f"✗ Ошибка создания словаря / Error creating wordlist: {result}")
                
        except Exception as e:
            self.logger.error(f"Error creating custom wordlist: {e}")
            print(f"Ошибка создания пользовательского словаря / Error creating custom wordlist: {e}")
    
    def _import_wordlist(self):
        """Import wordlist from file"""
        print("\nИмпорт словаря / Import Wordlist")
        print("-" * 50)
        
        try:
            file_path = input("Путь к файлу словаря / Path to wordlist file: ").strip()
            if not file_path:
                print("Путь к файлу обязателен / File path is required")
                return
            
            validate_choice = input("Валидировать пароли? (y/N) / Validate passwords? (y/N): ").strip().lower()
            validate = validate_choice in ['y', 'yes', 'да']
            
            print(f"\nИмпорт словаря из {file_path}...")
            print(f"Importing wordlist from {file_path}...")
            
            success, message, password_count = self.wordlist_manager.import_wordlist(
                file_path, validate
            )
            
            if success:
                print(f"✓ {message}")
                print(f"  Импортировано паролей / Imported passwords: {password_count:,}")
            else:
                print(f"✗ Ошибка импорта / Import error: {message}")
                
        except Exception as e:
            self.logger.error(f"Error importing wordlist: {e}")
            print(f"Ошибка импорта словаря / Error importing wordlist: {e}")
    
    def _combine_wordlists(self):
        """Combine multiple wordlists"""
        print("\nОбъединение словарей / Combine Wordlists")
        print("-" * 50)
        
        try:
            # Show available wordlists
            wordlists = self.wordlist_manager.get_available_wordlists()
            if not wordlists:
                print("Нет доступных словарей / No available wordlists")
                return
            
            print("\nДоступные словари / Available wordlists:")
            wordlist_names = list(wordlists.keys())
            for i, name in enumerate(wordlist_names, 1):
                info = wordlists[name]
                if info.get('type') == 'builtin':
                    print(f"{i}. {name} (встроенный / built-in)")
                else:
                    count = info.get('password_count', 0)
                    print(f"{i}. {name} ({count:,} паролей / passwords)")
            
            # Get wordlists to combine
            print("\nВыберите словари для объединения (номера через запятую):")
            print("Select wordlists to combine (numbers separated by commas):")
            
            selection = input("Номера / Numbers: ").strip()
            if not selection:
                print("Выбор не сделан / No selection made")
                return
            
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_wordlists = []
                
                for idx in indices:
                    if 0 <= idx < len(wordlist_names):
                        selected_wordlists.append(wordlist_names[idx])
                    else:
                        print(f"Неверный номер: {idx + 1} / Invalid number: {idx + 1}")
                        return
                
                if len(selected_wordlists) < 2:
                    print("Выберите минимум 2 словаря / Select at least 2 wordlists")
                    return
                
                # Get combined wordlist name
                combined_name = input("Имя объединенного словаря / Combined wordlist name: ").strip()
                if not combined_name:
                    print("Имя обязательно / Name is required")
                    return
                
                # Ask about duplicate removal
                remove_dupes = input("Удалить дубликаты? (Y/n) / Remove duplicates? (Y/n): ").strip().lower()
                remove_duplicates = remove_dupes not in ['n', 'no', 'нет']
                
                print(f"\nОбъединение {len(selected_wordlists)} словарей...")
                print(f"Combining {len(selected_wordlists)} wordlists...")
                
                success, result = self.wordlist_manager.create_combined_wordlist(
                    combined_name, selected_wordlists, remove_duplicates
                )
                
                if success:
                    print(f"✓ Объединенный словарь создан / Combined wordlist created: {result}")
                else:
                    print(f"✗ Ошибка объединения / Combination error: {result}")
                    
            except ValueError:
                print("Неверный формат номеров / Invalid number format")
                
        except Exception as e:
            self.logger.error(f"Error combining wordlists: {e}")
            print(f"Ошибка объединения словарей / Error combining wordlists: {e}")
    
    def _analyze_wordlist(self):
        """Analyze wordlist"""
        print("\nАнализ словаря / Analyze Wordlist")
        print("-" * 50)
        
        try:
            # Show available custom wordlists
            wordlists = self.wordlist_manager.get_available_wordlists()
            custom_wordlists = {k: v for k, v in wordlists.items() if v.get('type') == 'custom'}
            
            if not custom_wordlists:
                print("Нет пользовательских словарей для анализа / No custom wordlists to analyze")
                return
            
            print("\nДоступные словари / Available wordlists:")
            wordlist_names = list(custom_wordlists.keys())
            for i, name in enumerate(wordlist_names, 1):
                info = custom_wordlists[name]
                count = info.get('password_count', 0)
                size = info.get('size_formatted', 'Unknown')
                print(f"{i}. {name} ({count:,} паролей / passwords, {size})")
            
            try:
                choice = int(input("\nВыберите словарь / Select wordlist (number): ")) - 1
                if 0 <= choice < len(wordlist_names):
                    selected_name = wordlist_names[choice]
                    wordlist_path = custom_wordlists[selected_name]['path']
                    
                    print(f"\nАнализ словаря {selected_name}...")
                    print(f"Analyzing wordlist {selected_name}...")
                    
                    analysis = self.wordlist_manager.analyze_wordlist_size(wordlist_path)
                    
                    if 'error' in analysis:
                        print(f"✗ Ошибка анализа / Analysis error: {analysis['error']}")
                        return
                    
                    # Display analysis results
                    print("\n" + "="*50)
                    print("РЕЗУЛЬТАТЫ АНАЛИЗА / ANALYSIS RESULTS")
                    print("="*50)
                    
                    print(f"Файл / File: {wordlist_path}")
                    print(f"Размер файла / File size: {analysis.get('file_size_formatted', 'Unknown')}")
                    print(f"Всего паролей / Total passwords: {analysis.get('password_count', 0):,}")
                    
                    if 'average_length' in analysis:
                        print(f"Средняя длина / Average length: {analysis['average_length']:.1f} символов / characters")
                    
                    if 'length_distribution' in analysis:
                        print("\nРаспределение по длине / Length Distribution:")
                        for length, count in sorted(analysis['length_distribution'].items()):
                            percentage = (count / analysis.get('password_count', 1)) * 100
                            print(f"  {length} символов / chars: {count:,} ({percentage:.1f}%)")
                    
                    if 'charset_analysis' in analysis:
                        print("\nАнализ символов / Character Analysis:")
                        charset = analysis['charset_analysis']
                        total = analysis.get('password_count', 1)
                        for char_type, count in charset.items():
                            percentage = (count / total) * 100
                            print(f"  {char_type}: {count:,} ({percentage:.1f}%)")
                    
                    if 'warnings' in analysis and analysis['warnings']:
                        print("\n⚠️  ПРЕДУПРЕЖДЕНИЯ / WARNINGS:")
                        for warning in analysis['warnings']:
                            print(f"  • {warning}")
                    
                    if 'recommendations' in analysis and analysis['recommendations']:
                        print("\n💡 РЕКОМЕНДАЦИИ / RECOMMENDATIONS:")
                        for rec in analysis['recommendations']:
                            print(f"  • {rec}")
                else:
                    print("Неверный номер / Invalid number")
            except ValueError:
                print("Неверный ввод / Invalid input")
                
        except Exception as e:
            self.logger.error(f"Error analyzing wordlist: {e}")
            print(f"Ошибка анализа словаря / Error analyzing wordlist: {e}")
    
    def _optimize_wordlist(self):
        """Optimize wordlist"""
        print("\nОптимизация словаря / Optimize Wordlist")
        print("-" * 50)
        
        try:
            # Show available custom wordlists
            wordlists = self.wordlist_manager.get_available_wordlists()
            custom_wordlists = {k: v for k, v in wordlists.items() if v.get('type') == 'custom'}
            
            if not custom_wordlists:
                print("Нет пользовательских словарей для оптимизации / No custom wordlists to optimize")
                return
            
            print("\nДоступные словари / Available wordlists:")
            wordlist_names = list(custom_wordlists.keys())
            for i, name in enumerate(wordlist_names, 1):
                info = custom_wordlists[name]
                count = info.get('password_count', 0)
                size = info.get('size_formatted', 'Unknown')
                print(f"{i}. {name} ({count:,} паролей / passwords, {size})")
            
            try:
                choice = int(input("\nВыберите словарь / Select wordlist (number): ")) - 1
                if 0 <= choice < len(wordlist_names):
                    selected_name = wordlist_names[choice]
                    wordlist_path = custom_wordlists[selected_name]['path']
                    
                    print(f"\n⚠️  ВНИМАНИЕ: Оптимизация изменит файл словаря!")
                    print(f"⚠️  WARNING: Optimization will modify the wordlist file!")
                    print(f"Будет создана резервная копия с расширением .bak")
                    print(f"A backup will be created with .bak extension")
                    
                    confirm = input(f"\nПродолжить оптимизацию {selected_name}? (y/N): ").strip().lower()
                    if confirm not in ['y', 'yes', 'да']:
                        print("Оптимизация отменена / Optimization cancelled")
                        return
                    
                    print(f"\nОптимизация словаря {selected_name}...")
                    print(f"Optimizing wordlist {selected_name}...")
                    
                    success, message, stats = self.wordlist_manager.optimize_wordlist(wordlist_path)
                    
                    if success:
                        print(f"✓ {message}")
                        if stats:
                            print("\nСтатистика оптимизации / Optimization Statistics:")
                            print(f"  Исходное количество / Original count: {stats.get('original_count', 0):,}")
                            print(f"  Оптимизированное количество / Optimized count: {stats.get('optimized_count', 0):,}")
                            print(f"  Удалено дубликатов / Duplicates removed: {stats.get('duplicates_removed', 0):,}")
                            print(f"  Уменьшение размера / Size reduction: {stats.get('size_reduction_percent', 0):.1f}%")
                    else:
                        print(f"✗ Ошибка оптимизации / Optimization error: {message}")
                else:
                    print("Неверный номер / Invalid number")
            except ValueError:
                print("Неверный ввод / Invalid input")
                
        except Exception as e:
            self.logger.error(f"Error optimizing wordlist: {e}")
            print(f"Ошибка оптимизации словаря / Error optimizing wordlist: {e}")
    
    def _exit_handler(self):
        """Handle exit menu option"""
        print("\nЗавершение работы...")
        print("Shutting down...")
        self.running = False
    
    def display_header(self):
        """Display application header"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print("="*70)
        print("           WiFi Security Test Tool - macOS Edition")
        print("="*70)
        print("ВНИМАНИЕ: Используйте только для тестирования собственных сетей!")
        print("WARNING: Use only for testing your own networks!")
        print("="*70)
    
    def display_menu(self):
        """Display main menu options"""
        print("\nДоступные опции / Available Options:")
        print("-" * 40)
        
        for key, item in self.menu_items.items():
            print(f"{key}. {item['title']}")
            print(f"   {item['description']}")
            print()
    
    def get_user_choice(self) -> Optional[str]:
        """Get and validate user menu choice"""
        try:
            choice = input("Выберите опцию / Select option: ").strip()
            if choice in self.menu_items:
                return choice
            else:
                print(f"\nНеверный выбор: {choice}")
                print(f"Invalid choice: {choice}")
                return None
        except (EOFError, KeyboardInterrupt):
            return "0"  # Exit on Ctrl+C or EOF
    
    def execute_choice(self, choice: str):
        """Execute the selected menu option"""
        try:
            handler = self.menu_items[choice]["handler"]
            self.logger.info(f"Executing menu option: {choice}")
            handler()
        except Exception as e:
            self.logger.error(f"Error executing menu option {choice}: {e}")
            print(f"\nОшибка выполнения: {e}")
            print(f"Execution error: {e}")
            input("\nНажмите Enter для продолжения / Press Enter to continue...")
    
    def run(self):
        """Main menu loop"""
        self.logger.info("Menu system started")
        
        while self.running:
            try:
                self.display_header()
                self.display_menu()
                
                choice = self.get_user_choice()
                if choice:
                    self.execute_choice(choice)
                else:
                    input("\nНажмите Enter для продолжения / Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nПрограмма прервана пользователем.")
                print("Program interrupted by user.")
                break
            except Exception as e:
                self.logger.error(f"Menu system error: {e}")
                print(f"\nОшибка системы меню: {e}")
                print(f"Menu system error: {e}")
                input("\nНажмите Enter для продолжения / Press Enter to continue...")
        
        self.logger.info("Menu system stopped")
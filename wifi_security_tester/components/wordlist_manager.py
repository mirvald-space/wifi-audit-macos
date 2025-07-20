"""
Wordlist Manager - Manages password wordlists for WiFi security testing
Handles creation, import, validation, and optimization of password dictionaries

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import os
import sys
import hashlib
import time
from typing import List, Dict, Set, Tuple, Optional, Union
from pathlib import Path
import re

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.logger import get_logger
from utils.common import ensure_directory, validate_file_path, format_bytes


class WordlistManager:
    """Manages password wordlists for WiFi security testing"""
    
    def __init__(self):
        self.logger = get_logger("wordlist_manager")
        self.base_dir = Path(__file__).parent.parent
        self.wordlists_dir = self.base_dir / "wordlists"
        self.ensure_wordlists_directory()
        
        # Built-in wordlist categories
        self.builtin_categories = {
            'common': 'Most common WiFi passwords',
            'numeric': 'Numeric patterns and sequences',
            'keyboard': 'Keyboard patterns and combinations',
            'dates': 'Date-based passwords',
            'names': 'Common names and words',
            'wifi_specific': 'WiFi-specific common passwords'
        }
        
        # Performance thresholds
        self.max_wordlist_size = 10_000_000  # 10M passwords max
        self.warning_size = 1_000_000  # 1M passwords warning
        
    def ensure_wordlists_directory(self) -> None:
        """Ensure wordlists directory exists"""
        try:
            ensure_directory(self.wordlists_dir)
            self.logger.info(f"Wordlists directory: {self.wordlists_dir}")
        except Exception as e:
            self.logger.error(f"Error creating wordlists directory: {e}")
            raise
    
    def generate_builtin_wordlist(self, category: str) -> List[str]:
        """
        Generate built-in password dictionary for specified category
        
        Args:
            category (str): Category of passwords to generate
            
        Returns:
            List[str]: List of passwords for the category
        """
        try:
            if category not in self.builtin_categories:
                raise ValueError(f"Unknown category: {category}")
            
            self.logger.info(f"Generating built-in wordlist for category: {category}")
            
            if category == 'common':
                return self._generate_common_passwords()
            elif category == 'numeric':
                return self._generate_numeric_passwords()
            elif category == 'keyboard':
                return self._generate_keyboard_patterns()
            elif category == 'dates':
                return self._generate_date_passwords()
            elif category == 'names':
                return self._generate_name_passwords()
            elif category == 'wifi_specific':
                return self._generate_wifi_specific_passwords()
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Error generating built-in wordlist for {category}: {e}")
            return []
    
    def _generate_common_passwords(self) -> List[str]:
        """Generate most common WiFi passwords"""
        common_passwords = [
            # Basic common passwords
            'password', 'password123', 'password1', 'password12',
            '12345678', '123456789', '1234567890', '87654321',
            'qwertyuiop', 'qwerty123', 'qwerty', 'asdfghjkl',
            'admin', 'admin123', 'administrator', 'root',
            'welcome', 'welcome123', 'guest', 'user',
            'default', 'letmein', 'changeme', 'secret',
            
            # WiFi router defaults
            'admin', 'password', 'admin123', 'root',
            '1234', '0000', '1111', '2222', '3333',
            '4444', '5555', '6666', '7777', '8888', '9999',
            
            # Common variations
            '123123123', '12341234', '1q2w3e4r', '1q2w3e',
            'abc123', '123abc', 'test123', 'pass123',
            'wifi', 'internet', 'network', 'wireless',
            
            # Simple patterns
            '00000000', '11111111', '22222222', '33333333',
            '44444444', '55555555', '66666666', '77777777',
            '88888888', '99999999', '12121212', '21212121'
        ]
        
        return common_passwords
    
    def _generate_numeric_passwords(self) -> List[str]:
        """Generate numeric password patterns"""
        numeric_passwords = []
        
        # Sequential numbers
        for length in range(8, 13):  # 8-12 digit sequences
            for start in range(0, 10):
                sequence = ''.join(str((start + i) % 10) for i in range(length))
                numeric_passwords.append(sequence)
        
        # Repeated digits
        for digit in range(10):
            for length in range(8, 13):
                numeric_passwords.append(str(digit) * length)
        
        # Common numeric patterns
        patterns = [
            '01234567', '12345678', '23456789', '34567890',
            '87654321', '98765432', '09876543', '10987654',
            '13579246', '24681357', '97531864', '86420975'
        ]
        
        # Extend patterns to different lengths
        for pattern in patterns:
            numeric_passwords.append(pattern)
            if len(pattern) < 12:
                # Extend pattern
                extended = pattern + pattern[:12-len(pattern)]
                numeric_passwords.append(extended)
        
        # Phone number patterns (area codes + numbers)
        common_area_codes = ['123', '456', '789', '555', '800', '888', '999']
        for area_code in common_area_codes:
            for suffix in ['1234', '5678', '9999', '0000', '1111']:
                numeric_passwords.append(area_code + suffix + '1')
                numeric_passwords.append(area_code + suffix + '12')
        
        return list(set(numeric_passwords))  # Remove duplicates
    
    def _generate_keyboard_patterns(self) -> List[str]:
        """Generate keyboard pattern passwords"""
        keyboard_patterns = []
        
        # QWERTY rows
        qwerty_rows = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]
        
        # Generate patterns from keyboard rows
        for row in qwerty_rows:
            # Forward patterns
            for start in range(len(row) - 7):
                for length in range(8, min(len(row) - start + 1, 13)):
                    pattern = row[start:start + length]
                    keyboard_patterns.append(pattern)
                    keyboard_patterns.append(pattern.upper())
                    keyboard_patterns.append(pattern.capitalize())
            
            # Reverse patterns
            reversed_row = row[::-1]
            for start in range(len(reversed_row) - 7):
                for length in range(8, min(len(reversed_row) - start + 1, 13)):
                    pattern = reversed_row[start:start + length]
                    keyboard_patterns.append(pattern)
                    keyboard_patterns.append(pattern.upper())
        
        # Number row patterns
        number_row = '1234567890'
        for start in range(len(number_row) - 7):
            for length in range(8, len(number_row) - start + 1):
                pattern = number_row[start:start + length]
                keyboard_patterns.append(pattern)
        
        # Mixed patterns
        mixed_patterns = [
            'qwerty123', 'qwerty12', 'qwerty1',
            'asdf1234', 'asdf123', 'zxcv1234',
            '1qaz2wsx', '1q2w3e4r', '1q2w3e',
            'q1w2e3r4', 'a1s2d3f4', 'z1x2c3v4'
        ]
        
        keyboard_patterns.extend(mixed_patterns)
        
        return list(set(keyboard_patterns))  # Remove duplicates
    
    def _generate_date_passwords(self) -> List[str]:
        """Generate date-based passwords"""
        date_passwords = []
        
        # Years
        current_year = time.localtime().tm_year
        years = list(range(1990, current_year + 1))
        
        # Common date formats
        for year in years:
            year_str = str(year)
            
            # Year-based patterns
            date_passwords.append(year_str)
            date_passwords.append(year_str + '1234')
            date_passwords.append('password' + year_str)
            
            # Month/day combinations with year
            for month in range(1, 13):
                month_str = f"{month:02d}"
                for day in [1, 15, 31]:
                    day_str = f"{day:02d}"
                    
                    # Various date formats
                    date_passwords.append(f"{day_str}{month_str}{year_str}")
                    date_passwords.append(f"{month_str}{day_str}{year_str}")
                    date_passwords.append(f"{year_str}{month_str}{day_str}")
                    
                    # Short year
                    short_year = year_str[-2:]
                    date_passwords.append(f"{day_str}{month_str}{short_year}")
                    date_passwords.append(f"{month_str}{day_str}{short_year}")
        
        # Special dates
        special_dates = [
            '01011990', '01011991', '01011992', '01011993', '01011994',
            '01011995', '01011996', '01011997', '01011998', '01011999',
            '01012000', '01012001', '01012002', '01012003', '01012004',
            '01012005', '01012006', '01012007', '01012008', '01012009',
            '01012010', '01012011', '01012012', '01012013', '01012014',
            '01012015', '01012016', '01012017', '01012018', '01012019',
            '01012020', '01012021', '01012022', '01012023', '01012024'
        ]
        
        date_passwords.extend(special_dates)
        
        return list(set(date_passwords))  # Remove duplicates
    
    def _generate_name_passwords(self) -> List[str]:
        """Generate name-based passwords"""
        name_passwords = []
        
        # Common first names
        common_names = [
            'john', 'jane', 'mike', 'mary', 'david', 'sarah',
            'chris', 'lisa', 'mark', 'anna', 'paul', 'emma',
            'alex', 'kate', 'tom', 'amy', 'dan', 'sue',
            'bob', 'jen', 'tim', 'kim', 'joe', 'ann'
        ]
        
        # Common last names
        common_surnames = [
            'smith', 'johnson', 'brown', 'davis', 'miller',
            'wilson', 'moore', 'taylor', 'anderson', 'thomas',
            'jackson', 'white', 'harris', 'martin', 'garcia'
        ]
        
        # Generate name combinations
        for name in common_names:
            # Name with numbers
            for num in ['1', '12', '123', '1234', '01', '001']:
                name_passwords.append(name + num)
                name_passwords.append(name.capitalize() + num)
            
            # Name with years
            for year in ['2020', '2021', '2022', '2023', '2024']:
                name_passwords.append(name + year)
                name_passwords.append(name.capitalize() + year)
        
        # Full names
        for first in common_names[:10]:  # Limit combinations
            for last in common_surnames[:10]:
                name_passwords.append(first + last)
                name_passwords.append(first.capitalize() + last.capitalize())
                name_passwords.append(first + last + '1')
                name_passwords.append(first + last + '123')
        
        return list(set(name_passwords))  # Remove duplicates
    
    def _generate_wifi_specific_passwords(self) -> List[str]:
        """Generate WiFi-specific common passwords"""
        wifi_passwords = [
            # Router brand defaults
            'admin', 'password', 'admin123', 'root', 'user',
            'netgear', 'linksys', 'dlink', 'tplink', 'asus',
            'belkin', 'cisco', 'motorola', 'arris', 'technicolor',
            
            # WiFi-related terms
            'wifi', 'wireless', 'internet', 'network', 'router',
            'modem', 'broadband', 'connection', 'access', 'guest',
            
            # Common WiFi passwords
            'wifi123', 'wireless123', 'internet123', 'network123',
            'password123', 'welcome123', 'guest123', 'admin123',
            
            # ISP defaults
            'comcast', 'verizon', 'att', 'spectrum', 'xfinity',
            'optimum', 'cox', 'charter', 'frontier', 'centurylink',
            
            # Default patterns
            'homeWiFi', 'MyWiFi', 'HomeNetwork', 'FamilyWiFi',
            'GuestWiFi', 'OfficeWiFi', 'WiFiPassword', 'NetworkKey',
            
            # Security-related
            'wpa2key', 'wpakey', 'networkkey', 'securekey',
            'passphrase', 'accesskey', 'wifikey', 'routerkey'
        ]
        
        # Add variations with numbers
        base_passwords = wifi_passwords.copy()
        for password in base_passwords:
            for num in ['1', '12', '123', '2024']:
                wifi_passwords.append(password + num)
        
        return list(set(wifi_passwords))  # Remove duplicates 
   
    def create_custom_wordlist(self, name: str, passwords: List[str], 
                              description: str = "") -> Tuple[bool, str]:
        """
        Create a custom wordlist from provided passwords
        
        Args:
            name (str): Name for the wordlist file
            passwords (List[str]): List of passwords
            description (str): Optional description
            
        Returns:
            Tuple[bool, str]: (success, message_or_path)
        """
        try:
            if not name or not passwords:
                return False, "Name and passwords are required"
            
            # Sanitize filename
            safe_name = re.sub(r'[^\w\-_.]', '_', name)
            if not safe_name.endswith('.txt'):
                safe_name += '.txt'
            
            wordlist_path = self.wordlists_dir / safe_name
            
            # Validate and clean passwords
            valid_passwords = self._validate_passwords(passwords)
            if not valid_passwords:
                return False, "No valid passwords provided"
            
            # Remove duplicates while preserving order
            unique_passwords = list(dict.fromkeys(valid_passwords))
            
            self.logger.info(f"Creating custom wordlist: {safe_name} with {len(unique_passwords)} passwords")
            
            # Write wordlist file
            with open(wordlist_path, 'w', encoding='utf-8') as f:
                if description:
                    f.write(f"# {description}\n")
                    f.write(f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total passwords: {len(unique_passwords)}\n\n")
                
                for password in unique_passwords:
                    f.write(f"{password}\n")
            
            success_msg = f"Custom wordlist created: {wordlist_path} ({len(unique_passwords)} passwords)"
            self.logger.info(success_msg)
            return True, str(wordlist_path)
            
        except Exception as e:
            error_msg = f"Error creating custom wordlist: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def import_wordlist(self, file_path: str, validate: bool = True) -> Tuple[bool, str, int]:
        """
        Import wordlist from external file
        
        Args:
            file_path (str): Path to wordlist file
            validate (bool): Whether to validate passwords
            
        Returns:
            Tuple[bool, str, int]: (success, message, password_count)
        """
        try:
            if not validate_file_path(file_path):
                return False, f"File not found or not readable: {file_path}", 0
            
            source_path = Path(file_path)
            self.logger.info(f"Importing wordlist from: {source_path}")
            
            # Read passwords from file
            passwords = []
            with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    passwords.append(line)
                    
                    # Check size limits
                    if len(passwords) > self.max_wordlist_size:
                        self.logger.warning(f"Wordlist too large, truncating at {self.max_wordlist_size} passwords")
                        break
            
            if not passwords:
                return False, "No valid passwords found in file", 0
            
            # Validate passwords if requested
            if validate:
                valid_passwords = self._validate_passwords(passwords)
                invalid_count = len(passwords) - len(valid_passwords)
                if invalid_count > 0:
                    self.logger.warning(f"Filtered out {invalid_count} invalid passwords")
                passwords = valid_passwords
            
            if not passwords:
                return False, "No valid passwords after validation", 0
            
            # Create imported wordlist
            imported_name = f"imported_{source_path.stem}"
            success, result_path = self.create_custom_wordlist(
                imported_name, 
                passwords,
                f"Imported from {source_path.name}"
            )
            
            if success:
                success_msg = f"Imported {len(passwords)} passwords from {source_path.name}"
                self.logger.info(success_msg)
                return True, success_msg, len(passwords)
            else:
                return False, f"Failed to create imported wordlist: {result_path}", 0
                
        except Exception as e:
            error_msg = f"Error importing wordlist: {e}"
            self.logger.error(error_msg)
            return False, error_msg, 0
    
    def _validate_passwords(self, passwords: List[str]) -> List[str]:
        """
        Validate and filter password list
        
        Args:
            passwords (List[str]): List of passwords to validate
            
        Returns:
            List[str]: List of valid passwords
        """
        valid_passwords = []
        
        for password in passwords:
            if not isinstance(password, str):
                continue
            
            # Clean password
            clean_password = password.strip()
            
            # Skip empty passwords
            if not clean_password:
                continue
            
            # Length validation (WiFi passwords typically 8-63 characters)
            if len(clean_password) < 8 or len(clean_password) > 63:
                continue
            
            # Character validation (printable ASCII)
            if not all(32 <= ord(c) <= 126 for c in clean_password):
                continue
            
            valid_passwords.append(clean_password)
        
        return valid_passwords
    
    def optimize_wordlist(self, wordlist_path: str) -> Tuple[bool, str, Dict[str, int]]:
        """
        Optimize wordlist for performance by removing duplicates and sorting
        
        Args:
            wordlist_path (str): Path to wordlist file
            
        Returns:
            Tuple[bool, str, Dict[str, int]]: (success, message, stats)
        """
        try:
            if not validate_file_path(wordlist_path):
                return False, f"Wordlist file not found: {wordlist_path}", {}
            
            path = Path(wordlist_path)
            self.logger.info(f"Optimizing wordlist: {path}")
            
            # Read original passwords
            original_passwords = []
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        original_passwords.append(line)
            
            original_count = len(original_passwords)
            
            # Remove duplicates while preserving order
            unique_passwords = list(dict.fromkeys(original_passwords))
            duplicates_removed = original_count - len(unique_passwords)
            
            # Sort by length (shorter passwords first for faster cracking)
            unique_passwords.sort(key=len)
            
            # Create backup
            backup_path = path.with_suffix('.bak')
            path.rename(backup_path)
            
            # Write optimized wordlist
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f"# Optimized wordlist\n")
                f.write(f"# Original count: {original_count}\n")
                f.write(f"# Optimized count: {len(unique_passwords)}\n")
                f.write(f"# Duplicates removed: {duplicates_removed}\n")
                f.write(f"# Optimized: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for password in unique_passwords:
                    f.write(f"{password}\n")
            
            stats = {
                'original_count': original_count,
                'optimized_count': len(unique_passwords),
                'duplicates_removed': duplicates_removed,
                'size_reduction_percent': round((duplicates_removed / original_count) * 100, 2) if original_count > 0 else 0
            }
            
            success_msg = f"Wordlist optimized: {duplicates_removed} duplicates removed ({stats['size_reduction_percent']}% reduction)"
            self.logger.info(success_msg)
            
            return True, success_msg, stats
            
        except Exception as e:
            error_msg = f"Error optimizing wordlist: {e}"
            self.logger.error(error_msg)
            return False, error_msg, {}
    
    def get_available_wordlists(self) -> Dict[str, Dict[str, any]]:
        """
        Get information about available wordlists
        
        Returns:
            Dict[str, Dict[str, any]]: Dictionary of wordlist information
        """
        wordlists = {}
        
        try:
            # Built-in wordlists
            for category, description in self.builtin_categories.items():
                wordlists[f"builtin_{category}"] = {
                    'type': 'builtin',
                    'category': category,
                    'description': description,
                    'estimated_size': len(self.generate_builtin_wordlist(category)),
                    'path': None
                }
            
            # Custom wordlists
            if self.wordlists_dir.exists():
                for wordlist_file in self.wordlists_dir.glob('*.txt'):
                    try:
                        # Get file stats
                        file_stats = wordlist_file.stat()
                        
                        # Count passwords (quick estimate)
                        password_count = 0
                        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                if line.strip() and not line.startswith('#'):
                                    password_count += 1
                        
                        wordlists[wordlist_file.stem] = {
                            'type': 'custom',
                            'path': str(wordlist_file),
                            'size_bytes': file_stats.st_size,
                            'size_formatted': format_bytes(file_stats.st_size),
                            'password_count': password_count,
                            'modified': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                   time.localtime(file_stats.st_mtime))
                        }
                        
                    except Exception as e:
                        self.logger.warning(f"Error reading wordlist {wordlist_file}: {e}")
                        continue
            
            return wordlists
            
        except Exception as e:
            self.logger.error(f"Error getting available wordlists: {e}")
            return {}
    
    def create_combined_wordlist(self, name: str, wordlist_names: List[str], 
                               remove_duplicates: bool = True) -> Tuple[bool, str]:
        """
        Create a combined wordlist from multiple sources
        
        Args:
            name (str): Name for the combined wordlist
            wordlist_names (List[str]): List of wordlist names to combine
            remove_duplicates (bool): Whether to remove duplicates
            
        Returns:
            Tuple[bool, str]: (success, message_or_path)
        """
        try:
            if not name or not wordlist_names:
                return False, "Name and wordlist names are required"
            
            self.logger.info(f"Creating combined wordlist: {name} from {len(wordlist_names)} sources")
            
            all_passwords = []
            available_wordlists = self.get_available_wordlists()
            
            # Collect passwords from all sources
            for wordlist_name in wordlist_names:
                if wordlist_name.startswith('builtin_'):
                    category = wordlist_name.replace('builtin_', '')
                    if category in self.builtin_categories:
                        passwords = self.generate_builtin_wordlist(category)
                        all_passwords.extend(passwords)
                        self.logger.info(f"Added {len(passwords)} passwords from builtin {category}")
                
                elif wordlist_name in available_wordlists:
                    wordlist_info = available_wordlists[wordlist_name]
                    if wordlist_info['type'] == 'custom' and wordlist_info['path']:
                        try:
                            with open(wordlist_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                                passwords = []
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith('#'):
                                        passwords.append(line)
                                all_passwords.extend(passwords)
                                self.logger.info(f"Added {len(passwords)} passwords from {wordlist_name}")
                        except Exception as e:
                            self.logger.warning(f"Error reading wordlist {wordlist_name}: {e}")
                            continue
                else:
                    self.logger.warning(f"Wordlist not found: {wordlist_name}")
                    continue
            
            if not all_passwords:
                return False, "No passwords collected from specified wordlists"
            
            # Remove duplicates if requested
            if remove_duplicates:
                original_count = len(all_passwords)
                all_passwords = list(dict.fromkeys(all_passwords))
                duplicates_removed = original_count - len(all_passwords)
                self.logger.info(f"Removed {duplicates_removed} duplicate passwords")
            
            # Create combined wordlist
            description = f"Combined from: {', '.join(wordlist_names)}"
            success, result_path = self.create_custom_wordlist(name, all_passwords, description)
            
            if success:
                success_msg = f"Combined wordlist created with {len(all_passwords)} passwords"
                self.logger.info(success_msg)
                return True, result_path
            else:
                return False, f"Failed to create combined wordlist: {result_path}"
                
        except Exception as e:
            error_msg = f"Error creating combined wordlist: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def analyze_wordlist_size(self, wordlist_path: str) -> Dict[str, any]:
        """
        Analyze wordlist size and provide statistics
        
        Args:
            wordlist_path (str): Path to wordlist file
            
        Returns:
            Dict[str, any]: Analysis results including size stats and warnings
        """
        try:
            if not validate_file_path(wordlist_path):
                return {'error': f"Wordlist file not found: {wordlist_path}"}
            
            path = Path(wordlist_path)
            self.logger.info(f"Analyzing wordlist size: {path}")
            
            # File statistics
            file_stats = path.stat()
            file_size = file_stats.st_size
            
            # Count passwords and analyze
            password_count = 0
            total_chars = 0
            length_distribution = {}
            charset_analysis = {
                'lowercase': 0,
                'uppercase': 0,
                'digits': 0,
                'special': 0,
                'mixed': 0
            }
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    password_count += 1
                    password_length = len(line)
                    total_chars += password_length
                    
                    # Length distribution
                    length_distribution[password_length] = length_distribution.get(password_length, 0) + 1
                    
                    # Character set analysis
                    has_lower = any(c.islower() for c in line)
                    has_upper = any(c.isupper() for c in line)
                    has_digit = any(c.isdigit() for c in line)
                    has_special = any(not c.isalnum() for c in line)
                    
                    char_types = sum([has_lower, has_upper, has_digit, has_special])
                    
                    if char_types == 1:
                        if has_lower:
                            charset_analysis['lowercase'] += 1
                        elif has_upper:
                            charset_analysis['uppercase'] += 1
                        elif has_digit:
                            charset_analysis['digits'] += 1
                        else:
                            charset_analysis['special'] += 1
                    else:
                        charset_analysis['mixed'] += 1
            
            # Calculate statistics
            avg_length = total_chars / password_count if password_count > 0 else 0
            
            # Performance warnings
            warnings = []
            if password_count > self.warning_size:
                warnings.append(f"Large wordlist ({password_count:,} passwords) may take significant time")
            if password_count > self.max_wordlist_size:
                warnings.append(f"Wordlist exceeds recommended maximum ({self.max_wordlist_size:,} passwords)")
            if file_size > 100 * 1024 * 1024:  # 100MB
                warnings.append(f"Large file size ({format_bytes(file_size)}) may impact memory usage")
            
            analysis = {
                'file_path': str(path),
                'file_size_bytes': file_size,
                'file_size_formatted': format_bytes(file_size),
                'password_count': password_count,
                'average_length': round(avg_length, 2),
                'total_characters': total_chars,
                'length_distribution': dict(sorted(length_distribution.items())),
                'charset_analysis': charset_analysis,
                'warnings': warnings,
                'performance_category': self._categorize_performance(password_count)
            }
            
            self.logger.info(f"Wordlist analysis complete: {password_count:,} passwords, avg length {avg_length:.1f}")
            return analysis
            
        except Exception as e:
            error_msg = f"Error analyzing wordlist: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}
    
    def estimate_crack_time(self, wordlist_path: str, keys_per_second: int = 1000) -> Dict[str, any]:
        """
        Estimate time required to crack passwords using the wordlist
        
        Args:
            wordlist_path (str): Path to wordlist file
            keys_per_second (int): Estimated keys per second (default: 1000 for CPU)
            
        Returns:
            Dict[str, any]: Time estimation results
        """
        try:
            if not validate_file_path(wordlist_path):
                return {'error': f"Wordlist file not found: {wordlist_path}"}
            
            # Get wordlist size
            analysis = self.analyze_wordlist_size(wordlist_path)
            if 'error' in analysis:
                return analysis
            
            password_count = analysis['password_count']
            
            if password_count == 0:
                return {'error': 'Empty wordlist'}
            
            # Calculate time estimates
            # Average case: 50% of wordlist
            # Worst case: 100% of wordlist
            avg_time_seconds = (password_count * 0.5) / keys_per_second
            max_time_seconds = password_count / keys_per_second
            
            # Format time estimates
            def format_time(seconds):
                if seconds < 60:
                    return f"{seconds:.1f} seconds"
                elif seconds < 3600:
                    return f"{seconds/60:.1f} minutes"
                elif seconds < 86400:
                    return f"{seconds/3600:.1f} hours"
                else:
                    return f"{seconds/86400:.1f} days"
            
            # Performance recommendations
            recommendations = []
            if password_count > 100000:
                recommendations.append("Consider using GPU acceleration (hashcat) for faster cracking")
            if password_count > 1000000:
                recommendations.append("Large wordlist - consider filtering or using targeted attacks first")
            if keys_per_second < 10000:
                recommendations.append("CPU-only cracking detected - GPU would significantly improve speed")
            
            estimation = {
                'wordlist_path': wordlist_path,
                'password_count': password_count,
                'keys_per_second': keys_per_second,
                'average_time_seconds': int(avg_time_seconds),
                'maximum_time_seconds': int(max_time_seconds),
                'average_time_formatted': format_time(avg_time_seconds),
                'maximum_time_formatted': format_time(max_time_seconds),
                'recommendations': recommendations,
                'speed_category': self._categorize_speed(keys_per_second)
            }
            
            self.logger.info(f"Time estimation: avg {estimation['average_time_formatted']}, max {estimation['maximum_time_formatted']}")
            return estimation
            
        except Exception as e:
            error_msg = f"Error estimating crack time: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}
    
    def remove_duplicates(self, wordlist_path: str, create_backup: bool = True) -> Tuple[bool, str, Dict[str, int]]:
        """
        Remove duplicate passwords from wordlist
        
        Args:
            wordlist_path (str): Path to wordlist file
            create_backup (bool): Whether to create backup before modification
            
        Returns:
            Tuple[bool, str, Dict[str, int]]: (success, message, statistics)
        """
        try:
            if not validate_file_path(wordlist_path):
                return False, f"Wordlist file not found: {wordlist_path}", {}
            
            path = Path(wordlist_path)
            self.logger.info(f"Removing duplicates from: {path}")
            
            # Read all passwords
            passwords = []
            comments = []
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    if line.startswith('#'):
                        comments.append(line)
                    elif line.strip():
                        passwords.append(line.strip())
            
            original_count = len(passwords)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_passwords = []
            
            for password in passwords:
                if password not in seen:
                    seen.add(password)
                    unique_passwords.append(password)
            
            duplicates_removed = original_count - len(unique_passwords)
            
            if duplicates_removed == 0:
                return True, "No duplicates found", {'original_count': original_count, 'duplicates_removed': 0}
            
            # Create backup if requested
            if create_backup:
                backup_path = path.with_suffix('.bak')
                path.rename(backup_path)
                self.logger.info(f"Backup created: {backup_path}")
            
            # Write deduplicated wordlist
            with open(path, 'w', encoding='utf-8') as f:
                # Write comments
                for comment in comments:
                    f.write(f"{comment}\n")
                
                # Add deduplication info
                f.write(f"# Duplicates removed: {duplicates_removed}\n")
                f.write(f"# Processed: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write unique passwords
                for password in unique_passwords:
                    f.write(f"{password}\n")
            
            stats = {
                'original_count': original_count,
                'final_count': len(unique_passwords),
                'duplicates_removed': duplicates_removed,
                'reduction_percent': round((duplicates_removed / original_count) * 100, 2) if original_count > 0 else 0
            }
            
            success_msg = f"Removed {duplicates_removed} duplicates ({stats['reduction_percent']}% reduction)"
            self.logger.info(success_msg)
            
            return True, success_msg, stats
            
        except Exception as e:
            error_msg = f"Error removing duplicates: {e}"
            self.logger.error(error_msg)
            return False, error_msg, {}
    
    def merge_wordlists(self, output_name: str, wordlist_paths: List[str], 
                       remove_duplicates: bool = True, sort_by_length: bool = True) -> Tuple[bool, str]:
        """
        Efficiently merge multiple wordlists into one
        
        Args:
            output_name (str): Name for the merged wordlist
            wordlist_paths (List[str]): List of wordlist file paths
            remove_duplicates (bool): Whether to remove duplicates
            sort_by_length (bool): Whether to sort by password length
            
        Returns:
            Tuple[bool, str]: (success, message_or_path)
        """
        try:
            if not output_name or not wordlist_paths:
                return False, "Output name and wordlist paths are required"
            
            self.logger.info(f"Merging {len(wordlist_paths)} wordlists into: {output_name}")
            
            all_passwords = []
            source_info = []
            
            # Read passwords from all wordlists
            for wordlist_path in wordlist_paths:
                if not validate_file_path(wordlist_path):
                    self.logger.warning(f"Skipping invalid wordlist: {wordlist_path}")
                    continue
                
                path = Path(wordlist_path)
                passwords = []
                
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                passwords.append(line)
                    
                    all_passwords.extend(passwords)
                    source_info.append(f"{path.name}: {len(passwords)} passwords")
                    self.logger.info(f"Loaded {len(passwords)} passwords from {path.name}")
                    
                except Exception as e:
                    self.logger.warning(f"Error reading {wordlist_path}: {e}")
                    continue
            
            if not all_passwords:
                return False, "No passwords loaded from any wordlist"
            
            original_count = len(all_passwords)
            
            # Remove duplicates if requested
            if remove_duplicates:
                all_passwords = list(dict.fromkeys(all_passwords))
                duplicates_removed = original_count - len(all_passwords)
                self.logger.info(f"Removed {duplicates_removed} duplicate passwords")
            
            # Sort by length if requested (shorter passwords first for faster cracking)
            if sort_by_length:
                all_passwords.sort(key=len)
                self.logger.info("Sorted passwords by length")
            
            # Create merged wordlist
            description = f"Merged from {len(wordlist_paths)} wordlists:\\n" + "\\n".join(source_info)
            success, result_path = self.create_custom_wordlist(output_name, all_passwords, description)
            
            if success:
                success_msg = f"Merged wordlist created with {len(all_passwords)} passwords"
                self.logger.info(success_msg)
                return True, result_path
            else:
                return False, f"Failed to create merged wordlist: {result_path}"
                
        except Exception as e:
            error_msg = f"Error merging wordlists: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _categorize_performance(self, password_count: int) -> str:
        """Categorize wordlist performance impact"""
        if password_count < 10000:
            return "fast"
        elif password_count < 100000:
            return "moderate"
        elif password_count < 1000000:
            return "slow"
        else:
            return "very_slow"
    
    def _categorize_speed(self, keys_per_second: int) -> str:
        """Categorize cracking speed"""
        if keys_per_second < 1000:
            return "very_slow"
        elif keys_per_second < 10000:
            return "slow"
        elif keys_per_second < 100000:
            return "moderate"
        elif keys_per_second < 1000000:
            return "fast"
        else:
            return "very_fast"
    
    def get_wordlist_statistics(self, wordlist_path: str) -> Dict[str, any]:
        """
        Get comprehensive statistics for a wordlist
        
        Args:
            wordlist_path (str): Path to wordlist file
            
        Returns:
            Dict[str, any]: Comprehensive wordlist statistics
        """
        try:
            # Combine size analysis and time estimation
            size_analysis = self.analyze_wordlist_size(wordlist_path)
            if 'error' in size_analysis:
                return size_analysis
            
            # Default to CPU speed for estimation
            time_estimation = self.estimate_crack_time(wordlist_path, keys_per_second=1000)
            
            # Combine results
            statistics = {
                'file_info': {
                    'path': size_analysis['file_path'],
                    'size_bytes': size_analysis['file_size_bytes'],
                    'size_formatted': size_analysis['file_size_formatted']
                },
                'password_info': {
                    'count': size_analysis['password_count'],
                    'average_length': size_analysis['average_length'],
                    'total_characters': size_analysis['total_characters'],
                    'length_distribution': size_analysis['length_distribution']
                },
                'charset_analysis': size_analysis['charset_analysis'],
                'performance': {
                    'category': size_analysis['performance_category'],
                    'warnings': size_analysis['warnings']
                },
                'time_estimates': {
                    'average_seconds': time_estimation.get('average_time_seconds', 0),
                    'maximum_seconds': time_estimation.get('maximum_time_seconds', 0),
                    'average_formatted': time_estimation.get('average_time_formatted', 'Unknown'),
                    'maximum_formatted': time_estimation.get('maximum_time_formatted', 'Unknown')
                },
                'recommendations': time_estimation.get('recommendations', [])
            }
            
            return statistics
            
        except Exception as e:
            error_msg = f"Error getting wordlist statistics: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}
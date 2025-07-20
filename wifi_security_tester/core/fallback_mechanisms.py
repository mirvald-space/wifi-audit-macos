"""
Fallback Mechanisms - Implements automatic fallback to alternative methods
Provides specific recovery mechanisms for requirements 1.4, 2.4, and 3.4

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import sys
import subprocess
import shutil
import time
import os
from typing import Optional, Dict, Any, List, Tuple, Callable
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.exceptions import *
from core.logger import get_logger
from utils.common import run_command, get_system_info


class FallbackMechanisms:
    """Implements automatic fallback mechanisms for critical operations"""
    
    def __init__(self):
        self.logger = get_logger("fallback_mechanisms")
        self.system_info = get_system_info()
        
        # Track fallback usage for optimization
        self.fallback_usage = {}
        self.fallback_success_rates = {}
    
    def homebrew_installation_fallback(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Fallback mechanism for Homebrew installation (Requirement 1.4)
        IF Homebrew не установлен THEN система SHALL предложить установку Homebrew
        """
        try:
            self.logger.info("Attempting Homebrew installation fallback")
            
            # Check if Homebrew is already installed
            if shutil.which('brew'):
                return True, "Homebrew is already installed", {'homebrew_installed': True}
            
            # Method 1: Automatic installation using official script
            success, message, details = self._install_homebrew_automatic()
            if success:
                return True, message, details
            
            # Method 2: Provide manual installation guidance
            success, message, details = self._provide_homebrew_manual_guidance()
            return success, message, details
            
        except Exception as e:
            self.logger.error(f"Homebrew installation fallback failed: {e}")
            return False, f"Homebrew installation fallback failed: {e}", {}
    
    def _install_homebrew_automatic(self) -> Tuple[bool, str, Dict[str, Any]]:
        """Attempt automatic Homebrew installation"""
        try:
            self.logger.info("Attempting automatic Homebrew installation")
            
            # Download and run Homebrew installation script
            install_command = [
                '/bin/bash', '-c',
                '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
            ]
            
            # Run with timeout to prevent hanging
            result = run_command(install_command, timeout=600)  # 10 minutes timeout
            
            if result.returncode == 0:
                # Verify installation
                if shutil.which('brew'):
                    return True, "Homebrew installed successfully", {
                        'installation_method': 'automatic',
                        'homebrew_path': shutil.which('brew')
                    }
                else:
                    # Installation completed but brew not in PATH
                    return False, "Homebrew installed but not in PATH. Please restart terminal.", {
                        'installation_method': 'automatic',
                        'path_issue': True,
                        'solution': 'Restart terminal or run: echo \'export PATH="/opt/homebrew/bin:$PATH"\' >> ~/.zshrc'
                    }
            else:
                return False, f"Homebrew installation failed: {result.stderr}", {
                    'installation_method': 'automatic',
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return False, "Homebrew installation timed out", {
                'installation_method': 'automatic',
                'timeout': True
            }
        except Exception as e:
            return False, f"Automatic Homebrew installation failed: {e}", {
                'installation_method': 'automatic',
                'error': str(e)
            }
    
    def _provide_homebrew_manual_guidance(self) -> Tuple[bool, str, Dict[str, Any]]:
        """Provide manual Homebrew installation guidance"""
        guidance = {
            'title': 'Manual Homebrew Installation Required',
            'description': 'Automatic installation failed. Please install Homebrew manually.',
            'steps': [
                'Open Terminal application',
                'Copy and paste this command:',
                '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                'Follow the on-screen instructions',
                'After installation, restart your terminal',
                'Verify installation by running: brew --version'
            ],
            'alternative_methods': [
                {
                    'method': 'Download from website',
                    'url': 'https://brew.sh/',
                    'description': 'Visit the official Homebrew website for installation instructions'
                },
                {
                    'method': 'Use package manager',
                    'description': 'If you have MacPorts or another package manager, you can use that instead'
                }
            ],
            'troubleshooting': [
                'If you get permission errors, do NOT use sudo with the installation script',
                'Make sure you have Xcode Command Line Tools installed: xcode-select --install',
                'Check your internet connection if download fails'
            ]
        }
        
        return False, "Manual Homebrew installation required", {
            'installation_method': 'manual',
            'guidance': guidance,
            'requires_user_action': True
        }
    
    def network_scanning_fallback(self, interface: Optional[str] = None) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Fallback mechanism for network scanning (Requirement 2.4)
        IF wdutil недоступен THEN система SHALL предложить альтернативные методы сканирования
        """
        try:
            self.logger.info("Attempting network scanning fallback")
            
            # Method 1: Try wdutil (primary method)
            success, networks, details = self._scan_with_wdutil()
            if success and networks:
                return True, networks, details
            
            # Method 2: Try system_profiler
            success, networks, details = self._scan_with_system_profiler()
            if success and networks:
                return True, networks, details
            
            # Method 3: Try networksetup
            success, networks, details = self._scan_with_networksetup()
            if success and networks:
                return True, networks, details
            
            # Method 4: Try airport utility (if available)
            success, networks, details = self._scan_with_airport()
            if success and networks:
                return True, networks, details
            
            # Method 5: Provide manual scanning guidance
            return self._provide_manual_scanning_guidance()
            
        except Exception as e:
            self.logger.error(f"Network scanning fallback failed: {e}")
            return False, [], {'error': str(e)}
    
    def _scan_with_wdutil(self) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """Scan networks using wdutil"""
        try:
            wdutil_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/wdutil'
            
            if not os.path.exists(wdutil_path):
                return False, [], {'error': 'wdutil not found', 'method': 'wdutil'}
            
            result = run_command([wdutil_path, 'scan'], timeout=30)
            
            if result.returncode == 0:
                networks = self._parse_wdutil_output(result.stdout)
                return True, networks, {
                    'method': 'wdutil',
                    'networks_found': len(networks)
                }
            else:
                return False, [], {
                    'error': result.stderr,
                    'method': 'wdutil',
                    'exit_code': result.returncode
                }
                
        except Exception as e:
            return False, [], {'error': str(e), 'method': 'wdutil'}
    
    def _scan_with_system_profiler(self) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """Scan networks using system_profiler"""
        try:
            result = run_command(['system_profiler', 'SPAirPortDataType'], timeout=30)
            
            if result.returncode == 0:
                networks = self._parse_system_profiler_output(result.stdout)
                return True, networks, {
                    'method': 'system_profiler',
                    'networks_found': len(networks)
                }
            else:
                return False, [], {
                    'error': result.stderr,
                    'method': 'system_profiler',
                    'exit_code': result.returncode
                }
                
        except Exception as e:
            return False, [], {'error': str(e), 'method': 'system_profiler'}
    
    def _scan_with_networksetup(self) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """Scan networks using networksetup"""
        try:
            result = run_command(['networksetup', '-listpreferredwirelessnetworks', 'Wi-Fi'], timeout=15)
            
            if result.returncode == 0:
                networks = self._parse_networksetup_output(result.stdout)
                return True, networks, {
                    'method': 'networksetup',
                    'networks_found': len(networks),
                    'note': 'Limited information available - only preferred networks'
                }
            else:
                return False, [], {
                    'error': result.stderr,
                    'method': 'networksetup',
                    'exit_code': result.returncode
                }
                
        except Exception as e:
            return False, [], {'error': str(e), 'method': 'networksetup'}
    
    def _scan_with_airport(self) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """Scan networks using airport utility (legacy)"""
        try:
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            
            if not os.path.exists(airport_path):
                return False, [], {'error': 'airport utility not found', 'method': 'airport'}
            
            result = run_command([airport_path, '-s'], timeout=30)
            
            if result.returncode == 0:
                networks = self._parse_airport_output(result.stdout)
                return True, networks, {
                    'method': 'airport',
                    'networks_found': len(networks),
                    'note': 'Using legacy airport utility'
                }
            else:
                return False, [], {
                    'error': result.stderr,
                    'method': 'airport',
                    'exit_code': result.returncode
                }
                
        except Exception as e:
            return False, [], {'error': str(e), 'method': 'airport'}
    
    def _provide_manual_scanning_guidance(self) -> Tuple[bool, List[Dict[str, Any]], Dict[str, Any]]:
        """Provide manual network scanning guidance"""
        guidance = {
            'title': 'Manual Network Scanning Required',
            'description': 'All automatic scanning methods failed. Please scan manually.',
            'methods': [
                {
                    'method': 'System Preferences',
                    'steps': [
                        'Open System Preferences',
                        'Click on Network',
                        'Select Wi-Fi from the left panel',
                        'Click "Advanced..." button',
                        'Go to "Wi-Fi" tab to see preferred networks'
                    ]
                },
                {
                    'method': 'WiFi Menu',
                    'steps': [
                        'Click the WiFi icon in the menu bar',
                        'Hold Option key while clicking for detailed information',
                        'Note down network names and details'
                    ]
                },
                {
                    'method': 'Terminal Commands',
                    'steps': [
                        'Try: sudo wdutil scan',
                        'Try: system_profiler SPAirPortDataType',
                        'Try: networksetup -listpreferredwirelessnetworks Wi-Fi'
                    ]
                }
            ],
            'troubleshooting': [
                'Ensure WiFi is enabled',
                'Check if you have administrator privileges',
                'Try restarting WiFi: networksetup -setairportpower Wi-Fi off && networksetup -setairportpower Wi-Fi on'
            ]
        }
        
        return False, [], {
            'method': 'manual',
            'guidance': guidance,
            'requires_user_action': True
        }
    
    def monitor_mode_fallback(self, interface: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Fallback mechanism for monitor mode (Requirement 3.4)
        IF интерфейс не поддерживает режим мониторинга THEN система SHALL предупредить пользователя и предложить альтернативы
        """
        try:
            self.logger.info(f"Attempting monitor mode fallback for interface {interface}")
            
            # Check if interface supports monitor mode
            supports_monitor = self._check_monitor_mode_support(interface)
            
            if not supports_monitor:
                return self._provide_monitor_mode_alternatives(interface)
            
            # Try different methods to enable monitor mode
            methods = [
                self._enable_monitor_mode_networksetup,
                self._enable_monitor_mode_ifconfig,
                self._enable_monitor_mode_airport
            ]
            
            for method in methods:
                try:
                    success, message, details = method(interface)
                    if success:
                        return True, message, details
                except Exception as e:
                    self.logger.warning(f"Monitor mode method {method.__name__} failed: {e}")
            
            # All methods failed, provide alternatives
            return self._provide_monitor_mode_alternatives(interface)
            
        except Exception as e:
            self.logger.error(f"Monitor mode fallback failed: {e}")
            return False, f"Monitor mode fallback failed: {e}", {}
    
    def _check_monitor_mode_support(self, interface: str) -> bool:
        """Check if interface supports monitor mode"""
        try:
            # Check interface capabilities
            result = run_command(['ifconfig', interface])
            if result.returncode != 0:
                return False
            
            # Most built-in Mac WiFi interfaces don't support monitor mode
            # Check if it's a built-in interface
            if interface.startswith('en') and 'Wi-Fi' in result.stdout:
                return False
            
            # Check for monitor mode capability in interface info
            result = run_command(['iwconfig', interface], timeout=5)
            if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _enable_monitor_mode_networksetup(self, interface: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Try to enable monitor mode using networksetup"""
        try:
            # This typically doesn't work on macOS built-in interfaces
            result = run_command(['sudo', 'networksetup', '-setairportpower', interface, 'off'])
            if result.returncode != 0:
                return False, "Failed to disable interface", {'method': 'networksetup'}
            
            time.sleep(2)
            
            result = run_command(['sudo', 'networksetup', '-setairportpower', interface, 'on'])
            if result.returncode != 0:
                return False, "Failed to re-enable interface", {'method': 'networksetup'}
            
            return False, "Monitor mode not supported via networksetup", {'method': 'networksetup'}
            
        except Exception as e:
            return False, f"networksetup method failed: {e}", {'method': 'networksetup'}
    
    def _enable_monitor_mode_ifconfig(self, interface: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Try to enable monitor mode using ifconfig"""
        try:
            # Try to set interface to monitor mode
            result = run_command(['sudo', 'ifconfig', interface, 'down'])
            if result.returncode != 0:
                return False, "Failed to bring interface down", {'method': 'ifconfig'}
            
            time.sleep(1)
            
            # This typically fails on macOS
            result = run_command(['sudo', 'ifconfig', interface, 'mediaopt', 'monitor'])
            if result.returncode == 0:
                result = run_command(['sudo', 'ifconfig', interface, 'up'])
                if result.returncode == 0:
                    return True, "Monitor mode enabled via ifconfig", {'method': 'ifconfig'}
            
            # Restore interface
            run_command(['sudo', 'ifconfig', interface, 'up'])
            return False, "Monitor mode not supported via ifconfig", {'method': 'ifconfig'}
            
        except Exception as e:
            return False, f"ifconfig method failed: {e}", {'method': 'ifconfig'}
    
    def _enable_monitor_mode_airport(self, interface: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Try to enable monitor mode using airport utility"""
        try:
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            
            if not os.path.exists(airport_path):
                return False, "airport utility not found", {'method': 'airport'}
            
            # Try to enable monitor mode
            result = run_command(['sudo', airport_path, interface, 'monitor'])
            if result.returncode == 0:
                return True, "Monitor mode enabled via airport utility", {'method': 'airport'}
            else:
                return False, "Monitor mode not supported via airport", {'method': 'airport'}
                
        except Exception as e:
            return False, f"airport method failed: {e}", {'method': 'airport'}
    
    def _provide_monitor_mode_alternatives(self, interface: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Provide alternatives when monitor mode is not supported"""
        alternatives = {
            'title': 'Monitor Mode Not Supported',
            'description': f'Interface {interface} does not support monitor mode. Here are alternatives:',
            'alternatives': [
                {
                    'option': 'External WiFi Adapter',
                    'description': 'Use a USB WiFi adapter that supports monitor mode',
                    'recommended_models': [
                        'Alfa AWUS036ACS (802.11ac, dual-band)',
                        'Alfa AWUS036NHA (802.11n, high power)',
                        'Panda PAU09 (budget option)',
                        'TP-Link AC600T2U Plus'
                    ],
                    'pros': ['Full monitor mode support', 'Better range', 'Dedicated for testing'],
                    'cons': ['Additional hardware cost', 'USB port required']
                },
                {
                    'option': 'Passive Scanning',
                    'description': 'Use passive scanning methods without monitor mode',
                    'methods': [
                        'wdutil scan (built-in macOS tool)',
                        'system_profiler SPAirPortDataType',
                        'WiFi Explorer app (third-party)'
                    ],
                    'pros': ['Works with built-in interface', 'No additional hardware'],
                    'cons': ['Limited information', 'Cannot capture handshakes']
                },
                {
                    'option': 'Alternative Capture Methods',
                    'description': 'Use tcpdump or other tools for limited packet capture',
                    'methods': [
                        'tcpdump with specific filters',
                        'Wireshark in promiscuous mode',
                        'Built-in packet capture tools'
                    ],
                    'pros': ['Some packet capture capability'],
                    'cons': ['Limited effectiveness', 'May miss handshakes']
                },
                {
                    'option': 'Virtual Machine',
                    'description': 'Use a Linux VM with USB passthrough',
                    'requirements': [
                        'VMware Fusion or Parallels Desktop',
                        'Linux distribution (Kali, Ubuntu)',
                        'USB WiFi adapter',
                        'USB passthrough configuration'
                    ],
                    'pros': ['Full Linux toolset', 'Better driver support'],
                    'cons': ['Complex setup', 'Performance overhead']
                }
            ],
            'recommendations': [
                'For serious WiFi security testing, invest in a dedicated USB WiFi adapter',
                'Alfa AWUS036ACS is highly recommended for macOS compatibility',
                'Check adapter compatibility before purchase',
                'Consider dual-band adapters for 2.4GHz and 5GHz testing'
            ]
        }
        
        return False, "Monitor mode alternatives provided", {
            'method': 'alternatives',
            'alternatives': alternatives,
            'requires_user_decision': True
        }
    
    # Parsing methods
    def _parse_wdutil_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse wdutil scan output"""
        networks = []
        lines = output.strip().split('\n')
        
        current_network = {}
        for line in lines:
            line = line.strip()
            if not line:
                if current_network:
                    networks.append(current_network)
                    current_network = {}
                continue
            
            if line.startswith('SSID:'):
                current_network['ssid'] = line.replace('SSID:', '').strip()
            elif line.startswith('BSSID:'):
                current_network['bssid'] = line.replace('BSSID:', '').strip()
            elif line.startswith('Channel:'):
                current_network['channel'] = line.replace('Channel:', '').strip()
            elif line.startswith('RSSI:'):
                current_network['signal_strength'] = line.replace('RSSI:', '').strip()
            elif line.startswith('Security:'):
                current_network['encryption'] = line.replace('Security:', '').strip()
        
        # Add last network if exists
        if current_network:
            networks.append(current_network)
        
        # Add source information
        for network in networks:
            network['source'] = 'wdutil'
            network.setdefault('ssid', 'Unknown')
            network.setdefault('bssid', 'Unknown')
            network.setdefault('channel', 'Unknown')
            network.setdefault('signal_strength', 'Unknown')
            network.setdefault('encryption', 'Unknown')
        
        return networks
    
    def _parse_system_profiler_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse system_profiler output"""
        networks = []
        lines = output.strip().split('\n')
        
        current_network = {}
        in_network_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for network entries
            if 'Preferred Networks:' in line or 'Available Networks:' in line:
                in_network_section = True
                continue
            elif line.startswith('AirPort Card Information:'):
                in_network_section = False
                continue
            
            if in_network_section and line and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'SSID':
                    if current_network:
                        networks.append(current_network)
                    current_network = {'ssid': value}
                elif key == 'BSSID':
                    current_network['bssid'] = value
                elif key == 'Channel':
                    current_network['channel'] = value
                elif key == 'Signal / Noise':
                    current_network['signal_strength'] = value.split('/')[0].strip()
                elif key == 'Security':
                    current_network['encryption'] = value
        
        # Add last network if exists
        if current_network:
            networks.append(current_network)
        
        # Add source information and defaults
        for network in networks:
            network['source'] = 'system_profiler'
            network.setdefault('bssid', 'Unknown')
            network.setdefault('channel', 'Unknown')
            network.setdefault('signal_strength', 'Unknown')
            network.setdefault('encryption', 'Unknown')
        
        return networks
    
    def _parse_networksetup_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse networksetup output"""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('Preferred networks'):
                networks.append({
                    'ssid': line,
                    'bssid': 'Unknown',
                    'channel': 'Unknown',
                    'signal_strength': 'Unknown',
                    'encryption': 'Unknown',
                    'source': 'networksetup'
                })
        
        return networks
    
    def _parse_airport_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse airport utility output"""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'signal_strength': parts[2],
                    'channel': parts[3],
                    'encryption': ' '.join(parts[6:]) if len(parts) > 6 else 'Unknown',
                    'source': 'airport'
                })
        
        return networks


# Global fallback mechanisms instance
_global_fallback_mechanisms = None


def get_fallback_mechanisms() -> FallbackMechanisms:
    """Get the global fallback mechanisms instance"""
    global _global_fallback_mechanisms
    if _global_fallback_mechanisms is None:
        _global_fallback_mechanisms = FallbackMechanisms()
    return _global_fallback_mechanisms
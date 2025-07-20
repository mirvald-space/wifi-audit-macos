"""
Recovery Manager - Implements automatic fallback methods and system state recovery
Provides comprehensive recovery mechanisms for WiFi Security Tester operations

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import sys
import subprocess
import time
import shutil
import os
from typing import Optional, Dict, Any, List, Callable, Tuple
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.exceptions import *
from core.logger import get_logger
from utils.common import run_command, get_system_info


@dataclass
class SystemState:
    """Represents system state that can be restored"""
    interface_states: Dict[str, str]
    network_configuration: Dict[str, Any]
    running_processes: List[str]
    temporary_files: List[str]
    timestamp: float


class FallbackMethod:
    """Represents a fallback method for an operation"""
    
    def __init__(self, name: str, method: Callable, priority: int = 1,
                 requirements: Optional[List[str]] = None):
        self.name = name
        self.method = method
        self.priority = priority
        self.requirements = requirements or []
        self.success_rate = 1.0
        self.last_used = None
        self.failure_count = 0


class RecoveryManager:
    """Manages system recovery and fallback mechanisms"""
    
    def __init__(self):
        self.logger = get_logger("recovery_manager")
        self.system_states: List[SystemState] = []
        self.fallback_methods: Dict[str, List[FallbackMethod]] = {}
        self.recovery_procedures: Dict[str, Callable] = {}
        self.max_state_history = 10
        
        # Initialize fallback methods
        self._initialize_fallback_methods()
        
        # Initialize recovery procedures
        self._initialize_recovery_procedures()
    
    def _initialize_fallback_methods(self) -> None:
        """Initialize fallback methods for different operations"""
        
        # Network scanning fallbacks
        self.register_fallback_method(
            'network_scan',
            FallbackMethod('wdutil_scan', self._wdutil_network_scan, priority=1, 
                          requirements=['wdutil'])
        )
        self.register_fallback_method(
            'network_scan',
            FallbackMethod('system_profiler_scan', self._system_profiler_network_scan, priority=2)
        )
        self.register_fallback_method(
            'network_scan',
            FallbackMethod('networksetup_scan', self._networksetup_network_scan, priority=3)
        )
        
        # Interface management fallbacks
        self.register_fallback_method(
            'interface_control',
            FallbackMethod('networksetup_control', self._networksetup_interface_control, priority=1)
        )
        self.register_fallback_method(
            'interface_control',
            FallbackMethod('ifconfig_control', self._ifconfig_interface_control, priority=2)
        )
        
        # Packet capture fallbacks
        self.register_fallback_method(
            'packet_capture',
            FallbackMethod('airodump_capture', self._airodump_packet_capture, priority=1,
                          requirements=['aircrack-ng'])
        )
        self.register_fallback_method(
            'packet_capture',
            FallbackMethod('tcpdump_capture', self._tcpdump_packet_capture, priority=2)
        )
        
        # Password cracking fallbacks
        self.register_fallback_method(
            'password_crack',
            FallbackMethod('hashcat_gpu', self._hashcat_gpu_crack, priority=1,
                          requirements=['hashcat'])
        )
        self.register_fallback_method(
            'password_crack',
            FallbackMethod('hashcat_cpu', self._hashcat_cpu_crack, priority=2,
                          requirements=['hashcat'])
        )
        self.register_fallback_method(
            'password_crack',
            FallbackMethod('aircrack_ng', self._aircrack_ng_crack, priority=3,
                          requirements=['aircrack-ng'])
        )
        
        # Dependency installation fallbacks
        self.register_fallback_method(
            'dependency_install',
            FallbackMethod('homebrew_install', self._homebrew_install, priority=1,
                          requirements=['brew'])
        )
        self.register_fallback_method(
            'dependency_install',
            FallbackMethod('manual_install_guide', self._manual_install_guide, priority=2)
        )
    
    def _initialize_recovery_procedures(self) -> None:
        """Initialize recovery procedures for different failure scenarios"""
        self.recovery_procedures.update({
            'interface_stuck': self._recover_stuck_interface,
            'process_hanging': self._recover_hanging_process,
            'permission_denied': self._recover_permission_issues,
            'sip_restriction': self._recover_sip_restrictions,
            'dependency_missing': self._recover_missing_dependencies,
            'capture_failed': self._recover_failed_capture,
            'system_state_corrupted': self._recover_system_state
        })
    
    def save_system_state(self) -> str:
        """Save current system state for recovery purposes"""
        try:
            state = SystemState(
                interface_states=self._get_interface_states(),
                network_configuration=self._get_network_configuration(),
                running_processes=self._get_relevant_processes(),
                temporary_files=self._get_temporary_files(),
                timestamp=time.time()
            )
            
            self.system_states.append(state)
            
            # Limit history size
            if len(self.system_states) > self.max_state_history:
                self.system_states.pop(0)
            
            state_id = f"state_{int(state.timestamp)}"
            self.logger.info(f"System state saved: {state_id}")
            return state_id
            
        except Exception as e:
            self.logger.error(f"Failed to save system state: {e}")
            raise SystemError(f"Could not save system state: {e}")
    
    def restore_system_state(self, state_id: Optional[str] = None) -> bool:
        """Restore system to a previous state"""
        try:
            if not self.system_states:
                self.logger.warning("No system states available for restoration")
                return False
            
            # Use latest state if no specific state requested
            if state_id is None:
                state = self.system_states[-1]
            else:
                # Find state by ID
                target_timestamp = int(state_id.replace('state_', ''))
                state = None
                for s in self.system_states:
                    if int(s.timestamp) == target_timestamp:
                        state = s
                        break
                
                if state is None:
                    self.logger.error(f"State {state_id} not found")
                    return False
            
            # Restore interface states
            self._restore_interface_states(state.interface_states)
            
            # Clean up temporary files
            self._cleanup_temporary_files(state.temporary_files)
            
            # Terminate hanging processes
            self._cleanup_processes(state.running_processes)
            
            self.logger.info(f"System state restored successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore system state: {e}")
            return False
    
    def execute_with_fallback(self, operation: str, primary_method: Callable,
                            *args, **kwargs) -> Tuple[bool, Any, Optional[str]]:
        """Execute operation with automatic fallback on failure"""
        fallback_methods = self.get_available_fallback_methods(operation)
        
        # Try primary method first
        try:
            self.logger.debug(f"Attempting primary method for {operation}")
            result = primary_method(*args, **kwargs)
            return True, result, "primary"
        except Exception as primary_error:
            self.logger.warning(f"Primary method failed for {operation}: {primary_error}")
        
        # Try fallback methods in order of priority
        for fallback in fallback_methods:
            try:
                self.logger.info(f"Trying fallback method: {fallback.name}")
                
                # Check requirements
                if not self._check_fallback_requirements(fallback):
                    self.logger.debug(f"Fallback {fallback.name} requirements not met")
                    continue
                
                result = fallback.method(*args, **kwargs)
                fallback.last_used = time.time()
                self.logger.info(f"Fallback method {fallback.name} succeeded")
                return True, result, fallback.name
                
            except Exception as fallback_error:
                fallback.failure_count += 1
                fallback.success_rate = max(0.1, fallback.success_rate * 0.8)
                self.logger.warning(f"Fallback {fallback.name} failed: {fallback_error}")
        
        return False, None, None
    
    def register_fallback_method(self, operation: str, fallback: FallbackMethod) -> None:
        """Register a fallback method for an operation"""
        if operation not in self.fallback_methods:
            self.fallback_methods[operation] = []
        
        self.fallback_methods[operation].append(fallback)
        
        # Sort by priority
        self.fallback_methods[operation].sort(key=lambda x: x.priority)
        
        self.logger.debug(f"Registered fallback method {fallback.name} for {operation}")
    
    def get_available_fallback_methods(self, operation: str) -> List[FallbackMethod]:
        """Get available fallback methods for an operation"""
        if operation not in self.fallback_methods:
            return []
        
        # Filter by requirements and success rate
        available = []
        for fallback in self.fallback_methods[operation]:
            if (self._check_fallback_requirements(fallback) and 
                fallback.success_rate > 0.2):  # Minimum success rate threshold
                available.append(fallback)
        
        return available
    
    def recover_from_error(self, error: Exception, operation: str,
                          context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Attempt to recover from a specific error"""
        recovery_result = {
            'recovery_attempted': True,
            'recovery_successful': False,
            'recovery_method': None,
            'recovery_message': '',
            'state_restored': False
        }
        
        try:
            # Determine recovery procedure based on error type
            recovery_procedure = self._get_recovery_procedure(error, operation)
            
            if recovery_procedure:
                self.logger.info(f"Attempting recovery procedure: {recovery_procedure.__name__}")
                success, message = recovery_procedure(error, context)
                
                recovery_result.update({
                    'recovery_successful': success,
                    'recovery_method': recovery_procedure.__name__,
                    'recovery_message': message
                })
            else:
                # Generic recovery attempt
                success, message = self._generic_recovery(error, operation, context)
                recovery_result.update({
                    'recovery_successful': success,
                    'recovery_method': 'generic_recovery',
                    'recovery_message': message
                })
        
        except Exception as recovery_error:
            recovery_result['recovery_message'] = f"Recovery failed: {recovery_error}"
            self.logger.error(f"Recovery attempt failed: {recovery_error}")
        
        return recovery_result
    
    def _get_recovery_procedure(self, error: Exception, operation: str) -> Optional[Callable]:
        """Get appropriate recovery procedure for error and operation"""
        error_type = type(error).__name__.lower()
        
        # Check for specific error type procedures
        for procedure_key, procedure in self.recovery_procedures.items():
            if procedure_key in error_type or error_type in procedure_key:
                return procedure
        
        # Check for operation-specific procedures
        operation_key = f"{operation}_recovery"
        if operation_key in self.recovery_procedures:
            return self.recovery_procedures[operation_key]
        
        return None
    
    def _generic_recovery(self, error: Exception, operation: str,
                         context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Generic recovery procedure for unspecified errors"""
        try:
            # Try to restore last known good state
            if self.system_states:
                if self.restore_system_state():
                    return True, "System state restored to last known good configuration"
            
            # Try to clean up any hanging processes
            self._cleanup_hanging_processes()
            
            # Reset interfaces to managed mode
            self._reset_interfaces_to_managed()
            
            return True, "Generic recovery procedures completed"
            
        except Exception as e:
            return False, f"Generic recovery failed: {e}"
    
    # Fallback method implementations
    def _wdutil_network_scan(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Network scanning using wdutil"""
        try:
            result = run_command(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/wdutil', 'scan'])
            if result.returncode != 0:
                raise ExecutionFailedError('wdutil', 'scan', result.returncode, result.stderr)
            
            # Parse wdutil output
            networks = self._parse_wdutil_output(result.stdout)
            return networks
            
        except Exception as e:
            raise NetworkError(f"wdutil scan failed: {e}")
    
    def _system_profiler_network_scan(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Network scanning using system_profiler"""
        try:
            result = run_command(['system_profiler', 'SPAirPortDataType'])
            if result.returncode != 0:
                raise ExecutionFailedError('system_profiler', 'SPAirPortDataType', result.returncode, result.stderr)
            
            # Parse system_profiler output
            networks = self._parse_system_profiler_output(result.stdout)
            return networks
            
        except Exception as e:
            raise NetworkError(f"system_profiler scan failed: {e}")
    
    def _networksetup_network_scan(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """Basic network scanning using networksetup"""
        try:
            result = run_command(['networksetup', '-listpreferredwirelessnetworks', 'Wi-Fi'])
            if result.returncode != 0:
                raise ExecutionFailedError('networksetup', 'listpreferredwirelessnetworks', result.returncode, result.stderr)
            
            # Parse networksetup output (limited information)
            networks = self._parse_networksetup_output(result.stdout)
            return networks
            
        except Exception as e:
            raise NetworkError(f"networksetup scan failed: {e}")
    
    def _networksetup_interface_control(self, interface: str, action: str, *args, **kwargs) -> bool:
        """Interface control using networksetup"""
        try:
            if action == 'up':
                result = run_command(['networksetup', '-setairportpower', interface, 'on'])
            elif action == 'down':
                result = run_command(['networksetup', '-setairportpower', interface, 'off'])
            else:
                raise InvalidInputError('action', action, 'up|down')
            
            return result.returncode == 0
            
        except Exception as e:
            raise InterfaceDownError(interface)
    
    def _ifconfig_interface_control(self, interface: str, action: str, *args, **kwargs) -> bool:
        """Interface control using ifconfig"""
        try:
            result = run_command(['sudo', 'ifconfig', interface, action])
            return result.returncode == 0
            
        except Exception as e:
            raise InterfaceDownError(interface)
    
    def _airodump_packet_capture(self, interface: str, target: str, *args, **kwargs) -> str:
        """Packet capture using airodump-ng"""
        try:
            output_file = f"/tmp/capture_{int(time.time())}"
            cmd = ['airodump-ng', '--bssid', target, '-w', output_file, interface]
            
            # This would normally run in background with timeout
            result = run_command(cmd, timeout=kwargs.get('timeout', 60))
            
            return f"{output_file}-01.cap"
            
        except Exception as e:
            raise CaptureFailedError(f"airodump-ng capture failed: {e}", interface)
    
    def _tcpdump_packet_capture(self, interface: str, target: str, *args, **kwargs) -> str:
        """Packet capture using tcpdump"""
        try:
            output_file = f"/tmp/capture_{int(time.time())}.pcap"
            cmd = ['sudo', 'tcpdump', '-i', interface, '-w', output_file, 
                   f'ether host {target}', '-c', '1000']
            
            result = run_command(cmd, timeout=kwargs.get('timeout', 60))
            
            return output_file
            
        except Exception as e:
            raise CaptureFailedError(f"tcpdump capture failed: {e}", interface)
    
    def _hashcat_gpu_crack(self, capture_file: str, wordlist: str, *args, **kwargs) -> Optional[str]:
        """Password cracking using hashcat with GPU"""
        try:
            cmd = ['hashcat', '-m', '22000', capture_file, wordlist, '--force']
            result = run_command(cmd, timeout=kwargs.get('timeout', 3600))
            
            # Parse hashcat output for found password
            return self._parse_hashcat_output(result.stdout)
            
        except Exception as e:
            raise ExecutionFailedError('hashcat', ' '.join(cmd), 1, str(e))
    
    def _hashcat_cpu_crack(self, capture_file: str, wordlist: str, *args, **kwargs) -> Optional[str]:
        """Password cracking using hashcat with CPU only"""
        try:
            cmd = ['hashcat', '-m', '22000', capture_file, wordlist, '--force', '-D', '1']
            result = run_command(cmd, timeout=kwargs.get('timeout', 3600))
            
            return self._parse_hashcat_output(result.stdout)
            
        except Exception as e:
            raise ExecutionFailedError('hashcat', ' '.join(cmd), 1, str(e))
    
    def _aircrack_ng_crack(self, capture_file: str, wordlist: str, *args, **kwargs) -> Optional[str]:
        """Password cracking using aircrack-ng"""
        try:
            cmd = ['aircrack-ng', '-w', wordlist, capture_file]
            result = run_command(cmd, timeout=kwargs.get('timeout', 3600))
            
            return self._parse_aircrack_output(result.stdout)
            
        except Exception as e:
            raise ExecutionFailedError('aircrack-ng', ' '.join(cmd), 1, str(e))
    
    def _homebrew_install(self, package: str, *args, **kwargs) -> bool:
        """Install package using Homebrew"""
        try:
            result = run_command(['brew', 'install', package])
            return result.returncode == 0
            
        except Exception as e:
            raise DependencyMissingError(package)
    
    def _manual_install_guide(self, package: str, *args, **kwargs) -> str:
        """Provide manual installation guide"""
        guides = {
            'aircrack-ng': "Visit https://aircrack-ng.org/ for installation instructions",
            'hashcat': "Visit https://hashcat.net/hashcat/ for installation instructions",
            'homebrew': "Visit https://brew.sh/ for Homebrew installation instructions"
        }
        
        return guides.get(package, f"Please install {package} manually")
    
    # Recovery procedure implementations
    def _recover_stuck_interface(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover stuck network interface"""
        try:
            interface = context.get('interface') if context else None
            if not interface:
                return False, "No interface specified for recovery"
            
            # Try to reset interface
            run_command(['sudo', 'ifconfig', interface, 'down'])
            time.sleep(2)
            run_command(['sudo', 'ifconfig', interface, 'up'])
            
            return True, f"Interface {interface} reset successfully"
            
        except Exception as e:
            return False, f"Interface recovery failed: {e}"
    
    def _recover_hanging_process(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover from hanging processes"""
        try:
            # Kill common hanging processes
            hanging_processes = ['airodump-ng', 'hashcat', 'aircrack-ng', 'tcpdump']
            killed_count = 0
            
            for process in hanging_processes:
                try:
                    result = run_command(['pkill', '-f', process])
                    if result.returncode == 0:
                        killed_count += 1
                except:
                    pass
            
            return True, f"Terminated {killed_count} hanging processes"
            
        except Exception as e:
            return False, f"Process recovery failed: {e}"
    
    def _recover_permission_issues(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover from permission issues"""
        try:
            # Check if running with sudo
            if os.geteuid() != 0:
                return False, "Restart application with sudo for elevated privileges"
            
            # Try to fix common permission issues
            temp_dirs = ['/tmp', '/var/tmp']
            for temp_dir in temp_dirs:
                try:
                    os.chmod(temp_dir, 0o1777)
                except:
                    pass
            
            return True, "Permission issues addressed"
            
        except Exception as e:
            return False, f"Permission recovery failed: {e}"
    
    def _recover_sip_restrictions(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Provide guidance for SIP restrictions"""
        return False, ("SIP is blocking the operation. Consider:\n"
                      "1. Using external WiFi adapter\n"
                      "2. Disabling SIP temporarily (not recommended)\n"
                      "3. Using alternative methods that don't require SIP bypass")
    
    def _recover_missing_dependencies(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover from missing dependencies"""
        try:
            if isinstance(error, DependencyMissingError):
                tool_name = error.tool_name
                
                # Try automatic installation
                success, _, method = self.execute_with_fallback(
                    'dependency_install', 
                    lambda: self._homebrew_install(tool_name),
                    tool_name
                )
                
                if success:
                    return True, f"Successfully installed {tool_name} using {method}"
                else:
                    return False, f"Could not install {tool_name}. Manual installation required."
            
            return False, "Unknown dependency issue"
            
        except Exception as e:
            return False, f"Dependency recovery failed: {e}"
    
    def _recover_failed_capture(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover from failed packet capture"""
        try:
            # Reset interface and try alternative capture method
            interface = context.get('interface') if context else None
            if interface:
                self._recover_stuck_interface(error, context)
            
            return True, "Capture recovery completed, try alternative capture method"
            
        except Exception as e:
            return False, f"Capture recovery failed: {e}"
    
    def _recover_system_state(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """Recover corrupted system state"""
        try:
            success = self.restore_system_state()
            if success:
                return True, "System state restored successfully"
            else:
                return False, "Could not restore system state"
                
        except Exception as e:
            return False, f"System state recovery failed: {e}"
    
    # Helper methods
    def _get_interface_states(self) -> Dict[str, str]:
        """Get current interface states"""
        states = {}
        try:
            result = run_command(['networksetup', '-listallhardwareports'])
            # Parse and store interface states
            # This is a simplified implementation
            states['wifi_power'] = 'on'  # Would get actual state
        except:
            pass
        return states
    
    def _get_network_configuration(self) -> Dict[str, Any]:
        """Get current network configuration"""
        config = {}
        try:
            # Get current network settings
            result = run_command(['networksetup', '-getinfo', 'Wi-Fi'])
            # Parse configuration
        except:
            pass
        return config
    
    def _get_relevant_processes(self) -> List[str]:
        """Get list of relevant running processes"""
        processes = []
        try:
            result = run_command(['pgrep', '-f', 'airodump|hashcat|aircrack'])
            if result.stdout:
                processes = result.stdout.strip().split('\n')
        except:
            pass
        return processes
    
    def _get_temporary_files(self) -> List[str]:
        """Get list of temporary files created by the application"""
        temp_files = []
        temp_patterns = ['/tmp/capture_*', '/tmp/wordlist_*', '/tmp/wifi_*']
        
        for pattern in temp_patterns:
            try:
                import glob
                temp_files.extend(glob.glob(pattern))
            except:
                pass
        
        return temp_files
    
    def _restore_interface_states(self, states: Dict[str, str]) -> None:
        """Restore interface states"""
        try:
            for interface, state in states.items():
                if interface == 'wifi_power':
                    run_command(['networksetup', '-setairportpower', 'Wi-Fi', state])
        except Exception as e:
            self.logger.warning(f"Could not restore interface states: {e}")
    
    def _cleanup_temporary_files(self, temp_files: List[str]) -> None:
        """Clean up temporary files"""
        for file_path in temp_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                self.logger.warning(f"Could not remove temporary file {file_path}: {e}")
    
    def _cleanup_processes(self, process_list: List[str]) -> None:
        """Clean up hanging processes"""
        for pid in process_list:
            try:
                run_command(['kill', '-TERM', pid])
            except:
                try:
                    run_command(['kill', '-KILL', pid])
                except:
                    pass
    
    def _cleanup_hanging_processes(self) -> None:
        """Clean up known hanging processes"""
        hanging_processes = ['airodump-ng', 'hashcat', 'aircrack-ng', 'tcpdump']
        for process in hanging_processes:
            try:
                run_command(['pkill', '-f', process])
            except:
                pass
    
    def _reset_interfaces_to_managed(self) -> None:
        """Reset all interfaces to managed mode"""
        try:
            # Get WiFi interface
            result = run_command(['networksetup', '-listallhardwareports'])
            # Reset to managed mode (simplified)
            run_command(['networksetup', '-setairportpower', 'Wi-Fi', 'off'])
            time.sleep(2)
            run_command(['networksetup', '-setairportpower', 'Wi-Fi', 'on'])
        except Exception as e:
            self.logger.warning(f"Could not reset interfaces: {e}")
    
    def _check_fallback_requirements(self, fallback: FallbackMethod) -> bool:
        """Check if fallback method requirements are met"""
        for requirement in fallback.requirements:
            if not shutil.which(requirement):
                return False
        return True
    
    # Output parsing methods (complete implementations)
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
            if 'Preferred Networks:' in line:
                in_network_section = True
                continue
            elif 'Available Networks:' in line:
                in_network_section = True
                continue
            elif line.startswith('AirPort Card Information:'):
                in_network_section = False
                continue
            
            if in_network_section and line:
                if ':' in line:
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
                    'bssid': 'unknown',
                    'channel': 'unknown',
                    'signal_strength': 'unknown',
                    'encryption': 'unknown',
                    'source': 'networksetup'
                })
        
        return networks
    
    def _parse_hashcat_output(self, output: str) -> Optional[str]:
        """Parse hashcat output to extract found password"""
        lines = output.split('\n')
        for line in lines:
            if ':' in line and 'Recovered' in output:
                # Look for password in hashcat output format
                parts = line.split(':')
                if len(parts) >= 2:
                    return parts[-1].strip()
        return None
    
    def _parse_aircrack_output(self, output: str) -> Optional[str]:
        """Parse aircrack-ng output to extract found password"""
        lines = output.split('\n')
        for line in lines:
            if 'KEY FOUND!' in line:
                # Extract password from aircrack output
                if '[' in line and ']' in line:
                    start = line.find('[') + 1
                    end = line.find(']')
                    return line[start:end].strip()
        return None


# Global recovery manager instance
_global_recovery_manager = None


def get_recovery_manager() -> RecoveryManager:
    """Get the global recovery manager instance"""
    global _global_recovery_manager
    if _global_recovery_manager is None:
        _global_recovery_manager = RecoveryManager()
    return _global_recovery_manager


def execute_with_fallback(operation: str, primary_method: Callable, *args, **kwargs) -> Tuple[bool, Any, Optional[str]]:
    """Convenience function to execute operation with fallback"""
    return get_recovery_manager().execute_with_fallback(operation, primary_method, *args, **kwargs)


def save_system_state() -> str:
    """Convenience function to save system state"""
    return get_recovery_manager().save_system_state()


def restore_system_state(state_id: Optional[str] = None) -> bool:
    """Convenience function to restore system state"""
    return get_recovery_manager().restore_system_state(state_id)
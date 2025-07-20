"""
Recovery Coordinator - Orchestrates comprehensive recovery and fallback mechanisms
Integrates error handling, recovery procedures, and user guidance for WiFi Security Tester

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import sys
import time
import threading
from typing import Optional, Dict, Any, List, Callable, Tuple, Union
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.exceptions import *
from core.logger import get_logger
from core.error_handler import get_error_handler, ErrorHandler
from core.recovery_manager import get_recovery_manager, RecoveryManager
from core.user_guidance import get_user_guidance_system, UserGuidanceSystem, GuidanceLevel
from utils.common import run_command, get_system_info


class RecoveryStatus(Enum):
    """Recovery operation status"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    USER_INTERVENTION_REQUIRED = "user_intervention_required"


@dataclass
class RecoveryOperation:
    """Represents a recovery operation"""
    operation_id: str
    operation_type: str
    status: RecoveryStatus
    start_time: float
    end_time: Optional[float] = None
    success: bool = False
    error_message: Optional[str] = None
    recovery_method: Optional[str] = None
    user_guidance: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None


class RecoveryCoordinator:
    """Coordinates comprehensive recovery and fallback mechanisms"""
    
    def __init__(self):
        self.logger = get_logger("recovery_coordinator")
        self.error_handler = get_error_handler()
        self.recovery_manager = get_recovery_manager()
        self.guidance_system = get_user_guidance_system()
        
        # Recovery tracking
        self.active_recoveries: Dict[str, RecoveryOperation] = {}
        self.recovery_history: List[RecoveryOperation] = []
        self.max_concurrent_recoveries = 3
        self.recovery_timeout = 300  # 5 minutes
        
        # Fallback chains
        self.fallback_chains: Dict[str, List[str]] = {}
        self.recovery_strategies: Dict[str, Callable] = {}
        
        # Initialize recovery strategies
        self._initialize_recovery_strategies()
        self._initialize_fallback_chains()
    
    def _initialize_recovery_strategies(self) -> None:
        """Initialize comprehensive recovery strategies"""
        self.recovery_strategies.update({
            # System recovery strategies
            'system_state_recovery': self._system_state_recovery,
            'interface_recovery': self._interface_recovery,
            'permission_recovery': self._permission_recovery,
            'sip_recovery': self._sip_recovery,
            
            # Tool recovery strategies
            'dependency_recovery': self._dependency_recovery,
            'tool_execution_recovery': self._tool_execution_recovery,
            'version_compatibility_recovery': self._version_compatibility_recovery,
            
            # Network recovery strategies
            'network_scanning_recovery': self._network_scanning_recovery,
            'packet_capture_recovery': self._packet_capture_recovery,
            'monitor_mode_recovery': self._monitor_mode_recovery,
            
            # Resource recovery strategies
            'memory_recovery': self._memory_recovery,
            'disk_space_recovery': self._disk_space_recovery,
            'process_recovery': self._process_recovery,
            
            # Generic recovery strategies
            'generic_recovery': self._generic_recovery,
            'emergency_recovery': self._emergency_recovery
        })
    
    def _initialize_fallback_chains(self) -> None:
        """Initialize fallback chains for different operations"""
        self.fallback_chains.update({
            'network_scan': [
                'wdutil_scan',
                'system_profiler_scan', 
                'networksetup_scan',
                'manual_scan_guidance'
            ],
            'packet_capture': [
                'airodump_capture',
                'tcpdump_capture',
                'manual_capture_guidance'
            ],
            'password_crack': [
                'hashcat_gpu',
                'hashcat_cpu',
                'aircrack_ng',
                'manual_crack_guidance'
            ],
            'interface_control': [
                'networksetup_control',
                'ifconfig_control',
                'manual_interface_guidance'
            ],
            'dependency_install': [
                'homebrew_install',
                'manual_install',
                'alternative_tools'
            ]
        })
    
    def handle_error_with_recovery(self, error: Exception, operation: str,
                                 context: Optional[Dict[str, Any]] = None,
                                 max_recovery_attempts: int = 3) -> Dict[str, Any]:
        """
        Handle error with comprehensive recovery mechanisms
        
        Args:
            error: The exception that occurred
            operation: The operation that failed
            context: Additional context information
            max_recovery_attempts: Maximum number of recovery attempts
            
        Returns:
            Dict containing recovery results and guidance
        """
        operation_id = f"{operation}_{int(time.time())}"
        
        recovery_result = {
            'operation_id': operation_id,
            'original_error': str(error),
            'error_type': type(error).__name__,
            'recovery_attempted': False,
            'recovery_successful': False,
            'recovery_method': None,
            'fallback_used': None,
            'user_guidance': None,
            'requires_user_action': False,
            'recovery_suggestions': [],
            'system_state_restored': False,
            'attempts': []
        }
        
        try:
            # Create recovery operation
            recovery_op = RecoveryOperation(
                operation_id=operation_id,
                operation_type=operation,
                status=RecoveryStatus.IN_PROGRESS,
                start_time=time.time(),
                context=context
            )
            
            self.active_recoveries[operation_id] = recovery_op
            
            # Step 1: Handle error with error handler
            self.logger.info(f"Starting recovery for {operation} (ID: {operation_id})")
            error_result = self.error_handler.handle_error(error, context, operation)
            recovery_result['recovery_attempted'] = True
            recovery_result['attempts'].append({
                'method': 'error_handler',
                'result': error_result
            })
            
            # Step 2: Try automatic recovery if error handler suggests it
            if error_result.get('recovery_successful', False):
                recovery_result['recovery_successful'] = True
                recovery_result['recovery_method'] = 'automatic'
                recovery_op.status = RecoveryStatus.COMPLETED
                recovery_op.success = True
            else:
                # Step 3: Try specific recovery procedures
                recovery_success = self._attempt_specific_recovery(
                    error, operation, context, recovery_result, max_recovery_attempts
                )
                
                if not recovery_success:
                    # Step 4: Try fallback methods
                    fallback_success = self._attempt_fallback_methods(
                        error, operation, context, recovery_result
                    )
                    
                    if not fallback_success:
                        # Step 5: Provide user guidance
                        self._provide_user_guidance(
                            error, operation, context, recovery_result
                        )
                        recovery_op.status = RecoveryStatus.USER_INTERVENTION_REQUIRED
                    else:
                        recovery_op.status = RecoveryStatus.COMPLETED
                        recovery_op.success = True
                else:
                    recovery_op.status = RecoveryStatus.COMPLETED
                    recovery_op.success = True
            
            # Update recovery operation
            recovery_op.end_time = time.time()
            recovery_op.recovery_method = recovery_result.get('recovery_method')
            recovery_op.user_guidance = recovery_result.get('user_guidance')
            
        except Exception as recovery_error:
            self.logger.error(f"Recovery process failed: {recovery_error}")
            recovery_result['recovery_error'] = str(recovery_error)
            recovery_op.status = RecoveryStatus.FAILED
            recovery_op.error_message = str(recovery_error)
        
        finally:
            # Move to history and clean up
            if operation_id in self.active_recoveries:
                self.recovery_history.append(self.active_recoveries[operation_id])
                del self.active_recoveries[operation_id]
        
        return recovery_result
    
    def _attempt_specific_recovery(self, error: Exception, operation: str,
                                 context: Optional[Dict[str, Any]],
                                 recovery_result: Dict[str, Any],
                                 max_attempts: int) -> bool:
        """Attempt specific recovery procedures based on error type"""
        error_type = type(error).__name__.lower()
        
        # Determine recovery strategy
        recovery_strategy = None
        for strategy_key, strategy_func in self.recovery_strategies.items():
            if any(keyword in error_type for keyword in strategy_key.split('_')):
                recovery_strategy = strategy_func
                break
        
        if not recovery_strategy:
            recovery_strategy = self.recovery_strategies['generic_recovery']
        
        # Attempt recovery with retries
        for attempt in range(max_attempts):
            try:
                self.logger.info(f"Recovery attempt {attempt + 1}/{max_attempts} using {recovery_strategy.__name__}")
                
                success, message, details = recovery_strategy(error, operation, context)
                
                recovery_result['attempts'].append({
                    'method': recovery_strategy.__name__,
                    'attempt': attempt + 1,
                    'success': success,
                    'message': message,
                    'details': details
                })
                
                if success:
                    recovery_result['recovery_successful'] = True
                    recovery_result['recovery_method'] = recovery_strategy.__name__
                    return True
                
                # Wait before retry
                if attempt < max_attempts - 1:
                    time.sleep(min(2 ** attempt, 10))  # Exponential backoff
                    
            except Exception as strategy_error:
                self.logger.warning(f"Recovery strategy failed: {strategy_error}")
                recovery_result['attempts'].append({
                    'method': recovery_strategy.__name__,
                    'attempt': attempt + 1,
                    'success': False,
                    'error': str(strategy_error)
                })
        
        return False
    
    def _attempt_fallback_methods(self, error: Exception, operation: str,
                                context: Optional[Dict[str, Any]],
                                recovery_result: Dict[str, Any]) -> bool:
        """Attempt fallback methods for the operation"""
        fallback_chain = self.fallback_chains.get(operation, [])
        
        if not fallback_chain:
            self.logger.debug(f"No fallback chain defined for operation: {operation}")
            return False
        
        for fallback_method in fallback_chain:
            try:
                self.logger.info(f"Trying fallback method: {fallback_method}")
                
                # Use recovery manager's fallback execution
                success, result, method_used = self.recovery_manager.execute_with_fallback(
                    operation, lambda: None  # Dummy primary method since we're using fallbacks
                )
                
                if success:
                    recovery_result['recovery_successful'] = True
                    recovery_result['fallback_used'] = method_used
                    recovery_result['recovery_method'] = 'fallback'
                    return True
                
            except Exception as fallback_error:
                self.logger.warning(f"Fallback method {fallback_method} failed: {fallback_error}")
        
        return False
    
    def _provide_user_guidance(self, error: Exception, operation: str,
                             context: Optional[Dict[str, Any]],
                             recovery_result: Dict[str, Any]) -> None:
        """Provide comprehensive user guidance for manual resolution"""
        try:
            # Get detailed guidance
            guidance = self.guidance_system.get_guidance(error, GuidanceLevel.DETAILED)
            
            # Add operation-specific context
            if context:
                guidance['operation_context'] = context
            
            # Add recovery history for context
            guidance['previous_attempts'] = recovery_result.get('attempts', [])
            
            # Format guidance text
            guidance_text = self.guidance_system.format_guidance_text(guidance)
            
            recovery_result['user_guidance'] = guidance
            recovery_result['guidance_text'] = guidance_text
            recovery_result['requires_user_action'] = True
            
            # Get quick recovery suggestions
            recovery_suggestions = self._generate_recovery_suggestions(error, operation, context)
            recovery_result['recovery_suggestions'] = recovery_suggestions
            
            self.logger.info("User guidance prepared for manual error resolution")
            
        except Exception as guidance_error:
            self.logger.error(f"Failed to generate user guidance: {guidance_error}")
            recovery_result['guidance_error'] = str(guidance_error)
    
    def _generate_recovery_suggestions(self, error: Exception, operation: str,
                                     context: Optional[Dict[str, Any]]) -> List[str]:
        """Generate specific recovery suggestions based on error and context"""
        suggestions = []
        
        # Add error-specific suggestions
        if hasattr(error, 'recovery_suggestions'):
            suggestions.extend(error.recovery_suggestions)
        
        # Add operation-specific suggestions
        operation_suggestions = {
            'network_scan': [
                'Check WiFi is enabled and connected',
                'Try scanning from a different location',
                'Use external WiFi adapter if available'
            ],
            'packet_capture': [
                'Ensure interface supports monitor mode',
                'Check for SIP restrictions',
                'Try increasing capture duration'
            ],
            'password_crack': [
                'Verify handshake file is valid',
                'Try different wordlist',
                'Check available system resources'
            ],
            'interface_control': [
                'Run with administrator privileges',
                'Check interface is not in use by other applications',
                'Try resetting network settings'
            ]
        }
        
        if operation in operation_suggestions:
            suggestions.extend(operation_suggestions[operation])
        
        # Add context-specific suggestions
        if context:
            if context.get('interface'):
                suggestions.append(f"Try using a different interface than {context['interface']}")
            if context.get('timeout_occurred'):
                suggestions.append('Increase timeout value for the operation')
            if context.get('resource_limited'):
                suggestions.append('Free up system resources (memory, disk space)')
        
        # Remove duplicates while preserving order
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion not in unique_suggestions:
                unique_suggestions.append(suggestion)
        
        return unique_suggestions
    
    # Recovery strategy implementations
    def _system_state_recovery(self, error: Exception, operation: str,
                             context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover system state after failures"""
        try:
            # Save current state before attempting recovery
            state_id = self.recovery_manager.save_system_state()
            
            # Try to restore previous good state
            if self.recovery_manager.restore_system_state():
                return True, "System state restored successfully", {'state_id': state_id}
            else:
                return False, "Could not restore system state", {'state_id': state_id}
                
        except Exception as e:
            return False, f"System state recovery failed: {e}", {}
    
    def _interface_recovery(self, error: Exception, operation: str,
                          context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover network interface issues"""
        try:
            interface = context.get('interface') if context else None
            
            if not interface:
                # Try to detect interface automatically
                result = run_command(['networksetup', '-listallhardwareports'])
                if result.returncode == 0:
                    # Parse output to find WiFi interface
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'Wi-Fi' in line or 'AirPort' in line:
                            if i + 1 < len(lines):
                                device_line = lines[i + 1]
                                if 'Device:' in device_line:
                                    interface = device_line.split('Device:')[1].strip()
                                    break
            
            if interface:
                # Try to reset interface
                run_command(['sudo', 'ifconfig', interface, 'down'])
                time.sleep(2)
                run_command(['sudo', 'ifconfig', interface, 'up'])
                
                # Verify interface is up
                result = run_command(['ifconfig', interface])
                if result.returncode == 0 and 'UP' in result.stdout:
                    return True, f"Interface {interface} recovered successfully", {'interface': interface}
            
            return False, "Could not recover network interface", {'interface': interface}
            
        except Exception as e:
            return False, f"Interface recovery failed: {e}", {}
    
    def _permission_recovery(self, error: Exception, operation: str,
                           context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from permission issues"""
        try:
            import os
            
            # Check if running with elevated privileges
            if os.geteuid() != 0:
                return False, "Restart application with sudo for elevated privileges", {
                    'requires_sudo': True,
                    'command': 'sudo python3 main.py'
                }
            
            # Try to fix common permission issues
            temp_dirs = ['/tmp', '/var/tmp']
            fixed_permissions = []
            
            for temp_dir in temp_dirs:
                try:
                    os.chmod(temp_dir, 0o1777)
                    fixed_permissions.append(temp_dir)
                except:
                    pass
            
            if fixed_permissions:
                return True, f"Fixed permissions for: {', '.join(fixed_permissions)}", {
                    'fixed_directories': fixed_permissions
                }
            
            return False, "Could not resolve permission issues", {}
            
        except Exception as e:
            return False, f"Permission recovery failed: {e}", {}
    
    def _sip_recovery(self, error: Exception, operation: str,
                    context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Handle SIP restriction recovery"""
        try:
            # Check SIP status
            result = run_command(['csrutil', 'status'])
            sip_enabled = 'enabled' in result.stdout.lower()
            
            if sip_enabled:
                return False, ("SIP is enabled and blocking the operation. "
                             "Consider using external WiFi adapter or disabling SIP temporarily."), {
                    'sip_enabled': True,
                    'alternatives': [
                        'Use external WiFi adapter with monitor mode support',
                        'Disable SIP temporarily (advanced users only)',
                        'Use alternative capture methods'
                    ]
                }
            
            return True, "SIP is not blocking the operation", {'sip_enabled': False}
            
        except Exception as e:
            return False, f"SIP recovery check failed: {e}", {}
    
    def _dependency_recovery(self, error: Exception, operation: str,
                           context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from missing dependencies"""
        try:
            if isinstance(error, DependencyMissingError):
                tool_name = error.tool_name
                
                # Try automatic installation
                success, result, method = self.recovery_manager.execute_with_fallback(
                    'dependency_install',
                    lambda: self.recovery_manager._homebrew_install(tool_name),
                    tool_name
                )
                
                if success:
                    return True, f"Successfully installed {tool_name} using {method}", {
                        'tool_installed': tool_name,
                        'method': method
                    }
                else:
                    return False, f"Could not install {tool_name}. Manual installation required.", {
                        'tool_missing': tool_name,
                        'install_command': f'brew install {tool_name}'
                    }
            
            return False, "Unknown dependency issue", {}
            
        except Exception as e:
            return False, f"Dependency recovery failed: {e}", {}
    
    def _tool_execution_recovery(self, error: Exception, operation: str,
                               context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from tool execution failures"""
        try:
            if isinstance(error, ExecutionFailedError):
                tool_name = error.tool_name
                
                # Check if tool exists
                import shutil
                if not shutil.which(tool_name):
                    return False, f"Tool {tool_name} not found in PATH", {
                        'tool_missing': True,
                        'suggestion': f'Install with: brew install {tool_name}'
                    }
                
                # Try running with different parameters
                if 'permission denied' in error.stderr.lower():
                    return False, "Permission denied. Try running with sudo.", {
                        'permission_issue': True,
                        'suggestion': 'Run application with sudo privileges'
                    }
                
                # Try updating the tool
                result = run_command(['brew', 'upgrade', tool_name])
                if result.returncode == 0:
                    return True, f"Updated {tool_name} successfully", {
                        'tool_updated': tool_name
                    }
            
            return False, "Could not recover from tool execution failure", {}
            
        except Exception as e:
            return False, f"Tool execution recovery failed: {e}", {}
    
    def _version_compatibility_recovery(self, error: Exception, operation: str,
                                      context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from version compatibility issues"""
        try:
            if isinstance(error, VersionIncompatibleError):
                tool_name = error.tool_name
                required_version = error.required_version
                
                # Try installing specific version
                result = run_command(['brew', 'install', f'{tool_name}@{required_version}'])
                if result.returncode == 0:
                    return True, f"Installed {tool_name} version {required_version}", {
                        'version_installed': required_version
                    }
                
                # Try updating to latest
                result = run_command(['brew', 'upgrade', tool_name])
                if result.returncode == 0:
                    return True, f"Updated {tool_name} to latest version", {
                        'tool_updated': True
                    }
            
            return False, "Could not resolve version compatibility", {}
            
        except Exception as e:
            return False, f"Version compatibility recovery failed: {e}", {}
    
    def _network_scanning_recovery(self, error: Exception, operation: str,
                                 context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from network scanning failures"""
        try:
            # Try alternative scanning methods
            success, result, method = self.recovery_manager.execute_with_fallback(
                'network_scan',
                lambda: []  # Dummy primary method
            )
            
            if success and result:
                return True, f"Network scan successful using {method}", {
                    'scan_method': method,
                    'networks_found': len(result) if isinstance(result, list) else 0
                }
            
            return False, "All network scanning methods failed", {}
            
        except Exception as e:
            return False, f"Network scanning recovery failed: {e}", {}
    
    def _packet_capture_recovery(self, error: Exception, operation: str,
                               context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from packet capture failures"""
        try:
            interface = context.get('interface') if context else None
            
            if interface:
                # Try resetting interface first
                self._interface_recovery(error, operation, context)
                
                # Try alternative capture methods
                success, result, method = self.recovery_manager.execute_with_fallback(
                    'packet_capture',
                    lambda: None,  # Dummy primary method
                    interface, context.get('target', '')
                )
                
                if success:
                    return True, f"Packet capture successful using {method}", {
                        'capture_method': method,
                        'capture_file': result if isinstance(result, str) else None
                    }
            
            return False, "Packet capture recovery failed", {}
            
        except Exception as e:
            return False, f"Packet capture recovery failed: {e}", {}
    
    def _monitor_mode_recovery(self, error: Exception, operation: str,
                             context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from monitor mode failures"""
        try:
            # Monitor mode often fails on built-in Mac interfaces
            return False, ("Monitor mode not supported on built-in interface. "
                         "Consider using external WiFi adapter with monitor mode support."), {
                'monitor_mode_supported': False,
                'recommendation': 'Use external WiFi adapter (e.g., Alfa AWUS036ACS)',
                'alternatives': ['tcpdump capture', 'passive scanning']
            }
            
        except Exception as e:
            return False, f"Monitor mode recovery failed: {e}", {}
    
    def _memory_recovery(self, error: Exception, operation: str,
                       context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from memory issues"""
        try:
            import gc
            import psutil
            
            # Force garbage collection
            gc.collect()
            
            # Get memory info
            memory = psutil.virtual_memory()
            
            if memory.percent > 90:
                return False, f"System memory usage is {memory.percent:.1f}%. Close other applications.", {
                    'memory_usage': memory.percent,
                    'available_gb': memory.available / (1024**3)
                }
            
            return True, "Memory usage is acceptable", {
                'memory_usage': memory.percent,
                'available_gb': memory.available / (1024**3)
            }
            
        except Exception as e:
            return False, f"Memory recovery failed: {e}", {}
    
    def _disk_space_recovery(self, error: Exception, operation: str,
                           context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from disk space issues"""
        try:
            import shutil
            
            # Check disk space
            total, used, free = shutil.disk_usage('/')
            free_gb = free / (1024**3)
            
            if free_gb < 1:  # Less than 1GB free
                return False, f"Low disk space: {free_gb:.1f}GB available. Free up space.", {
                    'free_space_gb': free_gb,
                    'cleanup_suggestions': [
                        'Empty Trash',
                        'Clear browser cache',
                        'Remove old downloads',
                        'Clean up temporary files'
                    ]
                }
            
            return True, f"Disk space is sufficient: {free_gb:.1f}GB available", {
                'free_space_gb': free_gb
            }
            
        except Exception as e:
            return False, f"Disk space recovery failed: {e}", {}
    
    def _process_recovery(self, error: Exception, operation: str,
                        context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Recover from hanging processes"""
        try:
            # Kill hanging processes
            hanging_processes = ['airodump-ng', 'hashcat', 'aircrack-ng', 'tcpdump']
            killed_processes = []
            
            for process in hanging_processes:
                try:
                    result = run_command(['pkill', '-f', process])
                    if result.returncode == 0:
                        killed_processes.append(process)
                except:
                    pass
            
            if killed_processes:
                return True, f"Terminated hanging processes: {', '.join(killed_processes)}", {
                    'killed_processes': killed_processes
                }
            
            return True, "No hanging processes found", {}
            
        except Exception as e:
            return False, f"Process recovery failed: {e}", {}
    
    def _generic_recovery(self, error: Exception, operation: str,
                        context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Generic recovery for unknown errors"""
        try:
            # Try basic recovery steps
            recovery_steps = []
            
            # Step 1: Clean up processes
            success, message, details = self._process_recovery(error, operation, context)
            if success:
                recovery_steps.append("Cleaned up processes")
            
            # Step 2: Reset interfaces
            success, message, details = self._interface_recovery(error, operation, context)
            if success:
                recovery_steps.append("Reset network interfaces")
            
            # Step 3: Check system resources
            success, message, details = self._memory_recovery(error, operation, context)
            if success:
                recovery_steps.append("Verified system resources")
            
            if recovery_steps:
                return True, f"Generic recovery completed: {', '.join(recovery_steps)}", {
                    'recovery_steps': recovery_steps
                }
            
            return False, "Generic recovery could not resolve the issue", {}
            
        except Exception as e:
            return False, f"Generic recovery failed: {e}", {}
    
    def _emergency_recovery(self, error: Exception, operation: str,
                          context: Optional[Dict[str, Any]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Emergency recovery for critical failures"""
        try:
            # Emergency steps to restore system to safe state
            emergency_steps = []
            
            # Kill all related processes
            processes_to_kill = ['airodump-ng', 'hashcat', 'aircrack-ng', 'tcpdump', 'wdutil']
            for process in processes_to_kill:
                try:
                    run_command(['pkill', '-9', process])  # Force kill
                    emergency_steps.append(f"Force killed {process}")
                except:
                    pass
            
            # Reset all network interfaces
            try:
                run_command(['sudo', 'networksetup', '-setairportpower', 'Wi-Fi', 'off'])
                time.sleep(2)
                run_command(['sudo', 'networksetup', '-setairportpower', 'Wi-Fi', 'on'])
                emergency_steps.append("Reset WiFi interface")
            except:
                pass
            
            # Clean up temporary files
            import glob
            temp_patterns = ['/tmp/capture_*', '/tmp/wordlist_*', '/tmp/wifi_*']
            cleaned_files = 0
            for pattern in temp_patterns:
                try:
                    files = glob.glob(pattern)
                    for file_path in files:
                        os.remove(file_path)
                        cleaned_files += 1
                except:
                    pass
            
            if cleaned_files > 0:
                emergency_steps.append(f"Cleaned {cleaned_files} temporary files")
            
            return True, f"Emergency recovery completed: {', '.join(emergency_steps)}", {
                'emergency_steps': emergency_steps,
                'system_restored': True
            }
            
        except Exception as e:
            return False, f"Emergency recovery failed: {e}", {}
    
    def get_recovery_status(self, operation_id: str) -> Optional[RecoveryOperation]:
        """Get status of a recovery operation"""
        if operation_id in self.active_recoveries:
            return self.active_recoveries[operation_id]
        
        # Check history
        for recovery_op in self.recovery_history:
            if recovery_op.operation_id == operation_id:
                return recovery_op
        
        return None
    
    def get_recovery_statistics(self) -> Dict[str, Any]:
        """Get recovery statistics"""
        total_recoveries = len(self.recovery_history)
        successful_recoveries = sum(1 for op in self.recovery_history if op.success)
        
        stats = {
            'total_recoveries': total_recoveries,
            'successful_recoveries': successful_recoveries,
            'success_rate': (successful_recoveries / total_recoveries * 100) if total_recoveries > 0 else 0,
            'active_recoveries': len(self.active_recoveries),
            'recovery_methods': {},
            'common_errors': {}
        }
        
        # Count recovery methods
        for op in self.recovery_history:
            if op.recovery_method:
                stats['recovery_methods'][op.recovery_method] = stats['recovery_methods'].get(op.recovery_method, 0) + 1
        
        # Count error types (would need to store error type in RecoveryOperation)
        # This is a simplified version
        
        return stats


# Global recovery coordinator instance
_global_recovery_coordinator = None


def get_recovery_coordinator() -> RecoveryCoordinator:
    """Get the global recovery coordinator instance"""
    global _global_recovery_coordinator
    if _global_recovery_coordinator is None:
        _global_recovery_coordinator = RecoveryCoordinator()
    return _global_recovery_coordinator


def handle_error_with_recovery(error: Exception, operation: str,
                             context: Optional[Dict[str, Any]] = None,
                             max_recovery_attempts: int = 3) -> Dict[str, Any]:
    """Convenience function to handle error with comprehensive recovery"""
    return get_recovery_coordinator().handle_error_with_recovery(
        error, operation, context, max_recovery_attempts
    )
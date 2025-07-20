"""
Security Manager - Manages system security, privileges, and ethical usage enforcement
Handles SIP status checking, privilege management, and ethical usage compliance

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import os
import sys
import getpass
import time
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.logger import get_logger


class SecurityManager:
    """Manages system security, privileges, and ethical usage enforcement"""
    
    def __init__(self):
        self.logger = get_logger("security_manager")
        self.sip_status_cache = None
        self.sip_cache_timestamp = None
        self.cache_duration = 300  # 5 minutes cache for SIP status
        self.audit_log_path = Path("logs/security_audit.log")
        self.consent_file_path = Path("logs/user_consent.json")
        self.suspicious_activity_threshold = 10  # Max operations per minute
        self.operation_history = []
        
        # Ethical usage enforcement
        self.legal_warnings_shown = False
        self.user_consent_given = False
        self.consent_timestamp = None
        self.suspicious_activity_detected = False
        
        # Ensure audit log directory exists
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize audit logging
        self._initialize_audit_logging()
        
        # Load existing consent if available
        self._load_user_consent()
    
    def _initialize_audit_logging(self):
        """Initialize security audit logging system"""
        try:
            if not self.audit_log_path.exists():
                self.audit_log_path.touch()
                self.logger.info(f"Created security audit log: {self.audit_log_path}")
            
            # Log initialization
            self._log_security_event("SYSTEM", "Security Manager initialized", {
                "timestamp": datetime.now().isoformat(),
                "user": getpass.getuser(),
                "pid": os.getpid()
            })
            
        except Exception as e:
            self.logger.error(f"Error initializing audit logging: {e}")
    
    def check_sip_status(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Check System Integrity Protection (SIP) status using csrutil
        
        Returns:
            Tuple[bool, Dict]: (success, sip_info)
        """
        try:
            # Check cache first
            current_time = time.time()
            if (self.sip_status_cache and self.sip_cache_timestamp and 
                current_time - self.sip_cache_timestamp < self.cache_duration):
                self.logger.debug("Returning cached SIP status")
                return True, self.sip_status_cache
            
            self.logger.info("Checking SIP status using csrutil...")
            
            # Run csrutil status command
            result = subprocess.run(
                ['csrutil', 'status'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            sip_info = {
                'enabled': False,
                'status_text': '',
                'detailed_status': {},
                'restrictions': [],
                'recommendations': [],
                'last_checked': datetime.now().isoformat()
            }
            
            if result.returncode == 0:
                output = result.stdout.strip()
                sip_info['status_text'] = output
                
                # Parse SIP status
                if 'System Integrity Protection status: enabled' in output.lower():
                    sip_info['enabled'] = True
                    self.logger.info("SIP is enabled")
                elif 'System Integrity Protection status: disabled' in output.lower():
                    sip_info['enabled'] = False
                    self.logger.warning("SIP is disabled")
                else:
                    # Try to parse partial status
                    sip_info['enabled'] = 'enabled' in output.lower()
                    self.logger.warning(f"Unclear SIP status: {output}")
                
                # Parse detailed configuration if available
                self._parse_detailed_sip_status(output, sip_info)
                
            else:
                error_msg = result.stderr.strip() if result.stderr else f"csrutil failed with code {result.returncode}"
                self.logger.error(f"Failed to check SIP status: {error_msg}")
                
                sip_info['error'] = error_msg
                sip_info['enabled'] = True  # Assume enabled if we can't check
                sip_info['status_text'] = f"Could not determine SIP status: {error_msg}"
            
            # Add restrictions and recommendations based on SIP status
            self._add_sip_restrictions_and_recommendations(sip_info)
            
            # Cache the result
            self.sip_status_cache = sip_info
            self.sip_cache_timestamp = current_time
            
            # Log security event
            self._log_security_event("SIP_CHECK", "SIP status checked", {
                "sip_enabled": sip_info['enabled'],
                "status": sip_info['status_text']
            })
            
            return True, sip_info
            
        except subprocess.TimeoutExpired:
            error_msg = "Timeout checking SIP status"
            self.logger.error(error_msg)
            return False, {"error": error_msg, "enabled": True}
        except FileNotFoundError:
            error_msg = "csrutil command not found - may not be available on this macOS version"
            self.logger.error(error_msg)
            return False, {"error": error_msg, "enabled": True}
        except Exception as e:
            error_msg = f"Error checking SIP status: {e}"
            self.logger.error(error_msg)
            return False, {"error": error_msg, "enabled": True}
    
    def _parse_detailed_sip_status(self, output: str, sip_info: Dict[str, Any]):
        """
        Parse detailed SIP configuration from csrutil output
        
        Args:
            output (str): csrutil command output
            sip_info (Dict): SIP information dictionary to update
        """
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Look for configuration details
                if ':' in line and ('enabled' in line.lower() or 'disabled' in line.lower()):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        sip_info['detailed_status'][key] = value
                
                # Look for specific restrictions
                if 'filesystem protections' in line.lower():
                    if 'enabled' in line.lower():
                        sip_info['restrictions'].append("Filesystem protections enabled")
                    else:
                        sip_info['restrictions'].append("Filesystem protections disabled")
                
                if 'kext signing' in line.lower():
                    if 'enabled' in line.lower():
                        sip_info['restrictions'].append("Kernel extension signing required")
                    else:
                        sip_info['restrictions'].append("Kernel extension signing disabled")
                
                if 'nvram protections' in line.lower():
                    if 'enabled' in line.lower():
                        sip_info['restrictions'].append("NVRAM protections enabled")
                    else:
                        sip_info['restrictions'].append("NVRAM protections disabled")
            
        except Exception as e:
            self.logger.warning(f"Error parsing detailed SIP status: {e}")
    
    def _add_sip_restrictions_and_recommendations(self, sip_info: Dict[str, Any]):
        """
        Add SIP-related restrictions and recommendations
        
        Args:
            sip_info (Dict): SIP information dictionary to update
        """
        try:
            if sip_info['enabled']:
                # Add common SIP restrictions
                sip_info['restrictions'].extend([
                    "Cannot modify system files and directories",
                    "Cannot load unsigned kernel extensions",
                    "Cannot attach debugger to system processes",
                    "Cannot modify NVRAM variables",
                    "Limited access to system frameworks"
                ])
                
                # Add recommendations for SIP-enabled systems
                sip_info['recommendations'].extend([
                    "Use alternative methods that don't require system modification",
                    "Consider using built-in macOS tools when possible",
                    "Some WiFi monitoring features may be limited",
                    "Packet capture may require different approaches",
                    "Monitor mode switching may not work on all interfaces"
                ])
                
                # Add specific WiFi security testing recommendations
                sip_info['recommendations'].extend([
                    "Use wdutil instead of deprecated airport utility",
                    "Prefer tcpdump over airodump-ng for packet capture",
                    "Use networksetup for interface management",
                    "Consider USB WiFi adapters for monitor mode"
                ])
                
            else:
                # SIP is disabled - add security warnings
                sip_info['recommendations'].extend([
                    "WARNING: SIP is disabled - system is less secure",
                    "Consider re-enabling SIP after testing: csrutil enable",
                    "More WiFi testing features available with SIP disabled",
                    "Exercise caution when modifying system components"
                ])
            
        except Exception as e:
            self.logger.error(f"Error adding SIP restrictions and recommendations: {e}")
    
    def get_sip_alternative_methods(self, operation: str) -> List[str]:
        """
        Get alternative methods for operations that may be blocked by SIP
        
        Args:
            operation (str): The operation that might be blocked
            
        Returns:
            List[str]: List of alternative methods
        """
        try:
            alternatives = {
                'monitor_mode': [
                    "Use USB WiFi adapter with monitor mode support",
                    "Use tcpdump with appropriate filters instead of airodump-ng",
                    "Use wdutil for network scanning instead of monitor mode",
                    "Consider using Wireshark with proper permissions"
                ],
                'packet_capture': [
                    "Use tcpdump with sudo privileges",
                    "Use built-in packet capture tools",
                    "Capture on specific interfaces only",
                    "Use network analysis tools that don't require raw sockets"
                ],
                'interface_modification': [
                    "Use networksetup command-line tool",
                    "Use System Preferences Network panel",
                    "Use ifconfig with appropriate permissions",
                    "Consider using virtual interfaces"
                ],
                'system_file_access': [
                    "Use user-space alternatives",
                    "Work with copies in user directories",
                    "Use APIs instead of direct file access",
                    "Request specific permissions through proper channels"
                ]
            }
            
            operation_lower = operation.lower()
            for key, methods in alternatives.items():
                if key in operation_lower or operation_lower in key:
                    self.logger.info(f"Found {len(methods)} alternative methods for {operation}")
                    return methods
            
            # Generic alternatives
            generic_alternatives = [
                "Use built-in macOS tools when possible",
                "Request administrator privileges if needed",
                "Use user-space alternatives",
                "Consider different approach that doesn't require system modification"
            ]
            
            self.logger.info(f"Returning generic alternatives for {operation}")
            return generic_alternatives
            
        except Exception as e:
            self.logger.error(f"Error getting alternative methods for {operation}: {e}")
            return ["Consider alternative approaches or consult documentation"]
    
    def generate_sip_warnings(self, operation: str) -> List[str]:
        """
        Generate SIP-related warnings for specific operations
        
        Args:
            operation (str): The operation being attempted
            
        Returns:
            List[str]: List of warnings
        """
        try:
            success, sip_info = self.check_sip_status()
            
            if not success:
                return ["Could not determine SIP status - proceed with caution"]
            
            warnings = []
            
            if sip_info['enabled']:
                operation_warnings = {
                    'monitor_mode': [
                        "SIP may prevent switching WiFi interface to monitor mode",
                        "Some network interfaces may not support monitor mode with SIP enabled",
                        "Consider using alternative packet capture methods"
                    ],
                    'packet_capture': [
                        "SIP may limit raw socket access for packet capture",
                        "Administrator privileges may be required",
                        "Some capture methods may not work with SIP enabled"
                    ],
                    'interface_management': [
                        "SIP may restrict direct interface manipulation",
                        "Use networksetup command instead of direct interface modification",
                        "Some interface operations may require administrator privileges"
                    ],
                    'system_modification': [
                        "SIP prevents modification of system files and directories",
                        "Cannot load unsigned kernel extensions",
                        "System framework access is limited"
                    ]
                }
                
                operation_lower = operation.lower()
                for key, op_warnings in operation_warnings.items():
                    if key in operation_lower or operation_lower in key:
                        warnings.extend(op_warnings)
                        break
                else:
                    # Generic SIP warning
                    warnings.append(f"SIP is enabled - {operation} may be restricted")
            
            else:
                warnings.extend([
                    "WARNING: SIP is disabled - system security is reduced",
                    f"{operation} should work normally with SIP disabled",
                    "Consider re-enabling SIP after testing for security"
                ])
            
            # Log warning generation
            self._log_security_event("SIP_WARNING", f"Generated SIP warnings for {operation}", {
                "operation": operation,
                "sip_enabled": sip_info['enabled'],
                "warning_count": len(warnings)
            })
            
            return warnings
            
        except Exception as e:
            self.logger.error(f"Error generating SIP warnings for {operation}: {e}")
            return [f"Error checking SIP restrictions for {operation}"]
    
    def check_admin_privileges(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if the current process has administrator privileges
        
        Returns:
            Tuple[bool, Dict]: (has_admin_privileges, privilege_info)
        """
        try:
            privilege_info = {
                'has_admin': False,
                'user': getpass.getuser(),
                'uid': os.getuid(),
                'gid': os.getgid(),
                'effective_uid': os.geteuid(),
                'effective_gid': os.getegid(),
                'is_root': False,
                'can_sudo': False,
                'sudo_check_method': None,
                'recommendations': []
            }
            
            # Check if running as root
            if os.getuid() == 0:
                privilege_info['has_admin'] = True
                privilege_info['is_root'] = True
                self.logger.info("Running as root user")
            
            # Check if effective UID is root (e.g., via sudo)
            elif os.geteuid() == 0:
                privilege_info['has_admin'] = True
                privilege_info['is_root'] = True
                self.logger.info("Running with root effective UID")
            
            # Check sudo capabilities
            else:
                can_sudo, sudo_method = self._check_sudo_capabilities()
                privilege_info['can_sudo'] = can_sudo
                privilege_info['sudo_check_method'] = sudo_method
                
                if can_sudo:
                    privilege_info['has_admin'] = True
                    self.logger.info("User has sudo capabilities")
                else:
                    self.logger.warning("User does not have administrator privileges")
            
            # Add recommendations based on privilege status
            self._add_privilege_recommendations(privilege_info)
            
            # Log privilege check
            self._log_security_event("PRIVILEGE_CHECK", "Administrator privileges checked", {
                "has_admin": privilege_info['has_admin'],
                "user": privilege_info['user'],
                "uid": privilege_info['uid'],
                "is_root": privilege_info['is_root'],
                "can_sudo": privilege_info['can_sudo']
            })
            
            return True, privilege_info
            
        except Exception as e:
            error_msg = f"Error checking administrator privileges: {e}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    def _check_sudo_capabilities(self) -> Tuple[bool, str]:
        """
        Check if the current user can use sudo
        
        Returns:
            Tuple[bool, str]: (can_sudo, check_method)
        """
        try:
            # Method 1: Check sudo -n (non-interactive)
            try:
                result = subprocess.run(
                    ['sudo', '-n', 'true'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    return True, "sudo -n test successful"
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Method 2: Check if user is in admin group (macOS specific)
            try:
                result = subprocess.run(
                    ['groups'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    groups = result.stdout.strip()
                    if 'admin' in groups.split():
                        return True, "user in admin group"
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Method 3: Check dscl for admin group membership
            try:
                username = getpass.getuser()
                result = subprocess.run(
                    ['dscl', '.', '-read', f'/Groups/admin', 'GroupMembership'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and username in result.stdout:
                    return True, "dscl admin group check"
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return False, "no sudo capabilities detected"
            
        except Exception as e:
            self.logger.error(f"Error checking sudo capabilities: {e}")
            return False, f"error checking sudo: {e}"
    
    def _add_privilege_recommendations(self, privilege_info: Dict[str, Any]):
        """
        Add privilege-related recommendations
        
        Args:
            privilege_info (Dict): Privilege information dictionary to update
        """
        try:
            if privilege_info['has_admin']:
                if privilege_info['is_root']:
                    privilege_info['recommendations'].extend([
                        "Running as root - exercise extreme caution",
                        "Consider running as regular user with sudo when possible",
                        "Ensure all operations are intentional and necessary"
                    ])
                else:
                    privilege_info['recommendations'].extend([
                        "Administrator privileges available",
                        "Use sudo only when necessary for specific operations",
                        "Avoid running entire application as root"
                    ])
            else:
                privilege_info['recommendations'].extend([
                    "No administrator privileges detected",
                    "Some WiFi security testing operations may be limited",
                    "Consider running with 'sudo' for privileged operations",
                    "Packet capture and interface management may require admin rights"
                ])
                
        except Exception as e:
            self.logger.error(f"Error adding privilege recommendations: {e}")
    
    def request_admin_privileges(self, operation: str, reason: str = None) -> Tuple[bool, str]:
        """
        Request administrator privileges for a specific operation
        
        Args:
            operation (str): The operation requiring admin privileges
            reason (str): Optional reason for the privilege request
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Check current privilege status
            has_privileges, privilege_info = self.check_admin_privileges()
            
            if not has_privileges:
                return False, "Could not determine current privilege status"
            
            if privilege_info['has_admin']:
                message = f"Administrator privileges already available for {operation}"
                self.logger.info(message)
                
                # Log privilege usage
                self._log_security_event("PRIVILEGE_USED", f"Admin privileges used for {operation}", {
                    "operation": operation,
                    "reason": reason,
                    "user": privilege_info['user'],
                    "method": "existing_privileges"
                })
                
                return True, message
            
            # Privileges not available - provide guidance
            if privilege_info['can_sudo']:
                message = f"Administrator privileges required for {operation}. Please run with 'sudo' or provide admin password when prompted."
                guidance = [
                    f"Run: sudo python3 {sys.argv[0] if sys.argv else 'this_script'}",
                    "Or provide admin password when system prompts",
                    f"Operation: {operation}",
                ]
                
                if reason:
                    guidance.append(f"Reason: {reason}")
                
                full_message = message + "\n" + "\n".join(f"  {g}" for g in guidance)
                
            else:
                message = f"Administrator privileges required for {operation}, but user is not in admin group."
                guidance = [
                    "Contact system administrator to add user to admin group",
                    "Or run this tool from an administrator account",
                    f"Operation: {operation}",
                ]
                
                if reason:
                    guidance.append(f"Reason: {reason}")
                
                full_message = message + "\n" + "\n".join(f"  {g}" for g in guidance)
            
            # Log privilege request
            self._log_security_event("PRIVILEGE_REQUEST", f"Admin privileges requested for {operation}", {
                "operation": operation,
                "reason": reason,
                "user": privilege_info['user'],
                "can_sudo": privilege_info['can_sudo'],
                "granted": False
            })
            
            self.logger.warning(full_message)
            return False, full_message
            
        except Exception as e:
            error_msg = f"Error requesting administrator privileges: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def execute_privileged_operation(self, command: List[str], operation_name: str, 
                                   require_sudo: bool = True) -> Tuple[bool, str, str]:
        """
        Execute a command that requires administrator privileges
        
        Args:
            command (List[str]): Command to execute
            operation_name (str): Name of the operation for logging
            require_sudo (bool): Whether to prepend sudo if not running as admin
            
        Returns:
            Tuple[bool, str, str]: (success, stdout, stderr)
        """
        try:
            # Check privileges
            has_privileges, privilege_info = self.check_admin_privileges()
            
            if not has_privileges:
                return False, "", "Could not determine privilege status"
            
            # Prepare command
            final_command = command.copy()
            
            # Add sudo if needed and available
            if not privilege_info['has_admin'] and require_sudo:
                if privilege_info['can_sudo']:
                    final_command = ['sudo'] + final_command
                    self.logger.info(f"Adding sudo to command for {operation_name}")
                else:
                    error_msg = f"Administrator privileges required for {operation_name} but sudo not available"
                    self.logger.error(error_msg)
                    return False, "", error_msg
            
            # Log operation attempt
            self._log_security_event("PRIVILEGED_OPERATION", f"Executing privileged operation: {operation_name}", {
                "operation": operation_name,
                "command": " ".join(final_command),
                "user": privilege_info['user'],
                "has_admin": privilege_info['has_admin'],
                "using_sudo": 'sudo' in final_command
            })
            
            # Execute command
            self.logger.info(f"Executing privileged operation: {operation_name}")
            result = subprocess.run(
                final_command,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            
            # Log operation result
            self._log_security_event("PRIVILEGED_OPERATION_RESULT", f"Privileged operation completed: {operation_name}", {
                "operation": operation_name,
                "success": success,
                "return_code": result.returncode,
                "stdout_length": len(stdout),
                "stderr_length": len(stderr)
            })
            
            if success:
                self.logger.info(f"Privileged operation {operation_name} completed successfully")
            else:
                self.logger.error(f"Privileged operation {operation_name} failed with code {result.returncode}")
                if stderr:
                    self.logger.error(f"Error output: {stderr}")
            
            return success, stdout, stderr
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout executing privileged operation: {operation_name}"
            self.logger.error(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Error executing privileged operation {operation_name}: {e}"
            self.logger.error(error_msg)
            return False, "", error_msg
    
    def validate_privilege_for_operation(self, operation: str) -> Tuple[bool, List[str]]:
        """
        Validate if current privileges are sufficient for a specific operation
        
        Args:
            operation (str): The operation to validate
            
        Returns:
            Tuple[bool, List[str]]: (is_sufficient, requirements_or_warnings)
        """
        try:
            # Check current privileges
            has_privileges, privilege_info = self.check_admin_privileges()
            
            if not has_privileges:
                return False, ["Could not determine privilege status"]
            
            # Define privilege requirements for different operations
            privilege_requirements = {
                'packet_capture': {
                    'requires_admin': True,
                    'reason': 'Raw socket access for packet capture',
                    'alternatives': ['Use tcpdump with sudo', 'Use built-in capture tools']
                },
                'monitor_mode': {
                    'requires_admin': True,
                    'reason': 'Interface mode switching requires system access',
                    'alternatives': ['Use USB WiFi adapter', 'Use alternative scanning methods']
                },
                'interface_management': {
                    'requires_admin': True,
                    'reason': 'Network interface configuration requires admin rights',
                    'alternatives': ['Use networksetup command', 'Use System Preferences']
                },
                'network_scanning': {
                    'requires_admin': False,
                    'reason': 'Basic network scanning can use user-level tools',
                    'alternatives': ['Use wdutil', 'Use system_profiler']
                },
                'wordlist_management': {
                    'requires_admin': False,
                    'reason': 'File operations in user space',
                    'alternatives': []
                },
                'password_cracking': {
                    'requires_admin': False,
                    'reason': 'CPU/GPU operations in user space',
                    'alternatives': []
                }
            }
            
            operation_lower = operation.lower()
            requirements = None
            
            # Find matching requirement
            for req_key, req_info in privilege_requirements.items():
                if req_key in operation_lower or operation_lower in req_key:
                    requirements = req_info
                    break
            
            if not requirements:
                # Unknown operation - assume admin required for safety
                return False, [f"Unknown operation '{operation}' - admin privileges recommended for safety"]
            
            messages = []
            
            if requirements['requires_admin']:
                if privilege_info['has_admin']:
                    messages.append(f"✓ Administrator privileges available for {operation}")
                    messages.append(f"Reason: {requirements['reason']}")
                    return True, messages
                else:
                    messages.append(f"✗ Administrator privileges required for {operation}")
                    messages.append(f"Reason: {requirements['reason']}")
                    
                    if privilege_info['can_sudo']:
                        messages.append("Solution: Run with 'sudo' or provide admin password")
                    else:
                        messages.append("Solution: Contact administrator or use admin account")
                    
                    if requirements['alternatives']:
                        messages.append("Alternatives:")
                        for alt in requirements['alternatives']:
                            messages.append(f"  - {alt}")
                    
                    return False, messages
            else:
                messages.append(f"✓ No administrator privileges required for {operation}")
                messages.append(f"Reason: {requirements['reason']}")
                return True, messages
                
        except Exception as e:
            error_msg = f"Error validating privileges for {operation}: {e}"
            self.logger.error(error_msg)
            return False, [error_msg]
    
    def _log_security_event(self, event_type: str, description: str, details: Dict[str, Any]):
        """
        Log security-related events for audit trail
        
        Args:
            event_type (str): Type of security event
            description (str): Event description
            details (Dict): Additional event details
        """
        try:
            event_record = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "description": description,
                "details": details,
                "user": getpass.getuser(),
                "pid": os.getpid()
            }
            
            # Write to audit log
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(event_record) + '\n')
            
            self.logger.debug(f"Logged security event: {event_type}")
            
        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
    
    def display_legal_warnings(self) -> bool:
        """
        Display legal usage warnings and disclaimers
        
        Returns:
            bool: True if warnings were displayed successfully
        """
        try:
            if self.legal_warnings_shown:
                self.logger.debug("Legal warnings already shown in this session")
                return True
            
            legal_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           LEGAL USAGE WARNING                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This WiFi Security Testing Tool is intended for AUTHORIZED TESTING ONLY    ║
║                                                                              ║
║  LEGAL REQUIREMENTS:                                                         ║
║  • Only test networks you own or have explicit written permission to test   ║
║  • Unauthorized access to computer networks is illegal in most jurisdictions║
║  • Penalties may include fines, imprisonment, and civil liability           ║
║                                                                              ║
║  ETHICAL GUIDELINES:                                                         ║
║  • Use this tool only for legitimate security research and testing          ║
║  • Do not access, modify, or damage systems without authorization           ║
║  • Respect privacy and confidentiality of network traffic                   ║
║  • Report vulnerabilities responsibly through proper channels               ║
║                                                                              ║
║  EDUCATIONAL PURPOSE:                                                        ║
║  • This tool is designed for learning about network security               ║
║  • Understanding vulnerabilities helps improve security practices           ║
║  • Knowledge should be used to protect, not to harm                         ║
║                                                                              ║
║  DISCLAIMER:                                                                 ║
║  • The authors are not responsible for misuse of this tool                  ║
║  • Users are solely responsible for compliance with applicable laws         ║
║  • Use at your own risk and legal responsibility                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

IMPORTANT: By continuing to use this tool, you acknowledge that you have read,
understood, and agree to comply with all legal requirements and ethical guidelines.

You confirm that you will only use this tool on networks you own or have explicit
written authorization to test.
"""
            
            print(legal_text)
            self.legal_warnings_shown = True
            
            # Log legal warning display
            self._log_security_event("LEGAL_WARNING", "Legal usage warnings displayed", {
                "timestamp": datetime.now().isoformat(),
                "user": getpass.getuser()
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error displaying legal warnings: {e}")
            return False
    
    def request_user_consent(self, force_new_consent: bool = False) -> bool:
        """
        Request and validate user consent for tool usage
        
        Args:
            force_new_consent (bool): Force new consent even if already given
            
        Returns:
            bool: True if consent is given, False otherwise
        """
        try:
            # Check if consent already given and still valid
            if not force_new_consent and self.user_consent_given and self._is_consent_valid():
                self.logger.info("Valid user consent already exists")
                return True
            
            # Display legal warnings first
            if not self.display_legal_warnings():
                return False
            
            print("\nCONSENT VERIFICATION:")
            print("To proceed, you must confirm your understanding and agreement.")
            print()
            
            # Ask consent questions
            consent_questions = [
                "Do you own the network(s) you plan to test, or do you have explicit written authorization? (yes/no): ",
                "Do you understand that unauthorized network testing is illegal? (yes/no): ",
                "Do you agree to use this tool only for legitimate security research and testing? (yes/no): ",
                "Do you acknowledge that you are solely responsible for compliance with applicable laws? (yes/no): "
            ]
            
            responses = []
            for question in consent_questions:
                while True:
                    try:
                        response = input(question).strip().lower()
                        if response in ['yes', 'y', 'no', 'n']:
                            responses.append(response in ['yes', 'y'])
                            break
                        else:
                            print("Please answer 'yes' or 'no'")
                    except (EOFError, KeyboardInterrupt):
                        print("\nConsent process interrupted. Exiting.")
                        return False
            
            # All questions must be answered 'yes'
            consent_given = all(responses)
            
            if consent_given:
                self.user_consent_given = True
                self.consent_timestamp = datetime.now()
                
                # Save consent to file
                self._save_user_consent()
                
                print("\n✓ Consent recorded. You may proceed with authorized testing.")
                
                # Log consent
                self._log_security_event("USER_CONSENT", "User consent obtained", {
                    "consent_given": True,
                    "timestamp": self.consent_timestamp.isoformat(),
                    "user": getpass.getuser(),
                    "questions_answered": len(consent_questions)
                })
                
            else:
                print("\n✗ Consent not given. Tool usage is not authorized.")
                print("This application will now exit.")
                
                # Log consent denial
                self._log_security_event("USER_CONSENT", "User consent denied", {
                    "consent_given": False,
                    "timestamp": datetime.now().isoformat(),
                    "user": getpass.getuser()
                })
            
            return consent_given
            
        except Exception as e:
            self.logger.error(f"Error requesting user consent: {e}")
            return False
    
    def _is_consent_valid(self) -> bool:
        """
        Check if existing consent is still valid (within 24 hours)
        
        Returns:
            bool: True if consent is valid, False otherwise
        """
        try:
            if not self.consent_timestamp:
                return False
            
            # Consent expires after 24 hours
            consent_age = datetime.now() - self.consent_timestamp
            return consent_age.total_seconds() < 86400  # 24 hours
            
        except Exception as e:
            self.logger.error(f"Error checking consent validity: {e}")
            return False
    
    def _save_user_consent(self):
        """Save user consent to file for persistence"""
        try:
            consent_data = {
                "consent_given": self.user_consent_given,
                "timestamp": self.consent_timestamp.isoformat() if self.consent_timestamp else None,
                "user": getpass.getuser(),
                "version": "1.0"
            }
            
            with open(self.consent_file_path, 'w') as f:
                json.dump(consent_data, f, indent=2)
            
            self.logger.debug("User consent saved to file")
            
        except Exception as e:
            self.logger.error(f"Error saving user consent: {e}")
    
    def _load_user_consent(self):
        """Load existing user consent from file"""
        try:
            if not self.consent_file_path.exists():
                return
            
            with open(self.consent_file_path, 'r') as f:
                consent_data = json.load(f)
            
            self.user_consent_given = consent_data.get('consent_given', False)
            
            timestamp_str = consent_data.get('timestamp')
            if timestamp_str:
                self.consent_timestamp = datetime.fromisoformat(timestamp_str)
            
            # Validate loaded consent
            if not self._is_consent_valid():
                self.user_consent_given = False
                self.consent_timestamp = None
                self.logger.info("Loaded consent has expired")
            else:
                self.logger.info("Valid consent loaded from file")
                
        except Exception as e:
            self.logger.error(f"Error loading user consent: {e}")
            # Reset consent on error
            self.user_consent_given = False
            self.consent_timestamp = None
    
    def log_operation(self, operation_type: str, operation_details: Dict[str, Any], 
                     target_info: Dict[str, Any] = None):
        """
        Log security testing operations for audit trail
        
        Args:
            operation_type (str): Type of operation (scan, capture, crack, etc.)
            operation_details (Dict): Details about the operation
            target_info (Dict): Information about the target (optional)
        """
        try:
            # Add to operation history for suspicious activity detection
            operation_record = {
                "timestamp": datetime.now(),
                "type": operation_type,
                "details": operation_details,
                "target": target_info
            }
            
            self.operation_history.append(operation_record)
            
            # Keep only recent operations (last hour)
            cutoff_time = datetime.now() - timedelta(hours=1)
            self.operation_history = [
                op for op in self.operation_history 
                if op["timestamp"] > cutoff_time
            ]
            
            # Create audit log entry
            audit_entry = {
                "timestamp": operation_record["timestamp"].isoformat(),
                "operation_type": operation_type,
                "operation_details": operation_details,
                "target_info": target_info,
                "user": getpass.getuser(),
                "consent_status": self.user_consent_given,
                "session_id": os.getpid()
            }
            
            # Log to security audit
            self._log_security_event("OPERATION_LOG", f"Security operation: {operation_type}", audit_entry)
            
            # Check for suspicious activity
            self._check_suspicious_activity()
            
        except Exception as e:
            self.logger.error(f"Error logging operation: {e}")
    
    def _check_suspicious_activity(self):
        """Check for patterns that might indicate suspicious activity"""
        try:
            current_time = datetime.now()
            recent_operations = [
                op for op in self.operation_history 
                if (current_time - op["timestamp"]).total_seconds() < 300  # Last 5 minutes
            ]
            
            suspicious_patterns = []
            
            # Pattern 1: Too many operations in short time
            if len(recent_operations) > self.suspicious_activity_threshold:
                suspicious_patterns.append(f"High operation frequency: {len(recent_operations)} operations in 5 minutes")
            
            # Pattern 2: Multiple different targets
            targets = set()
            for op in recent_operations:
                if op.get("target") and op["target"].get("ssid"):
                    targets.add(op["target"]["ssid"])
            
            if len(targets) > 5:
                suspicious_patterns.append(f"Multiple targets: {len(targets)} different networks")
            
            # Pattern 3: Rapid scanning followed by attacks
            scan_ops = [op for op in recent_operations if op["type"] in ["network_scan", "target_scan"]]
            attack_ops = [op for op in recent_operations if op["type"] in ["packet_capture", "password_crack"]]
            
            if len(scan_ops) > 3 and len(attack_ops) > 1:
                suspicious_patterns.append("Rapid scan-to-attack pattern detected")
            
            # Pattern 4: Operations without consent
            if not self.user_consent_given and len(recent_operations) > 0:
                suspicious_patterns.append("Operations performed without valid consent")
            
            if suspicious_patterns:
                self.suspicious_activity_detected = True
                
                warning_message = "SUSPICIOUS ACTIVITY DETECTED:\n"
                for pattern in suspicious_patterns:
                    warning_message += f"  - {pattern}\n"
                
                warning_message += "\nREMINDER: This tool should only be used on networks you own or have authorization to test."
                
                print(f"\n⚠️  {warning_message}")
                
                # Log suspicious activity
                self._log_security_event("SUSPICIOUS_ACTIVITY", "Suspicious usage pattern detected", {
                    "patterns": suspicious_patterns,
                    "recent_operations_count": len(recent_operations),
                    "unique_targets": len(targets),
                    "consent_status": self.user_consent_given
                })
                
                # Ask for confirmation (skip during testing)
                if not hasattr(self, '_testing_mode'):
                    try:
                        response = input("\nDo you confirm you have authorization for these operations? (yes/no): ").strip().lower()
                        if response not in ['yes', 'y']:
                            print("⚠️  Please ensure you have proper authorization before continuing.")
                            
                            # Log confirmation response
                            self._log_security_event("SUSPICIOUS_ACTIVITY_RESPONSE", "User response to suspicious activity warning", {
                                "response": response,
                                "confirmed_authorization": response in ['yes', 'y']
                            })
                            
                    except (EOFError, KeyboardInterrupt):
                        print("\nSuspicious activity check interrupted.")
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious activity: {e}")
    
    def validate_ethical_usage(self) -> Tuple[bool, List[str]]:
        """
        Validate that the tool is being used ethically
        
        Returns:
            Tuple[bool, List[str]]: (is_ethical, warnings_or_violations)
        """
        try:
            violations = []
            warnings = []
            
            # Check consent status
            if not self.user_consent_given:
                violations.append("No user consent obtained for tool usage")
            elif not self._is_consent_valid():
                violations.append("User consent has expired (older than 24 hours)")
            
            # Check for suspicious activity
            if self.suspicious_activity_detected:
                warnings.append("Suspicious activity patterns detected in recent usage")
            
            # Check operation frequency
            recent_ops = [
                op for op in self.operation_history 
                if (datetime.now() - op["timestamp"]).total_seconds() < 3600  # Last hour
            ]
            
            if len(recent_ops) > 20:
                warnings.append(f"High operation frequency: {len(recent_ops)} operations in the last hour")
            
            # Check for diverse targeting (potential scanning)
            targets = set()
            for op in recent_ops:
                if op.get("target") and op["target"].get("ssid"):
                    targets.add(op["target"]["ssid"])
            
            if len(targets) > 10:
                warnings.append(f"Multiple targets detected: {len(targets)} different networks")
            
            # Determine overall ethical status
            is_ethical = len(violations) == 0
            
            all_issues = violations + warnings
            
            if is_ethical and not warnings:
                all_issues = ["✓ Ethical usage validated - no violations detected"]
            
            return is_ethical, all_issues
            
        except Exception as e:
            error_msg = f"Error validating ethical usage: {e}"
            self.logger.error(error_msg)
            return False, [error_msg]
    
    def enforce_ethical_usage(self) -> bool:
        """
        Enforce ethical usage by checking consent and validating usage patterns
        
        Returns:
            bool: True if usage is ethical and can continue, False otherwise
        """
        try:
            # Request consent if not already given
            if not self.request_user_consent():
                return False
            
            # Validate current usage
            is_ethical, issues = self.validate_ethical_usage()
            
            if not is_ethical:
                print("\n❌ ETHICAL USAGE VIOLATION DETECTED:")
                for issue in issues:
                    print(f"  - {issue}")
                
                print("\nTool usage is not authorized. Please ensure compliance with legal and ethical guidelines.")
                
                # Log enforcement action
                self._log_security_event("ETHICAL_ENFORCEMENT", "Ethical usage enforcement blocked tool usage", {
                    "violations": issues,
                    "user": getpass.getuser(),
                    "action": "blocked"
                })
                
                return False
            
            # Show warnings if any
            warnings = [issue for issue in issues if not issue.startswith("✓")]
            if warnings:
                print("\n⚠️  ETHICAL USAGE WARNINGS:")
                for warning in warnings:
                    print(f"  - {warning}")
                print()
            
            # Log successful enforcement
            self._log_security_event("ETHICAL_ENFORCEMENT", "Ethical usage validation passed", {
                "status": "passed",
                "warnings_count": len(warnings),
                "user": getpass.getuser()
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error enforcing ethical usage: {e}")
            return False


if __name__ == "__main__":
    # Test Security Manager functionality
    security_manager = SecurityManager()
    
    print("Testing SIP Status Checking...")
    success, sip_info = security_manager.check_sip_status()
    
    if success:
        print(f"SIP Status: {'Enabled' if sip_info['enabled'] else 'Disabled'}")
        print(f"Status Text: {sip_info['status_text']}")
        
        if sip_info.get('restrictions'):
            print("\nRestrictions:")
            for restriction in sip_info['restrictions']:
                print(f"  - {restriction}")
        
        if sip_info.get('recommendations'):
            print("\nRecommendations:")
            for recommendation in sip_info['recommendations']:
                print(f"  - {recommendation}")
    else:
        print(f"Failed to check SIP status: {sip_info.get('error', 'Unknown error')}")
    
    print("\nTesting SIP warnings...")
    warnings = security_manager.generate_sip_warnings("monitor_mode")
    for warning in warnings:
        print(f"  WARNING: {warning}")
    
    print("\nTesting alternative methods...")
    alternatives = security_manager.get_sip_alternative_methods("packet_capture")
    for alt in alternatives:
        print(f"  ALTERNATIVE: {alt}")
    
    print("\n" + "="*60)
    print("Testing Privilege Management...")
    
    # Test privilege checking
    success, privilege_info = security_manager.check_admin_privileges()
    if success:
        print(f"Has Admin Privileges: {privilege_info['has_admin']}")
        print(f"User: {privilege_info['user']}")
        print(f"UID: {privilege_info['uid']}")
        print(f"Is Root: {privilege_info['is_root']}")
        print(f"Can Sudo: {privilege_info['can_sudo']}")
        
        if privilege_info.get('recommendations'):
            print("\nPrivilege Recommendations:")
            for rec in privilege_info['recommendations']:
                print(f"  - {rec}")
    else:
        print(f"Failed to check privileges: {privilege_info.get('error', 'Unknown error')}")
    
    print("\nTesting privilege validation for different operations...")
    operations = ['packet_capture', 'monitor_mode', 'network_scanning', 'wordlist_management']
    
    for operation in operations:
        is_sufficient, messages = security_manager.validate_privilege_for_operation(operation)
        print(f"\n{operation.upper()}:")
        print(f"  Sufficient privileges: {is_sufficient}")
        for message in messages:
            print(f"  {message}")
    
    print("\nTesting privilege request...")
    success, message = security_manager.request_admin_privileges("packet_capture", "Testing privilege request system")
    print(f"Privilege request result: {success}")
    print(f"Message: {message}")
    
    print("\n" + "="*60)
    print("Testing Ethical Usage Enforcement...")
    
    # Test legal warnings display
    print("\nTesting legal warnings display...")
    success = security_manager.display_legal_warnings()
    print(f"Legal warnings displayed: {success}")
    
    # Test ethical usage validation
    print("\nTesting ethical usage validation...")
    is_ethical, issues = security_manager.validate_ethical_usage()
    print(f"Ethical usage status: {is_ethical}")
    print("Issues/Warnings:")
    for issue in issues:
        print(f"  - {issue}")
    
    # Test operation logging
    print("\nTesting operation logging...")
    security_manager.log_operation("network_scan", {
        "method": "wdutil",
        "duration": 5.2,
        "networks_found": 3
    }, {
        "ssid": "TestNetwork",
        "bssid": "00:11:22:33:44:55"
    })
    print("Operation logged successfully")
    
    # Test suspicious activity detection (simulate multiple operations)
    print("\nTesting suspicious activity detection...")
    for i in range(3):
        security_manager.log_operation("target_scan", {
            "target": f"TestTarget{i}",
            "method": "test"
        })
    
    print("Suspicious activity check completed")
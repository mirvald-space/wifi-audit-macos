"""
Comprehensive error handling system for WiFi Security Tester
Provides hierarchical error classification and graceful degradation strategies

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import sys
import traceback
from typing import Optional, Dict, Any, List
from enum import Enum
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.logger import get_logger


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification"""
    SYSTEM = "system"
    TOOL = "tool"
    NETWORK = "network"
    USER = "user"
    SECURITY = "security"


class WiFiSecurityError(Exception):
    """Base exception class for WiFi Security Tester"""
    
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.SYSTEM, 
                 recovery_suggestions: Optional[List[str]] = None,
                 technical_details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.category = category
        self.recovery_suggestions = recovery_suggestions or []
        self.technical_details = technical_details
        self.timestamp = None
        self.context = {}
        
        # Log the error
        logger = get_logger("error_handler")
        logger.error(f"[{category.value.upper()}] {message}")
        if technical_details:
            logger.debug(f"Technical details: {technical_details}")
    
    def add_context(self, key: str, value: Any) -> None:
        """Add contextual information to the error"""
        self.context[key] = value
    
    def get_user_message(self) -> str:
        """Get user-friendly error message"""
        return self.message
    
    def get_recovery_suggestions(self) -> List[str]:
        """Get recovery suggestions for the error"""
        return self.recovery_suggestions
    
    def is_recoverable(self) -> bool:
        """Check if error is recoverable"""
        return len(self.recovery_suggestions) > 0


# System Error Classes
class SystemError(WiFiSecurityError):
    """Base class for system-related errors"""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.SYSTEM)
        super().__init__(message, **kwargs)


class SIPRestrictionError(SystemError):
    """Error when System Integrity Protection blocks operations"""
    
    def __init__(self, operation: str, **kwargs):
        message = f"System Integrity Protection (SIP) is blocking operation: {operation}"
        recovery_suggestions = [
            "Disable SIP temporarily (not recommended for production systems)",
            "Use alternative methods that don't require SIP bypass",
            "Run the operation from Recovery Mode",
            "Consider using external WiFi adapter with better driver support"
        ]
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.operation = operation


class InterfaceNotFoundError(SystemError):
    """Error when WiFi interface is not found or accessible"""
    
    def __init__(self, interface_name: Optional[str] = None, **kwargs):
        if interface_name:
            message = f"WiFi interface '{interface_name}' not found or not accessible"
        else:
            message = "No WiFi interfaces found on the system"
        
        recovery_suggestions = [
            "Check if WiFi is enabled in System Preferences",
            "Verify WiFi adapter is properly connected",
            "Try running with administrator privileges",
            "Check if interface name has changed (use 'networksetup -listallhardwareports')"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.interface_name = interface_name


class PermissionDeniedError(SystemError):
    """Error when operation requires elevated privileges"""
    
    def __init__(self, operation: str, **kwargs):
        message = f"Permission denied for operation: {operation}"
        recovery_suggestions = [
            "Run the application with administrator privileges (sudo)",
            "Check file/directory permissions",
            "Ensure user is in appropriate groups (admin, wheel)"
        ]
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.operation = operation


class InsufficientPrivilegesError(SystemError):
    """Error when user lacks necessary system privileges"""
    
    def __init__(self, required_privilege: str, **kwargs):
        message = f"Insufficient privileges: {required_privilege} access required"
        recovery_suggestions = [
            "Run application as administrator (sudo)",
            "Add user to required system groups",
            "Check system security settings"
        ]
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.required_privilege = required_privilege


# Tool Error Classes
class ToolError(WiFiSecurityError):
    """Base class for tool-related errors"""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.TOOL)
        super().__init__(message, **kwargs)


class DependencyMissingError(ToolError):
    """Error when required dependency is missing"""
    
    def __init__(self, tool_name: str, **kwargs):
        message = f"Required tool '{tool_name}' is not installed or not found in PATH"
        recovery_suggestions = [
            f"Install {tool_name} using Homebrew: brew install {tool_name}",
            "Check if tool is installed but not in PATH",
            "Use automatic dependency installation feature",
            "Verify Homebrew is properly installed"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.tool_name = tool_name


class VersionIncompatibleError(ToolError):
    """Error when tool version is incompatible"""
    
    def __init__(self, tool_name: str, current_version: str, required_version: str, **kwargs):
        message = f"Tool '{tool_name}' version {current_version} is incompatible (required: {required_version})"
        recovery_suggestions = [
            f"Update {tool_name}: brew upgrade {tool_name}",
            f"Install specific version: brew install {tool_name}@{required_version}",
            "Check for alternative compatible versions"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.tool_name = tool_name
        self.current_version = current_version
        self.required_version = required_version


class ExecutionFailedError(ToolError):
    """Error when tool execution fails"""
    
    def __init__(self, tool_name: str, command: str, exit_code: int, stderr: str = "", **kwargs):
        message = f"Tool '{tool_name}' execution failed with exit code {exit_code}"
        recovery_suggestions = [
            "Check tool installation and permissions",
            "Verify command parameters are correct",
            "Check system resources (disk space, memory)",
            "Try running with different parameters"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        kwargs.setdefault('technical_details', f"Command: {command}\nStderr: {stderr}")
        super().__init__(message, **kwargs)
        self.tool_name = tool_name
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class ToolNotRespondingError(ToolError):
    """Error when tool becomes unresponsive"""
    
    def __init__(self, tool_name: str, timeout: int, **kwargs):
        message = f"Tool '{tool_name}' not responding after {timeout} seconds"
        recovery_suggestions = [
            "Increase timeout value for complex operations",
            "Check system resources and performance",
            "Try terminating and restarting the tool",
            "Use alternative tool if available"
        ]
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.tool_name = tool_name
        self.timeout = timeout


# Network Error Classes
class NetworkError(WiFiSecurityError):
    """Base class for network-related errors"""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.NETWORK)
        super().__init__(message, **kwargs)


class InterfaceDownError(NetworkError):
    """Error when network interface is down or unavailable"""
    
    def __init__(self, interface_name: str, **kwargs):
        message = f"Network interface '{interface_name}' is down or unavailable"
        recovery_suggestions = [
            f"Bring interface up: sudo ifconfig {interface_name} up",
            "Check physical connection",
            "Restart network services",
            "Check interface configuration"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.interface_name = interface_name


class CaptureFailedError(NetworkError):
    """Error when packet capture fails"""
    
    def __init__(self, reason: str, interface: Optional[str] = None, **kwargs):
        message = f"Packet capture failed: {reason}"
        recovery_suggestions = [
            "Check interface is in monitor mode",
            "Verify sufficient privileges for packet capture",
            "Try different capture method or tool",
            "Check interface compatibility with monitor mode"
        ]
        if interface:
            recovery_suggestions.append(f"Try different interface (current: {interface})")
        
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.reason = reason
        self.interface = interface


class NoHandshakeError(NetworkError):
    """Error when no handshake is captured"""
    
    def __init__(self, target_network: str, capture_duration: int, **kwargs):
        message = f"No handshake captured for network '{target_network}' after {capture_duration} seconds"
        recovery_suggestions = [
            "Increase capture duration",
            "Try deauthenticating clients to force handshake",
            "Move closer to target network for better signal",
            "Verify network has active clients",
            "Check if network uses WPS (different attack method needed)"
        ]
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.target_network = target_network
        self.capture_duration = capture_duration


class MonitorModeError(NetworkError):
    """Error when monitor mode cannot be enabled"""
    
    def __init__(self, interface: str, reason: str, **kwargs):
        message = f"Cannot enable monitor mode on interface '{interface}': {reason}"
        recovery_suggestions = [
            "Check if interface supports monitor mode",
            "Try using external WiFi adapter with monitor mode support",
            "Disable SIP if it's blocking monitor mode",
            "Use alternative capture methods"
        ]
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.interface = interface
        self.reason = reason


# User Error Classes
class UserError(WiFiSecurityError):
    """Base class for user-related errors"""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.USER)
        kwargs.setdefault('severity', ErrorSeverity.LOW)
        super().__init__(message, **kwargs)


class InvalidInputError(UserError):
    """Error when user provides invalid input"""
    
    def __init__(self, input_type: str, provided_value: str, expected_format: str, **kwargs):
        message = f"Invalid {input_type}: '{provided_value}' (expected format: {expected_format})"
        recovery_suggestions = [
            f"Provide {input_type} in correct format: {expected_format}",
            "Check input for typos or formatting errors",
            "Use help command for input examples"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.input_type = input_type
        self.provided_value = provided_value
        self.expected_format = expected_format


class FileNotFoundError(UserError):
    """Error when specified file is not found"""
    
    def __init__(self, file_path: str, file_type: str = "file", **kwargs):
        message = f"{file_type.capitalize()} not found: {file_path}"
        recovery_suggestions = [
            "Check file path for typos",
            "Verify file exists and is accessible",
            "Check file permissions",
            "Use absolute path if relative path fails"
        ]
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.file_path = file_path
        self.file_type = file_type


class IllegalUsageError(UserError):
    """Error when tool is used for illegal purposes"""
    
    def __init__(self, detected_activity: str, **kwargs):
        message = f"Potentially illegal usage detected: {detected_activity}"
        recovery_suggestions = [
            "Ensure you have permission to test the target network",
            "Use tool only on networks you own or have written authorization",
            "Review legal usage guidelines",
            "Contact legal counsel if unsure about usage rights"
        ]
        kwargs.setdefault('severity', ErrorSeverity.CRITICAL)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.detected_activity = detected_activity


# Security Error Classes
class SecurityError(WiFiSecurityError):
    """Base class for security-related errors"""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('category', ErrorCategory.SECURITY)
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        super().__init__(message, **kwargs)


class UnauthorizedAccessError(SecurityError):
    """Error when unauthorized access is attempted"""
    
    def __init__(self, resource: str, **kwargs):
        message = f"Unauthorized access attempt to: {resource}"
        recovery_suggestions = [
            "Verify you have permission to access this resource",
            "Check authentication credentials",
            "Ensure proper authorization for testing"
        ]
        kwargs.setdefault('severity', ErrorSeverity.CRITICAL)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.resource = resource


class SuspiciousActivityError(SecurityError):
    """Error when suspicious activity is detected"""
    
    def __init__(self, activity_description: str, **kwargs):
        message = f"Suspicious activity detected: {activity_description}"
        recovery_suggestions = [
            "Review your testing activities",
            "Ensure compliance with legal and ethical guidelines",
            "Document authorization for testing activities"
        ]
        kwargs.setdefault('severity', ErrorSeverity.CRITICAL)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.activity_description = activity_description


# Configuration Error Classes
class ConfigurationError(WiFiSecurityError):
    """Error in system or application configuration"""
    
    def __init__(self, config_item: str, issue: str, **kwargs):
        message = f"Configuration error in {config_item}: {issue}"
        recovery_suggestions = [
            "Check configuration file syntax",
            "Verify configuration values are valid",
            "Reset to default configuration if needed",
            "Check system requirements"
        ]
        kwargs.setdefault('category', ErrorCategory.SYSTEM)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.config_item = config_item
        self.issue = issue


# Resource Error Classes
class ResourceError(WiFiSecurityError):
    """Error related to system resources"""
    
    def __init__(self, resource_type: str, issue: str, **kwargs):
        message = f"Resource error ({resource_type}): {issue}"
        recovery_suggestions = [
            "Check available system resources",
            "Close unnecessary applications",
            "Free up disk space if needed",
            "Consider upgrading hardware"
        ]
        kwargs.setdefault('category', ErrorCategory.SYSTEM)
        kwargs.setdefault('recovery_suggestions', recovery_suggestions)
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.issue = issue


class InsufficientDiskSpaceError(ResourceError):
    """Error when insufficient disk space is available"""
    
    def __init__(self, required_space: int, available_space: int, **kwargs):
        message = f"Insufficient disk space: {required_space}MB required, {available_space}MB available"
        recovery_suggestions = [
            "Free up disk space by deleting unnecessary files",
            "Move large files to external storage",
            "Clean up temporary files and caches",
            "Use disk cleanup utilities"
        ]
        super().__init__("disk_space", message, **kwargs)
        self.required_space = required_space
        self.available_space = available_space


class MemoryError(ResourceError):
    """Error when insufficient memory is available"""
    
    def __init__(self, operation: str, **kwargs):
        message = f"Insufficient memory for operation: {operation}"
        recovery_suggestions = [
            "Close unnecessary applications",
            "Reduce wordlist size for password cracking",
            "Use swap file if available",
            "Consider upgrading system memory"
        ]
        super().__init__("memory", message, **kwargs)
        self.operation = operation
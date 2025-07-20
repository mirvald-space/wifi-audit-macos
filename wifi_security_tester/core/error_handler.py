"""
Error Handler - Provides graceful degradation and recovery mechanisms
Implements comprehensive error handling strategies for WiFi Security Tester

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import sys
import traceback
import json
import time
from typing import Optional, Dict, Any, List, Callable, Union
from pathlib import Path
from datetime import datetime
from enum import Enum

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.exceptions import *
from core.logger import get_logger


class RecoveryStrategy(Enum):
    """Recovery strategy types"""
    RETRY = "retry"
    FALLBACK = "fallback"
    DEGRADE = "degrade"
    ABORT = "abort"
    USER_INTERVENTION = "user_intervention"


class ErrorHandler:
    """Comprehensive error handler with graceful degradation"""
    
    def __init__(self, log_errors: bool = True, max_retries: int = 3):
        self.logger = get_logger("error_handler")
        self.log_errors = log_errors
        self.max_retries = max_retries
        self.error_history: List[Dict[str, Any]] = []
        self.recovery_strategies: Dict[type, RecoveryStrategy] = {}
        self.fallback_methods: Dict[str, Callable] = {}
        self.degradation_modes: Dict[str, Dict[str, Any]] = {}
        
        # Initialize default recovery strategies
        self._initialize_recovery_strategies()
        
        # Initialize degradation modes
        self._initialize_degradation_modes()
    
    def _initialize_recovery_strategies(self) -> None:
        """Initialize default recovery strategies for different error types"""
        self.recovery_strategies.update({
            # System errors
            SIPRestrictionError: RecoveryStrategy.FALLBACK,
            InterfaceNotFoundError: RecoveryStrategy.RETRY,
            PermissionDeniedError: RecoveryStrategy.USER_INTERVENTION,
            InsufficientPrivilegesError: RecoveryStrategy.USER_INTERVENTION,
            
            # Tool errors
            DependencyMissingError: RecoveryStrategy.USER_INTERVENTION,
            VersionIncompatibleError: RecoveryStrategy.FALLBACK,
            ExecutionFailedError: RecoveryStrategy.RETRY,
            ToolNotRespondingError: RecoveryStrategy.RETRY,
            
            # Network errors
            InterfaceDownError: RecoveryStrategy.RETRY,
            CaptureFailedError: RecoveryStrategy.FALLBACK,
            NoHandshakeError: RecoveryStrategy.RETRY,
            MonitorModeError: RecoveryStrategy.FALLBACK,
            
            # User errors
            InvalidInputError: RecoveryStrategy.USER_INTERVENTION,
            FileNotFoundError: RecoveryStrategy.USER_INTERVENTION,
            IllegalUsageError: RecoveryStrategy.ABORT,
            
            # Security errors
            UnauthorizedAccessError: RecoveryStrategy.ABORT,
            SuspiciousActivityError: RecoveryStrategy.ABORT,
            
            # Resource errors
            InsufficientDiskSpaceError: RecoveryStrategy.USER_INTERVENTION,
            MemoryError: RecoveryStrategy.DEGRADE,
        })
    
    def _initialize_degradation_modes(self) -> None:
        """Initialize degradation modes for different scenarios"""
        self.degradation_modes = {
            'network_scanning': {
                'primary': 'wdutil_scan',
                'fallback': 'system_profiler_scan',
                'minimal': 'basic_iwlist_scan'
            },
            'packet_capture': {
                'primary': 'airodump_ng_capture',
                'fallback': 'tcpdump_capture',
                'minimal': 'basic_capture'
            },
            'password_cracking': {
                'primary': 'hashcat_gpu',
                'fallback': 'hashcat_cpu',
                'minimal': 'aircrack_ng'
            },
            'interface_management': {
                'primary': 'networksetup_control',
                'fallback': 'ifconfig_control',
                'minimal': 'manual_control'
            }
        }
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                    operation: Optional[str] = None) -> Dict[str, Any]:
        """
        Handle an error with appropriate recovery strategy
        
        Args:
            error: The exception that occurred
            context: Additional context information
            operation: The operation that failed
            
        Returns:
            Dict containing error handling results and recovery information
        """
        # Record error in history
        error_record = self._record_error(error, context, operation)
        
        # Determine recovery strategy
        strategy = self._determine_recovery_strategy(error)
        
        # Execute recovery strategy
        recovery_result = self._execute_recovery_strategy(error, strategy, context, operation)
        
        # Update error record with recovery results
        error_record.update(recovery_result)
        
        return error_record
    
    def _record_error(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                     operation: Optional[str] = None) -> Dict[str, Any]:
        """Record error details for analysis and reporting"""
        error_record = {
            'timestamp': datetime.now().isoformat(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            'operation': operation,
            'context': context or {},
            'traceback': traceback.format_exc() if self.log_errors else None,
            'severity': getattr(error, 'severity', ErrorSeverity.MEDIUM).value,
            'category': getattr(error, 'category', ErrorCategory.SYSTEM).value,
            'recovery_suggestions': getattr(error, 'recovery_suggestions', []),
            'is_recoverable': getattr(error, 'is_recoverable', lambda: False)()
        }
        
        self.error_history.append(error_record)
        
        # Log the error
        if self.log_errors:
            self.logger.error(f"Error in {operation or 'unknown operation'}: {error}")
            if hasattr(error, 'technical_details') and error.technical_details:
                self.logger.debug(f"Technical details: {error.technical_details}")
        
        return error_record
    
    def _determine_recovery_strategy(self, error: Exception) -> RecoveryStrategy:
        """Determine the appropriate recovery strategy for an error"""
        error_type = type(error)
        
        # Check for specific error type strategy
        if error_type in self.recovery_strategies:
            return self.recovery_strategies[error_type]
        
        # Check parent classes
        for parent_type in error_type.__mro__[1:]:
            if parent_type in self.recovery_strategies:
                return self.recovery_strategies[parent_type]
        
        # Default strategy based on error severity
        if hasattr(error, 'severity'):
            if error.severity == ErrorSeverity.CRITICAL:
                return RecoveryStrategy.ABORT
            elif error.severity == ErrorSeverity.HIGH:
                return RecoveryStrategy.USER_INTERVENTION
            elif error.severity == ErrorSeverity.MEDIUM:
                return RecoveryStrategy.FALLBACK
            else:
                return RecoveryStrategy.RETRY
        
        return RecoveryStrategy.RETRY
    
    def _execute_recovery_strategy(self, error: Exception, strategy: RecoveryStrategy,
                                 context: Optional[Dict[str, Any]] = None,
                                 operation: Optional[str] = None) -> Dict[str, Any]:
        """Execute the determined recovery strategy"""
        recovery_result = {
            'strategy_used': strategy.value,
            'recovery_successful': False,
            'recovery_message': '',
            'fallback_method': None,
            'user_action_required': False,
            'retry_count': 0
        }
        
        try:
            if strategy == RecoveryStrategy.RETRY:
                recovery_result.update(self._handle_retry_strategy(error, context, operation))
            
            elif strategy == RecoveryStrategy.FALLBACK:
                recovery_result.update(self._handle_fallback_strategy(error, context, operation))
            
            elif strategy == RecoveryStrategy.DEGRADE:
                recovery_result.update(self._handle_degradation_strategy(error, context, operation))
            
            elif strategy == RecoveryStrategy.USER_INTERVENTION:
                recovery_result.update(self._handle_user_intervention_strategy(error, context, operation))
            
            elif strategy == RecoveryStrategy.ABORT:
                recovery_result.update(self._handle_abort_strategy(error, context, operation))
            
        except Exception as recovery_error:
            self.logger.error(f"Recovery strategy failed: {recovery_error}")
            recovery_result['recovery_message'] = f"Recovery failed: {recovery_error}"
        
        return recovery_result
    
    def _handle_retry_strategy(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                              operation: Optional[str] = None) -> Dict[str, Any]:
        """Handle retry recovery strategy"""
        retry_count = context.get('retry_count', 0) if context else 0
        
        if retry_count >= self.max_retries:
            return {
                'recovery_successful': False,
                'recovery_message': f'Maximum retries ({self.max_retries}) exceeded',
                'retry_count': retry_count
            }
        
        # Add delay between retries
        delay = min(2 ** retry_count, 30)  # Exponential backoff, max 30 seconds
        time.sleep(delay)
        
        return {
            'recovery_successful': True,
            'recovery_message': f'Retrying operation (attempt {retry_count + 1}/{self.max_retries})',
            'retry_count': retry_count + 1,
            'retry_delay': delay
        }
    
    def _handle_fallback_strategy(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                                 operation: Optional[str] = None) -> Dict[str, Any]:
        """Handle fallback recovery strategy"""
        fallback_method = None
        
        # Determine fallback method based on operation
        if operation and operation in self.fallback_methods:
            fallback_method = self.fallback_methods[operation]
        
        # Check for operation-specific degradation modes
        degradation_info = self._get_degradation_mode(operation)
        
        return {
            'recovery_successful': True,
            'recovery_message': 'Switching to fallback method',
            'fallback_method': fallback_method.__name__ if fallback_method else 'unknown',
            'degradation_mode': degradation_info
        }
    
    def _handle_degradation_strategy(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                                   operation: Optional[str] = None) -> Dict[str, Any]:
        """Handle graceful degradation strategy"""
        degradation_info = self._get_degradation_mode(operation)
        
        return {
            'recovery_successful': True,
            'recovery_message': 'Operating in degraded mode with reduced functionality',
            'degradation_mode': degradation_info,
            'performance_impact': 'Reduced performance and features'
        }
    
    def _handle_user_intervention_strategy(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                                         operation: Optional[str] = None) -> Dict[str, Any]:
        """Handle user intervention recovery strategy"""
        recovery_suggestions = getattr(error, 'recovery_suggestions', [])
        
        return {
            'recovery_successful': False,
            'recovery_message': 'User intervention required to resolve the issue',
            'user_action_required': True,
            'recovery_suggestions': recovery_suggestions,
            'user_guidance': self._generate_user_guidance(error)
        }
    
    def _handle_abort_strategy(self, error: Exception, context: Optional[Dict[str, Any]] = None,
                              operation: Optional[str] = None) -> Dict[str, Any]:
        """Handle abort recovery strategy"""
        return {
            'recovery_successful': False,
            'recovery_message': 'Operation aborted due to critical error',
            'abort_reason': str(error),
            'requires_restart': True
        }
    
    def _get_degradation_mode(self, operation: Optional[str]) -> Optional[Dict[str, Any]]:
        """Get degradation mode information for an operation"""
        if not operation:
            return None
        
        # Check for exact match
        if operation in self.degradation_modes:
            return self.degradation_modes[operation]
        
        # Check for partial matches
        for mode_key, mode_info in self.degradation_modes.items():
            if mode_key in operation or operation in mode_key:
                return mode_info
        
        return None
    
    def _generate_user_guidance(self, error: Exception) -> str:
        """Generate user-friendly guidance for error resolution"""
        guidance_parts = []
        
        # Add error description
        guidance_parts.append(f"Issue: {error.get_user_message() if hasattr(error, 'get_user_message') else str(error)}")
        
        # Add recovery suggestions
        if hasattr(error, 'recovery_suggestions') and error.recovery_suggestions:
            guidance_parts.append("Suggested solutions:")
            for i, suggestion in enumerate(error.recovery_suggestions, 1):
                guidance_parts.append(f"  {i}. {suggestion}")
        
        # Add context-specific guidance
        if isinstance(error, DependencyMissingError):
            guidance_parts.append("\nYou can use the automatic dependency installation feature in the main menu.")
        
        elif isinstance(error, SIPRestrictionError):
            guidance_parts.append("\nNote: Disabling SIP reduces system security. Only do this on test systems.")
        
        elif isinstance(error, PermissionDeniedError):
            guidance_parts.append("\nTry running the application with 'sudo' for elevated privileges.")
        
        return "\n".join(guidance_parts)
    
    def register_fallback_method(self, operation: str, fallback_method: Callable) -> None:
        """Register a fallback method for a specific operation"""
        self.fallback_methods[operation] = fallback_method
        self.logger.debug(f"Registered fallback method for operation: {operation}")
    
    def register_recovery_strategy(self, error_type: type, strategy: RecoveryStrategy) -> None:
        """Register a custom recovery strategy for an error type"""
        self.recovery_strategies[error_type] = strategy
        self.logger.debug(f"Registered recovery strategy {strategy.value} for {error_type.__name__}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get statistics about handled errors"""
        if not self.error_history:
            return {'total_errors': 0}
        
        stats = {
            'total_errors': len(self.error_history),
            'errors_by_type': {},
            'errors_by_category': {},
            'errors_by_severity': {},
            'recovery_success_rate': 0,
            'most_common_errors': []
        }
        
        # Count errors by type, category, and severity
        successful_recoveries = 0
        for error_record in self.error_history:
            error_type = error_record['error_type']
            category = error_record['category']
            severity = error_record['severity']
            
            stats['errors_by_type'][error_type] = stats['errors_by_type'].get(error_type, 0) + 1
            stats['errors_by_category'][category] = stats['errors_by_category'].get(category, 0) + 1
            stats['errors_by_severity'][severity] = stats['errors_by_severity'].get(severity, 0) + 1
            
            if error_record.get('recovery_successful', False):
                successful_recoveries += 1
        
        # Calculate recovery success rate
        if len(self.error_history) > 0:
            stats['recovery_success_rate'] = (successful_recoveries / len(self.error_history)) * 100
        
        # Find most common errors
        stats['most_common_errors'] = sorted(
            stats['errors_by_type'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return stats
    
    def export_error_log(self, file_path: str) -> bool:
        """Export error history to a JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump({
                    'export_timestamp': datetime.now().isoformat(),
                    'error_history': self.error_history,
                    'statistics': self.get_error_statistics()
                }, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to export error log: {e}")
            return False
    
    def clear_error_history(self) -> None:
        """Clear the error history"""
        self.error_history.clear()
        self.logger.info("Error history cleared")


# Global error handler instance
_global_error_handler = None


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler


def handle_error(error: Exception, context: Optional[Dict[str, Any]] = None,
                operation: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function to handle errors using the global error handler"""
    return get_error_handler().handle_error(error, context, operation)


def with_error_handling(operation_name: str):
    """Decorator to add error handling to functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = {
                    'function': func.__name__,
                    'args': str(args)[:200],  # Limit length
                    'kwargs': str(kwargs)[:200]
                }
                error_result = handle_error(e, context, operation_name)
                
                # Re-raise if not recoverable or recovery failed
                if not error_result.get('recovery_successful', False):
                    raise e
                
                # Return None or appropriate default for successful recovery
                return None
        return wrapper
    return decorator
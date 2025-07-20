#!/usr/bin/env python3
"""
Comprehensive Test Suite for Error Handling System
Tests error classification, recovery strategies, and graceful degradation
"""

import unittest
import tempfile
import os
import json
import time
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.core.error_handler import ErrorHandler, RecoveryStrategy, get_error_handler, handle_error, with_error_handling
from wifi_security_tester.core.exceptions import *


class TestErrorClassification(unittest.TestCase):
    """Test error classification and hierarchy"""
    
    def test_base_error_class(self):
        """Test base WiFiSecurityError class"""
        error = WiFiSecurityError(
            "Test error message",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SYSTEM,
            recovery_suggestions=["Try again", "Check settings"],
            technical_details="Technical info"
        )
        
        self.assertEqual(str(error), "Test error message")
        self.assertEqual(error.severity, ErrorSeverity.HIGH)
        self.assertEqual(error.category, ErrorCategory.SYSTEM)
        self.assertEqual(len(error.recovery_suggestions), 2)
        self.assertEqual(error.technical_details, "Technical info")
        self.assertTrue(error.is_recoverable())
        
        # Test context addition
        error.add_context("operation", "test_operation")
        self.assertEqual(error.context["operation"], "test_operation")
    
    def test_system_error_hierarchy(self):
        """Test system error class hierarchy"""
        # Test SIPRestrictionError
        sip_error = SIPRestrictionError("monitor_mode")
        self.assertIsInstance(sip_error, SystemError)
        self.assertIsInstance(sip_error, WiFiSecurityError)
        self.assertEqual(sip_error.category, ErrorCategory.SYSTEM)
        self.assertEqual(sip_error.severity, ErrorSeverity.HIGH)
        self.assertIn("SIP", str(sip_error))
        self.assertGreater(len(sip_error.recovery_suggestions), 0)
        
        # Test InterfaceNotFoundError
        interface_error = InterfaceNotFoundError("en0")
        self.assertIsInstance(interface_error, SystemError)
        self.assertEqual(interface_error.interface_name, "en0")
        self.assertIn("en0", str(interface_error))
        
        # Test PermissionDeniedError
        perm_error = PermissionDeniedError("packet_capture")
        self.assertIsInstance(perm_error, SystemError)
        self.assertEqual(perm_error.operation, "packet_capture")
        self.assertEqual(perm_error.severity, ErrorSeverity.HIGH)
    
    def test_tool_error_hierarchy(self):
        """Test tool error class hierarchy"""
        # Test DependencyMissingError
        dep_error = DependencyMissingError("aircrack-ng")
        self.assertIsInstance(dep_error, ToolError)
        self.assertEqual(dep_error.category, ErrorCategory.TOOL)
        self.assertEqual(dep_error.tool_name, "aircrack-ng")
        self.assertIn("aircrack-ng", str(dep_error))
        
        # Test VersionIncompatibleError
        version_error = VersionIncompatibleError("hashcat", "6.1.0", "6.2.0")
        self.assertIsInstance(version_error, ToolError)
        self.assertEqual(version_error.current_version, "6.1.0")
        self.assertEqual(version_error.required_version, "6.2.0")
        
        # Test ExecutionFailedError
        exec_error = ExecutionFailedError("aircrack-ng", "aircrack-ng -w wordlist.txt", 1, "Error message")
        self.assertIsInstance(exec_error, ToolError)
        self.assertEqual(exec_error.exit_code, 1)
        self.assertEqual(exec_error.stderr, "Error message")
    
    def test_network_error_hierarchy(self):
        """Test network error class hierarchy"""
        # Test CaptureFailedError
        capture_error = CaptureFailedError("No handshake", "en0")
        self.assertIsInstance(capture_error, NetworkError)
        self.assertEqual(capture_error.category, ErrorCategory.NETWORK)
        self.assertEqual(capture_error.reason, "No handshake")
        self.assertEqual(capture_error.interface, "en0")
        
        # Test NoHandshakeError
        handshake_error = NoHandshakeError("TestNetwork", 300)
        self.assertIsInstance(handshake_error, NetworkError)
        self.assertEqual(handshake_error.target_network, "TestNetwork")
        self.assertEqual(handshake_error.capture_duration, 300)
        self.assertEqual(handshake_error.severity, ErrorSeverity.MEDIUM)
        
        # Test MonitorModeError
        monitor_error = MonitorModeError("en0", "SIP restriction")
        self.assertIsInstance(monitor_error, NetworkError)
        self.assertEqual(monitor_error.interface, "en0")
        self.assertEqual(monitor_error.reason, "SIP restriction")
        self.assertEqual(monitor_error.severity, ErrorSeverity.HIGH)
    
    def test_user_error_hierarchy(self):
        """Test user error class hierarchy"""
        # Test InvalidInputError
        input_error = InvalidInputError("BSSID", "invalid_mac", "XX:XX:XX:XX:XX:XX")
        self.assertIsInstance(input_error, UserError)
        self.assertEqual(input_error.category, ErrorCategory.USER)
        self.assertEqual(input_error.severity, ErrorSeverity.LOW)
        self.assertEqual(input_error.input_type, "BSSID")
        
        # Test FileNotFoundError
        file_error = FileNotFoundError("/path/to/file.txt", "wordlist")
        self.assertIsInstance(file_error, UserError)
        self.assertEqual(file_error.file_path, "/path/to/file.txt")
        self.assertEqual(file_error.file_type, "wordlist")
        
        # Test IllegalUsageError
        illegal_error = IllegalUsageError("Unauthorized network testing")
        self.assertIsInstance(illegal_error, UserError)
        self.assertEqual(illegal_error.severity, ErrorSeverity.CRITICAL)
        self.assertEqual(illegal_error.detected_activity, "Unauthorized network testing")
    
    def test_security_error_hierarchy(self):
        """Test security error class hierarchy"""
        # Test UnauthorizedAccessError
        auth_error = UnauthorizedAccessError("protected_network")
        self.assertIsInstance(auth_error, SecurityError)
        self.assertEqual(auth_error.category, ErrorCategory.SECURITY)
        self.assertEqual(auth_error.severity, ErrorSeverity.CRITICAL)
        self.assertEqual(auth_error.resource, "protected_network")
        
        # Test SuspiciousActivityError
        suspicious_error = SuspiciousActivityError("High frequency scanning")
        self.assertIsInstance(suspicious_error, SecurityError)
        self.assertEqual(suspicious_error.activity_description, "High frequency scanning")
        self.assertEqual(suspicious_error.severity, ErrorSeverity.CRITICAL)


class TestErrorHandler(unittest.TestCase):
    """Test ErrorHandler functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.error_handler = ErrorHandler(log_errors=False)  # Disable logging for tests
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_error_handler_initialization(self):
        """Test error handler initialization"""
        self.assertEqual(self.error_handler.max_retries, 3)
        self.assertEqual(len(self.error_handler.error_history), 0)
        self.assertIsInstance(self.error_handler.recovery_strategies, dict)
        self.assertIsInstance(self.error_handler.fallback_methods, dict)
        self.assertIsInstance(self.error_handler.degradation_modes, dict)
        
        # Check that default recovery strategies are set
        self.assertIn(SIPRestrictionError, self.error_handler.recovery_strategies)
        self.assertIn(DependencyMissingError, self.error_handler.recovery_strategies)
        self.assertIn(CaptureFailedError, self.error_handler.recovery_strategies)
    
    def test_recovery_strategy_determination(self):
        """Test recovery strategy determination"""
        # Test specific error type strategies
        sip_error = SIPRestrictionError("test_operation")
        strategy = self.error_handler._determine_recovery_strategy(sip_error)
        self.assertEqual(strategy, RecoveryStrategy.FALLBACK)
        
        dep_error = DependencyMissingError("test_tool")
        strategy = self.error_handler._determine_recovery_strategy(dep_error)
        self.assertEqual(strategy, RecoveryStrategy.USER_INTERVENTION)
        
        # Test severity-based fallback
        custom_error = WiFiSecurityError("Test", severity=ErrorSeverity.CRITICAL)
        strategy = self.error_handler._determine_recovery_strategy(custom_error)
        self.assertEqual(strategy, RecoveryStrategy.ABORT)
    
    def test_error_recording(self):
        """Test error recording functionality"""
        error = DependencyMissingError("test_tool")
        context = {"operation": "test_op", "user": "testuser"}
        
        error_record = self.error_handler._record_error(error, context, "test_operation")
        
        self.assertIn('timestamp', error_record)
        self.assertEqual(error_record['error_type'], 'DependencyMissingError')
        self.assertEqual(error_record['operation'], 'test_operation')
        self.assertEqual(error_record['context'], context)
        self.assertEqual(error_record['severity'], ErrorSeverity.MEDIUM.value)
        self.assertEqual(error_record['category'], ErrorCategory.TOOL.value)
        self.assertTrue(error_record['is_recoverable'])
        
        # Check error was added to history
        self.assertEqual(len(self.error_handler.error_history), 1)
        self.assertEqual(self.error_handler.error_history[0], error_record)
    
    def test_retry_strategy(self):
        """Test retry recovery strategy"""
        error = InterfaceDownError("en0")
        context = {"retry_count": 0}
        
        # First retry should succeed
        result = self.error_handler._handle_retry_strategy(error, context, "interface_up")
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['retry_count'], 1)
        self.assertIn('retry_delay', result)
        
        # Max retries exceeded
        context = {"retry_count": 5}
        result = self.error_handler._handle_retry_strategy(error, context, "interface_up")
        self.assertFalse(result['recovery_successful'])
        self.assertIn('Maximum retries', result['recovery_message'])
    
    def test_fallback_strategy(self):
        """Test fallback recovery strategy"""
        error = ToolNotRespondingError("aircrack-ng", 30)
        
        # Register a fallback method
        def fallback_method():
            return "fallback_result"
        
        self.error_handler.register_fallback_method("password_cracking", fallback_method)
        
        result = self.error_handler._handle_fallback_strategy(error, None, "password_cracking")
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['fallback_method'], 'fallback_method')
        self.assertIn('degradation_mode', result)
    
    def test_degradation_strategy(self):
        """Test graceful degradation strategy"""
        error = MemoryError("large_wordlist_processing")
        
        result = self.error_handler._handle_degradation_strategy(error, None, "password_cracking")
        self.assertTrue(result['recovery_successful'])
        self.assertIn('degradation_mode', result)
        self.assertIn('performance_impact', result)
    
    def test_user_intervention_strategy(self):
        """Test user intervention strategy"""
        error = PermissionDeniedError("packet_capture")
        
        result = self.error_handler._handle_user_intervention_strategy(error, None, "capture")
        self.assertFalse(result['recovery_successful'])
        self.assertTrue(result['user_action_required'])
        self.assertIn('recovery_suggestions', result)
        self.assertIn('user_guidance', result)
        
        # Check user guidance content
        guidance = result['user_guidance']
        self.assertIn("Issue:", guidance)
        self.assertIn("Suggested solutions:", guidance)
    
    def test_abort_strategy(self):
        """Test abort recovery strategy"""
        error = IllegalUsageError("Unauthorized testing")
        
        result = self.error_handler._handle_abort_strategy(error, None, "network_scan")
        self.assertFalse(result['recovery_successful'])
        self.assertIn('abort_reason', result)
        self.assertTrue(result['requires_restart'])
    
    def test_complete_error_handling_flow(self):
        """Test complete error handling flow"""
        error = CaptureFailedError("No handshake", "en0")
        context = {"attempt": 1, "target": "TestNetwork"}
        
        result = self.error_handler.handle_error(error, context, "packet_capture")
        
        # Check result structure
        required_keys = [
            'timestamp', 'error_type', 'error_message', 'operation', 'context',
            'severity', 'category', 'recovery_suggestions', 'is_recoverable',
            'strategy_used', 'recovery_successful', 'recovery_message'
        ]
        
        for key in required_keys:
            self.assertIn(key, result)
        
        # Check that error was recorded
        self.assertEqual(len(self.error_handler.error_history), 1)
    
    def test_error_statistics(self):
        """Test error statistics generation"""
        # Generate various errors
        errors = [
            DependencyMissingError("tool1"),
            DependencyMissingError("tool2"),
            SIPRestrictionError("operation1"),
            CaptureFailedError("reason1", "en0"),
            PermissionDeniedError("operation2")
        ]
        
        for error in errors:
            result = self.error_handler.handle_error(error)
            # Simulate some successful recoveries
            if isinstance(error, (DependencyMissingError, CaptureFailedError)):
                result['recovery_successful'] = True
        
        stats = self.error_handler.get_error_statistics()
        
        self.assertEqual(stats['total_errors'], 5)
        self.assertIn('errors_by_type', stats)
        self.assertIn('errors_by_category', stats)
        self.assertIn('errors_by_severity', stats)
        self.assertIn('recovery_success_rate', stats)
        self.assertIn('most_common_errors', stats)
        
        # Check specific statistics
        self.assertEqual(stats['errors_by_type']['DependencyMissingError'], 2)
        self.assertEqual(stats['errors_by_category']['TOOL'], 2)
        self.assertGreater(stats['recovery_success_rate'], 0)
    
    def test_error_log_export(self):
        """Test error log export functionality"""
        # Generate some errors
        errors = [
            DependencyMissingError("test_tool"),
            SIPRestrictionError("test_operation")
        ]
        
        for error in errors:
            self.error_handler.handle_error(error)
        
        # Export log
        export_file = os.path.join(self.temp_dir, "error_log.json")
        success = self.error_handler.export_error_log(export_file)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(export_file))
        
        # Verify export content
        with open(export_file, 'r') as f:
            exported_data = json.load(f)
        
        self.assertIn('export_timestamp', exported_data)
        self.assertIn('error_history', exported_data)
        self.assertIn('statistics', exported_data)
        self.assertEqual(len(exported_data['error_history']), 2)
    
    def test_custom_recovery_strategy_registration(self):
        """Test custom recovery strategy registration"""
        # Register custom strategy
        self.error_handler.register_recovery_strategy(
            ConfigurationError, 
            RecoveryStrategy.DEGRADE
        )
        
        # Test that custom strategy is used
        config_error = ConfigurationError("test_config", "invalid_value")
        strategy = self.error_handler._determine_recovery_strategy(config_error)
        self.assertEqual(strategy, RecoveryStrategy.DEGRADE)
    
    def test_fallback_method_registration(self):
        """Test fallback method registration"""
        def custom_fallback():
            return "custom_result"
        
        self.error_handler.register_fallback_method("custom_operation", custom_fallback)
        
        self.assertIn("custom_operation", self.error_handler.fallback_methods)
        self.assertEqual(
            self.error_handler.fallback_methods["custom_operation"], 
            custom_fallback
        )


class TestErrorHandlerIntegration(unittest.TestCase):
    """Test error handler integration features"""
    
    def test_global_error_handler(self):
        """Test global error handler functionality"""
        # Test singleton behavior
        handler1 = get_error_handler()
        handler2 = get_error_handler()
        self.assertIs(handler1, handler2)
        
        # Test convenience function
        error = DependencyMissingError("test_tool")
        result = handle_error(error, {"test": True}, "test_operation")
        
        self.assertIn('error_type', result)
        self.assertEqual(result['error_type'], 'DependencyMissingError')
    
    def test_error_handling_decorator(self):
        """Test error handling decorator"""
        @with_error_handling("test_operation")
        def test_function(should_fail=False):
            if should_fail:
                raise DependencyMissingError("test_tool")
            return "success"
        
        # Test successful execution
        result = test_function(should_fail=False)
        self.assertEqual(result, "success")
        
        # Test error handling
        with self.assertRaises(DependencyMissingError):
            test_function(should_fail=True)
        
        # Check that error was recorded
        handler = get_error_handler()
        self.assertGreater(len(handler.error_history), 0)
    
    def test_degradation_mode_selection(self):
        """Test degradation mode selection"""
        handler = ErrorHandler()
        
        # Test exact match
        degradation = handler._get_degradation_mode("network_scanning")
        self.assertIsNotNone(degradation)
        self.assertIn('primary', degradation)
        self.assertIn('fallback', degradation)
        self.assertIn('minimal', degradation)
        
        # Test partial match
        degradation = handler._get_degradation_mode("packet_capture_advanced")
        self.assertIsNotNone(degradation)
        
        # Test no match
        degradation = handler._get_degradation_mode("unknown_operation")
        self.assertIsNone(degradation)
    
    def test_user_guidance_generation(self):
        """Test user guidance generation"""
        handler = ErrorHandler()
        
        # Test with recovery suggestions
        error = DependencyMissingError("aircrack-ng")
        guidance = handler._generate_user_guidance(error)
        
        self.assertIn("Issue:", guidance)
        self.assertIn("Suggested solutions:", guidance)
        self.assertIn("automatic dependency installation", guidance)
        
        # Test SIP-specific guidance
        sip_error = SIPRestrictionError("monitor_mode")
        guidance = handler._generate_user_guidance(sip_error)
        
        self.assertIn("Disabling SIP reduces system security", guidance)
        
        # Test permission error guidance
        perm_error = PermissionDeniedError("packet_capture")
        guidance = handler._generate_user_guidance(perm_error)
        
        self.assertIn("sudo", guidance)


class TestErrorHandlerPerformance(unittest.TestCase):
    """Test error handler performance and edge cases"""
    
    def test_large_error_history_handling(self):
        """Test handling of large error history"""
        handler = ErrorHandler(log_errors=False)
        
        # Generate many errors
        for i in range(1000):
            error = DependencyMissingError(f"tool_{i}")
            handler.handle_error(error)
        
        # Test that statistics can still be generated efficiently
        start_time = time.time()
        stats = handler.get_error_statistics()
        end_time = time.time()
        
        self.assertLess(end_time - start_time, 1.0)  # Should complete within 1 second
        self.assertEqual(stats['total_errors'], 1000)
    
    def test_concurrent_error_handling(self):
        """Test concurrent error handling (basic thread safety)"""
        import threading
        
        handler = ErrorHandler(log_errors=False)
        errors = []
        
        def generate_errors():
            for i in range(100):
                error = DependencyMissingError(f"tool_{threading.current_thread().ident}_{i}")
                try:
                    handler.handle_error(error)
                except Exception as e:
                    errors.append(e)
        
        # Create multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=generate_errors)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check that no errors occurred during concurrent access
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(handler.error_history), 500)  # 5 threads * 100 errors each
    
    def test_memory_cleanup(self):
        """Test memory cleanup functionality"""
        handler = ErrorHandler(log_errors=False)
        
        # Generate errors
        for i in range(100):
            error = DependencyMissingError(f"tool_{i}")
            handler.handle_error(error)
        
        self.assertEqual(len(handler.error_history), 100)
        
        # Clear history
        handler.clear_error_history()
        self.assertEqual(len(handler.error_history), 0)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestErrorClassification,
        TestErrorHandler,
        TestErrorHandlerIntegration,
        TestErrorHandlerPerformance
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
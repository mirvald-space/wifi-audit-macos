#!/usr/bin/env python3
"""
Test suite for comprehensive error handling system
Tests error classification, recovery mechanisms, and user guidance
"""

import sys
import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))

from core.exceptions import *
from core.error_handler import ErrorHandler, get_error_handler, RecoveryStrategy
from core.recovery_manager import RecoveryManager, get_recovery_manager, FallbackMethod
from core.user_guidance import UserGuidanceSystem, get_user_guidance_system, GuidanceLevel


class TestErrorClassification(unittest.TestCase):
    """Test error classification and hierarchy"""
    
    def test_system_errors(self):
        """Test system error classification"""
        # Test SIP restriction error
        sip_error = SIPRestrictionError("monitor_mode")
        self.assertEqual(sip_error.category, ErrorCategory.SYSTEM)
        self.assertEqual(sip_error.severity, ErrorSeverity.HIGH)
        self.assertTrue(len(sip_error.recovery_suggestions) > 0)
        
        # Test interface not found error
        interface_error = InterfaceNotFoundError("en0")
        self.assertEqual(interface_error.category, ErrorCategory.SYSTEM)
        self.assertEqual(interface_error.interface_name, "en0")
        
        # Test permission denied error
        perm_error = PermissionDeniedError("packet_capture")
        self.assertEqual(perm_error.severity, ErrorSeverity.HIGH)
        self.assertEqual(perm_error.operation, "packet_capture")
    
    def test_tool_errors(self):
        """Test tool error classification"""
        # Test dependency missing error
        dep_error = DependencyMissingError("aircrack-ng")
        self.assertEqual(dep_error.category, ErrorCategory.TOOL)
        self.assertEqual(dep_error.tool_name, "aircrack-ng")
        
        # Test version incompatible error
        version_error = VersionIncompatibleError("hashcat", "6.0.0", "6.2.0")
        self.assertEqual(version_error.current_version, "6.0.0")
        self.assertEqual(version_error.required_version, "6.2.0")
        
        # Test execution failed error
        exec_error = ExecutionFailedError("aircrack-ng", "aircrack-ng -w wordlist.txt", 1, "File not found")
        self.assertEqual(exec_error.exit_code, 1)
        self.assertEqual(exec_error.stderr, "File not found")
    
    def test_network_errors(self):
        """Test network error classification"""
        # Test interface down error
        interface_down = InterfaceDownError("en0")
        self.assertEqual(interface_down.category, ErrorCategory.NETWORK)
        self.assertEqual(interface_down.interface_name, "en0")
        
        # Test capture failed error
        capture_error = CaptureFailedError("No monitor mode", "en0")
        self.assertEqual(capture_error.reason, "No monitor mode")
        self.assertEqual(capture_error.interface, "en0")
        
        # Test no handshake error
        handshake_error = NoHandshakeError("TestNetwork", 300)
        self.assertEqual(handshake_error.target_network, "TestNetwork")
        self.assertEqual(handshake_error.capture_duration, 300)
    
    def test_user_errors(self):
        """Test user error classification"""
        # Test invalid input error
        input_error = InvalidInputError("MAC address", "invalid-mac", "XX:XX:XX:XX:XX:XX")
        self.assertEqual(input_error.category, ErrorCategory.USER)
        self.assertEqual(input_error.severity, ErrorSeverity.LOW)
        
        # Test file not found error
        file_error = FileNotFoundError("/path/to/file.txt", "wordlist")
        self.assertEqual(file_error.file_path, "/path/to/file.txt")
        self.assertEqual(file_error.file_type, "wordlist")
        
        # Test illegal usage error
        illegal_error = IllegalUsageError("Scanning unauthorized network")
        self.assertEqual(illegal_error.severity, ErrorSeverity.CRITICAL)
    
    def test_security_errors(self):
        """Test security error classification"""
        # Test unauthorized access error
        auth_error = UnauthorizedAccessError("/etc/passwd")
        self.assertEqual(auth_error.category, ErrorCategory.SECURITY)
        self.assertEqual(auth_error.severity, ErrorSeverity.CRITICAL)
        
        # Test suspicious activity error
        suspicious_error = SuspiciousActivityError("Multiple failed authentication attempts")
        self.assertEqual(suspicious_error.severity, ErrorSeverity.CRITICAL)
    
    def test_error_context(self):
        """Test error context functionality"""
        error = WiFiSecurityError("Test error")
        error.add_context("operation", "network_scan")
        error.add_context("interface", "en0")
        
        self.assertEqual(error.context["operation"], "network_scan")
        self.assertEqual(error.context["interface"], "en0")
    
    def test_error_recoverability(self):
        """Test error recoverability detection"""
        recoverable_error = DependencyMissingError("aircrack-ng")
        self.assertTrue(recoverable_error.is_recoverable())
        
        critical_error = IllegalUsageError("Unauthorized access")
        # Critical errors typically have recovery suggestions but may not be automatically recoverable
        self.assertTrue(len(critical_error.recovery_suggestions) > 0)


class TestErrorHandler(unittest.TestCase):
    """Test error handler functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.error_handler = ErrorHandler(log_errors=False)
    
    def test_error_recording(self):
        """Test error recording functionality"""
        error = DependencyMissingError("test-tool")
        context = {"operation": "test_operation"}
        
        result = self.error_handler.handle_error(error, context, "test_operation")
        
        self.assertEqual(result['error_type'], 'DependencyMissingError')
        self.assertEqual(result['operation'], 'test_operation')
        self.assertEqual(result['context'], context)
        self.assertEqual(len(self.error_handler.error_history), 1)
    
    def test_recovery_strategy_determination(self):
        """Test recovery strategy determination"""
        # Test retry strategy
        exec_error = ExecutionFailedError("test-tool", "test command", 1)
        strategy = self.error_handler._determine_recovery_strategy(exec_error)
        self.assertEqual(strategy, RecoveryStrategy.RETRY)
        
        # Test fallback strategy
        sip_error = SIPRestrictionError("test_operation")
        strategy = self.error_handler._determine_recovery_strategy(sip_error)
        self.assertEqual(strategy, RecoveryStrategy.FALLBACK)
        
        # Test abort strategy
        illegal_error = IllegalUsageError("test activity")
        strategy = self.error_handler._determine_recovery_strategy(illegal_error)
        self.assertEqual(strategy, RecoveryStrategy.ABORT)
    
    def test_retry_strategy(self):
        """Test retry recovery strategy"""
        error = ExecutionFailedError("test-tool", "test command", 1)
        context = {"retry_count": 0}
        
        result = self.error_handler._handle_retry_strategy(error, context)
        
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['retry_count'], 1)
        self.assertIn('retry_delay', result)
    
    def test_max_retries_exceeded(self):
        """Test maximum retries exceeded"""
        error = ExecutionFailedError("test-tool", "test command", 1)
        context = {"retry_count": 5}  # Exceeds default max_retries (3)
        
        result = self.error_handler._handle_retry_strategy(error, context)
        
        self.assertFalse(result['recovery_successful'])
        self.assertIn('Maximum retries', result['recovery_message'])
    
    def test_fallback_strategy(self):
        """Test fallback recovery strategy"""
        error = SIPRestrictionError("test_operation")
        
        result = self.error_handler._handle_fallback_strategy(error, None, "network_scanning")
        
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['recovery_message'], 'Switching to fallback method')
    
    def test_user_intervention_strategy(self):
        """Test user intervention recovery strategy"""
        error = DependencyMissingError("test-tool")
        
        result = self.error_handler._handle_user_intervention_strategy(error)
        
        self.assertFalse(result['recovery_successful'])
        self.assertTrue(result['user_action_required'])
        self.assertIn('recovery_suggestions', result)
    
    def test_error_statistics(self):
        """Test error statistics generation"""
        # Generate some test errors
        errors = [
            DependencyMissingError("tool1"),
            DependencyMissingError("tool2"),
            ExecutionFailedError("tool3", "cmd", 1),
            SIPRestrictionError("operation")
        ]
        
        for error in errors:
            self.error_handler.handle_error(error)
        
        stats = self.error_handler.get_error_statistics()
        
        self.assertEqual(stats['total_errors'], 4)
        self.assertIn('DependencyMissingError', stats['errors_by_type'])
        self.assertEqual(stats['errors_by_type']['DependencyMissingError'], 2)
        self.assertIn('tool', stats['errors_by_category'])
    
    def test_custom_recovery_strategy_registration(self):
        """Test custom recovery strategy registration"""
        self.error_handler.register_recovery_strategy(
            WiFiSecurityError, RecoveryStrategy.DEGRADE
        )
        
        error = WiFiSecurityError("test error")
        strategy = self.error_handler._determine_recovery_strategy(error)
        self.assertEqual(strategy, RecoveryStrategy.DEGRADE)
    
    @patch('builtins.open', create=True)
    def test_error_log_export(self, mock_open):
        """Test error log export functionality"""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        # Add some errors to history
        self.error_handler.handle_error(DependencyMissingError("test-tool"))
        
        result = self.error_handler.export_error_log("/tmp/test_log.json")
        
        self.assertTrue(result)
        mock_open.assert_called_once()
        mock_file.write.assert_called()


class TestRecoveryManager(unittest.TestCase):
    """Test recovery manager functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.recovery_manager = RecoveryManager()
    
    def test_fallback_method_registration(self):
        """Test fallback method registration"""
        def test_method():
            return "test_result"
        
        fallback = FallbackMethod("test_method", test_method, priority=1)
        self.recovery_manager.register_fallback_method("test_operation", fallback)
        
        methods = self.recovery_manager.get_available_fallback_methods("test_operation")
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0].name, "test_method")
    
    def test_fallback_method_priority_sorting(self):
        """Test fallback method priority sorting"""
        def method1():
            return "method1"
        
        def method2():
            return "method2"
        
        fallback1 = FallbackMethod("method1", method1, priority=2)
        fallback2 = FallbackMethod("method2", method2, priority=1)
        
        self.recovery_manager.register_fallback_method("test_op", fallback1)
        self.recovery_manager.register_fallback_method("test_op", fallback2)
        
        methods = self.recovery_manager.get_available_fallback_methods("test_op")
        self.assertEqual(methods[0].name, "method2")  # Lower priority number = higher priority
        self.assertEqual(methods[1].name, "method1")
    
    @patch('wifi_security_tester.core.recovery_manager.run_command')
    def test_system_state_save_restore(self, mock_run_command):
        """Test system state save and restore"""
        # Mock system command responses
        mock_run_command.return_value = Mock(returncode=0, stdout="mock output")
        
        # Save system state
        state_id = self.recovery_manager.save_system_state()
        self.assertIsNotNone(state_id)
        self.assertTrue(state_id.startswith("state_"))
        
        # Restore system state
        result = self.recovery_manager.restore_system_state(state_id)
        self.assertTrue(result)
    
    def test_execute_with_fallback_success(self):
        """Test successful execution with fallback"""
        def primary_method():
            return "primary_success"
        
        success, result, method = self.recovery_manager.execute_with_fallback(
            "test_operation", primary_method
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "primary_success")
        self.assertEqual(method, "primary")
    
    def test_execute_with_fallback_failure_and_recovery(self):
        """Test execution with primary failure and fallback success"""
        def failing_primary():
            raise Exception("Primary method failed")
        
        def working_fallback():
            return "fallback_success"
        
        # Register fallback method
        fallback = FallbackMethod("working_fallback", working_fallback, priority=1)
        self.recovery_manager.register_fallback_method("test_operation", fallback)
        
        success, result, method = self.recovery_manager.execute_with_fallback(
            "test_operation", failing_primary
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "fallback_success")
        self.assertEqual(method, "working_fallback")
    
    def test_recovery_procedure_execution(self):
        """Test recovery procedure execution"""
        error = InterfaceDownError("en0")
        context = {"interface": "en0"}
        
        result = self.recovery_manager.recover_from_error(error, "interface_control", context)
        
        self.assertTrue(result['recovery_attempted'])
        self.assertIn('recovery_method', result)
    
    @patch('wifi_security_tester.core.recovery_manager.run_command')
    def test_interface_recovery(self, mock_run_command):
        """Test interface recovery procedure"""
        mock_run_command.return_value = Mock(returncode=0)
        
        error = InterfaceDownError("en0")
        context = {"interface": "en0"}
        
        success, message = self.recovery_manager._recover_stuck_interface(error, context)
        
        self.assertTrue(success)
        self.assertIn("reset successfully", message)
    
    @patch('wifi_security_tester.core.recovery_manager.run_command')
    def test_hanging_process_recovery(self, mock_run_command):
        """Test hanging process recovery"""
        mock_run_command.return_value = Mock(returncode=0)
        
        error = ToolNotRespondingError("test-tool", 30)
        
        success, message = self.recovery_manager._recover_hanging_process(error)
        
        self.assertTrue(success)
        self.assertIn("processes", message)


class TestUserGuidanceSystem(unittest.TestCase):
    """Test user guidance system functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.guidance_system = UserGuidanceSystem()
    
    def test_guidance_template_initialization(self):
        """Test guidance template initialization"""
        self.assertIn(SIPRestrictionError, self.guidance_system.guidance_templates)
        self.assertIn(DependencyMissingError, self.guidance_system.guidance_templates)
        self.assertIn(MonitorModeError, self.guidance_system.guidance_templates)
    
    def test_get_guidance_for_known_error(self):
        """Test getting guidance for known error types"""
        error = SIPRestrictionError("test_operation")
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertIn('title', guidance)
        self.assertIn('description', guidance)
        self.assertIn('solutions', guidance)
        self.assertEqual(guidance['severity'], 'HIGH')
    
    def test_get_guidance_for_unknown_error(self):
        """Test getting guidance for unknown error types"""
        class UnknownError(Exception):
            pass
        
        error = UnknownError("Unknown error occurred")
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertEqual(guidance['title'], 'Unexpected Error')
        self.assertIn('solutions', guidance)
    
    def test_guidance_level_filtering(self):
        """Test guidance filtering by user level"""
        error = DependencyMissingError("test-tool")
        
        # Basic level should only show easy solutions
        basic_guidance = self.guidance_system.get_guidance(error, GuidanceLevel.BASIC)
        easy_solutions = [sol for sol in basic_guidance['solutions'] if sol.get('difficulty') == 'Easy']
        self.assertEqual(len(basic_guidance['solutions']), len(easy_solutions))
        
        # Detailed level should show all solutions
        detailed_guidance = self.guidance_system.get_guidance(error, GuidanceLevel.DETAILED)
        self.assertGreaterEqual(len(detailed_guidance['solutions']), len(easy_solutions))
    
    def test_guidance_text_formatting(self):
        """Test guidance text formatting"""
        error = DependencyMissingError("test-tool")
        guidance = self.guidance_system.get_guidance(error)
        formatted_text = self.guidance_system.format_guidance_text(guidance)
        
        self.assertIn("ERROR:", formatted_text)
        self.assertIn("DETAILED SOLUTIONS:", formatted_text)
        self.assertIn("="*60, formatted_text)
    
    def test_quick_help_suggestions(self):
        """Test quick help suggestions"""
        permission_help = self.guidance_system.get_quick_help("permission")
        self.assertIn("Run with sudo privileges", permission_help)
        
        dependency_help = self.guidance_system.get_quick_help("dependency")
        self.assertIn("Use automatic dependency installation", dependency_help)
        
        unknown_help = self.guidance_system.get_quick_help("unknown_type")
        self.assertIn("Restart the application", unknown_help)
    
    def test_system_specific_guidance(self):
        """Test system-specific guidance customization"""
        error = SIPRestrictionError("test_operation")
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertIn('system_info', guidance)
        self.assertIn('macos_version', guidance['system_info'])


class TestIntegration(unittest.TestCase):
    """Test integration between error handling components"""
    
    def setUp(self):
        """Set up test environment"""
        self.error_handler = ErrorHandler(log_errors=False)
        self.recovery_manager = RecoveryManager()
        self.guidance_system = UserGuidanceSystem()
    
    def test_end_to_end_error_handling(self):
        """Test complete error handling workflow"""
        # Create a test error
        error = DependencyMissingError("test-tool")
        context = {"operation": "dependency_check"}
        
        # Handle the error
        result = self.error_handler.handle_error(error, context, "dependency_check")
        
        # Verify error was recorded
        self.assertEqual(result['error_type'], 'DependencyMissingError')
        self.assertTrue(result['is_recoverable'])
        
        # Get user guidance
        guidance = self.guidance_system.get_guidance(error)
        self.assertIn('solutions', guidance)
        
        # Attempt recovery
        recovery_result = self.recovery_manager.recover_from_error(error, "dependency_check", context)
        self.assertTrue(recovery_result['recovery_attempted'])
    
    def test_error_handler_with_recovery_manager(self):
        """Test error handler integration with recovery manager"""
        # Register a fallback method in recovery manager
        def test_fallback():
            return "fallback_success"
        
        fallback = FallbackMethod("test_fallback", test_fallback, priority=1)
        self.recovery_manager.register_fallback_method("test_operation", fallback)
        
        # Register the fallback in error handler
        self.error_handler.register_fallback_method("test_operation", test_fallback)
        
        # Test error handling with fallback
        error = ExecutionFailedError("test-tool", "test command", 1)
        result = self.error_handler.handle_error(error, None, "test_operation")
        
        self.assertIn('strategy_used', result)
    
    def test_guidance_with_error_context(self):
        """Test guidance system with error context"""
        error = CaptureFailedError("Monitor mode not supported", "en0")
        error.add_context("interface_type", "built-in")
        error.add_context("macos_version", "12.0")
        
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertIn('context', guidance)
        self.assertEqual(guidance['context']['interface_type'], "built-in")


def run_error_handling_tests():
    """Run all error handling tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestErrorClassification,
        TestErrorHandler,
        TestRecoveryManager,
        TestUserGuidanceSystem,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("Running WiFi Security Tester Error Handling Tests...")
    print("="*60)
    
    success = run_error_handling_tests()
    
    if success:
        print("\n✅ All error handling tests passed!")
    else:
        print("\n❌ Some error handling tests failed!")
        sys.exit(1)
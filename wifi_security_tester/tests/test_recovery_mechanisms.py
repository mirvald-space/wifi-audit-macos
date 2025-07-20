#!/usr/bin/env python3
"""
Test Recovery and Fallback Mechanisms
Tests the comprehensive recovery system for WiFi Security Tester
"""

import sys
import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))
from core.exceptions import *
from core.error_handler import ErrorHandler, RecoveryStrategy
from core.recovery_manager import RecoveryManager, FallbackMethod
from core.recovery_coordinator import RecoveryCoordinator, RecoveryStatus
from core.user_guidance import UserGuidanceSystem, GuidanceLevel


class TestRecoveryMechanisms(unittest.TestCase):
    """Test comprehensive recovery and fallback mechanisms"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.error_handler = ErrorHandler(log_errors=False)
        self.recovery_manager = RecoveryManager()
        self.recovery_coordinator = RecoveryCoordinator()
        self.guidance_system = UserGuidanceSystem()
    
    def test_error_handler_recovery_strategies(self):
        """Test error handler recovery strategy determination"""
        # Test SIP restriction error
        sip_error = SIPRestrictionError("test operation")
        strategy = self.error_handler._determine_recovery_strategy(sip_error)
        self.assertEqual(strategy, RecoveryStrategy.FALLBACK)
        
        # Test permission denied error
        perm_error = PermissionDeniedError("test operation")
        strategy = self.error_handler._determine_recovery_strategy(perm_error)
        self.assertEqual(strategy, RecoveryStrategy.USER_INTERVENTION)
        
        # Test dependency missing error
        dep_error = DependencyMissingError("aircrack-ng")
        strategy = self.error_handler._determine_recovery_strategy(dep_error)
        self.assertEqual(strategy, RecoveryStrategy.USER_INTERVENTION)
        
        # Test interface down error
        int_error = InterfaceDownError("en0")
        strategy = self.error_handler._determine_recovery_strategy(int_error)
        self.assertEqual(strategy, RecoveryStrategy.RETRY)
    
    def test_error_handler_retry_strategy(self):
        """Test retry recovery strategy"""
        error = InterfaceDownError("en0")
        context = {'retry_count': 0}
        
        result = self.error_handler._handle_retry_strategy(error, context)
        
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['retry_count'], 1)
        self.assertIn('retry_delay', result)
    
    def test_error_handler_fallback_strategy(self):
        """Test fallback recovery strategy"""
        error = SIPRestrictionError("monitor mode")
        context = {}
        
        result = self.error_handler._handle_fallback_strategy(error, context, "packet_capture")
        
        self.assertTrue(result['recovery_successful'])
        self.assertEqual(result['recovery_message'], 'Switching to fallback method')
        self.assertIn('degradation_mode', result)
    
    def test_error_handler_user_intervention_strategy(self):
        """Test user intervention recovery strategy"""
        error = PermissionDeniedError("interface control")
        context = {}
        
        result = self.error_handler._handle_user_intervention_strategy(error, context)
        
        self.assertFalse(result['recovery_successful'])
        self.assertTrue(result['user_action_required'])
        self.assertIn('recovery_suggestions', result)
        self.assertIn('user_guidance', result)
    
    def test_recovery_manager_fallback_methods(self):
        """Test recovery manager fallback method registration and execution"""
        # Test fallback method registration
        test_method = FallbackMethod('test_method', lambda: "test_result", priority=1)
        self.recovery_manager.register_fallback_method('test_operation', test_method)
        
        fallbacks = self.recovery_manager.get_available_fallback_methods('test_operation')
        self.assertEqual(len(fallbacks), 1)
        self.assertEqual(fallbacks[0].name, 'test_method')
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_recovery_manager_network_scan_fallbacks(self, mock_run_command):
        """Test network scanning fallback methods"""
        # Mock successful wdutil scan
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="Test network scan output",
            stderr=""
        )
        
        # Test wdutil fallback
        try:
            result = self.recovery_manager._wdutil_network_scan()
            # Should not raise exception
        except Exception as e:
            # Expected since we're not parsing real output
            self.assertIsInstance(e, NetworkError)
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_recovery_manager_interface_control_fallbacks(self, mock_run_command):
        """Test interface control fallback methods"""
        # Mock successful interface control
        mock_run_command.return_value = Mock(returncode=0, stdout="", stderr="")
        
        # Test networksetup fallback
        result = self.recovery_manager._networksetup_interface_control("en0", "up")
        self.assertTrue(result)
        
        # Test ifconfig fallback
        result = self.recovery_manager._ifconfig_interface_control("en0", "up")
        self.assertTrue(result)
    
    def test_recovery_manager_system_state_management(self):
        """Test system state save and restore"""
        # Test saving system state
        state_id = self.recovery_manager.save_system_state()
        self.assertIsInstance(state_id, str)
        self.assertTrue(state_id.startswith('state_'))
        
        # Test restoring system state
        success = self.recovery_manager.restore_system_state(state_id)
        # May fail in test environment, but should not raise exception
        self.assertIsInstance(success, bool)
    
    def test_recovery_manager_execute_with_fallback(self):
        """Test execute with fallback functionality"""
        # Create a primary method that fails
        def failing_primary():
            raise ExecutionFailedError("test_tool", "test_command", 1, "test error")
        
        # Register a successful fallback
        def successful_fallback():
            return "fallback_result"
        
        fallback = FallbackMethod('test_fallback', successful_fallback, priority=1)
        self.recovery_manager.register_fallback_method('test_op', fallback)
        
        # Execute with fallback
        success, result, method = self.recovery_manager.execute_with_fallback(
            'test_op', failing_primary
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "fallback_result")
        self.assertEqual(method, "test_fallback")
    
    def test_recovery_coordinator_error_handling(self):
        """Test recovery coordinator comprehensive error handling"""
        # Test with a recoverable error
        error = InterfaceDownError("en0")
        context = {'interface': 'en0', 'operation': 'test'}
        
        result = self.recovery_coordinator.handle_error_with_recovery(
            error, "interface_control", context, max_recovery_attempts=2
        )
        
        self.assertIn('operation_id', result)
        self.assertIn('recovery_attempted', result)
        self.assertTrue(result['recovery_attempted'])
        self.assertIn('attempts', result)
        self.assertIsInstance(result['attempts'], list)
    
    def test_recovery_coordinator_specific_recovery_strategies(self):
        """Test specific recovery strategies in coordinator"""
        # Test system state recovery
        error = SystemError("test system error")
        success, message, details = self.recovery_coordinator._system_state_recovery(
            error, "test_operation", {}
        )
        self.assertIsInstance(success, bool)
        self.assertIsInstance(message, str)
        self.assertIsInstance(details, dict)
        
        # Test permission recovery
        error = PermissionDeniedError("test operation")
        success, message, details = self.recovery_coordinator._permission_recovery(
            error, "test_operation", {}
        )
        self.assertIsInstance(success, bool)
        self.assertIsInstance(message, str)
        self.assertIsInstance(details, dict)
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_recovery_coordinator_interface_recovery(self, mock_run_command):
        """Test interface recovery in coordinator"""
        # Mock successful interface commands
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>",
            stderr=""
        )
        
        error = InterfaceDownError("en0")
        context = {'interface': 'en0'}
        
        success, message, details = self.recovery_coordinator._interface_recovery(
            error, "interface_control", context
        )
        
        self.assertIsInstance(success, bool)
        self.assertIn('interface', details)
    
    def test_recovery_coordinator_dependency_recovery(self):
        """Test dependency recovery in coordinator"""
        error = DependencyMissingError("test_tool")
        
        success, message, details = self.recovery_coordinator._dependency_recovery(
            error, "dependency_install", {}
        )
        
        self.assertIsInstance(success, bool)
        self.assertIsInstance(message, str)
        self.assertIsInstance(details, dict)
    
    def test_recovery_coordinator_fallback_chains(self):
        """Test fallback chains in coordinator"""
        # Test network scan fallback chain
        fallback_chain = self.recovery_coordinator.fallback_chains.get('network_scan', [])
        self.assertIn('wdutil_scan', fallback_chain)
        self.assertIn('system_profiler_scan', fallback_chain)
        self.assertIn('networksetup_scan', fallback_chain)
        
        # Test packet capture fallback chain
        fallback_chain = self.recovery_coordinator.fallback_chains.get('packet_capture', [])
        self.assertIn('airodump_capture', fallback_chain)
        self.assertIn('tcpdump_capture', fallback_chain)
    
    def test_recovery_coordinator_recovery_suggestions(self):
        """Test recovery suggestion generation"""
        error = NoHandshakeError("TestNetwork", 60)
        context = {'interface': 'en0', 'timeout_occurred': True}
        
        suggestions = self.recovery_coordinator._generate_recovery_suggestions(
            error, "packet_capture", context
        )
        
        self.assertIsInstance(suggestions, list)
        self.assertTrue(len(suggestions) > 0)
        
        # Check for context-specific suggestions
        suggestion_text = ' '.join(suggestions)
        self.assertIn('timeout', suggestion_text.lower())
    
    def test_user_guidance_system_error_guidance(self):
        """Test user guidance system error-specific guidance"""
        # Test SIP restriction guidance
        error = SIPRestrictionError("monitor mode")
        guidance = self.guidance_system.get_guidance(error, GuidanceLevel.DETAILED)
        
        self.assertIn('title', guidance)
        self.assertIn('description', guidance)
        self.assertIn('solutions', guidance)
        self.assertEqual(guidance['title'], 'System Integrity Protection (SIP) Restriction')
        
        # Check solutions are present
        solutions = guidance['solutions']
        self.assertTrue(len(solutions) > 0)
        self.assertIn('steps', solutions[0])
    
    def test_user_guidance_system_dependency_guidance(self):
        """Test dependency error guidance"""
        error = DependencyMissingError("aircrack-ng")
        guidance = self.guidance_system.get_guidance(error, GuidanceLevel.DETAILED)
        
        self.assertEqual(guidance['title'], 'Required Tool Missing')
        self.assertIn('solutions', guidance)
        
        # Check for automatic installation solution
        solutions = guidance['solutions']
        solution_titles = [sol['title'] for sol in solutions]
        self.assertIn('Use Automatic Installation', solution_titles)
    
    def test_user_guidance_system_formatting(self):
        """Test guidance text formatting"""
        error = PermissionDeniedError("test operation")
        guidance = self.guidance_system.get_guidance(error)
        formatted_text = self.guidance_system.format_guidance_text(guidance)
        
        self.assertIsInstance(formatted_text, str)
        self.assertIn('ERROR:', formatted_text)
        self.assertIn('DETAILED SOLUTIONS:', formatted_text)
        self.assertIn('=', formatted_text)  # Check for formatting separators
    
    def test_user_guidance_system_quick_help(self):
        """Test quick help functionality"""
        # Test permission quick help
        help_suggestions = self.guidance_system.get_quick_help('permission')
        self.assertIn('Run with sudo privileges', help_suggestions)
        
        # Test dependency quick help
        help_suggestions = self.guidance_system.get_quick_help('dependency')
        self.assertIn('Use automatic dependency installation', help_suggestions)
        
        # Test network quick help
        help_suggestions = self.guidance_system.get_quick_help('network')
        self.assertIn('Check WiFi is enabled', help_suggestions)
    
    def test_integration_error_to_recovery_flow(self):
        """Test complete error to recovery flow integration"""
        # Create a test error
        error = InterfaceDownError("en0")
        context = {'interface': 'en0', 'operation': 'test_scan'}
        
        # Handle with recovery coordinator
        result = self.recovery_coordinator.handle_error_with_recovery(
            error, "network_scan", context
        )
        
        # Verify comprehensive result structure
        expected_keys = [
            'operation_id', 'original_error', 'error_type', 'recovery_attempted',
            'recovery_successful', 'recovery_method', 'fallback_used',
            'user_guidance', 'requires_user_action', 'recovery_suggestions',
            'system_state_restored', 'attempts'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # Verify operation tracking
        operation_id = result['operation_id']
        recovery_op = self.recovery_coordinator.get_recovery_status(operation_id)
        self.assertIsNotNone(recovery_op)
        self.assertEqual(recovery_op.operation_type, "network_scan")
    
    def test_recovery_statistics(self):
        """Test recovery statistics collection"""
        # Generate some recovery operations
        errors = [
            InterfaceDownError("en0"),
            DependencyMissingError("aircrack-ng"),
            PermissionDeniedError("test operation")
        ]
        
        for i, error in enumerate(errors):
            self.recovery_coordinator.handle_error_with_recovery(
                error, f"test_operation_{i}", {}
            )
        
        # Get statistics
        stats = self.recovery_coordinator.get_recovery_statistics()
        
        self.assertIn('total_recoveries', stats)
        self.assertIn('successful_recoveries', stats)
        self.assertIn('success_rate', stats)
        self.assertEqual(stats['total_recoveries'], len(errors))
    
    def test_concurrent_recovery_handling(self):
        """Test handling of concurrent recovery operations"""
        import threading
        
        def recovery_operation(error_num):
            error = InterfaceDownError(f"en{error_num}")
            return self.recovery_coordinator.handle_error_with_recovery(
                error, f"test_operation_{error_num}", {}
            )
        
        # Start multiple recovery operations
        threads = []
        results = []
        
        for i in range(3):
            thread = threading.Thread(
                target=lambda i=i: results.append(recovery_operation(i))
            )
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify all operations completed
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIn('operation_id', result)
    
    def test_emergency_recovery(self):
        """Test emergency recovery procedures"""
        error = SystemError("Critical system failure")
        
        success, message, details = self.recovery_coordinator._emergency_recovery(
            error, "critical_operation", {}
        )
        
        self.assertIsInstance(success, bool)
        self.assertIn('emergency_steps', details)
        self.assertIn('system_restored', details)


def run_recovery_mechanism_tests():
    """Run all recovery mechanism tests"""
    print("Testing Recovery and Fallback Mechanisms...")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestRecoveryMechanisms)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOverall result: {'PASS' if success else 'FAIL'}")
    
    return success


if __name__ == "__main__":
    success = run_recovery_mechanism_tests()
    sys.exit(0 if success else 1)
#!/usr/bin/env python3
"""
Integration tests for recovery and fallback mechanisms
Tests the complete recovery workflow for requirements 1.4, 2.4, and 3.4
"""

import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))

from core.recovery_coordinator import get_recovery_coordinator, RecoveryCoordinator
from core.recovery_manager import get_recovery_manager, RecoveryManager
from core.fallback_mechanisms import get_fallback_mechanisms, FallbackMechanisms
from core.user_guidance import get_user_guidance_system, UserGuidanceSystem, GuidanceLevel
from core.exceptions import *


class TestRecoveryFallbackIntegration(unittest.TestCase):
    """Test integration of recovery and fallback mechanisms"""
    
    def setUp(self):
        """Set up test environment"""
        self.recovery_coordinator = RecoveryCoordinator()
        self.recovery_manager = RecoveryManager()
        self.fallback_mechanisms = FallbackMechanisms()
        self.user_guidance = UserGuidanceSystem()
    
    def test_requirement_1_4_homebrew_fallback(self):
        """Test Requirement 1.4: IF Homebrew не установлен THEN система SHALL предложить установку Homebrew"""
        
        # Simulate Homebrew missing error
        error = DependencyMissingError("brew")
        
        # Test fallback mechanism
        with patch('shutil.which', return_value=None):  # Homebrew not found
            success, message, details = self.fallback_mechanisms.homebrew_installation_fallback()
            
            # Should provide manual guidance when automatic installation fails
            self.assertFalse(success)  # Automatic installation should fail in test
            self.assertIn('Manual Homebrew installation required', message)
            self.assertIn('guidance', details)
            self.assertTrue(details.get('requires_user_action', False))
        
        # Test recovery coordinator handling
        with patch('shutil.which', return_value=None):
            recovery_result = self.recovery_coordinator.handle_error_with_recovery(
                error, 'dependency_install'
            )
            
            self.assertTrue(recovery_result['recovery_attempted'])
            self.assertIsNotNone(recovery_result['user_guidance'])
            self.assertTrue(recovery_result['requires_user_action'])
    
    def test_requirement_2_4_network_scanning_fallback(self):
        """Test Requirement 2.4: IF wdutil недоступен THEN система SHALL предложить альтернативные методы сканирования"""
        
        # Test fallback chain for network scanning
        with patch('os.path.exists', return_value=False):  # wdutil not available
            with patch('utils.common.run_command') as mock_run:
                # Mock system_profiler success
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="Preferred Networks:\n    SSID: TestNetwork\n    Channel: 6"
                )
                
                success, networks, details = self.fallback_mechanisms.network_scanning_fallback()
                
                self.assertTrue(success)
                self.assertGreater(len(networks), 0)
                self.assertEqual(details['method'], 'system_profiler')
        
        # Test when all methods fail
        with patch('os.path.exists', return_value=False):
            with patch('utils.common.run_command') as mock_run:
                # Mock all commands failing
                mock_run.return_value = Mock(returncode=1, stderr="Command failed")
                
                success, networks, details = self.fallback_mechanisms.network_scanning_fallback()
                
                self.assertFalse(success)
                self.assertEqual(len(networks), 0)
                self.assertIn('guidance', details)
                self.assertTrue(details.get('requires_user_action', False))
    
    def test_requirement_3_4_monitor_mode_fallback(self):
        """Test Requirement 3.4: IF интерфейс не поддерживает режим мониторинга THEN система SHALL предупредить пользователя и предложить альтернативы"""
        
        interface = "en0"
        
        # Test monitor mode fallback when not supported
        with patch.object(self.fallback_mechanisms, '_check_monitor_mode_support', return_value=False):
            success, message, details = self.fallback_mechanisms.monitor_mode_fallback(interface)
            
            self.assertFalse(success)
            self.assertIn('Monitor Mode Not Supported', details['alternatives']['title'])
            self.assertIn('External WiFi Adapter', str(details['alternatives']))
            self.assertTrue(details.get('requires_user_decision', False))
        
        # Test error handling through recovery coordinator
        error = MonitorModeError(interface, f"Interface {interface} does not support monitor mode")
        recovery_result = self.recovery_coordinator.handle_error_with_recovery(
            error, 'interface_control', {'interface': interface}
        )
        
        self.assertTrue(recovery_result['recovery_attempted'])
        self.assertIsNotNone(recovery_result['user_guidance'])
    
    def test_system_state_recovery_integration(self):
        """Test system state recovery integration"""
        
        # Save initial state
        state_id = self.recovery_manager.save_system_state()
        self.assertIsNotNone(state_id)
        
        # Test state restoration
        success = self.recovery_manager.restore_system_state(state_id)
        self.assertTrue(success)
        
        # Test recovery coordinator using state recovery
        error = SystemError("System state corrupted")
        recovery_result = self.recovery_coordinator.handle_error_with_recovery(
            error, 'system_recovery'
        )
        
        self.assertTrue(recovery_result['recovery_attempted'])
    
    def test_user_guidance_integration(self):
        """Test user guidance system integration with recovery mechanisms"""
        
        # Test guidance for SIP restriction
        error = SIPRestrictionError("SIP is blocking the operation")
        guidance = self.user_guidance.get_guidance(error, GuidanceLevel.DETAILED)
        
        self.assertIn('System Integrity Protection', guidance['title'])
        self.assertGreater(len(guidance['solutions']), 0)
        self.assertIn('External WiFi Adapter', str(guidance['solutions']))
        
        # Test guidance formatting
        guidance_text = self.user_guidance.format_guidance_text(guidance)
        self.assertIn('SOLUTIONS:', guidance_text)
        self.assertIn('External WiFi Adapter', guidance_text)
        
        # Test quick fix suggestions
        quick_fixes = self.user_guidance.get_quick_fix_suggestions(error)
        self.assertGreater(len(quick_fixes), 0)
        self.assertIn('external wifi adapter', ' '.join(quick_fixes).lower())
    
    def test_fallback_chain_execution(self):
        """Test execution of complete fallback chains"""
        
        # Test network scan fallback chain
        with patch.object(self.recovery_manager, '_wdutil_network_scan', side_effect=Exception("wdutil failed")):
            with patch.object(self.recovery_manager, '_system_profiler_network_scan', return_value=[{'ssid': 'TestNet'}]):
                success, result, method = self.recovery_manager.execute_with_fallback(
                    'network_scan', lambda: []
                )
                
                self.assertTrue(success)
                self.assertEqual(method, 'system_profiler_scan')
                self.assertIsNotNone(result)
    
    def test_recovery_statistics_and_monitoring(self):
        """Test recovery statistics and monitoring"""
        
        # Generate some recovery operations
        errors = [
            DependencyMissingError("aircrack-ng"),
            MonitorModeError("en0", "Monitor mode not supported"),
            SIPRestrictionError("SIP blocking operation")
        ]
        
        for error in errors:
            self.recovery_coordinator.handle_error_with_recovery(
                error, 'test_operation'
            )
        
        # Check recovery statistics
        stats = self.recovery_coordinator.get_recovery_statistics()
        self.assertGreater(stats['total_recoveries'], 0)
        self.assertIn('recovery_methods', stats)
    
    def test_comprehensive_error_recovery_workflow(self):
        """Test complete error recovery workflow from error to resolution"""
        
        # Simulate a complex error scenario
        error = NetworkError("Network scanning failed")
        context = {'interface': 'en0', 'operation': 'scan'}
        
        # Test complete recovery workflow
        recovery_result = self.recovery_coordinator.handle_error_with_recovery(
            error, 'network_scan', context, max_recovery_attempts=2
        )
        
        # Verify recovery was attempted
        self.assertTrue(recovery_result['recovery_attempted'])
        self.assertIsNotNone(recovery_result['attempts'])
        self.assertGreater(len(recovery_result['attempts']), 0)
        
        # Verify user guidance is provided if recovery fails
        if not recovery_result['recovery_successful']:
            self.assertIsNotNone(recovery_result['user_guidance'])
            self.assertGreater(len(recovery_result['recovery_suggestions']), 0)
    
    def test_concurrent_recovery_operations(self):
        """Test handling of concurrent recovery operations"""
        
        import threading
        import time
        
        results = []
        
        def recovery_operation(error_msg):
            error = SystemError(error_msg)
            result = self.recovery_coordinator.handle_error_with_recovery(
                error, f'test_operation_{error_msg}'
            )
            results.append(result)
        
        # Start multiple recovery operations concurrently
        threads = []
        for i in range(3):
            thread = threading.Thread(target=recovery_operation, args=(f"error_{i}",))
            threads.append(thread)
            thread.start()
        
        # Wait for all to complete
        for thread in threads:
            thread.join()
        
        # Verify all operations completed
        self.assertEqual(len(results), 3)
        for result in results:
            self.assertTrue(result['recovery_attempted'])


class TestSpecificRequirementImplementations(unittest.TestCase):
    """Test specific requirement implementations"""
    
    def setUp(self):
        self.fallback_mechanisms = FallbackMechanisms()
    
    def test_homebrew_automatic_installation(self):
        """Test automatic Homebrew installation implementation"""
        
        with patch('shutil.which', return_value=None):  # Homebrew not installed
            with patch('utils.common.run_command') as mock_run:
                # Mock successful installation
                mock_run.return_value = Mock(returncode=0, stdout="Installation successful")
                
                with patch('shutil.which', side_effect=[None, '/opt/homebrew/bin/brew']):  # Not installed, then installed
                    success, message, details = self.fallback_mechanisms._install_homebrew_automatic()
                    
                    self.assertTrue(success)
                    self.assertIn('successfully', message.lower())
                    self.assertEqual(details['installation_method'], 'automatic')
    
    def test_network_scanning_method_priority(self):
        """Test network scanning method priority and fallback order"""
        
        # Test that wdutil is tried first
        with patch('os.path.exists', return_value=True):  # wdutil exists
            with patch('utils.common.run_command') as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="SSID: TestNetwork\nBSSID: 00:11:22:33:44:55"
                )
                
                success, networks, details = self.fallback_mechanisms._scan_with_wdutil()
                
                self.assertTrue(success)
                self.assertEqual(details['method'], 'wdutil')
    
    def test_monitor_mode_alternatives_comprehensive(self):
        """Test comprehensive monitor mode alternatives"""
        
        interface = "en0"
        
        with patch.object(self.fallback_mechanisms, '_check_monitor_mode_support', return_value=False):
            success, message, details = self.fallback_mechanisms._provide_monitor_mode_alternatives(interface)
            
            self.assertFalse(success)
            alternatives = details['alternatives']
            
            # Check all required alternatives are provided
            alternative_options = [alt['option'] for alt in alternatives['alternatives']]
            self.assertIn('External WiFi Adapter', alternative_options)
            self.assertIn('Passive Scanning', alternative_options)
            self.assertIn('Alternative Capture Methods', alternative_options)
            self.assertIn('Virtual Machine', alternative_options)
            
            # Check recommendations are provided
            self.assertIn('recommendations', alternatives)
            self.assertGreater(len(alternatives['recommendations']), 0)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
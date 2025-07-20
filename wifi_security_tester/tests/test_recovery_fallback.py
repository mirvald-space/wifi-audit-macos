#!/usr/bin/env python3
"""
Test Recovery and Fallback Mechanisms
Tests the implementation of task 10.2: Add recovery and fallback mechanisms
"""

import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))

from core.exceptions import *
from core.fallback_mechanisms import FallbackMechanisms, get_fallback_mechanisms
from core.user_guidance import UserGuidanceSystem, get_user_guidance_system, GuidanceLevel
from core.recovery_coordinator import RecoveryCoordinator
from core.recovery_manager import RecoveryManager, get_recovery_manager


class TestFallbackMechanisms(unittest.TestCase):
    """Test fallback mechanisms for requirements 1.4, 2.4, and 3.4"""
    
    def setUp(self):
        self.fallback_mechanisms = FallbackMechanisms()
    
    def test_homebrew_installation_fallback_already_installed(self):
        """Test Homebrew fallback when Homebrew is already installed"""
        with patch('shutil.which', return_value='/opt/homebrew/bin/brew'):
            success, message, details = self.fallback_mechanisms.homebrew_installation_fallback()
            
            self.assertTrue(success)
            self.assertIn('already installed', message)
            self.assertTrue(details['homebrew_installed'])
    
    def test_homebrew_installation_fallback_not_installed(self):
        """Test Homebrew fallback when Homebrew is not installed"""
        with patch('shutil.which', return_value=None):
            with patch.object(self.fallback_mechanisms, '_install_homebrew_automatic', 
                            return_value=(False, 'Installation failed', {})):
                with patch.object(self.fallback_mechanisms, '_provide_homebrew_manual_guidance',
                                return_value=(False, 'Manual installation required', {'guidance': {}})):
                    
                    success, message, details = self.fallback_mechanisms.homebrew_installation_fallback()
                    
                    self.assertFalse(success)
                    self.assertIn('Manual installation required', message)
                    self.assertIn('guidance', details)
    
    def test_network_scanning_fallback_wdutil_success(self):
        """Test network scanning fallback with successful wdutil"""
        mock_networks = [{'ssid': 'TestNetwork', 'bssid': '00:11:22:33:44:55'}]
        
        with patch.object(self.fallback_mechanisms, '_scan_with_wdutil',
                         return_value=(True, mock_networks, {'method': 'wdutil'})):
            
            success, networks, details = self.fallback_mechanisms.network_scanning_fallback()
            
            self.assertTrue(success)
            self.assertEqual(len(networks), 1)
            self.assertEqual(networks[0]['ssid'], 'TestNetwork')
            self.assertEqual(details['method'], 'wdutil')
    
    def test_network_scanning_fallback_all_methods_fail(self):
        """Test network scanning fallback when all methods fail"""
        with patch.object(self.fallback_mechanisms, '_scan_with_wdutil',
                         return_value=(False, [], {'error': 'wdutil failed'})):
            with patch.object(self.fallback_mechanisms, '_scan_with_system_profiler',
                             return_value=(False, [], {'error': 'system_profiler failed'})):
                with patch.object(self.fallback_mechanisms, '_scan_with_networksetup',
                                 return_value=(False, [], {'error': 'networksetup failed'})):
                    with patch.object(self.fallback_mechanisms, '_scan_with_airport',
                                     return_value=(False, [], {'error': 'airport failed'})):
                        with patch.object(self.fallback_mechanisms, '_provide_manual_scanning_guidance',
                                         return_value=(False, [], {'guidance': {}})):
                            
                            success, networks, details = self.fallback_mechanisms.network_scanning_fallback()
                            
                            self.assertFalse(success)
                            self.assertEqual(len(networks), 0)
                            self.assertIn('guidance', details)
    
    def test_monitor_mode_fallback_not_supported(self):
        """Test monitor mode fallback when interface doesn't support monitor mode"""
        with patch.object(self.fallback_mechanisms, '_check_monitor_mode_support',
                         return_value=False):
            with patch.object(self.fallback_mechanisms, '_provide_monitor_mode_alternatives',
                             return_value=(False, 'Alternatives provided', {'alternatives': {}})):
                
                success, message, details = self.fallback_mechanisms.monitor_mode_fallback('en0')
                
                self.assertFalse(success)
                self.assertIn('Alternatives provided', message)
                self.assertIn('alternatives', details)
    
    def test_monitor_mode_fallback_supported_but_fails(self):
        """Test monitor mode fallback when interface supports it but enabling fails"""
        with patch.object(self.fallback_mechanisms, '_check_monitor_mode_support',
                         return_value=True):
            with patch.object(self.fallback_mechanisms, '_enable_monitor_mode_networksetup',
                             return_value=(False, 'Failed', {})):
                with patch.object(self.fallback_mechanisms, '_enable_monitor_mode_ifconfig',
                                 return_value=(False, 'Failed', {})):
                    with patch.object(self.fallback_mechanisms, '_enable_monitor_mode_airport',
                                     return_value=(False, 'Failed', {})):
                        with patch.object(self.fallback_mechanisms, '_provide_monitor_mode_alternatives',
                                         return_value=(False, 'Alternatives provided', {'alternatives': {}})):
                            
                            success, message, details = self.fallback_mechanisms.monitor_mode_fallback('en0')
                            
                            self.assertFalse(success)
                            self.assertIn('alternatives', details)
    
    def test_parse_wdutil_output(self):
        """Test parsing of wdutil output"""
        sample_output = """SSID: TestNetwork
BSSID: 00:11:22:33:44:55
Channel: 6
RSSI: -45
Security: WPA2

SSID: AnotherNetwork
BSSID: 66:77:88:99:AA:BB
Channel: 11
RSSI: -60
Security: WPA3"""
        
        networks = self.fallback_mechanisms._parse_wdutil_output(sample_output)
        
        self.assertEqual(len(networks), 2)
        self.assertEqual(networks[0]['ssid'], 'TestNetwork')
        self.assertEqual(networks[0]['bssid'], '00:11:22:33:44:55')
        self.assertEqual(networks[0]['channel'], '6')
        self.assertEqual(networks[1]['ssid'], 'AnotherNetwork')
        self.assertEqual(networks[1]['encryption'], 'WPA3')


class TestUserGuidanceSystem(unittest.TestCase):
    """Test user guidance system for manual error resolution"""
    
    def setUp(self):
        self.guidance_system = UserGuidanceSystem()
    
    def test_get_guidance_for_sip_restriction_error(self):
        """Test guidance for SIP restriction error"""
        error = SIPRestrictionError('monitor mode')
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertEqual(guidance['title'], 'System Integrity Protection (SIP) Restriction')
        self.assertEqual(guidance['severity'], 'HIGH')
        self.assertIn('solutions', guidance)
        self.assertTrue(len(guidance['solutions']) > 0)
    
    def test_get_guidance_for_dependency_missing_error(self):
        """Test guidance for dependency missing error"""
        error = DependencyMissingError('aircrack-ng')
        guidance = self.guidance_system.get_guidance(error)
        
        self.assertEqual(guidance['title'], 'Required Tool Missing')
        self.assertIn('aircrack-ng', guidance['error_message'])
        self.assertIn('solutions', guidance)
    
    def test_get_guidance_basic_level(self):
        """Test basic level guidance filtering"""
        error = SIPRestrictionError('monitor mode')
        guidance = self.guidance_system.get_guidance(error, GuidanceLevel.BASIC)
        
        # Should only contain easy solutions
        for solution in guidance['solutions']:
            self.assertEqual(solution.get('difficulty', '').lower(), 'easy')
    
    def test_get_guidance_expert_level(self):
        """Test expert level guidance with technical details"""
        error = DependencyMissingError('hashcat')
        guidance = self.guidance_system.get_guidance(error, GuidanceLevel.EXPERT)
        
        self.assertIn('technical_details', guidance)
        self.assertIn('advanced_troubleshooting', guidance)
        self.assertIn('debugging_commands', guidance)
    
    def test_format_guidance_text(self):
        """Test formatting guidance as readable text"""
        error = InterfaceNotFoundError('en0')
        guidance = self.guidance_system.get_guidance(error)
        text = self.guidance_system.format_guidance_text(guidance)
        
        self.assertIn('WiFi Interface Not Found', text)
        self.assertIn('SOLUTIONS:', text)
        self.assertIn('Steps:', text)
    
    def test_get_quick_fix_suggestions(self):
        """Test quick fix suggestions"""
        error = PermissionDeniedError('packet capture')
        suggestions = self.guidance_system.get_quick_fix_suggestions(error)
        
        self.assertIsInstance(suggestions, list)
        self.assertTrue(len(suggestions) > 0)
        self.assertIn('sudo', ' '.join(suggestions).lower())
    
    def test_generate_troubleshooting_report(self):
        """Test troubleshooting report generation"""
        errors = [
            DependencyMissingError('aircrack-ng'),
            SIPRestrictionError('monitor mode'),
            InterfaceNotFoundError('en0')
        ]
        
        report = self.guidance_system.generate_troubleshooting_report(errors)
        
        self.assertIn('TROUBLESHOOTING REPORT', report)
        self.assertIn('Total Errors: 3', report)
        self.assertIn('DependencyMissingError', report)
        self.assertIn('SIPRestrictionError', report)
        self.assertIn('SYSTEM RECOMMENDATIONS', report)


class TestRecoveryIntegration(unittest.TestCase):
    """Test integration of recovery mechanisms"""
    
    def setUp(self):
        self.recovery_manager = RecoveryManager()
        self.fallback_mechanisms = FallbackMechanisms()
        self.guidance_system = UserGuidanceSystem()
    
    def test_execute_with_fallback_success(self):
        """Test successful execution with fallback"""
        def primary_method():
            raise Exception("Primary failed")
        
        def fallback_method():
            return "Fallback success"
        
        # Register fallback
        from core.recovery_manager import FallbackMethod
        fallback = FallbackMethod('test_fallback', fallback_method, priority=1)
        self.recovery_manager.register_fallback_method('test_operation', fallback)
        
        success, result, method = self.recovery_manager.execute_with_fallback(
            'test_operation', primary_method
        )
        
        self.assertTrue(success)
        self.assertEqual(result, "Fallback success")
        self.assertEqual(method, 'test_fallback')
    
    def test_system_state_save_and_restore(self):
        """Test system state save and restore functionality"""
        # Save current state
        state_id = self.recovery_manager.save_system_state()
        self.assertIsInstance(state_id, str)
        self.assertTrue(state_id.startswith('state_'))
        
        # Restore state
        success = self.recovery_manager.restore_system_state(state_id)
        self.assertTrue(success)
    
    def test_recovery_from_specific_error(self):
        """Test recovery from specific error types"""
        error = DependencyMissingError('test-tool')
        context = {'operation': 'test_operation'}
        
        recovery_result = self.recovery_manager.recover_from_error(error, 'test_operation', context)
        
        self.assertIn('recovery_attempted', recovery_result)
        self.assertIn('recovery_method', recovery_result)
        self.assertTrue(recovery_result['recovery_attempted'])


class TestRequirementCompliance(unittest.TestCase):
    """Test compliance with specific requirements 1.4, 2.4, and 3.4"""
    
    def test_requirement_1_4_homebrew_fallback(self):
        """Test Requirement 1.4: IF Homebrew не установлен THEN система SHALL предложить установку Homebrew"""
        fallback_mechanisms = get_fallback_mechanisms()
        
        with patch('shutil.which', return_value=None):  # Homebrew not installed
            success, message, details = fallback_mechanisms.homebrew_installation_fallback()
            
            # Should provide installation guidance
            self.assertIn('guidance', details)
            self.assertIn('steps', details['guidance'])
            
            # Should suggest Homebrew installation
            guidance_text = str(details['guidance'])
            self.assertIn('homebrew', guidance_text.lower())
    
    def test_requirement_2_4_scanning_fallback(self):
        """Test Requirement 2.4: IF wdutil недоступен THEN система SHALL предложить альтернативные методы сканирования"""
        fallback_mechanisms = get_fallback_mechanisms()
        
        # Mock wdutil as unavailable
        with patch.object(fallback_mechanisms, '_scan_with_wdutil',
                         return_value=(False, [], {'error': 'wdutil not available'})):
            # Mock system_profiler as working
            with patch.object(fallback_mechanisms, '_scan_with_system_profiler',
                             return_value=(True, [{'ssid': 'test'}], {'method': 'system_profiler'})):
                
                success, networks, details = fallback_mechanisms.network_scanning_fallback()
                
                # Should succeed with alternative method
                self.assertTrue(success)
                self.assertEqual(details['method'], 'system_profiler')
                self.assertTrue(len(networks) > 0)
    
    def test_requirement_3_4_monitor_mode_fallback(self):
        """Test Requirement 3.4: IF интерфейс не поддерживает режим мониторинга THEN система SHALL предупредить пользователя и предложить альтернативы"""
        fallback_mechanisms = get_fallback_mechanisms()
        
        # Mock interface as not supporting monitor mode
        with patch.object(fallback_mechanisms, '_check_monitor_mode_support',
                         return_value=False):
            
            success, message, details = fallback_mechanisms.monitor_mode_fallback('en0')
            
            # Should provide alternatives
            self.assertFalse(success)  # Monitor mode not available
            self.assertIn('alternatives', details)
            
            # Should warn user and provide alternatives
            alternatives = details['alternatives']
            self.assertIn('alternatives', alternatives)
            self.assertTrue(len(alternatives['alternatives']) > 0)
            
            # Should mention external WiFi adapter as alternative
            alternatives_text = str(alternatives)
            self.assertIn('external', alternatives_text.lower())
            self.assertIn('wifi', alternatives_text.lower())


def run_recovery_fallback_tests():
    """Run all recovery and fallback mechanism tests"""
    print("Running Recovery and Fallback Mechanism Tests...")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_suite.addTest(unittest.makeSuite(TestFallbackMechanisms))
    test_suite.addTest(unittest.makeSuite(TestUserGuidanceSystem))
    test_suite.addTest(unittest.makeSuite(TestRecoveryIntegration))
    test_suite.addTest(unittest.makeSuite(TestRequirementCompliance))
    
    # Run tests
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


if __name__ == '__main__':
    run_recovery_fallback_tests()
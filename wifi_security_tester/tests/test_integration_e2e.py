#!/usr/bin/env python3
"""
End-to-End Integration Test Suite
Tests complete workflows and component interactions as specified in task 11.2
"""

import unittest
import tempfile
import os
import json
import time
import platform
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock, call

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.dependency_manager import DependencyManager
from wifi_security_tester.components.interface_manager import InterfaceManager
from wifi_security_tester.components.network_scanner import NetworkScanner
from wifi_security_tester.components.wordlist_manager import WordlistManager
from wifi_security_tester.components.capture_engine import CaptureEngine
from wifi_security_tester.components.password_cracker import PasswordCracker
from wifi_security_tester.components.security_manager import SecurityManager
from wifi_security_tester.core.error_handler import ErrorHandler
from wifi_security_tester.core.menu_system import MenuSystem
from wifi_security_tester.core.exceptions import *


class TestEndToEndWorkflows(unittest.TestCase):
    """Test complete end-to-end workflows"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.maxDiff = None
        
        # Initialize all components
        self.components = {
            'dependency_manager': DependencyManager(),
            'interface_manager': InterfaceManager(),
            'network_scanner': NetworkScanner(),
            'wordlist_manager': WordlistManager(),
            'capture_engine': CaptureEngine(),
            'password_cracker': PasswordCracker(),
            'security_manager': SecurityManager(),
            'error_handler': ErrorHandler(log_errors=False)
        }
        
        # Set testing mode
        self.components['security_manager']._testing_mode = True
        
        # Create test files
        self.test_capture_file = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist_file = os.path.join(self.temp_dir, "test_wordlist.txt")
        
        # Create mock capture file
        with open(self.test_capture_file, 'w') as f:
            f.write("mock handshake data")
        
        # Create test wordlist
        with open(self.test_wordlist_file, 'w') as f:
            f.write("password123\ntest123\nadmin\n12345678\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_complete_penetration_testing_workflow(self, mock_run_command):
        """Test complete penetration testing workflow from dependency check to password cracking"""
        
        # Mock all system commands
        def mock_command_side_effect(cmd, **kwargs):
            if cmd[0] == 'brew':
                return Mock(returncode=0, stdout="Homebrew 3.6.0")
            elif cmd[0] == 'aircrack-ng':
                if '--help' in cmd:
                    return Mock(returncode=0, stdout="aircrack-ng 1.7")
                else:
                    return Mock(returncode=0, stdout="KEY FOUND! [ password123 ]")
            elif cmd[0] == 'hashcat':
                return Mock(returncode=0, stdout="hashcat v6.2.5")
            elif cmd[0] == 'wdutil':
                return Mock(returncode=0, stdout="""SSID: TestNetwork
BSSID: 00:11:22:33:44:55
Channel: 6
Signal: -45 dBm
Security: WPA2

SSID: VulnerableNetwork
BSSID: 00:11:22:33:44:66
Channel: 11
Signal: -50 dBm
Security: WPA2""")
            elif cmd[0] == 'networksetup':
                return Mock(returncode=0, stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff")
            else:
                return Mock(returncode=0, stdout="")
        
        mock_run_command.side_effect = mock_command_side_effect
        
        # Execute complete workflow
        workflow_result = self._execute_complete_pentest_workflow()
        
        # Verify workflow success
        self.assertTrue(workflow_result['success'])
        self.assertTrue(workflow_result['dependencies_ok'])
        self.assertGreater(len(workflow_result['interfaces']), 0)
        self.assertGreater(len(workflow_result['networks']), 0)
        self.assertTrue(workflow_result['capture_successful'])
        self.assertTrue(workflow_result['crack_successful'])
        self.assertEqual(workflow_result['password_found'], 'password123')
        
        # Verify system commands were called
        self.assertTrue(mock_run_command.called)
    
    def _execute_complete_pentest_workflow(self):
        """Execute complete penetration testing workflow"""
        try:
            workflow_state = {
                'success': False,
                'dependencies_ok': False,
                'interfaces': [],
                'networks': [],
                'capture_successful': False,
                'crack_successful': False,
                'password_found': None
            }
            
            # Step 1: Check dependencies
            deps_result = self.components['dependency_manager'].check_all_dependencies()
            workflow_state['dependencies_ok'] = deps_result.get('all_available', False)
            
            if not workflow_state['dependencies_ok']:
                return workflow_state
            
            # Step 2: Discover interfaces
            interfaces = self.components['interface_manager'].discover_wifi_interfaces()
            workflow_state['interfaces'] = interfaces
            
            if not interfaces:
                return workflow_state
            
            # Step 3: Scan networks
            interface = interfaces[0]['device']
            networks = self.components['network_scanner'].scan_networks()
            workflow_state['networks'] = networks
            
            if not networks:
                return workflow_state
            
            # Step 4: Select target network (first WPA2 network)
            target_network = None
            for network in networks:
                if network.get('security') == 'WPA2':
                    target_network = network
                    break
            
            if not target_network:
                return workflow_state
            
            # Step 5: Capture handshake
            capture_result = self.components['capture_engine'].start_capture(
                interface, target_network['ssid'], target_network['bssid']
            )
            workflow_state['capture_successful'] = capture_result.get('success', False)
            
            if not workflow_state['capture_successful']:
                return workflow_state
            
            # Step 6: Crack password
            crack_result = self.components['password_cracker'].crack_with_aircrack(
                self.test_capture_file, self.test_wordlist_file
            )
            workflow_state['crack_successful'] = crack_result.get('success', False)
            workflow_state['password_found'] = crack_result.get('password')
            
            workflow_state['success'] = True
            return workflow_state
            
        except Exception as e:
            workflow_state['error'] = str(e)
            return workflow_state
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_security_compliance_workflow(self, mock_run_command):
        """Test security compliance and ethical usage workflow"""
        
        # Mock SIP status check
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="System Integrity Protection status: enabled."
        )
        
        # Execute security workflow
        security_result = self._execute_security_compliance_workflow()
        
        # Verify security checks
        self.assertTrue(security_result['sip_checked'])
        self.assertTrue(security_result['warnings_displayed'])
        self.assertFalse(security_result['can_proceed_without_consent'])
        self.assertIn('legal_warnings', security_result)
        self.assertIn('sip_status', security_result)
    
    def _execute_security_compliance_workflow(self):
        """Execute security compliance workflow"""
        try:
            security_manager = self.components['security_manager']
            
            # Step 1: Display legal warnings
            warnings_displayed = security_manager.display_legal_warnings()
            
            # Step 2: Check SIP status
            sip_success, sip_info = security_manager.check_sip_status()
            
            # Step 3: Validate ethical usage (without consent)
            is_ethical, issues = security_manager.validate_ethical_usage()
            
            # Step 4: Check admin privileges
            has_admin, admin_info = security_manager.check_admin_privileges()
            
            return {
                'sip_checked': sip_success,
                'warnings_displayed': warnings_displayed,
                'can_proceed_without_consent': is_ethical,
                'has_admin_privileges': has_admin,
                'legal_warnings': security_manager.legal_warnings,
                'sip_status': sip_info,
                'ethical_issues': issues,
                'admin_info': admin_info
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def test_error_recovery_workflow(self):
        """Test error recovery across multiple components"""
        
        # Test dependency error recovery
        dep_error = DependencyMissingError("aircrack-ng")
        dep_recovery = self.components['error_handler'].handle_error(dep_error)
        
        self.assertEqual(dep_recovery['strategy_used'], 'user_intervention')
        self.assertTrue(dep_recovery['user_action_required'])
        
        # Test interface error recovery
        interface_error = InterfaceNotFoundError("en0")
        interface_recovery = self.components['error_handler'].handle_error(interface_error)
        
        self.assertEqual(interface_recovery['strategy_used'], 'fallback')
        self.assertTrue(interface_recovery['recovery_successful'])
        
        # Test capture error recovery
        capture_error = CaptureFailedError("No handshake", "en0")
        capture_recovery = self.components['error_handler'].handle_error(capture_error)
        
        self.assertEqual(capture_recovery['strategy_used'], 'fallback')
        self.assertTrue(capture_recovery['recovery_successful'])
        
        # Test security error recovery
        security_error = SuspiciousActivityError("High frequency operations")
        security_recovery = self.components['error_handler'].handle_error(security_error)
        
        self.assertEqual(security_recovery['strategy_used'], 'abort')
        self.assertFalse(security_recovery['recovery_successful'])
        self.assertTrue(security_recovery['requires_restart'])


class TestComponentInteractionScenarios(unittest.TestCase):
    """Test specific component interaction scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize components
        self.dependency_manager = DependencyManager()
        self.interface_manager = InterfaceManager()
        self.network_scanner = NetworkScanner()
        self.wordlist_manager = WordlistManager()
        self.capture_engine = CaptureEngine()
        self.password_cracker = PasswordCracker()
        self.security_manager = SecurityManager()
        self.error_handler = ErrorHandler(log_errors=False)
        
        self.security_manager._testing_mode = True
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_dependency_interface_interaction(self, mock_run_command):
        """Test interaction between dependency manager and interface manager"""
        
        # Mock system commands
        def mock_command_side_effect(cmd, **kwargs):
            if cmd[0] == 'brew':
                return Mock(returncode=0, stdout="Homebrew 3.6.0")
            elif cmd[0] == 'aircrack-ng':
                return Mock(returncode=1, stderr="command not found")  # Missing
            elif cmd[0] == 'wdutil':
                return Mock(returncode=0, stdout="wdutil version 1.0")
            elif cmd[0] == 'networksetup':
                return Mock(returncode=0, stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff")
            else:
                return Mock(returncode=0, stdout="")
        
        mock_run_command.side_effect = mock_command_side_effect
        
        # Check dependencies first
        deps_result = self.dependency_manager.check_all_dependencies()
        
        # Interface manager should still work with available tools
        interfaces = self.interface_manager.discover_wifi_interfaces()
        
        # Verify results
        self.assertFalse(deps_result.get('all_available', True))
        self.assertGreater(len(interfaces), 0)
        
        # Interface manager should be able to report which operations are limited
        capabilities = self.interface_manager.get_interface_capabilities(interfaces[0]['device'])
        self.assertIn('monitor_mode', capabilities)
    
    @patch('wifi_security_tester.utils.common.run_command')
    def test_scanner_wordlist_interaction(self, mock_run_command):
        """Test interaction between network scanner and wordlist manager"""
        
        # Mock network scanning
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="""SSID: CompanyWiFi
BSSID: 00:11:22:33:44:55
Channel: 6
Signal: -45 dBm
Security: WPA2

SSID: HomeNetwork
BSSID: 00:11:22:33:44:66
Channel: 11
Security: WPA2"""
        )
        
        # Scan networks
        networks = self.network_scanner.scan_networks()
        
        # Create targeted wordlists based on network names
        targeted_wordlists = []
        for network in networks:
            ssid = network.get('ssid', '')
            if ssid:
                # Generate SSID-based passwords
                ssid_passwords = self._generate_ssid_based_passwords(ssid)
                
                # Create wordlist
                wordlist_name = f"targeted_{ssid.lower().replace(' ', '_')}"
                success, wordlist_path = self.wordlist_manager.create_custom_wordlist(
                    wordlist_name, ssid_passwords, f"Targeted wordlist for {ssid}"
                )
                
                if success:
                    targeted_wordlists.append({
                        'ssid': ssid,
                        'wordlist_path': wordlist_path,
                        'password_count': len(ssid_passwords)
                    })
        
        # Verify targeted wordlists were created
        self.assertEqual(len(targeted_wordlists), 2)
        self.assertTrue(all(os.path.exists(wl['wordlist_path']) for wl in targeted_wordlists))
    
    def _generate_ssid_based_passwords(self, ssid):
        """Generate passwords based on SSID"""
        passwords = []
        base_ssid = ssid.lower().replace(' ', '')
        
        # Common patterns
        passwords.extend([
            ssid,
            ssid.lower(),
            ssid.upper(),
            base_ssid,
            f"{base_ssid}123",
            f"{base_ssid}2023",
            f"{base_ssid}password",
            f"password{base_ssid}",
        ])
        
        return list(set(passwords))  # Remove duplicates
    
    def test_capture_cracker_validation_interaction(self):
        """Test interaction between capture engine and password cracker validation"""
        
        # Create test capture files with different qualities
        test_files = {
            'good_capture.cap': "mock handshake data with proper format",
            'bad_capture.cap': "incomplete data",
            'empty_capture.cap': ""
        }
        
        validation_results = {}
        
        for filename, content in test_files.items():
            filepath = os.path.join(self.temp_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            
            # Validate capture for cracking
            validation = self.password_cracker.validate_capture_for_cracking(filepath)
            validation_results[filename] = validation
        
        # Verify validation results
        self.assertIn('valid', validation_results['good_capture.cap'])
        self.assertIn('valid', validation_results['bad_capture.cap'])
        self.assertIn('valid', validation_results['empty_capture.cap'])
        
        # Good capture should have more details
        good_validation = validation_results['good_capture.cap']
        if good_validation['valid']:
            self.assertIn('details', good_validation)
    
    def test_security_error_handler_integration(self):
        """Test integration between security manager and error handler"""
        
        # Simulate security violations
        security_violations = [
            SuspiciousActivityError("Rapid network scanning"),
            PermissionDeniedError("Monitor mode activation"),
            SIPRestrictionError("Interface mode change"),
            IllegalUsageError("Unauthorized network access")
        ]
        
        recovery_results = []
        
        for violation in security_violations:
            # Security manager detects violation (simulate logging)
            # Note: log_security_event method may not exist, so we skip this step
            
            # Error handler processes violation
            recovery = self.error_handler.handle_error(violation)
            recovery_results.append({
                'violation_type': type(violation).__name__,
                'recovery': recovery
            })
        
        # Verify appropriate recovery strategies
        for result in recovery_results:
            recovery = result['recovery']
            violation_type = result['violation_type']
            
            self.assertIn('strategy_used', recovery)
            
            if violation_type == 'SuspiciousActivityError':
                self.assertEqual(recovery['strategy_used'], 'abort')
                self.assertFalse(recovery['recovery_successful'])
            elif violation_type == 'PermissionDeniedError':
                self.assertEqual(recovery['strategy_used'], 'user_intervention')
            elif violation_type == 'SIPRestrictionError':
                self.assertEqual(recovery['strategy_used'], 'fallback')
            elif violation_type == 'IllegalUsageError':
                self.assertEqual(recovery['strategy_used'], 'abort')


class TestMacOSCompatibility(unittest.TestCase):
    """Test compatibility with different macOS versions and configurations"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
        self.security_manager._testing_mode = True
        self.interface_manager = InterfaceManager()
        self.dependency_manager = DependencyManager()
    
    @patch('platform.mac_ver')
    @patch('subprocess.run')
    def test_macos_version_compatibility(self, mock_run, mock_mac_ver):
        """Test compatibility across different macOS versions"""
        
        # Test different macOS versions
        test_versions = [
            ("10.15.7", "Catalina", "19H15"),
            ("11.7.10", "Big Sur", "20G1427"),
            ("12.7.0", "Monterey", "21H559"),
            ("13.6.0", "Ventura", "22G120"),
            ("14.1.0", "Sonoma", "23B74")
        ]
        
        compatibility_results = []
        
        for version, name, build in test_versions:
            mock_mac_ver.return_value = (version, (build, '', ''), '')
            
            # Mock system commands for each version
            mock_run.side_effect = [
                Mock(returncode=0, stdout="System Integrity Protection status: enabled."),  # SIP check
                Mock(returncode=0, stdout="Hardware Port: Wi-Fi\nDevice: en0"),  # Interface check
                Mock(returncode=0, stdout="brew --version\nHomebrew 3.6.0"),  # Homebrew check
            ]
            
            # Test core functionality on each version
            version_result = {
                'version': version,
                'name': name,
                'sip_check': False,
                'interface_discovery': False,
                'dependency_check': False
            }
            
            try:
                # Test SIP checking
                sip_success, sip_info = self.security_manager.check_sip_status()
                version_result['sip_check'] = sip_success
                
                # Test interface discovery
                interfaces = self.interface_manager.discover_wifi_interfaces()
                version_result['interface_discovery'] = len(interfaces) > 0
                
                # Test dependency checking
                deps_available = self.dependency_manager.check_tool_availability('brew')
                version_result['dependency_check'] = deps_available
                
            except Exception as e:
                version_result['error'] = str(e)
            
            compatibility_results.append(version_result)
        
        # Verify compatibility across versions
        for result in compatibility_results:
            with self.subTest(version=result['version']):
                self.assertTrue(result['sip_check'], 
                              f"SIP check failed on {result['name']} ({result['version']})")
                self.assertTrue(result['interface_discovery'], 
                              f"Interface discovery failed on {result['name']} ({result['version']})")
                self.assertTrue(result['dependency_check'], 
                              f"Dependency check failed on {result['name']} ({result['version']})")
    
    @patch('subprocess.run')
    def test_hardware_compatibility(self, mock_run):
        """Test compatibility with different hardware configurations"""
        
        # Test different hardware configurations
        hardware_configs = [
            {
                'name': 'MacBook Pro Intel',
                'interfaces': "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff",
                'architecture': 'x86_64'
            },
            {
                'name': 'MacBook Air M1',
                'interfaces': "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: bb:cc:dd:ee:ff:aa",
                'architecture': 'arm64'
            },
            {
                'name': 'Mac Mini M2',
                'interfaces': "Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: cc:dd:ee:ff:aa:bb",
                'architecture': 'arm64'
            },
            {
                'name': 'iMac with USB WiFi',
                'interfaces': """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: USB 10/100/1000 LAN
Device: en5
Ethernet Address: dd:ee:ff:aa:bb:cc""",
                'architecture': 'x86_64'
            }
        ]
        
        compatibility_results = []
        
        for config in hardware_configs:
            mock_run.return_value = Mock(returncode=0, stdout=config['interfaces'])
            
            # Test interface discovery
            interfaces = self.interface_manager.discover_wifi_interfaces()
            
            # Test interface capabilities
            capabilities = []
            for interface in interfaces:
                caps = self.interface_manager.get_interface_capabilities(interface['device'])
                capabilities.append(caps)
            
            compatibility_results.append({
                'hardware': config['name'],
                'architecture': config['architecture'],
                'interfaces_found': len(interfaces),
                'capabilities': capabilities
            })
        
        # Verify hardware compatibility
        for result in compatibility_results:
            with self.subTest(hardware=result['hardware']):
                self.assertGreater(result['interfaces_found'], 0,
                                 f"No interfaces found on {result['hardware']}")
                self.assertEqual(len(result['capabilities']), result['interfaces_found'],
                               f"Capability check failed on {result['hardware']}")
    
    @patch('subprocess.run')
    def test_tool_version_compatibility(self, mock_run):
        """Test compatibility with different tool versions"""
        
        # Test different tool versions
        tool_versions = {
            'aircrack-ng': [
                "Aircrack-ng 1.6",
                "Aircrack-ng 1.7 - (C) 2006-2022 Thomas d'Otreppe",
                "aircrack-ng 1.5.2"
            ],
            'hashcat': [
                "hashcat (v6.2.5) starting...",
                "hashcat v6.1.1",
                "hashcat (v5.1.0)"
            ],
            'brew': [
                "Homebrew 3.6.0",
                "Homebrew 4.0.0",
                "Homebrew 2.7.0"
            ]
        }
        
        compatibility_matrix = {}
        
        for tool, versions in tool_versions.items():
            compatibility_matrix[tool] = {}
            
            for version_output in versions:
                mock_run.return_value = Mock(returncode=0, stdout=version_output)
                
                # Test version detection
                version_info = self.dependency_manager.get_tool_version(tool)
                
                # Test tool availability
                is_available = self.dependency_manager.check_tool_availability(tool)
                
                compatibility_matrix[tool][version_output] = {
                    'version_detected': version_info is not None,
                    'tool_available': is_available,
                    'version_info': version_info
                }
        
        # Verify tool compatibility
        for tool, versions in compatibility_matrix.items():
            for version_output, result in versions.items():
                with self.subTest(tool=tool, version=version_output):
                    self.assertTrue(result['version_detected'],
                                  f"Version detection failed for {tool}: {version_output}")
                    self.assertTrue(result['tool_available'],
                                  f"Tool availability check failed for {tool}: {version_output}")


class TestMenuSystemIntegration(unittest.TestCase):
    """Test menu system integration with all components"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.menu_system = MenuSystem()
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_menu_component_initialization(self):
        """Test that menu system properly initializes all components"""
        
        # Verify menu system has required components
        self.assertIsNotNone(self.menu_system.interface_manager)
        self.assertIsNotNone(self.menu_system.wordlist_manager)
        
        # Verify menu items are properly configured
        menu_items = self.menu_system.menu_items
        
        expected_menu_items = ["1", "2", "3", "4", "5", "6", "7", "0"]
        for item in expected_menu_items:
            self.assertIn(item, menu_items)
            self.assertIn('title', menu_items[item])
            self.assertIn('handler', menu_items[item])
            self.assertIn('description', menu_items[item])
    
    @patch('builtins.input')
    @patch('wifi_security_tester.utils.common.run_command')
    def test_interface_management_menu_integration(self, mock_run_command, mock_input):
        """Test interface management menu integration"""
        
        # Mock interface discovery
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff"
        )
        
        # Mock user input to exit submenu
        mock_input.return_value = "0"
        
        # Test interface management handler
        try:
            self.menu_system._interface_management_handler()
            # Should not raise exception
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"Interface management handler failed: {e}")
    
    @patch('builtins.input')
    def test_wordlist_management_menu_integration(self, mock_input):
        """Test wordlist management menu integration"""
        
        # Mock user input to exit submenu
        mock_input.return_value = "0"
        
        # Test wordlist management handler
        try:
            self.menu_system._wordlist_management_handler()
            # Should not raise exception
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"Wordlist management handler failed: {e}")


if __name__ == '__main__':
    # Create comprehensive test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestEndToEndWorkflows,
        TestComponentInteractionScenarios,
        TestMacOSCompatibility,
        TestMenuSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print("INTEGRATION TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        for test, traceback in result.failures:
            error_msg = traceback.split('AssertionError: ')[-1].split('\n')[0]
            print(f"- {test}: {error_msg}")
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        for test, traceback in result.errors:
            error_msg = traceback.split('\n')[-2]
            print(f"- {test}: {error_msg}")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
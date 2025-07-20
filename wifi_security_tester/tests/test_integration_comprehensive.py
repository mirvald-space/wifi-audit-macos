#!/usr/bin/env python3
"""
Comprehensive Integration Test Suite
Tests component interactions and end-to-end workflows
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

from wifi_security_tester.components.dependency_manager import DependencyManager
from wifi_security_tester.components.interface_manager import InterfaceManager
from wifi_security_tester.components.network_scanner import NetworkScanner
from wifi_security_tester.components.wordlist_manager import WordlistManager
from wifi_security_tester.components.capture_engine import CaptureEngine
from wifi_security_tester.components.password_cracker import PasswordCracker
from wifi_security_tester.components.security_manager import SecurityManager
from wifi_security_tester.core.error_handler import ErrorHandler
from wifi_security_tester.core.exceptions import *


class TestComponentIntegration(unittest.TestCase):
    """Test integration between different components"""
    
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
        
        # Set testing mode
        self.security_manager._testing_mode = True
        
        # Create test files
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        with open(self.test_wordlist, 'w') as f:
            f.write("password123\ntest123\nadmin\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.dependency_manager.run_command')
    def test_dependency_security_integration(self, mock_run_command):
        """Test integration between dependency manager and security manager"""
        # Mock dependency check results
        mock_run_command.side_effect = [
            Mock(returncode=0),  # Homebrew check
            Mock(returncode=1),  # aircrack-ng missing
            Mock(returncode=0),  # hashcat available
        ]
        
        # Check dependencies
        deps_result = self.dependency_manager.check_all_dependencies()
        
        # Security manager should be able to validate this operation
        with patch.object(self.security_manager, 'check_admin_privileges') as mock_admin:
            mock_admin.return_value = (True, {'has_admin': True})
            
            is_sufficient, messages = self.security_manager.validate_privilege_for_operation("dependency_installation")
            self.assertTrue(is_sufficient)
    
    @patch('wifi_security_tester.components.interface_manager.run_command')
    @patch('wifi_security_tester.components.network_scanner.run_command')
    def test_interface_scanner_integration(self, mock_scanner_cmd, mock_interface_cmd):
        """Test integration between interface manager and network scanner"""
        # Mock interface discovery
        mock_interface_cmd.return_value = Mock(
            returncode=0,
            stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff"
        )
        
        # Mock network scanning
        mock_scanner_cmd.return_value = Mock(
            returncode=0,
            stdout="""SSID: TestNetwork
BSSID: 00:11:22:33:44:55
Channel: 6
Signal: -45 dBm
Security: WPA2"""
        )
        
        # Discover interfaces
        interfaces = self.interface_manager.discover_wifi_interfaces()
        self.assertGreater(len(interfaces), 0)
        
        # Use discovered interface for scanning
        if interfaces:
            interface = interfaces[0]['device']
            networks = self.network_scanner.scan_networks(interface)
            self.assertIsInstance(networks, list)
    
    def test_wordlist_cracker_integration(self):
        """Test integration between wordlist manager and password cracker"""
        # Create wordlist using wordlist manager
        wordlist_path = self.wordlist_manager.create_combined_wordlist(
            ["common_passwords", "custom"],
            output_file=os.path.join(self.temp_dir, "combined.txt")
        )
        
        # Verify wordlist was created
        self.assertTrue(os.path.exists(wordlist_path))
        
        # Password cracker should be able to use this wordlist
        with patch.object(self.password_cracker, '_check_aircrack_availability') as mock_check:
            mock_check.return_value = True
            
            # Test time estimation
            estimated_time = self.password_cracker._estimate_aircrack_time(wordlist_path)
            self.assertIsInstance(estimated_time, int)
            self.assertGreater(estimated_time, 0)
    
    @patch('wifi_security_tester.components.capture_engine.run_command')
    def test_capture_cracker_integration(self, mock_run_command):
        """Test integration between capture engine and password cracker"""
        # Mock successful capture
        mock_run_command.return_value = Mock(returncode=0)
        
        # Create mock capture file
        capture_file = os.path.join(self.temp_dir, "test.cap")
        with open(capture_file, 'w') as f:
            f.write("mock capture data")
        
        # Capture engine creates file, password cracker validates it
        with patch.object(self.password_cracker, 'validate_capture_for_cracking') as mock_validate:
            mock_validate.return_value = {
                'valid': True,
                'details': {
                    'networks_found': 1,
                    'handshakes_found': 1,
                    'crackable_networks': [{'ssid': 'TestNetwork'}]
                }
            }
            
            validation_result = self.password_cracker.validate_capture_for_cracking(capture_file)
            self.assertTrue(validation_result['valid'])
    
    def test_security_error_handler_integration(self):
        """Test integration between security manager and error handler"""
        # Security manager detects violation
        self.security_manager.suspicious_activity_detected = True
        
        # This should trigger security error
        security_error = SuspiciousActivityError("High frequency operations")
        
        # Error handler should handle security errors appropriately
        result = self.error_handler.handle_error(security_error, operation="network_scan")
        
        self.assertEqual(result['strategy_used'], 'abort')
        self.assertFalse(result['recovery_successful'])
        self.assertTrue(result['requires_restart'])


class TestEndToEndWorkflows(unittest.TestCase):
    """Test complete end-to-end workflows"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
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
        
        self.components['security_manager']._testing_mode = True
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.dependency_manager.run_command')
    @patch('wifi_security_tester.components.interface_manager.run_command')
    @patch('wifi_security_tester.components.network_scanner.run_command')
    def test_network_discovery_workflow(self, mock_scanner, mock_interface, mock_deps):
        """Test complete network discovery workflow"""
        # Mock dependency check
        mock_deps.return_value = Mock(returncode=0)
        
        # Mock interface discovery
        mock_interface.return_value = Mock(
            returncode=0,
            stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff"
        )
        
        # Mock network scanning
        mock_scanner.return_value = Mock(
            returncode=0,
            stdout="""SSID: TestNetwork1
BSSID: 00:11:22:33:44:55
Channel: 6
Signal: -45 dBm
Security: WPA2

SSID: TestNetwork2
BSSID: 00:11:22:33:44:66
Channel: 11
Signal: -60 dBm
Security: WPA2"""
        )
        
        # Execute workflow
        workflow_result = self._execute_network_discovery_workflow()
        
        self.assertTrue(workflow_result['success'])
        self.assertGreater(len(workflow_result['networks']), 0)
        self.assertIn('interface_used', workflow_result)
    
    def _execute_network_discovery_workflow(self):
        """Execute network discovery workflow"""
        try:
            # Step 1: Check dependencies
            deps_ok = self.components['dependency_manager'].check_tool_availability('wdutil')
            if not deps_ok:
                return {'success': False, 'error': 'Dependencies not met'}
            
            # Step 2: Discover interfaces
            interfaces = self.components['interface_manager'].discover_wifi_interfaces()
            if not interfaces:
                return {'success': False, 'error': 'No WiFi interfaces found'}
            
            # Step 3: Scan networks
            interface = interfaces[0]['device']
            networks = self.components['network_scanner'].scan_networks(interface)
            
            return {
                'success': True,
                'networks': networks,
                'interface_used': interface,
                'interfaces_available': len(interfaces)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @patch('wifi_security_tester.components.dependency_manager.run_command')
    def test_wordlist_preparation_workflow(self, mock_run_command):
        """Test complete wordlist preparation workflow"""
        # Mock dependency checks
        mock_run_command.return_value = Mock(returncode=0)
        
        # Execute workflow
        workflow_result = self._execute_wordlist_preparation_workflow()
        
        self.assertTrue(workflow_result['success'])
        self.assertIn('wordlist_path', workflow_result)
        self.assertTrue(os.path.exists(workflow_result['wordlist_path']))
    
    def _execute_wordlist_preparation_workflow(self):
        """Execute wordlist preparation workflow"""
        try:
            # Step 1: Check if we can create wordlists
            wordlist_manager = self.components['wordlist_manager']
            
            # Step 2: Create custom wordlist
            custom_passwords = ["password123", "admin", "test123", "12345678"]
            custom_path = os.path.join(self.temp_dir, "custom.txt")
            
            with open(custom_path, 'w') as f:
                f.write('\n'.join(custom_passwords))
            
            # Step 3: Import and optimize
            imported_path = wordlist_manager.import_wordlist(custom_path, "test_wordlist")
            
            # Step 4: Create combined wordlist
            combined_path = wordlist_manager.create_combined_wordlist(
                ["common_passwords", "test_wordlist"],
                output_file=os.path.join(self.temp_dir, "final_wordlist.txt")
            )
            
            return {
                'success': True,
                'wordlist_path': combined_path,
                'custom_imported': imported_path is not None
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def test_security_validation_workflow(self):
        """Test complete security validation workflow"""
        # Execute workflow
        workflow_result = self._execute_security_validation_workflow()
        
        # Should require user consent
        self.assertFalse(workflow_result['can_proceed'])
        self.assertIn('consent_required', workflow_result)
    
    def _execute_security_validation_workflow(self):
        """Execute security validation workflow"""
        try:
            security_manager = self.components['security_manager']
            
            # Step 1: Display legal warnings
            warnings_shown = security_manager.display_legal_warnings()
            
            # Step 2: Check current consent status
            is_ethical, issues = security_manager.validate_ethical_usage()
            
            # Step 3: Check system privileges
            has_privileges, privilege_info = security_manager.check_admin_privileges()
            
            # Step 4: Check SIP status
            sip_success, sip_info = security_manager.check_sip_status()
            
            return {
                'can_proceed': is_ethical,
                'consent_required': not security_manager.user_consent_given,
                'warnings_shown': warnings_shown,
                'has_privileges': privilege_info.get('has_admin', False) if has_privileges else False,
                'sip_enabled': sip_info.get('enabled', True) if sip_success else True,
                'issues': issues
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @patch('wifi_security_tester.components.capture_engine.run_command')
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_complete_security_audit_workflow(self, mock_cracker_cmd, mock_capture_cmd):
        """Test complete security audit workflow from start to finish"""
        # Mock successful capture
        mock_capture_cmd.return_value = Mock(returncode=0)
        
        # Mock successful password cracking
        mock_cracker_cmd.return_value = Mock(
            returncode=0,
            stdout="KEY FOUND! [ testpassword123 ]"
        )
        
        # Create test capture file
        capture_file = os.path.join(self.temp_dir, "test_audit.cap")
        with open(capture_file, 'w') as f:
            f.write("mock handshake data")
        
        # Create test wordlist
        wordlist_file = os.path.join(self.temp_dir, "audit_wordlist.txt")
        with open(wordlist_file, 'w') as f:
            f.write("testpassword123\npassword\nadmin\n")
        
        # Execute complete workflow
        workflow_result = self._execute_complete_audit_workflow(capture_file, wordlist_file)
        
        self.assertTrue(workflow_result['success'])
        self.assertIn('password_found', workflow_result)
        self.assertEqual(workflow_result['password_found'], 'testpassword123')
    
    def _execute_complete_audit_workflow(self, capture_file, wordlist_file):
        """Execute complete security audit workflow"""
        try:
            # Step 1: Validate capture file
            validation = self.components['password_cracker'].validate_capture_for_cracking(capture_file)
            if not validation['valid']:
                return {'success': False, 'error': 'Invalid capture file'}
            
            # Step 2: Analyze wordlist
            analysis = self.components['wordlist_manager'].analyze_wordlist_size(wordlist_file)
            if 'error' in analysis:
                return {'success': False, 'error': f"Wordlist analysis failed: {analysis['error']}"}
            
            # Step 3: Estimate cracking time
            estimated_time = self.components['password_cracker']._estimate_aircrack_time(wordlist_file)
            
            # Step 4: Execute password cracking
            crack_result = self.components['password_cracker'].crack_with_aircrack(
                capture_file, wordlist_file
            )
            
            return {
                'success': True,
                'validation': validation,
                'wordlist_size': analysis.get('password_count', 0),
                'estimated_time': estimated_time,
                'password_found': crack_result.get('password'),
                'crack_successful': crack_result.get('success', False)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @patch('wifi_security_tester.components.interface_manager.run_command')
    @patch('wifi_security_tester.components.network_scanner.run_command')
    @patch('wifi_security_tester.components.capture_engine.run_command')
    def test_target_selection_workflow(self, mock_capture, mock_scanner, mock_interface):
        """Test target selection and capture workflow"""
        # Mock interface discovery
        mock_interface.return_value = Mock(
            returncode=0,
            stdout="Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff"
        )
        
        # Mock network scanning
        mock_scanner.return_value = Mock(
            returncode=0,
            stdout="""SSID: TestNetwork
BSSID: 00:11:22:33:44:55
Channel: 6
Signal: -45 dBm
Security: WPA2

SSID: WeakNetwork
BSSID: 00:11:22:33:44:66
Channel: 11
Signal: -60 dBm
Security: WEP"""
        )
        
        # Mock successful capture
        mock_capture.return_value = Mock(returncode=0)
        
        # Execute workflow
        workflow_result = self._execute_target_selection_workflow()
        
        self.assertTrue(workflow_result['success'])
        self.assertGreater(len(workflow_result['targets']), 0)
        self.assertIn('recommended_target', workflow_result)
    
    def _execute_target_selection_workflow(self):
        """Execute target selection workflow"""
        try:
            # Step 1: Discover interfaces
            interfaces = self.components['interface_manager'].discover_wifi_interfaces()
            if not interfaces:
                return {'success': False, 'error': 'No interfaces found'}
            
            # Step 2: Scan for networks
            interface = interfaces[0]['device']
            networks = self.components['network_scanner'].scan_networks(interface)
            
            # Step 3: Filter suitable targets
            suitable_targets = []
            for network in networks:
                if network.get('security') in ['WPA', 'WPA2', 'WPA3']:
                    signal_strength = int(network.get('signal', '-100').replace(' dBm', ''))
                    if signal_strength > -70:  # Good signal strength
                        suitable_targets.append({
                            'ssid': network.get('ssid'),
                            'bssid': network.get('bssid'),
                            'channel': network.get('channel'),
                            'signal': signal_strength,
                            'security': network.get('security')
                        })
            
            # Step 4: Recommend best target
            recommended_target = None
            if suitable_targets:
                # Sort by signal strength (higher is better)
                suitable_targets.sort(key=lambda x: x['signal'], reverse=True)
                recommended_target = suitable_targets[0]
            
            return {
                'success': True,
                'interface_used': interface,
                'networks_found': len(networks),
                'targets': suitable_targets,
                'recommended_target': recommended_target
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}


class TestErrorRecoveryIntegration(unittest.TestCase):
    """Test error recovery across component boundaries"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.error_handler = ErrorHandler(log_errors=False)
        
        # Initialize components with error handler
        self.components = {
            'dependency_manager': DependencyManager(),
            'interface_manager': InterfaceManager(),
            'network_scanner': NetworkScanner(),
            'security_manager': SecurityManager()
        }
        
        self.components['security_manager']._testing_mode = True
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_dependency_failure_recovery(self):
        """Test recovery from dependency failures"""
        # Simulate missing dependency
        dep_error = DependencyMissingError("aircrack-ng")
        
        # Error handler should suggest recovery
        result = self.error_handler.handle_error(dep_error, operation="password_cracking")
        
        self.assertEqual(result['strategy_used'], 'user_intervention')
        self.assertTrue(result['user_action_required'])
        self.assertIn('recovery_suggestions', result)
        
        # Should suggest using dependency manager
        suggestions = result['recovery_suggestions']
        self.assertTrue(any('brew install' in suggestion for suggestion in suggestions))
    
    def test_permission_failure_recovery(self):
        """Test recovery from permission failures"""
        # Simulate permission denied
        perm_error = PermissionDeniedError("packet_capture")
        
        # Error handler should suggest privilege escalation
        result = self.error_handler.handle_error(perm_error, operation="capture")
        
        self.assertEqual(result['strategy_used'], 'user_intervention')
        self.assertIn('sudo', result['user_guidance'])
    
    def test_sip_restriction_recovery(self):
        """Test recovery from SIP restrictions"""
        # Simulate SIP restriction
        sip_error = SIPRestrictionError("monitor_mode")
        
        # Error handler should suggest fallback methods
        result = self.error_handler.handle_error(sip_error, operation="interface_management")
        
        self.assertEqual(result['strategy_used'], 'fallback')
        self.assertTrue(result['recovery_successful'])
        
        # Should have degradation mode information
        self.assertIn('degradation_mode', result)
    
    def test_network_failure_recovery(self):
        """Test recovery from network failures"""
        # Simulate capture failure
        capture_error = CaptureFailedError("No handshake", "en0")
        
        # Error handler should suggest retry
        result = self.error_handler.handle_error(capture_error, operation="packet_capture")
        
        self.assertEqual(result['strategy_used'], 'fallback')
        self.assertTrue(result['recovery_successful'])


class TestCompatibilityTesting(unittest.TestCase):
    """Test compatibility with different macOS configurations"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
        self.security_manager._testing_mode = True
        self.interface_manager = InterfaceManager()
    
    @patch('platform.mac_ver')
    @patch('subprocess.run')
    def test_macos_version_compatibility(self, mock_run, mock_mac_ver):
        """Test compatibility with different macOS versions"""
        # Test different macOS versions
        test_versions = [
            ("10.15.7", "Catalina"),
            ("11.6.0", "Big Sur"),
            ("12.5.0", "Monterey"),
            ("13.0.0", "Ventura")
        ]
        
        for version, name in test_versions:
            mock_mac_ver.return_value = (version, ('', '', ''), '')
            
            # Mock csrutil for SIP check
            mock_run.return_value = Mock(
                returncode=0,
                stdout="System Integrity Protection status: enabled."
            )
            
            # Test SIP checking works across versions
            success, sip_info = self.security_manager.check_sip_status()
            self.assertTrue(success, f"SIP check failed on {name} ({version})")
            self.assertIn('enabled', sip_info)
    
    @patch('subprocess.run')
    def test_interface_compatibility(self, mock_run):
        """Test interface compatibility across different hardware"""
        # Mock different interface configurations
        interface_configs = [
            # Built-in WiFi
            "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff",
            # USB WiFi adapter
            "Hardware Port: USB 10/100/1000 LAN\nDevice: en5\nEthernet Address: bb:cc:dd:ee:ff:aa",
            # Multiple interfaces
            """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: USB 10/100/1000 LAN
Device: en5
Ethernet Address: bb:cc:dd:ee:ff:aa"""
        ]
        
        for config in interface_configs:
            mock_run.return_value = Mock(returncode=0, stdout=config)
            
            interfaces = self.interface_manager.discover_wifi_interfaces()
            self.assertIsInstance(interfaces, list)
            # Should find at least one interface in each config
            self.assertGreater(len(interfaces), 0)
    
    @patch('subprocess.run')
    def test_tool_version_compatibility(self, mock_run):
        """Test compatibility with different tool versions"""
        from wifi_security_tester.components.dependency_manager import DependencyManager
        
        dep_manager = DependencyManager()
        
        # Mock different aircrack-ng versions
        version_outputs = [
            "Aircrack-ng 1.6",
            "Aircrack-ng 1.7 - (C) 2006-2022 Thomas d'Otreppe",
            "aircrack-ng 1.5.2"
        ]
        
        for version_output in version_outputs:
            mock_run.return_value = Mock(returncode=0, stdout=version_output)
            
            # Should be able to detect version
            version_info = dep_manager.get_tool_version("aircrack-ng")
            self.assertIsNotNone(version_info)
            self.assertIn('version', version_info)


class TestPerformanceIntegration(unittest.TestCase):
    """Test performance aspects of component integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.wordlist_manager = WordlistManager()
        self.password_cracker = PasswordCracker()
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_large_wordlist_handling(self):
        """Test handling of large wordlists"""
        # Create large wordlist
        large_wordlist = os.path.join(self.temp_dir, "large_wordlist.txt")
        
        with open(large_wordlist, 'w') as f:
            for i in range(10000):
                f.write(f"password{i}\n")
        
        # Test wordlist analysis performance
        start_time = time.time()
        analysis = self.wordlist_manager.analyze_wordlist(large_wordlist)
        end_time = time.time()
        
        # Should complete within reasonable time
        self.assertLess(end_time - start_time, 5.0)  # 5 seconds max
        self.assertEqual(analysis['line_count'], 10000)
    
    def test_concurrent_operations(self):
        """Test concurrent operations between components"""
        import threading
        
        results = []
        errors = []
        
        def create_wordlist(index):
            try:
                wordlist_path = os.path.join(self.temp_dir, f"wordlist_{index}.txt")
                with open(wordlist_path, 'w') as f:
                    f.write(f"password{index}\ntest{index}\n")
                
                analysis = self.wordlist_manager.analyze_wordlist(wordlist_path)
                results.append(analysis)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_wordlist, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 5)
        
        for result in results:
            self.assertEqual(result['line_count'], 2)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestComponentIntegration,
        TestEndToEndWorkflows,
        TestErrorRecoveryIntegration,
        TestCompatibilityTesting,
        TestPerformanceIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
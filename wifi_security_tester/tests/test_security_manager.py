#!/usr/bin/env python3
"""
Test Security Manager - SIP Status Checking
Tests the SIP status checking functionality of the Security Manager
"""

import unittest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess
from datetime import datetime, timedelta

# Add the project root to sys.path
sys.path.append(str(Path(__file__).parent))

from components.security_manager import SecurityManager


class TestSecurityManagerSIP(unittest.TestCase):
    """Test cases for Security Manager SIP functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.security_manager = SecurityManager()
    
    def tearDown(self):
        """Clean up after tests"""
        # Clear cache
        self.security_manager.sip_status_cache = None
        self.security_manager.sip_cache_timestamp = None
    
    @patch('subprocess.run')
    def test_check_sip_status_enabled(self, mock_run):
        """Test SIP status checking when SIP is enabled"""
        # Mock csrutil output for enabled SIP
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "System Integrity Protection status: enabled."
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertTrue(success)
        self.assertTrue(sip_info['enabled'])
        self.assertIn("enabled", sip_info['status_text'].lower())
        self.assertIsInstance(sip_info['restrictions'], list)
        self.assertIsInstance(sip_info['recommendations'], list)
        self.assertGreater(len(sip_info['restrictions']), 0)
        self.assertGreater(len(sip_info['recommendations']), 0)
    
    @patch('subprocess.run')
    def test_check_sip_status_disabled(self, mock_run):
        """Test SIP status checking when SIP is disabled"""
        # Mock csrutil output for disabled SIP
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "System Integrity Protection status: disabled."
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertTrue(success)
        self.assertFalse(sip_info['enabled'])
        self.assertIn("disabled", sip_info['status_text'].lower())
        self.assertIsInstance(sip_info['recommendations'], list)
        # Should have security warnings when SIP is disabled
        self.assertTrue(any("WARNING" in rec for rec in sip_info['recommendations']))
    
    @patch('subprocess.run')
    def test_check_sip_status_command_failure(self, mock_run):
        """Test SIP status checking when csrutil command fails"""
        # Mock csrutil command failure
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Operation not permitted"
        mock_run.return_value = mock_result
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertTrue(success)  # Should still return success with error info
        self.assertTrue(sip_info['enabled'])  # Should assume enabled if can't check
        self.assertIn('error', sip_info)
        self.assertIn("Operation not permitted", sip_info['error'])
    
    @patch('subprocess.run')
    def test_check_sip_status_timeout(self, mock_run):
        """Test SIP status checking with command timeout"""
        # Mock subprocess timeout
        mock_run.side_effect = subprocess.TimeoutExpired(['csrutil', 'status'], 10)
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertFalse(success)
        self.assertIn('error', sip_info)
        self.assertIn("Timeout", sip_info['error'])
        self.assertTrue(sip_info['enabled'])  # Should assume enabled on error
    
    @patch('subprocess.run')
    def test_check_sip_status_command_not_found(self, mock_run):
        """Test SIP status checking when csrutil command is not found"""
        # Mock FileNotFoundError
        mock_run.side_effect = FileNotFoundError("csrutil command not found")
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertFalse(success)
        self.assertIn('error', sip_info)
        self.assertIn("not found", sip_info['error'])
        self.assertTrue(sip_info['enabled'])  # Should assume enabled on error
    
    def test_get_sip_alternative_methods_monitor_mode(self):
        """Test getting alternative methods for monitor mode"""
        alternatives = self.security_manager.get_sip_alternative_methods("monitor_mode")
        
        self.assertIsInstance(alternatives, list)
        self.assertGreater(len(alternatives), 0)
        self.assertTrue(any("USB WiFi adapter" in alt for alt in alternatives))
        self.assertTrue(any("tcpdump" in alt for alt in alternatives))
    
    def test_get_sip_alternative_methods_packet_capture(self):
        """Test getting alternative methods for packet capture"""
        alternatives = self.security_manager.get_sip_alternative_methods("packet_capture")
        
        self.assertIsInstance(alternatives, list)
        self.assertGreater(len(alternatives), 0)
        self.assertTrue(any("tcpdump" in alt for alt in alternatives))
    
    def test_get_sip_alternative_methods_unknown_operation(self):
        """Test getting alternative methods for unknown operation"""
        alternatives = self.security_manager.get_sip_alternative_methods("unknown_operation")
        
        self.assertIsInstance(alternatives, list)
        self.assertGreater(len(alternatives), 0)
        # Should return generic alternatives
        self.assertTrue(any("built-in" in alt.lower() for alt in alternatives))
    
    @patch.object(SecurityManager, 'check_sip_status')
    def test_generate_sip_warnings_enabled(self, mock_check_sip):
        """Test generating SIP warnings when SIP is enabled"""
        # Mock SIP enabled
        mock_check_sip.return_value = (True, {'enabled': True})
        
        warnings = self.security_manager.generate_sip_warnings("monitor_mode")
        
        self.assertIsInstance(warnings, list)
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any("SIP may prevent" in warning for warning in warnings))
    
    @patch.object(SecurityManager, 'check_sip_status')
    def test_generate_sip_warnings_disabled(self, mock_check_sip):
        """Test generating SIP warnings when SIP is disabled"""
        # Mock SIP disabled
        mock_check_sip.return_value = (True, {'enabled': False})
        
        warnings = self.security_manager.generate_sip_warnings("monitor_mode")
        
        self.assertIsInstance(warnings, list)
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any("WARNING" in warning for warning in warnings))
        self.assertTrue(any("disabled" in warning for warning in warnings))
    
    @patch.object(SecurityManager, 'check_sip_status')
    def test_generate_sip_warnings_check_failure(self, mock_check_sip):
        """Test generating SIP warnings when SIP check fails"""
        # Mock SIP check failure
        mock_check_sip.return_value = (False, {'error': 'Check failed'})
        
        warnings = self.security_manager.generate_sip_warnings("monitor_mode")
        
        self.assertIsInstance(warnings, list)
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any("Could not determine" in warning for warning in warnings))
    
    @patch('subprocess.run')
    def test_sip_status_caching(self, mock_run):
        """Test that SIP status is cached properly"""
        # Mock csrutil output
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "System Integrity Protection status: enabled."
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        # First call should execute csrutil
        success1, sip_info1 = self.security_manager.check_sip_status()
        self.assertTrue(success1)
        self.assertEqual(mock_run.call_count, 1)
        
        # Second call should use cache
        success2, sip_info2 = self.security_manager.check_sip_status()
        self.assertTrue(success2)
        self.assertEqual(mock_run.call_count, 1)  # Should not call csrutil again
        
        # Results should be the same
        self.assertEqual(sip_info1['enabled'], sip_info2['enabled'])
        self.assertEqual(sip_info1['status_text'], sip_info2['status_text'])
    
    def test_audit_logging_initialization(self):
        """Test that audit logging is properly initialized"""
        # Check that audit log path is set
        self.assertIsNotNone(self.security_manager.audit_log_path)
        self.assertTrue(str(self.security_manager.audit_log_path).endswith('.log'))
        
        # Check that log directory exists
        self.assertTrue(self.security_manager.audit_log_path.parent.exists())


class TestSecurityManagerPrivileges(unittest.TestCase):
    """Test cases for Security Manager privilege functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.security_manager = SecurityManager()
    
    @patch('os.getuid')
    @patch('os.geteuid')
    def test_check_admin_privileges_root(self, mock_geteuid, mock_getuid):
        """Test privilege checking when running as root"""
        # Mock running as root
        mock_getuid.return_value = 0
        mock_geteuid.return_value = 0
        
        success, privilege_info = self.security_manager.check_admin_privileges()
        
        self.assertTrue(success)
        self.assertTrue(privilege_info['has_admin'])
        self.assertTrue(privilege_info['is_root'])
        self.assertEqual(privilege_info['uid'], 0)
        self.assertIsInstance(privilege_info['recommendations'], list)
    
    @patch('os.getuid')
    @patch('os.geteuid')
    @patch.object(SecurityManager, '_check_sudo_capabilities')
    def test_check_admin_privileges_sudo_user(self, mock_sudo_check, mock_geteuid, mock_getuid):
        """Test privilege checking for user with sudo capabilities"""
        # Mock regular user with sudo
        mock_getuid.return_value = 1000
        mock_geteuid.return_value = 1000
        mock_sudo_check.return_value = (True, "user in admin group")
        
        success, privilege_info = self.security_manager.check_admin_privileges()
        
        self.assertTrue(success)
        self.assertTrue(privilege_info['has_admin'])
        self.assertFalse(privilege_info['is_root'])
        self.assertTrue(privilege_info['can_sudo'])
        self.assertEqual(privilege_info['uid'], 1000)
    
    @patch('os.getuid')
    @patch('os.geteuid')
    @patch.object(SecurityManager, '_check_sudo_capabilities')
    def test_check_admin_privileges_regular_user(self, mock_sudo_check, mock_geteuid, mock_getuid):
        """Test privilege checking for regular user without sudo"""
        # Mock regular user without sudo
        mock_getuid.return_value = 1000
        mock_geteuid.return_value = 1000
        mock_sudo_check.return_value = (False, "no sudo capabilities detected")
        
        success, privilege_info = self.security_manager.check_admin_privileges()
        
        self.assertTrue(success)
        self.assertFalse(privilege_info['has_admin'])
        self.assertFalse(privilege_info['is_root'])
        self.assertFalse(privilege_info['can_sudo'])
        self.assertEqual(privilege_info['uid'], 1000)
    
    @patch('subprocess.run')
    def test_check_sudo_capabilities_sudo_n_success(self, mock_run):
        """Test sudo capability checking with sudo -n success"""
        # Mock successful sudo -n test
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        
        self.assertTrue(can_sudo)
        self.assertIn("sudo -n", method)
    
    @patch('subprocess.run')
    def test_check_sudo_capabilities_admin_group(self, mock_run):
        """Test sudo capability checking via admin group membership"""
        # Mock sudo -n failure but admin group membership
        mock_results = [
            MagicMock(returncode=1),  # sudo -n fails
            MagicMock(returncode=0, stdout="staff admin wheel")  # groups command
        ]
        mock_run.side_effect = mock_results
        
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        
        self.assertTrue(can_sudo)
        self.assertIn("admin group", method)
    
    @patch('subprocess.run')
    def test_check_sudo_capabilities_no_sudo(self, mock_run):
        """Test sudo capability checking when no sudo available"""
        # Mock all methods failing
        mock_run.return_value = MagicMock(returncode=1)
        
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        
        self.assertFalse(can_sudo)
        self.assertIn("no sudo capabilities", method)
    
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_request_admin_privileges_already_admin(self, mock_check_admin):
        """Test requesting admin privileges when already admin"""
        # Mock already having admin privileges
        mock_check_admin.return_value = (True, {'has_admin': True, 'user': 'testuser'})
        
        success, message = self.security_manager.request_admin_privileges("test_operation")
        
        self.assertTrue(success)
        self.assertIn("already available", message)
    
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_request_admin_privileges_can_sudo(self, mock_check_admin):
        """Test requesting admin privileges when user can sudo"""
        # Mock user without admin but can sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': True, 
            'user': 'testuser'
        })
        
        success, message = self.security_manager.request_admin_privileges("test_operation", "test reason")
        
        self.assertFalse(success)  # Request guidance, not immediate success
        self.assertIn("sudo", message)
        self.assertIn("test_operation", message)
        self.assertIn("test reason", message)
    
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_request_admin_privileges_cannot_sudo(self, mock_check_admin):
        """Test requesting admin privileges when user cannot sudo"""
        # Mock user without admin and cannot sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': False, 
            'user': 'testuser'
        })
        
        success, message = self.security_manager.request_admin_privileges("test_operation")
        
        self.assertFalse(success)
        self.assertIn("not in admin group", message)
        self.assertIn("Contact system administrator", message)
    
    def test_validate_privilege_for_operation_packet_capture(self):
        """Test privilege validation for packet capture operation"""
        with patch.object(self.security_manager, 'check_admin_privileges') as mock_check:
            # Test with admin privileges
            mock_check.return_value = (True, {'has_admin': True})
            
            is_sufficient, messages = self.security_manager.validate_privilege_for_operation("packet_capture")
            
            self.assertTrue(is_sufficient)
            self.assertTrue(any("Administrator privileges available" in msg for msg in messages))
    
    def test_validate_privilege_for_operation_network_scanning(self):
        """Test privilege validation for network scanning operation"""
        with patch.object(self.security_manager, 'check_admin_privileges') as mock_check:
            # Test without admin privileges (should still be sufficient)
            mock_check.return_value = (True, {'has_admin': False})
            
            is_sufficient, messages = self.security_manager.validate_privilege_for_operation("network_scanning")
            
            self.assertTrue(is_sufficient)
            self.assertTrue(any("No administrator privileges required" in msg for msg in messages))
    
    def test_validate_privilege_for_operation_unknown(self):
        """Test privilege validation for unknown operation"""
        with patch.object(self.security_manager, 'check_admin_privileges') as mock_check:
            mock_check.return_value = (True, {'has_admin': False})
            
            is_sufficient, messages = self.security_manager.validate_privilege_for_operation("unknown_operation")
            
            self.assertFalse(is_sufficient)
            self.assertTrue(any("Unknown operation" in msg for msg in messages))
    
    @patch('subprocess.run')
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_execute_privileged_operation_with_admin(self, mock_check_admin, mock_run):
        """Test executing privileged operation with admin privileges"""
        # Mock having admin privileges
        mock_check_admin.return_value = (True, {'has_admin': True, 'user': 'testuser'})
        
        # Mock successful command execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['echo', 'test'], 'test_operation'
        )
        
        self.assertTrue(success)
        self.assertEqual(stdout, "success output")
        self.assertEqual(stderr, "")
        
        # Should not add sudo since already admin
        mock_run.assert_called_once()
        called_command = mock_run.call_args[0][0]
        self.assertNotIn('sudo', called_command)
    
    @patch('subprocess.run')
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_execute_privileged_operation_with_sudo(self, mock_check_admin, mock_run):
        """Test executing privileged operation with sudo"""
        # Mock user without admin but can sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': True, 
            'user': 'testuser'
        })
        
        # Mock successful command execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['echo', 'test'], 'test_operation'
        )
        
        self.assertTrue(success)
        self.assertEqual(stdout, "success output")
        
        # Should add sudo
        mock_run.assert_called_once()
        called_command = mock_run.call_args[0][0]
        self.assertIn('sudo', called_command)
    
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_execute_privileged_operation_no_privileges(self, mock_check_admin):
        """Test executing privileged operation without privileges"""
        # Mock user without admin and cannot sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': False, 
            'user': 'testuser'
        })
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['echo', 'test'], 'test_operation'
        )
        
        self.assertFalse(success)
        self.assertEqual(stdout, "")
        self.assertIn("not available", stderr)


class TestSecurityManagerEthical(unittest.TestCase):
    """Test cases for Security Manager ethical usage functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.security_manager = SecurityManager()
        # Reset ethical state for each test
        self.security_manager.user_consent_given = False
        self.security_manager.consent_timestamp = None
        self.security_manager.legal_warnings_shown = False
        self.security_manager.suspicious_activity_detected = False
        self.security_manager.operation_history = []
        # Enable testing mode to skip interactive prompts
        self.security_manager._testing_mode = True
    
    def test_display_legal_warnings(self):
        """Test displaying legal warnings"""
        with patch('builtins.print') as mock_print:
            success = self.security_manager.display_legal_warnings()
            
            self.assertTrue(success)
            self.assertTrue(self.security_manager.legal_warnings_shown)
            
            # Check that legal text was printed
            mock_print.assert_called()
            printed_text = ''.join(str(call) for call in mock_print.call_args_list)
            self.assertIn("LEGAL USAGE WARNING", printed_text)
            self.assertIn("AUTHORIZED TESTING ONLY", printed_text)
    
    def test_display_legal_warnings_already_shown(self):
        """Test that legal warnings are only shown once per session"""
        with patch('builtins.print') as mock_print:
            # First call should show warnings
            success1 = self.security_manager.display_legal_warnings()
            call_count1 = mock_print.call_count
            
            # Second call should not show warnings again
            success2 = self.security_manager.display_legal_warnings()
            call_count2 = mock_print.call_count
            
            self.assertTrue(success1)
            self.assertTrue(success2)
            self.assertEqual(call_count1, call_count2)  # No additional prints
    
    @patch('builtins.input')
    @patch('builtins.print')
    def test_request_user_consent_given(self, mock_print, mock_input):
        """Test requesting user consent when user agrees"""
        # Mock user answering 'yes' to all questions
        mock_input.side_effect = ['yes', 'yes', 'yes', 'yes']
        
        consent_given = self.security_manager.request_user_consent()
        
        self.assertTrue(consent_given)
        self.assertTrue(self.security_manager.user_consent_given)
        self.assertIsNotNone(self.security_manager.consent_timestamp)
    
    @patch('builtins.input')
    @patch('builtins.print')
    def test_request_user_consent_denied(self, mock_print, mock_input):
        """Test requesting user consent when user refuses"""
        # Mock user answering 'no' to first question
        mock_input.side_effect = ['no', 'yes', 'yes', 'yes']
        
        consent_given = self.security_manager.request_user_consent()
        
        self.assertFalse(consent_given)
        self.assertFalse(self.security_manager.user_consent_given)
    
    @patch('builtins.input')
    @patch('builtins.print')
    def test_request_user_consent_keyboard_interrupt(self, mock_print, mock_input):
        """Test requesting user consent with keyboard interrupt"""
        # Mock keyboard interrupt
        mock_input.side_effect = KeyboardInterrupt()
        
        consent_given = self.security_manager.request_user_consent()
        
        self.assertFalse(consent_given)
        self.assertFalse(self.security_manager.user_consent_given)
    
    def test_is_consent_valid_fresh(self):
        """Test consent validity check for fresh consent"""
        self.security_manager.consent_timestamp = datetime.now()
        
        is_valid = self.security_manager._is_consent_valid()
        
        self.assertTrue(is_valid)
    
    def test_is_consent_valid_expired(self):
        """Test consent validity check for expired consent"""
        # Set consent timestamp to 25 hours ago
        self.security_manager.consent_timestamp = datetime.now() - timedelta(hours=25)
        
        is_valid = self.security_manager._is_consent_valid()
        
        self.assertFalse(is_valid)
    
    def test_is_consent_valid_no_timestamp(self):
        """Test consent validity check with no timestamp"""
        self.security_manager.consent_timestamp = None
        
        is_valid = self.security_manager._is_consent_valid()
        
        self.assertFalse(is_valid)
    
    def test_log_operation(self):
        """Test operation logging functionality"""
        operation_details = {"method": "test", "duration": 1.0}
        target_info = {"ssid": "TestNetwork", "bssid": "00:11:22:33:44:55"}
        
        initial_count = len(self.security_manager.operation_history)
        
        self.security_manager.log_operation("network_scan", operation_details, target_info)
        
        self.assertEqual(len(self.security_manager.operation_history), initial_count + 1)
        
        logged_op = self.security_manager.operation_history[-1]
        self.assertEqual(logged_op["type"], "network_scan")
        self.assertEqual(logged_op["details"], operation_details)
        self.assertEqual(logged_op["target"], target_info)
    
    def test_check_suspicious_activity_high_frequency(self):
        """Test suspicious activity detection for high operation frequency"""
        # Add many operations quickly
        for i in range(15):
            self.security_manager.log_operation(f"test_op_{i}", {"test": True})
        
        # Should detect suspicious activity
        self.assertTrue(self.security_manager.suspicious_activity_detected)
    
    def test_check_suspicious_activity_multiple_targets(self):
        """Test suspicious activity detection for multiple targets"""
        # Add operations with different targets
        for i in range(7):
            self.security_manager.log_operation("network_scan", {"test": True}, {
                "ssid": f"Network_{i}",
                "bssid": f"00:11:22:33:44:{i:02d}"
            })
        
        # Should detect suspicious activity due to multiple targets
        self.assertTrue(self.security_manager.suspicious_activity_detected)
    
    def test_validate_ethical_usage_no_consent(self):
        """Test ethical usage validation without consent"""
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        
        self.assertFalse(is_ethical)
        self.assertTrue(any("No user consent" in issue for issue in issues))
    
    def test_validate_ethical_usage_with_consent(self):
        """Test ethical usage validation with valid consent"""
        # Set valid consent
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now()
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        
        self.assertTrue(is_ethical)
        # Should have success message
        self.assertTrue(any("✓" in issue for issue in issues))
    
    def test_validate_ethical_usage_expired_consent(self):
        """Test ethical usage validation with expired consent"""
        # Set expired consent
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now() - timedelta(hours=25)
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        
        self.assertFalse(is_ethical)
        self.assertTrue(any("expired" in issue for issue in issues))
    
    @patch.object(SecurityManager, 'request_user_consent')
    @patch.object(SecurityManager, 'validate_ethical_usage')
    def test_enforce_ethical_usage_success(self, mock_validate, mock_consent):
        """Test successful ethical usage enforcement"""
        # Mock successful consent and validation
        mock_consent.return_value = True
        mock_validate.return_value = (True, ["✓ Ethical usage validated"])
        
        can_continue = self.security_manager.enforce_ethical_usage()
        
        self.assertTrue(can_continue)
        mock_consent.assert_called_once()
        mock_validate.assert_called_once()
    
    @patch.object(SecurityManager, 'request_user_consent')
    def test_enforce_ethical_usage_no_consent(self, mock_consent):
        """Test ethical usage enforcement when consent is denied"""
        # Mock consent denial
        mock_consent.return_value = False
        
        can_continue = self.security_manager.enforce_ethical_usage()
        
        self.assertFalse(can_continue)
        mock_consent.assert_called_once()
    
    @patch.object(SecurityManager, 'request_user_consent')
    @patch.object(SecurityManager, 'validate_ethical_usage')
    @patch('builtins.print')
    def test_enforce_ethical_usage_violations(self, mock_print, mock_validate, mock_consent):
        """Test ethical usage enforcement with violations"""
        # Mock consent given but validation fails
        mock_consent.return_value = True
        mock_validate.return_value = (False, ["Violation detected"])
        
        can_continue = self.security_manager.enforce_ethical_usage()
        
        self.assertFalse(can_continue)
        
        # Check that violation message was printed
        printed_text = ''.join(str(call) for call in mock_print.call_args_list)
        self.assertIn("VIOLATION DETECTED", printed_text)
    
    def test_save_and_load_user_consent(self):
        """Test saving and loading user consent"""
        # Set consent data
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now()
        
        # Save consent
        self.security_manager._save_user_consent()
        
        # Reset and load
        self.security_manager.user_consent_given = False
        self.security_manager.consent_timestamp = None
        self.security_manager._load_user_consent()
        
        # Should have loaded the consent
        self.assertTrue(self.security_manager.user_consent_given)
        self.assertIsNotNone(self.security_manager.consent_timestamp)


def run_security_tests():
    """Run all Security Manager tests"""
    print("Running Security Manager Tests...")
    
    # Create test suite for both SIP and Privilege tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add SIP tests
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityManagerSIP))
    
    # Add Privilege tests
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityManagerPrivileges))
    
    # Add Ethical Usage tests
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityManagerEthical))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return success status
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_security_tests()
    sys.exit(0 if success else 1)
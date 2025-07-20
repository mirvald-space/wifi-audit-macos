#!/usr/bin/env python3
"""
Advanced Test Suite for Security Manager Component
Tests comprehensive security management including SIP, privileges, and ethical usage
"""

import unittest
import tempfile
import os
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, call, mock_open
import subprocess

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.security_manager import SecurityManager


class TestSecurityManagerAdvanced(unittest.TestCase):
    """Advanced tests for Security Manager functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create security manager with test paths
        self.security_manager = SecurityManager()
        self.security_manager.audit_log_path = Path(self.temp_dir) / "test_audit.log"
        self.security_manager.consent_file_path = Path(self.temp_dir) / "test_consent.json"
        self.security_manager._testing_mode = True
        
        # Reset state for each test
        self.security_manager.sip_status_cache = None
        self.security_manager.sip_cache_timestamp = None
        self.security_manager.user_consent_given = False
        self.security_manager.consent_timestamp = None
        self.security_manager.legal_warnings_shown = False
        self.security_manager.suspicious_activity_detected = False
        self.security_manager.operation_history = []
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class TestSIPManagementAdvanced(TestSecurityManagerAdvanced):
    """Advanced SIP management tests"""
    
    @patch('subprocess.run')
    def test_sip_detailed_configuration_parsing(self, mock_run):
        """Test detailed SIP configuration parsing"""
        # Mock detailed csrutil output
        detailed_output = """System Integrity Protection status: enabled.

Configuration:
    Apple Internal: enabled
    Kext Signing: enabled
    Filesystem Protections: enabled
    Debugging Restrictions: enabled
    DTrace Restrictions: enabled
    NVRAM Protections: enabled
    BaseSystem Verification: enabled"""
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = detailed_output
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertTrue(success)
        self.assertTrue(sip_info['enabled'])
        
        # Check detailed status parsing
        self.assertIn('detailed_status', sip_info)
        self.assertIn('Apple Internal', sip_info['detailed_status'])
        self.assertIn('Kext Signing', sip_info['detailed_status'])
        
        # Check restrictions
        self.assertIn('restrictions', sip_info)
        self.assertTrue(any('Filesystem protections enabled' in r for r in sip_info['restrictions']))
        self.assertTrue(any('Kernel extension signing required' in r for r in sip_info['restrictions']))
    
    @patch('subprocess.run')
    def test_sip_partial_configuration(self, mock_run):
        """Test SIP with partial configuration"""
        partial_output = """System Integrity Protection status: enabled (Custom Configuration).

Configuration:
    Apple Internal: enabled
    Kext Signing: disabled
    Filesystem Protections: enabled
    Debugging Restrictions: disabled"""
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = partial_output
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        success, sip_info = self.security_manager.check_sip_status()
        
        self.assertTrue(success)
        self.assertTrue(sip_info['enabled'])
        
        # Should detect mixed configuration
        self.assertIn('Custom Configuration', sip_info['status_text'])
        self.assertTrue(any('disabled' in status for status in sip_info['detailed_status'].values()))
    
    def test_sip_alternative_methods_comprehensive(self):
        """Test comprehensive SIP alternative methods"""
        test_operations = [
            'monitor_mode',
            'packet_capture', 
            'interface_modification',
            'system_file_access',
            'kernel_extension_loading',
            'unknown_operation'
        ]
        
        for operation in test_operations:
            alternatives = self.security_manager.get_sip_alternative_methods(operation)
            
            self.assertIsInstance(alternatives, list)
            self.assertGreater(len(alternatives), 0)
            
            # Each alternative should be a non-empty string
            for alt in alternatives:
                self.assertIsInstance(alt, str)
                self.assertGreater(len(alt.strip()), 0)
    
    @patch.object(SecurityManager, 'check_sip_status')
    def test_sip_warnings_context_specific(self, mock_check_sip):
        """Test context-specific SIP warnings"""
        # Mock SIP enabled
        mock_check_sip.return_value = (True, {'enabled': True})
        
        test_cases = [
            ('monitor_mode', ['SIP may prevent', 'monitor mode']),
            ('packet_capture', ['SIP may limit', 'raw socket']),
            ('interface_management', ['SIP may restrict', 'interface manipulation']),
            ('system_modification', ['SIP prevents', 'system files']),
        ]
        
        for operation, expected_keywords in test_cases:
            warnings = self.security_manager.generate_sip_warnings(operation)
            
            self.assertIsInstance(warnings, list)
            self.assertGreater(len(warnings), 0)
            
            # Check that warnings contain expected keywords
            warning_text = ' '.join(warnings).lower()
            for keyword in expected_keywords:
                self.assertIn(keyword.lower(), warning_text)
    
    @patch('subprocess.run')
    def test_sip_caching_behavior(self, mock_run):
        """Test SIP status caching behavior"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "System Integrity Protection status: enabled."
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        # First call should execute csrutil
        success1, sip_info1 = self.security_manager.check_sip_status()
        self.assertEqual(mock_run.call_count, 1)
        
        # Second call within cache duration should use cache
        success2, sip_info2 = self.security_manager.check_sip_status()
        self.assertEqual(mock_run.call_count, 1)  # No additional calls
        
        # Results should be identical
        self.assertEqual(sip_info1, sip_info2)
        
        # Expire cache and call again
        self.security_manager.sip_cache_timestamp = time.time() - 400  # Older than cache duration
        success3, sip_info3 = self.security_manager.check_sip_status()
        self.assertEqual(mock_run.call_count, 2)  # Should call csrutil again


class TestPrivilegeManagementAdvanced(TestSecurityManagerAdvanced):
    """Advanced privilege management tests"""
    
    @patch('os.getuid')
    @patch('os.geteuid') 
    @patch('os.getgid')
    @patch('os.getegid')
    @patch('getpass.getuser')
    def test_privilege_detection_comprehensive(self, mock_getuser, mock_getegid, mock_getgid, mock_geteuid, mock_getuid):
        """Test comprehensive privilege detection"""
        mock_getuser.return_value = "testuser"
        mock_getuid.return_value = 1000
        mock_geteuid.return_value = 1000
        mock_getgid.return_value = 1000
        mock_getegid.return_value = 1000
        
        with patch.object(self.security_manager, '_check_sudo_capabilities') as mock_sudo:
            mock_sudo.return_value = (True, "user in admin group")
            
            success, privilege_info = self.security_manager.check_admin_privileges()
            
            self.assertTrue(success)
            self.assertTrue(privilege_info['has_admin'])
            self.assertFalse(privilege_info['is_root'])
            self.assertTrue(privilege_info['can_sudo'])
            self.assertEqual(privilege_info['user'], "testuser")
            self.assertEqual(privilege_info['uid'], 1000)
            self.assertIn('recommendations', privilege_info)
    
    @patch('subprocess.run')
    def test_sudo_capability_detection_methods(self, mock_run):
        """Test various sudo capability detection methods"""
        # Test sudo -n success
        mock_run.return_value = MagicMock(returncode=0)
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        self.assertTrue(can_sudo)
        self.assertIn("sudo -n", method)
        
        # Test admin group membership
        mock_run.side_effect = [
            MagicMock(returncode=1),  # sudo -n fails
            MagicMock(returncode=0, stdout="staff admin wheel")  # groups command
        ]
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        self.assertTrue(can_sudo)
        self.assertIn("admin group", method)
        
        # Test dscl check
        mock_run.side_effect = [
            MagicMock(returncode=1),  # sudo -n fails
            MagicMock(returncode=1),  # groups fails
            MagicMock(returncode=0, stdout="GroupMembership: testuser admin")  # dscl
        ]
        can_sudo, method = self.security_manager._check_sudo_capabilities()
        self.assertTrue(can_sudo)
        self.assertIn("dscl", method)
    
    def test_privilege_validation_operations(self):
        """Test privilege validation for specific operations"""
        test_operations = [
            ('packet_capture', True),  # Requires admin
            ('network_scanning', False),  # No admin needed
            ('interface_management', True),  # Requires admin
            ('file_modification', True),  # Requires admin
            ('unknown_operation', False),  # Unknown = no admin by default
        ]
        
        with patch.object(self.security_manager, 'check_admin_privileges') as mock_check:
            # Test with admin privileges
            mock_check.return_value = (True, {'has_admin': True})
            
            for operation, requires_admin in test_operations:
                is_sufficient, messages = self.security_manager.validate_privilege_for_operation(operation)
                
                if requires_admin:
                    self.assertTrue(is_sufficient)
                    self.assertTrue(any("Administrator privileges available" in msg for msg in messages))
                else:
                    # Should be sufficient regardless of admin status for non-admin operations
                    self.assertTrue(is_sufficient)
    
    @patch('subprocess.run')
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_privileged_operation_execution(self, mock_check_admin, mock_run):
        """Test privileged operation execution with various scenarios"""
        # Test with existing admin privileges
        mock_check_admin.return_value = (True, {'has_admin': True, 'user': 'testuser'})
        mock_run.return_value = MagicMock(returncode=0, stdout="success", stderr="")
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['echo', 'test'], 'test_operation'
        )
        
        self.assertTrue(success)
        self.assertEqual(stdout, "success")
        
        # Command should not include sudo since already admin
        called_command = mock_run.call_args[0][0]
        self.assertNotIn('sudo', called_command)
        
        # Test with sudo capabilities
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': True, 
            'user': 'testuser'
        })
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['echo', 'test'], 'test_operation'
        )
        
        self.assertTrue(success)
        
        # Command should include sudo
        called_command = mock_run.call_args[0][0]
        self.assertIn('sudo', called_command)
    
    @patch.object(SecurityManager, 'check_admin_privileges')
    def test_privilege_request_scenarios(self, mock_check_admin):
        """Test privilege request scenarios"""
        # Test already has admin
        mock_check_admin.return_value = (True, {'has_admin': True, 'user': 'testuser'})
        success, message = self.security_manager.request_admin_privileges("test_operation")
        self.assertTrue(success)
        self.assertIn("already available", message)
        
        # Test can sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': True, 
            'user': 'testuser'
        })
        success, message = self.security_manager.request_admin_privileges("test_operation", "test reason")
        self.assertFalse(success)  # Guidance provided, not immediate success
        self.assertIn("sudo", message)
        self.assertIn("test_operation", message)
        self.assertIn("test reason", message)
        
        # Test cannot sudo
        mock_check_admin.return_value = (True, {
            'has_admin': False, 
            'can_sudo': False, 
            'user': 'testuser'
        })
        success, message = self.security_manager.request_admin_privileges("test_operation")
        self.assertFalse(success)
        self.assertIn("not in admin group", message)


class TestEthicalUsageAdvanced(TestSecurityManagerAdvanced):
    """Advanced ethical usage enforcement tests"""
    
    def test_legal_warnings_display(self):
        """Test legal warnings display functionality"""
        with patch('builtins.print') as mock_print:
            success = self.security_manager.display_legal_warnings()
            
            self.assertTrue(success)
            self.assertTrue(self.security_manager.legal_warnings_shown)
            
            # Verify warning content
            printed_text = ''.join(str(call) for call in mock_print.call_args_list)
            required_warnings = [
                "LEGAL USAGE WARNING",
                "AUTHORIZED TESTING ONLY",
                "educational purposes",
                "written permission"
            ]
            
            for warning in required_warnings:
                self.assertIn(warning, printed_text)
    
    @patch('builtins.input')
    @patch('builtins.print')
    def test_user_consent_comprehensive(self, mock_print, mock_input):
        """Test comprehensive user consent process"""
        # Test full consent process
        consent_responses = ['yes', 'yes', 'yes', 'yes']  # All questions answered yes
        mock_input.side_effect = consent_responses
        
        consent_given = self.security_manager.request_user_consent()
        
        self.assertTrue(consent_given)
        self.assertTrue(self.security_manager.user_consent_given)
        self.assertIsNotNone(self.security_manager.consent_timestamp)
        
        # Verify all consent questions were asked
        self.assertEqual(mock_input.call_count, len(consent_responses))
    
    @patch('builtins.input')
    def test_user_consent_partial_denial(self, mock_input):
        """Test user consent with partial denial"""
        # Test denial on different questions
        denial_scenarios = [
            ['no', 'yes', 'yes', 'yes'],  # Deny first question
            ['yes', 'no', 'yes', 'yes'],  # Deny second question
            ['yes', 'yes', 'no', 'yes'],  # Deny third question
            ['yes', 'yes', 'yes', 'no'],  # Deny fourth question
        ]
        
        for scenario in denial_scenarios:
            # Reset state
            self.security_manager.user_consent_given = False
            self.security_manager.consent_timestamp = None
            
            mock_input.side_effect = scenario
            consent_given = self.security_manager.request_user_consent()
            
            self.assertFalse(consent_given)
            self.assertFalse(self.security_manager.user_consent_given)
    
    def test_consent_validity_checking(self):
        """Test consent validity checking"""
        # Test fresh consent
        self.security_manager.consent_timestamp = datetime.now()
        self.assertTrue(self.security_manager._is_consent_valid())
        
        # Test expired consent
        self.security_manager.consent_timestamp = datetime.now() - timedelta(hours=25)
        self.assertFalse(self.security_manager._is_consent_valid())
        
        # Test no consent
        self.security_manager.consent_timestamp = None
        self.assertFalse(self.security_manager._is_consent_valid())
    
    def test_operation_logging_and_tracking(self):
        """Test operation logging and tracking"""
        # Test basic operation logging
        operation_details = {"method": "scan", "duration": 2.5}
        target_info = {"ssid": "TestNetwork", "bssid": "00:11:22:33:44:55"}
        
        initial_count = len(self.security_manager.operation_history)
        
        self.security_manager.log_operation("network_scan", operation_details, target_info)
        
        self.assertEqual(len(self.security_manager.operation_history), initial_count + 1)
        
        logged_op = self.security_manager.operation_history[-1]
        self.assertEqual(logged_op["type"], "network_scan")
        self.assertEqual(logged_op["details"], operation_details)
        self.assertEqual(logged_op["target"], target_info)
        self.assertIn("timestamp", logged_op)
    
    def test_suspicious_activity_detection(self):
        """Test suspicious activity detection"""
        # Test high frequency operations
        for i in range(15):  # Above threshold
            self.security_manager.log_operation(f"scan_{i}", {"test": True})
        
        self.assertTrue(self.security_manager.suspicious_activity_detected)
        
        # Reset and test multiple targets
        self.security_manager.suspicious_activity_detected = False
        self.security_manager.operation_history = []
        
        for i in range(8):  # Above target threshold
            self.security_manager.log_operation("network_scan", {"test": True}, {
                "ssid": f"Network_{i}",
                "bssid": f"00:11:22:33:44:{i:02d}"
            })
        
        self.assertTrue(self.security_manager.suspicious_activity_detected)
    
    def test_ethical_usage_validation_comprehensive(self):
        """Test comprehensive ethical usage validation"""
        # Test without consent
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertFalse(is_ethical)
        self.assertTrue(any("No user consent" in issue for issue in issues))
        
        # Test with valid consent
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now()
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertTrue(is_ethical)
        self.assertTrue(any("✓" in issue for issue in issues))
        
        # Test with expired consent
        self.security_manager.consent_timestamp = datetime.now() - timedelta(hours=25)
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertFalse(is_ethical)
        self.assertTrue(any("expired" in issue for issue in issues))
        
        # Test with suspicious activity
        self.security_manager.consent_timestamp = datetime.now()  # Reset to valid
        self.security_manager.suspicious_activity_detected = True
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertFalse(is_ethical)
        self.assertTrue(any("Suspicious activity" in issue for issue in issues))
    
    def test_consent_persistence(self):
        """Test consent saving and loading"""
        # Set consent data
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now()
        
        # Save consent
        self.security_manager._save_user_consent()
        
        # Verify file was created
        self.assertTrue(self.security_manager.consent_file_path.exists())
        
        # Reset and load
        self.security_manager.user_consent_given = False
        self.security_manager.consent_timestamp = None
        
        self.security_manager._load_user_consent()
        
        # Should have loaded the consent
        self.assertTrue(self.security_manager.user_consent_given)
        self.assertIsNotNone(self.security_manager.consent_timestamp)
    
    @patch.object(SecurityManager, 'request_user_consent')
    @patch.object(SecurityManager, 'validate_ethical_usage')
    def test_ethical_usage_enforcement_scenarios(self, mock_validate, mock_consent):
        """Test various ethical usage enforcement scenarios"""
        # Test successful enforcement
        mock_consent.return_value = True
        mock_validate.return_value = (True, ["✓ Ethical usage validated"])
        
        can_continue = self.security_manager.enforce_ethical_usage()
        self.assertTrue(can_continue)
        
        # Test consent denied
        mock_consent.return_value = False
        
        can_continue = self.security_manager.enforce_ethical_usage()
        self.assertFalse(can_continue)
        
        # Test validation failure
        mock_consent.return_value = True
        mock_validate.return_value = (False, ["Violation detected"])
        
        with patch('builtins.print') as mock_print:
            can_continue = self.security_manager.enforce_ethical_usage()
            self.assertFalse(can_continue)
            
            # Should print violation message
            printed_text = ''.join(str(call) for call in mock_print.call_args_list)
            self.assertIn("VIOLATION DETECTED", printed_text)


class TestSecurityAuditingAdvanced(TestSecurityManagerAdvanced):
    """Advanced security auditing and logging tests"""
    
    def test_security_event_logging(self):
        """Test security event logging"""
        # Test basic event logging
        self.security_manager._log_security_event("TEST_EVENT", "Test message", {
            "key1": "value1",
            "key2": 123
        })
        
        # Verify log file exists and contains event
        self.assertTrue(self.security_manager.audit_log_path.exists())
        
        with open(self.security_manager.audit_log_path, 'r') as f:
            log_content = f.read()
            self.assertIn("TEST_EVENT", log_content)
            self.assertIn("Test message", log_content)
    
    def test_audit_log_analysis(self):
        """Test audit log analysis functionality"""
        # Generate various security events
        events = [
            ("SIP_CHECK", "SIP status checked", {"sip_enabled": True}),
            ("PRIVILEGE_CHECK", "Admin privileges checked", {"has_admin": False}),
            ("CRACK_START", "Password cracking started", {"method": "aircrack"}),
            ("SUSPICIOUS_ACTIVITY", "High frequency operations", {"count": 15}),
        ]
        
        for event_type, message, data in events:
            self.security_manager._log_security_event(event_type, message, data)
        
        # Test log analysis (if implemented)
        if hasattr(self.security_manager, 'analyze_audit_log'):
            analysis = self.security_manager.analyze_audit_log()
            self.assertIn('total_events', analysis)
            self.assertIn('event_types', analysis)
    
    def test_security_reporting(self):
        """Test security reporting functionality"""
        # Set up various security states
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = datetime.now()
        self.security_manager.suspicious_activity_detected = False
        
        # Log some operations
        for i in range(5):
            self.security_manager.log_operation(f"test_op_{i}", {"test": True})
        
        # Test security report generation (if implemented)
        if hasattr(self.security_manager, 'generate_security_report'):
            report = self.security_manager.generate_security_report()
            
            self.assertIn('consent_status', report)
            self.assertIn('operation_count', report)
            self.assertIn('suspicious_activity', report)
            self.assertIn('recommendations', report)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestSIPManagementAdvanced,
        TestPrivilegeManagementAdvanced,
        TestEthicalUsageAdvanced,
        TestSecurityAuditingAdvanced
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
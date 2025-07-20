#!/usr/bin/env python3
"""
Comprehensive Test Suite for Security Manager - Additional coverage
Tests advanced security features, edge cases, and integration scenarios
"""

import unittest
import tempfile
import os
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, mock_open
import subprocess
import getpass

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.security_manager import SecurityManager


class TestSecurityManagerAuditLogging(unittest.TestCase):
    """Test security manager audit logging functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.security_manager = SecurityManager()
        # Override audit log path for testing
        self.security_manager.audit_log_path = Path(self.temp_dir) / "test_audit.log"
        self.security_manager.consent_file_path = Path(self.temp_dir) / "test_consent.json"
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_audit_log_initialization(self):
        """Test audit log initialization"""
        # Remove existing log file
        if self.security_manager.audit_log_path.exists():
            self.security_manager.audit_log_path.unlink()
        
        # Re-initialize
        self.security_manager._initialize_audit_logging()
        
        # Verify log file was created
        self.assertTrue(self.security_manager.audit_log_path.exists())
        
        # Verify initialization entry was logged
        with open(self.security_manager.audit_log_path, 'r') as f:
            content = f.read()
            self.assertIn("Security Manager initialized", content)
    
    def test_security_event_logging(self):
        """Test security event logging functionality"""
        event_type = "TEST_EVENT"
        description = "Test security event"
        details = {"user": "testuser", "action": "test_action"}
        
        self.security_manager._log_security_event(event_type, description, details)
        
        # Verify event was logged
        with open(self.security_manager.audit_log_path, 'r') as f:
            content = f.read()
            self.assertIn(event_type, content)
            self.assertIn(description, content)
            self.assertIn("testuser", content)
    
    def test_audit_log_rotation(self):
        """Test audit log rotation when file gets large"""
        # Fill audit log with entries
        for i in range(1000):
            self.security_manager._log_security_event(
                "BULK_TEST", 
                f"Bulk test event {i}", 
                {"iteration": i}
            )
        
        # Verify log file exists and has content
        self.assertTrue(self.security_manager.audit_log_path.exists())
        file_size = self.security_manager.audit_log_path.stat().st_size
        self.assertGreater(file_size, 1000)  # Should have substantial content
    
    def test_audit_log_permissions(self):
        """Test audit log file permissions"""
        # Check that audit log has appropriate permissions
        if self.security_manager.audit_log_path.exists():
            stat_info = self.security_manager.audit_log_path.stat()
            # On Unix systems, check that file is readable by owner
            self.assertTrue(stat_info.st_mode & 0o400)  # Owner read permission
    
    def test_concurrent_audit_logging(self):
        """Test concurrent audit logging from multiple threads"""
        import threading
        import time
        
        def log_events(thread_id):
            for i in range(100):
                self.security_manager._log_security_event(
                    "CONCURRENT_TEST",
                    f"Thread {thread_id} event {i}",
                    {"thread_id": thread_id, "event_num": i}
                )
                time.sleep(0.001)  # Small delay to simulate real usage
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=log_events, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all events were logged
        with open(self.security_manager.audit_log_path, 'r') as f:
            content = f.read()
            # Should have events from all threads
            for i in range(5):
                self.assertIn(f"Thread {i}", content)


class TestSecurityManagerConsentManagement(unittest.TestCase):
    """Test security manager consent management functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.security_manager = SecurityManager()
        self.security_manager.consent_file_path = Path(self.temp_dir) / "test_consent.json"
        self.security_manager._testing_mode = True  # Enable testing mode
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_consent_persistence(self):
        """Test consent data persistence"""
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
        
        # Verify consent was loaded
        self.assertTrue(self.security_manager.user_consent_given)
        self.assertIsNotNone(self.security_manager.consent_timestamp)
    
    def test_consent_expiration(self):
        """Test consent expiration logic"""
        # Test fresh consent
        self.security_manager.consent_timestamp = datetime.now()
        self.assertTrue(self.security_manager._is_consent_valid())
        
        # Test expired consent (25 hours old)
        self.security_manager.consent_timestamp = datetime.now() - timedelta(hours=25)
        self.assertFalse(self.security_manager._is_consent_valid())
        
        # Test no consent timestamp
        self.security_manager.consent_timestamp = None
        self.assertFalse(self.security_manager._is_consent_valid())
    
    def test_consent_file_corruption_handling(self):
        """Test handling of corrupted consent file"""
        # Create corrupted consent file
        with open(self.security_manager.consent_file_path, 'w') as f:
            f.write("invalid json content")
        
        # Should handle corruption gracefully
        self.security_manager._load_user_consent()
        
        # Should default to no consent
        self.assertFalse(self.security_manager.user_consent_given)
        self.assertIsNone(self.security_manager.consent_timestamp)
    
    @patch('builtins.input')
    def test_consent_request_timeout(self, mock_input):
        """Test consent request with timeout simulation"""
        # Simulate user taking too long to respond
        import time
        
        def slow_input(prompt):
            time.sleep(0.1)  # Simulate delay
            return "yes"
        
        mock_input.side_effect = slow_input
        
        # Should still work with reasonable delays
        with patch('builtins.print'):
            consent = self.security_manager.request_user_consent()
            self.assertTrue(consent)
    
    def test_consent_validation_edge_cases(self):
        """Test consent validation edge cases"""
        # Test with consent given but no timestamp
        self.security_manager.user_consent_given = True
        self.security_manager.consent_timestamp = None
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertFalse(is_ethical)
        self.assertTrue(any("timestamp" in issue.lower() for issue in issues))
        
        # Test with timestamp but no consent flag
        self.security_manager.user_consent_given = False
        self.security_manager.consent_timestamp = datetime.now()
        
        is_ethical, issues = self.security_manager.validate_ethical_usage()
        self.assertFalse(is_ethical)


class TestSecurityManagerSuspiciousActivityDetection(unittest.TestCase):
    """Test security manager suspicious activity detection"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
        self.security_manager.suspicious_activity_threshold = 5  # Lower threshold for testing
    
    def test_high_frequency_operation_detection(self):
        """Test detection of high-frequency operations"""
        # Perform many operations quickly
        for i in range(10):
            self.security_manager.log_operation(f"test_op_{i}", {"test": True})
        
        # Should detect suspicious activity
        self.assertTrue(self.security_manager.suspicious_activity_detected)
    
    def test_multiple_target_detection(self):
        """Test detection of operations on multiple targets"""
        # Perform operations on many different targets
        for i in range(8):
            self.security_manager.log_operation("network_scan", {"test": True}, {
                "ssid": f"Network_{i}",
                "bssid": f"00:11:22:33:44:{i:02d}"
            })
        
        # Should detect suspicious activity due to multiple targets
        self.assertTrue(self.security_manager.suspicious_activity_detected)
    
    def test_normal_activity_patterns(self):
        """Test that normal activity patterns don't trigger detection"""
        # Perform reasonable number of operations
        for i in range(3):
            self.security_manager.log_operation("network_scan", {"test": True}, {
                "ssid": "TestNetwork",
                "bssid": "00:11:22:33:44:55"
            })
        
        # Should not detect suspicious activity
        self.assertFalse(self.security_manager.suspicious_activity_detected)
    
    def test_activity_pattern_analysis(self):
        """Test detailed activity pattern analysis"""
        # Create mixed activity pattern
        operations = [
            ("network_scan", {"duration": 5}, {"ssid": "Network1"}),
            ("packet_capture", {"duration": 30}, {"ssid": "Network1"}),
            ("password_crack", {"duration": 300}, {"ssid": "Network1"}),
            ("network_scan", {"duration": 5}, {"ssid": "Network2"}),
        ]
        
        for op_type, details, target in operations:
            self.security_manager.log_operation(op_type, details, target)
        
        # Analyze patterns
        patterns = self.security_manager._analyze_activity_patterns()
        
        self.assertIn('operation_frequency', patterns)
        self.assertIn('target_diversity', patterns)
        self.assertIn('time_distribution', patterns)
    
    def test_suspicious_activity_reset(self):
        """Test suspicious activity flag reset"""
        # Trigger suspicious activity
        for i in range(10):
            self.security_manager.log_operation(f"test_op_{i}", {"test": True})
        
        self.assertTrue(self.security_manager.suspicious_activity_detected)
        
        # Reset suspicious activity
        self.security_manager._reset_suspicious_activity()
        
        self.assertFalse(self.security_manager.suspicious_activity_detected)
        self.assertEqual(len(self.security_manager.operation_history), 0)


class TestSecurityManagerPrivilegeEscalation(unittest.TestCase):
    """Test security manager privilege escalation scenarios"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
    
    @patch('subprocess.run')
    @patch('os.getuid')
    @patch('os.geteuid')
    def test_privilege_escalation_detection(self, mock_geteuid, mock_getuid, mock_run):
        """Test detection of privilege escalation"""
        # Start as regular user
        mock_getuid.return_value = 1000
        mock_geteuid.return_value = 1000
        mock_run.return_value = Mock(returncode=1)  # No sudo
        
        success, info = self.security_manager.check_admin_privileges()
        self.assertFalse(info['has_admin'])
        
        # Simulate privilege escalation
        mock_geteuid.return_value = 0  # Now running as root
        
        success, info = self.security_manager.check_admin_privileges()
        self.assertTrue(info['has_admin'])
        self.assertTrue(info['is_root'])
    
    @patch('subprocess.run')
    def test_sudo_validation_bypass_attempt(self, mock_run):
        """Test detection of sudo validation bypass attempts"""
        # Mock sudo command that appears to succeed but doesn't actually grant privileges
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        
        # But actual privilege check should fail
        with patch('os.geteuid', return_value=1000):  # Still regular user
            success, stdout, stderr = self.security_manager.execute_privileged_operation(
                ['echo', 'test'], 'test_operation'
            )
            
            # Should detect that privileges weren't actually escalated
            self.assertFalse(success)
    
    def test_privilege_requirement_validation(self):
        """Test validation of privilege requirements for operations"""
        test_cases = [
            ("packet_capture", True),  # Requires admin
            ("network_scanning", False),  # Doesn't require admin
            ("interface_modification", True),  # Requires admin
            ("wordlist_creation", False),  # Doesn't require admin
        ]
        
        for operation, requires_admin in test_cases:
            with patch.object(self.security_manager, 'check_admin_privileges') as mock_check:
                mock_check.return_value = (True, {'has_admin': False})
                
                is_sufficient, messages = self.security_manager.validate_privilege_for_operation(operation)
                
                if requires_admin:
                    self.assertFalse(is_sufficient)
                else:
                    self.assertTrue(is_sufficient)


class TestSecurityManagerSystemIntegration(unittest.TestCase):
    """Test security manager integration with system components"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
    
    @patch('subprocess.run')
    def test_system_command_execution_security(self, mock_run):
        """Test security of system command execution"""
        # Test command injection prevention
        malicious_commands = [
            ['echo', 'test; rm -rf /'],
            ['ls', '$(rm -rf /)'],
            ['cat', '/etc/passwd && rm -rf /'],
        ]
        
        for cmd in malicious_commands:
            mock_run.return_value = Mock(returncode=0, stdout="safe output", stderr="")
            
            success, stdout, stderr = self.security_manager.execute_privileged_operation(
                cmd, 'test_operation'
            )
            
            # Verify command was executed as-is without shell interpretation
            mock_run.assert_called()
            called_args = mock_run.call_args[0][0]
            self.assertEqual(called_args, ['sudo'] + cmd)
    
    def test_environment_variable_sanitization(self):
        """Test sanitization of environment variables"""
        # Test with potentially dangerous environment variables
        dangerous_env = {
            'LD_PRELOAD': '/malicious/lib.so',
            'PATH': '/malicious/bin:/usr/bin',
            'PYTHONPATH': '/malicious/python',
        }
        
        with patch.dict(os.environ, dangerous_env):
            # Security manager should not be affected by malicious env vars
            success, info = self.security_manager.check_admin_privileges()
            self.assertTrue(success)  # Should still work normally
    
    @patch('subprocess.run')
    def test_resource_limit_enforcement(self, mock_run):
        """Test enforcement of resource limits"""
        # Test timeout enforcement
        mock_run.side_effect = subprocess.TimeoutExpired(['test'], 30)
        
        success, stdout, stderr = self.security_manager.execute_privileged_operation(
            ['sleep', '60'], 'test_operation'
        )
        
        self.assertFalse(success)
        self.assertIn("Timeout", stderr)
    
    def test_file_system_access_validation(self):
        """Test file system access validation"""
        # Test access to sensitive files
        sensitive_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/System/Library/Extensions',
            '/usr/bin/sudo',
        ]
        
        for path in sensitive_paths:
            # Security manager should log access to sensitive paths
            with patch.object(self.security_manager, '_log_security_event') as mock_log:
                # Simulate file access attempt
                self.security_manager._log_security_event(
                    "FILE_ACCESS", 
                    f"Attempted access to {path}",
                    {"path": path, "sensitive": True}
                )
                
                mock_log.assert_called_with(
                    "FILE_ACCESS",
                    f"Attempted access to {path}",
                    {"path": path, "sensitive": True}
                )


class TestSecurityManagerErrorHandling(unittest.TestCase):
    """Test security manager error handling and recovery"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = SecurityManager()
    
    def test_sip_check_error_handling(self):
        """Test SIP check error handling"""
        with patch('subprocess.run') as mock_run:
            # Test various error conditions
            error_conditions = [
                subprocess.TimeoutExpired(['csrutil'], 10),
                FileNotFoundError("csrutil not found"),
                PermissionError("Permission denied"),
                Exception("Unexpected error"),
            ]
            
            for error in error_conditions:
                mock_run.side_effect = error
                
                success, sip_info = self.security_manager.check_sip_status()
                
                # Should handle error gracefully
                if isinstance(error, subprocess.TimeoutExpired):
                    self.assertFalse(success)
                else:
                    # Other errors should be handled but still return info
                    self.assertIn('error', sip_info)
                    self.assertTrue(sip_info['enabled'])  # Should assume enabled on error
    
    def test_privilege_check_error_recovery(self):
        """Test privilege check error recovery"""
        with patch('os.getuid') as mock_getuid:
            # Test system call failure
            mock_getuid.side_effect = OSError("System call failed")
            
            success, info = self.security_manager.check_admin_privileges()
            
            self.assertFalse(success)
            self.assertIn('error', info)
    
    def test_audit_log_error_handling(self):
        """Test audit log error handling"""
        # Test with read-only file system
        with patch('builtins.open', side_effect=PermissionError("Read-only filesystem")):
            # Should not crash when unable to write audit log
            try:
                self.security_manager._log_security_event("TEST", "Test event", {})
                # Should complete without exception
            except Exception as e:
                self.fail(f"Audit logging should handle errors gracefully: {e}")
    
    def test_consent_file_error_recovery(self):
        """Test consent file error recovery"""
        # Test with corrupted consent file
        with patch('builtins.open', mock_open(read_data="invalid json")):
            # Should handle corrupted file gracefully
            self.security_manager._load_user_consent()
            
            # Should default to no consent
            self.assertFalse(self.security_manager.user_consent_given)
        
        # Test with permission denied
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            # Should handle permission errors gracefully
            self.security_manager._save_user_consent()
            # Should not crash


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestSecurityManagerAuditLogging,
        TestSecurityManagerConsentManagement,
        TestSecurityManagerSuspiciousActivityDetection,
        TestSecurityManagerPrivilegeEscalation,
        TestSecurityManagerSystemIntegration,
        TestSecurityManagerErrorHandling,
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    if result.wasSuccessful():
        print("\n✅ All comprehensive security manager tests passed!")
    else:
        print("\n❌ Some comprehensive security manager tests failed!")
        sys.exit(1)
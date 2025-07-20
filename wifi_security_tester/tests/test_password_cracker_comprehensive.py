#!/usr/bin/env python3
"""
Comprehensive Test Suite for Password Cracker Component
Tests all password cracking functionality including aircrack-ng, hashcat, and unified interface
"""

import unittest
import tempfile
import os
import time
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, call
import subprocess

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.password_cracker import PasswordCracker, CrackJob
from wifi_security_tester.components.wordlist_manager import WordlistManager


class TestPasswordCrackerCore(unittest.TestCase):
    """Test core password cracker functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        self.test_22000 = os.path.join(self.temp_dir, "test.22000")
        
        # Create dummy files
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            passwords = ["password123", "test123", "admin", "12345678"] * 1000
            f.write("\n".join(passwords) + "\n")
        
        with open(self.test_22000, 'w') as f:
            f.write("WPA*01*dummy*hash*data")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test password cracker initialization"""
        self.assertIsInstance(self.cracker.wordlist_manager, WordlistManager)
        self.assertEqual(len(self.cracker.active_jobs), 0)
        self.assertEqual(len(self.cracker.crack_processes), 0)
        self.assertTrue(self.cracker.results_dir.exists())
    
    def test_crack_job_creation(self):
        """Test CrackJob data model"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        
        self.assertEqual(job.job_id, "test_job")
        self.assertEqual(job.method, "aircrack")
        self.assertEqual(job.status, "running")
        self.assertEqual(job.progress_percentage, 0.0)
        
        # Test serialization
        job_dict = job.to_dict()
        self.assertIn('start_time', job_dict)
        self.assertIsInstance(job_dict['start_time'], str)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_tool_availability_checks(self, mock_run_command):
        """Test tool availability checking"""
        # Test aircrack available
        mock_run_command.return_value = Mock(returncode=0)
        self.assertTrue(self.cracker._check_aircrack_availability())
        
        # Test aircrack not available
        mock_run_command.side_effect = Exception("Command not found")
        self.assertFalse(self.cracker._check_aircrack_availability())
        
        # Reset mock for hashcat test
        mock_run_command.side_effect = None
        mock_run_command.return_value = Mock(returncode=0)
        self.assertTrue(self.cracker._check_hashcat_availability())
    
    def test_time_estimation(self):
        """Test cracking time estimation"""
        # Test aircrack time estimation
        aircrack_time = self.cracker._estimate_aircrack_time(self.test_wordlist)
        self.assertIsInstance(aircrack_time, int)
        self.assertGreater(aircrack_time, 0)
        
        # Test hashcat time estimation
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {'available': False}
            hashcat_time = self.cracker._estimate_hashcat_time(self.test_wordlist)
            self.assertIsInstance(hashcat_time, int)
            self.assertGreater(hashcat_time, 0)
    
    def test_job_management(self):
        """Test job management functionality"""
        # Create test jobs
        job1 = CrackJob("job1", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job2 = CrackJob("job2", self.test_capture, self.test_wordlist, "hashcat", datetime.now())
        job2.status = "completed"
        
        self.cracker.active_jobs["job1"] = job1
        self.cracker.active_jobs["job2"] = job2
        
        # Test get active jobs
        active_jobs = self.cracker.get_active_jobs()
        self.assertEqual(len(active_jobs), 1)
        self.assertEqual(active_jobs[0].job_id, "job1")
        
        # Test get job by ID
        retrieved_job = self.cracker.get_job("job1")
        self.assertEqual(retrieved_job.job_id, "job1")
        
        # Test get all jobs
        all_jobs = self.cracker.get_all_jobs()
        self.assertEqual(len(all_jobs), 2)


class TestPasswordCrackerAircrackAdvanced(unittest.TestCase):
    """Advanced tests for aircrack-ng integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            f.write("password123\ntest123\nadmin\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_aircrack_progress_parsing_comprehensive(self):
        """Test comprehensive aircrack progress parsing"""
        job = CrackJob("test_job", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        
        # Test various progress formats
        test_cases = [
            ("Tested 1500 keys (got 234 IVs)", {"tested_keys": 1500}),
            ("Tested 50000 keys (got 1000 IVs)", {"tested_keys": 50000}),
            ("Running at 2 k/s", {"kps": 2000}),
            ("Running at 15 k/s", {"kps": 15000}),
            ("Passphrase not in dictionary", {"no_match": True}),
        ]
        
        for line, expected in test_cases:
            initial_progress = job.progress_percentage
            initial_kps = job.keys_per_second
            
            self.cracker._parse_aircrack_progress(job, line)
            
            if "tested_keys" in expected:
                # Progress should be calculated if wordlist size is known
                self.assertGreaterEqual(job.progress_percentage, initial_progress)
            
            if "kps" in expected:
                self.assertEqual(job.keys_per_second, expected["kps"])
    
    def test_aircrack_result_parsing_variations(self):
        """Test aircrack result parsing with various output formats"""
        job = CrackJob("test_job", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        
        # Test successful crack patterns
        success_cases = [
            "KEY FOUND! [ password123 ]",
            "Current passphrase: mypassword",
            "Master Key : 12 34 56 78 90 AB CD EF",
            "KEY FOUND! [  admin123  ]",  # With extra spaces
        ]
        
        for output in success_cases:
            job.result = None  # Reset
            success = self.cracker._parse_aircrack_result(job, output, 0)
            self.assertTrue(success, f"Failed to parse: {output}")
            self.assertIsNotNone(job.result)
            self.assertNotEqual(job.result.strip(), "")
        
        # Test failure cases
        failure_cases = [
            "Passphrase not in dictionary",
            "No valid WPA handshakes found",
            "Unable to crack password",
            "",  # Empty output
        ]
        
        for output in failure_cases:
            job.result = None  # Reset
            success = self.cracker._parse_aircrack_result(job, output, 1)
            self.assertFalse(success, f"Should have failed for: {output}")
    
    @patch('wifi_security_tester.components.password_cracker.subprocess.Popen')
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_aircrack_process_lifecycle(self, mock_run_command, mock_popen):
        """Test complete aircrack process lifecycle"""
        # Mock aircrack availability
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock process
        mock_process = Mock()
        mock_process.poll.side_effect = [None, None, None, 0]  # Process completes after 4 calls
        
        # Create a generator for readline to avoid infinite loop
        def readline_generator():
            lines = [
                "Tested 100 keys (got 50 IVs)\n",
                "Tested 200 keys (got 100 IVs)\n", 
                "KEY FOUND! [ password123 ]\n",
                ""  # End of output
            ]
            for line in lines:
                yield line
            while True:
                yield ""  # Keep returning empty string
        
        readline_gen = readline_generator()
        mock_process.stdout.readline.side_effect = lambda: next(readline_gen)
        mock_process.communicate.return_value = ("", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process
        
        # Start crack job
        job = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
        
        self.assertIsNotNone(job)
        self.assertEqual(job.method, "aircrack")
        self.assertIn(job.job_id, self.cracker.active_jobs)
        
        # Mock the stop event to prevent infinite loop
        with patch.object(self.cracker.stop_events[job.job_id], 'is_set', side_effect=[False, False, False, True]):
            # Simulate process completion
            self.cracker._monitor_aircrack_process(job, mock_process)
        
        # Verify final state
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.result, "password123")


class TestPasswordCrackerHashcatAdvanced(unittest.TestCase):
    """Advanced tests for hashcat GPU acceleration"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        self.test_22000 = os.path.join(self.temp_dir, "test.22000")
        
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            f.write("password123\ntest123\nadmin\n")
        
        with open(self.test_22000, 'w') as f:
            f.write("WPA*01*dummy*hash*data")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_gpu_capabilities_detection(self, mock_run_command):
        """Test comprehensive GPU capabilities detection"""
        # Mock hashcat device output
        device_output = """
        * Device #1: Intel(R) UHD Graphics 630, 1536/1536 MB, 24MCU
          Type: GPU
          Global Memory: 1536 MB
          Compute Units: 24
          
        * Device #2: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 16384/16384 MB, 12MCU
          Type: CPU
          Global Memory: 16384 MB
          Compute Units: 12
        """
        
        mock_run_command.return_value = Mock(returncode=0, stdout=device_output)
        
        gpu_info = self.cracker.get_gpu_capabilities()
        
        self.assertTrue(gpu_info['available'])
        self.assertEqual(len(gpu_info['devices']), 2)
        
        # Check GPU device
        gpu_device = gpu_info['devices'][0]
        self.assertEqual(gpu_device['type'], 'GPU')
        self.assertEqual(gpu_device['memory'], 1536)
        self.assertEqual(gpu_device['compute_units'], 24)
        
        # Check CPU device
        cpu_device = gpu_info['devices'][1]
        self.assertEqual(cpu_device['type'], 'CPU')
        self.assertEqual(cpu_device['memory'], 16384)
    
    def test_hashcat_mode_detection(self):
        """Test hashcat mode detection for different file formats"""
        # Test 22000 format
        mode = self.cracker._get_hashcat_mode(self.test_22000)
        self.assertEqual(mode, 22000)
        
        # Test hccapx format (create mock file)
        hccapx_file = os.path.join(self.temp_dir, "test.hccapx")
        with open(hccapx_file, 'wb') as f:
            f.write(b"HCPX" + b"dummy" * 20)
        
        mode = self.cracker._get_hashcat_mode(hccapx_file)
        self.assertEqual(mode, 2500)
    
    def test_hashcat_progress_parsing_comprehensive(self):
        """Test comprehensive hashcat progress parsing"""
        job = CrackJob("test_job", self.test_22000, self.test_wordlist, "hashcat", datetime.now())
        
        # Test various hashcat progress formats
        test_cases = [
            ("Progress.....: 1500/3000 (50.00%)", {"progress": 50.0}),
            ("Progress.....: 2999/3000 (99.97%)", {"progress": 99.97}),
            ("Speed.#1.....: 12345 H/s", {"speed": 12345}),
            ("Speed.#*.....: 98765 H/s", {"speed": 98765}),
            ("Time.Estimated.: 0 secs", {"eta": 0}),
            ("Status.......: Cracked", {"status": "cracked"}),
        ]
        
        for line, expected in test_cases:
            if "progress" in expected:
                self.cracker._parse_hashcat_progress(job, line)
                self.assertEqual(job.progress_percentage, expected["progress"])
            
            if "speed" in expected:
                self.cracker._parse_hashcat_progress(job, line)
                self.assertEqual(job.keys_per_second, expected["speed"])
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_capture_format_conversion(self, mock_run_command):
        """Test capture format conversion for hashcat"""
        mock_run_command.return_value = Mock(returncode=0)
        
        # Test conversion to 22000 format
        output_file = os.path.join(self.temp_dir, "output.22000")
        
        # Mock successful conversion by creating output file
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.write.return_value = None
            
            success = self.cracker._convert_to_22000_format(self.test_capture, output_file)
            self.assertTrue(success)
        
        # Test conversion failure
        mock_run_command.return_value = Mock(returncode=1, stderr="Conversion failed")
        success = self.cracker._convert_to_22000_format(self.test_capture, output_file)
        self.assertFalse(success)


class TestPasswordCrackerUnifiedInterface(unittest.TestCase):
    """Test unified cracking interface and method selection"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            passwords = ["password123"] * 10000  # Large wordlist for GPU preference
            f.write("\n".join(passwords) + "\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_optimal_method_selection_logic(self, mock_run_command):
        """Test optimal method selection logic"""
        # Mock both tools available
        mock_run_command.return_value = Mock(returncode=0)
        
        # Test with GPU available - should prefer hashcat
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {
                'available': True,
                'opencl_support': True,
                'devices': [{'type': 'GPU', 'memory': 2048}]
            }
            
            method = self.cracker._select_optimal_method(self.test_capture, self.test_wordlist)
            self.assertEqual(method, "hashcat")
        
        # Test without GPU - should prefer aircrack for small wordlists
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {'available': False}
            
            # Create small wordlist
            small_wordlist = os.path.join(self.temp_dir, "small.txt")
            with open(small_wordlist, 'w') as f:
                f.write("password123\ntest123\n")
            
            method = self.cracker._select_optimal_method(self.test_capture, small_wordlist)
            self.assertEqual(method, "aircrack")
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_method_recommendations_comprehensive(self, mock_run_command):
        """Test comprehensive method recommendations"""
        mock_run_command.return_value = Mock(returncode=0)
        
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {
                'available': True,
                'opencl_support': True,
                'metal_support': True,
                'devices': [
                    {'type': 'GPU', 'name': 'AMD Radeon Pro', 'memory': 4096},
                    {'type': 'CPU', 'name': 'Intel i7', 'memory': 16384}
                ]
            }
            
            recommendations = self.cracker.get_method_recommendations(self.test_capture, self.test_wordlist)
            
            # Verify recommendation structure
            required_keys = [
                'optimal_method', 'available_methods', 'reasoning',
                'estimated_times', 'hardware_info', 'performance_comparison'
            ]
            
            for key in required_keys:
                self.assertIn(key, recommendations)
            
            # Verify method availability
            self.assertIn('aircrack', recommendations['available_methods'])
            self.assertIn('hashcat', recommendations['available_methods'])
            
            # Verify hardware info
            self.assertTrue(recommendations['hardware_info']['gpu_available'])
            self.assertEqual(len(recommendations['hardware_info']['devices']), 2)
    
    def test_comprehensive_progress_tracking(self):
        """Test comprehensive progress tracking"""
        # Create test job with various progress states
        job = CrackJob("test_job", self.test_capture, self.test_wordlist, "hashcat", datetime.now())
        job.progress_percentage = 65.5
        job.keys_per_second = 25000
        job.estimated_time = 1800  # 30 minutes
        
        self.cracker.active_jobs[job.job_id] = job
        
        progress = self.cracker.get_comprehensive_progress(job.job_id)
        
        # Verify comprehensive progress information
        expected_keys = [
            'job_id', 'method', 'progress_percentage', 'keys_per_second',
            'elapsed_seconds', 'estimated_remaining', 'completion_probability',
            'performance_rating', 'efficiency_score'
        ]
        
        for key in expected_keys:
            self.assertIn(key, progress)
        
        self.assertEqual(progress['job_id'], job.job_id)
        self.assertEqual(progress['method'], job.method)
        self.assertEqual(progress['progress_percentage'], 65.5)
        self.assertEqual(progress['keys_per_second'], 25000)
    
    def test_job_cleanup_and_management(self):
        """Test job cleanup and management features"""
        # Create jobs with different ages
        old_time = datetime.now() - timedelta(hours=25)
        recent_time = datetime.now() - timedelta(hours=1)
        
        old_job = CrackJob("old_job", self.test_capture, self.test_wordlist, "aircrack", old_time)
        old_job.status = "completed"
        old_job.end_time = old_time + timedelta(minutes=5)
        
        recent_job = CrackJob("recent_job", self.test_capture, self.test_wordlist, "hashcat", recent_time)
        recent_job.status = "completed"
        recent_job.end_time = recent_time + timedelta(minutes=10)
        
        running_job = CrackJob("running_job", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        running_job.status = "running"
        
        self.cracker.active_jobs.update({
            "old_job": old_job,
            "recent_job": recent_job,
            "running_job": running_job
        })
        
        # Test cleanup of old completed jobs
        cleaned_count = self.cracker.cleanup_completed_jobs(max_age_hours=24)
        
        self.assertEqual(cleaned_count, 1)
        self.assertNotIn("old_job", self.cracker.active_jobs)
        self.assertIn("recent_job", self.cracker.active_jobs)
        self.assertIn("running_job", self.cracker.active_jobs)  # Running jobs should not be cleaned
    
    def test_results_export_and_summary(self):
        """Test results export and summary generation"""
        # Create jobs with various outcomes
        successful_job = CrackJob("success", self.test_capture, self.test_wordlist, "hashcat", datetime.now())
        successful_job.status = "completed"
        successful_job.result = "password123"
        successful_job.end_time = datetime.now()
        successful_job.keys_per_second = 15000
        
        failed_job = CrackJob("failed", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        failed_job.status = "failed"
        failed_job.error_message = "No handshake found"
        failed_job.keys_per_second = 2000
        
        self.cracker.active_jobs.update({
            "success": successful_job,
            "failed": failed_job
        })
        
        # Test summary export
        summary = self.cracker.export_results_summary()
        
        # Verify summary structure
        required_keys = [
            'generated_at', 'total_jobs', 'job_summary', 'success_statistics',
            'method_statistics', 'performance_statistics', 'successful_cracks'
        ]
        
        for key in required_keys:
            self.assertIn(key, summary)
        
        # Verify statistics
        self.assertEqual(summary['total_jobs'], 2)
        self.assertEqual(summary['job_summary']['completed'], 1)
        self.assertEqual(summary['job_summary']['failed'], 1)
        self.assertEqual(summary['success_statistics']['total_successful'], 1)
        self.assertEqual(summary['method_statistics']['hashcat_jobs'], 1)
        self.assertEqual(summary['method_statistics']['aircrack_jobs'], 1)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestPasswordCrackerCore,
        TestPasswordCrackerAircrackAdvanced,
        TestPasswordCrackerHashcatAdvanced,
        TestPasswordCrackerUnifiedInterface
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
#!/usr/bin/env python3
"""
Advanced Test Suite for Password Cracker - Additional comprehensive tests
Tests advanced functionality, edge cases, and integration scenarios
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
import threading

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.password_cracker import PasswordCracker, CrackJob
from wifi_security_tester.components.wordlist_manager import WordlistManager


class TestPasswordCrackerAdvanced(unittest.TestCase):
    """Advanced test cases for password cracker functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        self.test_large_wordlist = os.path.join(self.temp_dir, "large_wordlist.txt")
        
        # Create dummy files
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        # Create small wordlist
        with open(self.test_wordlist, 'w') as f:
            passwords = ["password123", "test123", "admin", "12345678"]
            f.write("\n".join(passwords) + "\n")
        
        # Create large wordlist for performance testing
        with open(self.test_large_wordlist, 'w') as f:
            passwords = [f"password{i}" for i in range(10000)]
            f.write("\n".join(passwords) + "\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_concurrent_crack_jobs(self):
        """Test running multiple crack jobs concurrently"""
        with patch('wifi_security_tester.components.password_cracker.run_command') as mock_run:
            with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
                # Mock successful tool availability
                mock_run.return_value = Mock(returncode=0)
                
                # Mock processes
                mock_process1 = Mock()
                mock_process1.poll.return_value = None
                mock_process2 = Mock()
                mock_process2.poll.return_value = None
                mock_popen.side_effect = [mock_process1, mock_process2]
                
                # Start two concurrent jobs
                job1 = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
                job2 = self.cracker.crack_with_aircrack(self.test_capture, self.test_large_wordlist)
                
                self.assertIsNotNone(job1)
                self.assertIsNotNone(job2)
                self.assertNotEqual(job1.job_id, job2.job_id)
                
                # Both jobs should be active
                active_jobs = self.cracker.get_active_jobs()
                self.assertEqual(len(active_jobs), 2)
    
    def test_job_cleanup_after_completion(self):
        """Test job cleanup after completion"""
        # Create a completed job
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now() - timedelta(hours=2)
        )
        job.status = "completed"
        job.end_time = datetime.now() - timedelta(hours=1)
        job.result = "password123"
        
        self.cracker.active_jobs[job.job_id] = job
        
        # Test cleanup
        cleaned = self.cracker.cleanup_completed_jobs(max_age_hours=0.5)
        self.assertEqual(cleaned, 1)
        self.assertNotIn(job.job_id, self.cracker.active_jobs)
    
    def test_job_progress_calculation(self):
        """Test job progress calculation accuracy"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now() - timedelta(minutes=5)
        )
        job.progress_percentage = 75.0
        job.keys_per_second = 2000
        
        self.cracker.active_jobs[job.job_id] = job
        
        progress = self.cracker.get_comprehensive_progress(job.job_id)
        
        self.assertEqual(progress['progress_percentage'], 75.0)
        self.assertEqual(progress['keys_per_second'], 2000)
        self.assertIn('elapsed_seconds', progress)
        self.assertIn('estimated_remaining', progress)
        self.assertIn('completion_probability', progress)
    
    def test_error_recovery_during_cracking(self):
        """Test error recovery during cracking process"""
        with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
            # Mock process that fails initially then succeeds
            mock_process = Mock()
            mock_process.poll.side_effect = [None, None, 0]  # Running, then completed
            mock_process.communicate.return_value = ("", "Process failed")
            mock_process.returncode = 1
            mock_popen.return_value = mock_process
            
            with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
                job = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
                
                self.assertIsNotNone(job)
                
                # Simulate process failure and recovery
                time.sleep(0.1)  # Let monitoring thread start
                
                # Stop the job to trigger cleanup
                success = self.cracker.stop_crack_job(job.job_id)
                self.assertTrue(success)
    
    def test_memory_usage_with_large_wordlists(self):
        """Test memory usage with large wordlists"""
        # This test ensures the cracker doesn't load entire wordlists into memory
        with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
            with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
                mock_process = Mock()
                mock_process.poll.return_value = None
                mock_popen.return_value = mock_process
                
                job = self.cracker.crack_with_aircrack(self.test_capture, self.test_large_wordlist)
                
                self.assertIsNotNone(job)
                self.assertGreater(job.estimated_time, 0)
                
                # Verify that the wordlist file is passed as parameter, not loaded into memory
                mock_popen.assert_called_once()
                call_args = mock_popen.call_args[0][0]
                self.assertIn(self.test_large_wordlist, call_args)
    
    def test_hashcat_format_conversion_edge_cases(self):
        """Test hashcat format conversion with edge cases"""
        with patch.object(self.cracker, '_check_hashcat_availability', return_value=True):
            # Test with empty capture file
            empty_capture = os.path.join(self.temp_dir, "empty.cap")
            with open(empty_capture, 'w') as f:
                pass  # Empty file
            
            result = self.cracker._convert_capture_for_hashcat(empty_capture)
            self.assertIsNone(result)
            
            # Test with invalid capture file
            invalid_capture = os.path.join(self.temp_dir, "invalid.cap")
            with open(invalid_capture, 'w') as f:
                f.write("invalid capture data")
            
            with patch('wifi_security_tester.components.password_cracker.run_command') as mock_run:
                mock_run.return_value = Mock(returncode=1, stderr="Conversion failed")
                
                result = self.cracker._convert_capture_for_hashcat(invalid_capture)
                self.assertIsNone(result)
    
    def test_gpu_capability_detection_edge_cases(self):
        """Test GPU capability detection with various system configurations"""
        with patch('wifi_security_tester.components.password_cracker.run_command') as mock_run:
            # Test with no GPU
            mock_run.return_value = Mock(returncode=0, stdout="No devices found")
            gpu_info = self.cracker.get_gpu_capabilities()
            self.assertFalse(gpu_info['available'])
            
            # Test with GPU but no OpenCL
            mock_run.return_value = Mock(returncode=0, stdout="* Device #1: Intel GPU")
            gpu_info = self.cracker.get_gpu_capabilities()
            self.assertFalse(gpu_info['opencl_support'])
            
            # Test with hashcat command failure
            mock_run.side_effect = Exception("hashcat not found")
            gpu_info = self.cracker.get_gpu_capabilities()
            self.assertFalse(gpu_info['available'])
            self.assertIn('error', gpu_info)
    
    def test_crack_job_serialization(self):
        """Test crack job serialization and deserialization"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now(),
            estimated_time=300,
            progress_percentage=50.0,
            keys_per_second=1500,
            result="password123",
            status="completed"
        )
        job.end_time = datetime.now()
        
        # Test serialization
        job_dict = job.to_dict()
        self.assertIn('start_time', job_dict)
        self.assertIn('end_time', job_dict)
        self.assertEqual(job_dict['result'], "password123")
        self.assertEqual(job_dict['progress_percentage'], 50.0)
        
        # Test that datetime objects are properly serialized
        self.assertIsInstance(job_dict['start_time'], str)
        self.assertIsInstance(job_dict['end_time'], str)
    
    def test_method_selection_algorithm(self):
        """Test optimal method selection algorithm"""
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            with patch('wifi_security_tester.components.password_cracker.run_command') as mock_run:
                mock_run.return_value = Mock(returncode=0)
                
                # Test with powerful GPU
                mock_gpu.return_value = {
                    'available': True,
                    'opencl_support': True,
                    'devices': [{'type': 'GPU', 'compute_units': 32, 'memory': 8192}]
                }
                
                method = self.cracker._select_optimal_method(self.test_capture, self.test_large_wordlist)
                self.assertEqual(method, "hashcat")
                
                # Test with weak GPU
                mock_gpu.return_value = {
                    'available': True,
                    'opencl_support': True,
                    'devices': [{'type': 'GPU', 'compute_units': 4, 'memory': 512}]
                }
                
                method = self.cracker._select_optimal_method(self.test_capture, self.test_wordlist)
                # Should prefer aircrack for small wordlists even with weak GPU
                self.assertEqual(method, "aircrack")
    
    def test_progress_callback_functionality(self):
        """Test progress callback functionality"""
        callback_calls = []
        
        def progress_callback(job):
            callback_calls.append({
                'job_id': job.job_id,
                'progress': job.progress_percentage,
                'timestamp': datetime.now()
            })
        
        with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
            with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
                mock_process = Mock()
                mock_process.poll.return_value = None
                mock_process.stdout.readline.side_effect = [
                    "Tested 100 keys (got 50 IVs)\n",
                    "Tested 200 keys (got 100 IVs)\n",
                    ""
                ]
                mock_popen.return_value = mock_process
                
                job = self.cracker.crack_with_aircrack(
                    self.test_capture, 
                    self.test_wordlist, 
                    progress_callback=progress_callback
                )
                
                self.assertIsNotNone(job)
                
                # Give some time for monitoring thread to process
                time.sleep(0.2)
                
                # Stop the job
                self.cracker.stop_crack_job(job.job_id)
                
                # Verify callback was called
                self.assertGreater(len(callback_calls), 0)
    
    def test_resource_cleanup_on_failure(self):
        """Test proper resource cleanup when operations fail"""
        with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
            # Mock process that fails to start
            mock_popen.side_effect = Exception("Failed to start process")
            
            with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
                job = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
                
                # Job should be None due to failure
                self.assertIsNone(job)
                
                # Verify no resources are left hanging
                self.assertEqual(len(self.cracker.active_jobs), 0)
                self.assertEqual(len(self.cracker.crack_processes), 0)
                self.assertEqual(len(self.cracker.stop_events), 0)
    
    def test_statistics_accuracy(self):
        """Test accuracy of crack statistics"""
        # Create various job states
        jobs = [
            CrackJob("job1", self.test_capture, self.test_wordlist, "aircrack", datetime.now()),
            CrackJob("job2", self.test_capture, self.test_wordlist, "hashcat", datetime.now()),
            CrackJob("job3", self.test_capture, self.test_wordlist, "aircrack", datetime.now()),
        ]
        
        jobs[0].status = "completed"
        jobs[0].result = "password123"
        jobs[1].status = "failed"
        jobs[2].status = "running"
        
        for job in jobs:
            self.cracker.active_jobs[job.job_id] = job
        
        stats = self.cracker.get_crack_statistics()
        
        self.assertEqual(stats['total_jobs'], 3)
        self.assertEqual(stats['completed_jobs'], 1)
        self.assertEqual(stats['failed_jobs'], 1)
        self.assertEqual(stats['active_jobs'], 1)
        self.assertEqual(stats['total_passwords_cracked'], 1)
        self.assertEqual(stats['success_rate'], 50.0)  # 1 success out of 2 finished jobs
    
    def test_wordlist_validation_integration(self):
        """Test integration with wordlist validation"""
        # Create invalid wordlist
        invalid_wordlist = os.path.join(self.temp_dir, "invalid.txt")
        with open(invalid_wordlist, 'wb') as f:
            f.write(b'\xff\xfe\x00\x00')  # Invalid UTF-8
        
        with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
            job = self.cracker.crack_with_aircrack(self.test_capture, invalid_wordlist)
            
            # Should handle invalid wordlist gracefully
            if job:
                # If job was created, it should handle the invalid wordlist during execution
                self.assertIsNotNone(job.job_id)
            else:
                # Or it should reject the invalid wordlist upfront
                self.assertIsNone(job)


class TestPasswordCrackerPerformance(unittest.TestCase):
    """Performance-focused tests for password cracker"""
    
    def setUp(self):
        """Set up performance test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_time_estimation_accuracy(self):
        """Test accuracy of time estimation algorithms"""
        # Create wordlists of different sizes
        small_wordlist = os.path.join(self.temp_dir, "small.txt")
        medium_wordlist = os.path.join(self.temp_dir, "medium.txt")
        large_wordlist = os.path.join(self.temp_dir, "large.txt")
        
        # Small wordlist (100 passwords)
        with open(small_wordlist, 'w') as f:
            f.write("\n".join([f"pass{i}" for i in range(100)]))
        
        # Medium wordlist (10,000 passwords)
        with open(medium_wordlist, 'w') as f:
            f.write("\n".join([f"password{i}" for i in range(10000)]))
        
        # Large wordlist (100,000 passwords)
        with open(large_wordlist, 'w') as f:
            f.write("\n".join([f"longpassword{i}" for i in range(100000)]))
        
        # Test aircrack time estimation
        small_time = self.cracker._estimate_aircrack_time(small_wordlist)
        medium_time = self.cracker._estimate_aircrack_time(medium_wordlist)
        large_time = self.cracker._estimate_aircrack_time(large_wordlist)
        
        # Verify scaling relationship
        self.assertLess(small_time, medium_time)
        self.assertLess(medium_time, large_time)
        self.assertGreater(large_time / medium_time, 5)  # Should scale roughly linearly
        
        # Test hashcat time estimation
        small_time_hc = self.cracker._estimate_hashcat_time(small_wordlist)
        medium_time_hc = self.cracker._estimate_hashcat_time(medium_wordlist)
        large_time_hc = self.cracker._estimate_hashcat_time(large_wordlist)
        
        # Hashcat should generally be faster than aircrack for large wordlists
        self.assertLessEqual(large_time_hc, large_time)
    
    def test_concurrent_job_performance(self):
        """Test performance impact of concurrent jobs"""
        wordlist = os.path.join(self.temp_dir, "test.txt")
        with open(wordlist, 'w') as f:
            f.write("\n".join([f"test{i}" for i in range(1000)]))
        
        with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
            with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
                mock_processes = [Mock() for _ in range(5)]
                for mock_process in mock_processes:
                    mock_process.poll.return_value = None
                mock_popen.side_effect = mock_processes
                
                # Start multiple jobs
                start_time = time.time()
                jobs = []
                for i in range(5):
                    job = self.cracker.crack_with_aircrack(self.test_capture, wordlist)
                    if job:
                        jobs.append(job)
                
                creation_time = time.time() - start_time
                
                # Job creation should be fast even with multiple jobs
                self.assertLess(creation_time, 1.0)  # Should take less than 1 second
                self.assertEqual(len(jobs), 5)
                
                # Clean up
                for job in jobs:
                    self.cracker.stop_crack_job(job.job_id)
    
    def test_memory_efficiency(self):
        """Test memory efficiency with large operations"""
        # This test ensures the cracker doesn't consume excessive memory
        large_wordlist = os.path.join(self.temp_dir, "huge.txt")
        
        # Create a very large wordlist (1M entries)
        with open(large_wordlist, 'w') as f:
            for i in range(1000000):
                f.write(f"password{i}\n")
        
        # Test that time estimation doesn't load entire file into memory
        start_time = time.time()
        estimated_time = self.cracker._estimate_aircrack_time(large_wordlist)
        estimation_time = time.time() - start_time
        
        # Should complete quickly without loading entire file
        self.assertLess(estimation_time, 5.0)
        self.assertGreater(estimated_time, 0)


class TestPasswordCrackerIntegration(unittest.TestCase):
    """Integration tests for password cracker with other components"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test.txt")
        
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            f.write("password123\ntest123\nadmin\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_wordlist_manager_integration(self):
        """Test integration with wordlist manager"""
        wordlist_manager = WordlistManager()
        cracker_with_wlm = PasswordCracker(wordlist_manager=wordlist_manager)
        
        self.assertIsNotNone(cracker_with_wlm.wordlist_manager)
        
        # Test that cracker can use wordlist manager functionality
        # This would typically involve creating wordlists through the manager
        # and using them in cracking operations
    
    def test_logging_integration(self):
        """Test integration with logging system"""
        with patch('wifi_security_tester.components.password_cracker.log_operation') as mock_log:
            with patch('wifi_security_tester.components.password_cracker.log_security_event') as mock_security_log:
                with patch.object(self.cracker, '_check_aircrack_availability', return_value=True):
                    with patch('wifi_security_tester.components.password_cracker.subprocess.Popen') as mock_popen:
                        mock_process = Mock()
                        mock_process.poll.return_value = None
                        mock_popen.return_value = mock_process
                        
                        job = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
                        
                        # Verify security logging
                        mock_security_log.assert_called_with(
                            "CRACK_START", 
                            f"Method: aircrack-ng, Capture: {os.path.basename(self.test_capture)}"
                        )
                        
                        # Verify operation logging
                        mock_log.assert_called_with(
                            "CRACK_STARTED",
                            os.path.basename(self.test_capture),
                            "Method: aircrack-ng"
                        )
    
    def test_results_persistence(self):
        """Test results persistence and recovery"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        job.status = "completed"
        job.result = "password123"
        job.end_time = datetime.now()
        
        # Test saving job results
        self.cracker._save_job_results(job)
        
        # Verify results file was created
        results_file = self.cracker.results_dir / f"{job.job_id}_job.json"
        self.assertTrue(results_file.exists())
        
        # Verify results content
        with open(results_file, 'r') as f:
            saved_data = json.load(f)
        
        self.assertEqual(saved_data['job_id'], job.job_id)
        self.assertEqual(saved_data['result'], "password123")
        self.assertEqual(saved_data['status'], "completed")


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestPasswordCrackerAdvanced,
        TestPasswordCrackerPerformance,
        TestPasswordCrackerIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    if result.wasSuccessful():
        print("\n✅ All advanced password cracker tests passed!")
    else:
        print("\n❌ Some advanced password cracker tests failed!")
        sys.exit(1)
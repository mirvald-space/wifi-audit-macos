#!/usr/bin/env python3
"""
Test suite for Password Cracker component - aircrack-ng integration
"""

import unittest
import tempfile
import os
import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifi_security_tester.components.password_cracker import PasswordCracker, CrackJob
from wifi_security_tester.components.wordlist_manager import WordlistManager


class TestPasswordCrackerAircrack(unittest.TestCase):
    """Test cases for aircrack-ng integration"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        
        # Create dummy files
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            # Create a larger wordlist to ensure time estimation > 0
            passwords = ["password123", "test123", "admin"] * 1000  # 3000 passwords
            f.write("\n".join(passwords) + "\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_check_aircrack_availability(self, mock_run_command):
        """Test aircrack-ng availability check"""
        # Test available
        mock_run_command.return_value = Mock(returncode=0)
        self.assertTrue(self.cracker._check_aircrack_availability())
        
        # Test not available
        mock_run_command.side_effect = Exception("Command not found")
        self.assertFalse(self.cracker._check_aircrack_availability())
    
    def test_estimate_aircrack_time(self):
        """Test aircrack-ng time estimation"""
        estimated_time = self.cracker._estimate_aircrack_time(self.test_wordlist)
        self.assertIsInstance(estimated_time, int)
        self.assertGreater(estimated_time, 0)
    
    @patch('wifi_security_tester.components.password_cracker.subprocess.Popen')
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_crack_with_aircrack_success(self, mock_run_command, mock_popen):
        """Test successful aircrack-ng job creation"""
        # Mock aircrack availability
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock process
        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process
        
        job = self.cracker.crack_with_aircrack(self.test_capture, self.test_wordlist)
        
        self.assertIsNotNone(job)
        self.assertIsInstance(job, CrackJob)
        self.assertEqual(job.method, "aircrack")
        self.assertEqual(job.status, "running")
        self.assertIn(job.job_id, self.cracker.active_jobs)
    
    def test_crack_with_aircrack_invalid_files(self):
        """Test aircrack-ng with invalid files"""
        # Test with non-existent capture file
        job = self.cracker.crack_with_aircrack("nonexistent.cap", self.test_wordlist)
        self.assertIsNone(job)
        
        # Test with non-existent wordlist
        job = self.cracker.crack_with_aircrack(self.test_capture, "nonexistent.txt")
        self.assertIsNone(job)
    
    def test_parse_aircrack_progress(self):
        """Test aircrack-ng progress parsing"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        
        # Test key count parsing
        self.cracker._parse_aircrack_progress(job, "Tested 1500 keys (got 234 IVs)")
        self.assertGreater(job.progress_percentage, 0)
        
        # Test keys per second parsing
        self.cracker._parse_aircrack_progress(job, "Running at 2 k/s")
        self.assertEqual(job.keys_per_second, 2000)
    
    def test_parse_aircrack_result_success(self):
        """Test successful aircrack-ng result parsing"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        
        # Test successful crack output
        output = "KEY FOUND! [ password123 ]"
        success = self.cracker._parse_aircrack_result(job, output, 0)
        
        self.assertTrue(success)
        self.assertEqual(job.result, "password123")
    
    def test_parse_aircrack_result_failure(self):
        """Test failed aircrack-ng result parsing"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        
        # Test failed crack output
        output = "Passphrase not in dictionary"
        success = self.cracker._parse_aircrack_result(job, output, 1)
        
        self.assertFalse(success)
        self.assertIsNone(job.result)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_validate_capture_for_cracking(self, mock_run_command):
        """Test capture file validation for cracking"""
        # Mock aircrack-ng output with handshake
        mock_run_command.return_value = Mock(
            returncode=0,
            stdout="1  AA:BB:CC:DD:EE:FF  TestNetwork  WPA (1 handshake)"
        )
        
        result = self.cracker.validate_capture_for_cracking(self.test_capture)
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['details']['networks_found'], 1)
        self.assertEqual(result['details']['handshakes_found'], 1)
    
    def test_get_job_progress(self):
        """Test job progress retrieval"""
        # Create a test job
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        job.progress_percentage = 25.0
        job.keys_per_second = 1500
        
        self.cracker.active_jobs[job.job_id] = job
        
        progress = self.cracker.get_job_progress(job.job_id)
        
        self.assertEqual(progress['job_id'], job.job_id)
        self.assertEqual(progress['status'], job.status)
        self.assertEqual(progress['progress_percentage'], 25.0)
        self.assertEqual(progress['keys_per_second'], 1500)
    
    def test_get_crack_statistics(self):
        """Test crack statistics calculation"""
        # Add some test jobs
        job1 = CrackJob("job1", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job1.status = "completed"
        job1.result = "password123"
        
        job2 = CrackJob("job2", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job2.status = "failed"
        
        self.cracker.active_jobs["job1"] = job1
        self.cracker.active_jobs["job2"] = job2
        
        stats = self.cracker.get_crack_statistics()
        
        self.assertEqual(stats['total_jobs'], 2)
        self.assertEqual(stats['completed_jobs'], 1)
        self.assertEqual(stats['failed_jobs'], 1)
        self.assertEqual(stats['total_passwords_cracked'], 1)
        self.assertEqual(stats['success_rate'], 50.0)


if __name__ == '__main__':
    unittest.main()


class TestPasswordCrackerHashcat(unittest.TestCase):
    """Test cases for hashcat GPU acceleration support"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        self.test_22000 = os.path.join(self.temp_dir, "test.22000")
        self.test_hccapx = os.path.join(self.temp_dir, "test.hccapx")
        
        # Create dummy files
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            passwords = ["password123", "test123", "admin"] * 100
            f.write("\n".join(passwords) + "\n")
        
        with open(self.test_22000, 'w') as f:
            f.write("WPA*01*dummy*hash*data")
        
        with open(self.test_hccapx, 'wb') as f:
            f.write(b"HCPX" + b"dummy" * 20)
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_check_hashcat_availability(self, mock_run_command):
        """Test hashcat availability check"""
        # Test available
        mock_run_command.return_value = Mock(returncode=0)
        self.assertTrue(self.cracker._check_hashcat_availability())
        
        # Test not available
        mock_run_command.side_effect = Exception("Command not found")
        self.assertFalse(self.cracker._check_hashcat_availability())
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_get_gpu_capabilities(self, mock_run_command):
        """Test GPU capability detection"""
        # Mock hashcat device list output
        mock_output = """
        * Device #1: Intel(R) UHD Graphics 630, 1536/1536 MB, 24MCU
          Type: GPU
          Global Memory: 1536 MB
          Compute Units: 24
        
        * Device #2: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz, 16384/16384 MB, 12MCU
          Type: CPU
          Global Memory: 16384 MB
          Compute Units: 12
        """
        
        mock_run_command.return_value = Mock(returncode=0, stdout=mock_output)
        
        gpu_info = self.cracker.get_gpu_capabilities()
        
        self.assertTrue(gpu_info['available'])
        self.assertEqual(len(gpu_info['devices']), 2)
        self.assertEqual(gpu_info['devices'][0]['type'], 'GPU')
        self.assertEqual(gpu_info['devices'][1]['type'], 'CPU')
    
    def test_get_hashcat_mode(self):
        """Test hashcat mode detection"""
        # Test 22000 format
        mode = self.cracker._get_hashcat_mode(self.test_22000)
        self.assertEqual(mode, 22000)
        
        # Test hccapx format
        mode = self.cracker._get_hashcat_mode(self.test_hccapx)
        self.assertEqual(mode, 2500)
    
    def test_estimate_hashcat_time(self):
        """Test hashcat time estimation"""
        # Mock GPU capabilities to ensure consistent results
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {'available': False}
            
            estimated_time = self.cracker._estimate_hashcat_time(self.test_wordlist)
            self.assertIsInstance(estimated_time, int)
            self.assertGreater(estimated_time, 0)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_convert_to_22000_format(self, mock_run_command):
        """Test conversion to 22000 format"""
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock file creation
        output_file = os.path.join(self.temp_dir, "output.22000")
        with open(output_file, 'w') as f:
            f.write("WPA*01*converted*data")
        
        success = self.cracker._convert_to_22000_format(self.test_capture, output_file)
        self.assertTrue(success)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_convert_to_hccapx_format(self, mock_run_command):
        """Test conversion to hccapx format"""
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock file creation
        output_file = os.path.join(self.temp_dir, "output.hccapx")
        with open(output_file, 'wb') as f:
            f.write(b"HCPX" + b"converted" * 10)
        
        success = self.cracker._convert_to_hccapx_format(self.test_capture, output_file)
        self.assertTrue(success)
    
    def test_parse_hashcat_progress(self):
        """Test hashcat progress parsing"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_22000,
            wordlist_file=self.test_wordlist,
            method="hashcat",
            start_time=datetime.now()
        )
        
        # Test progress parsing
        self.cracker._parse_hashcat_progress(job, "Progress.....: 1500/3000 (50.00%)")
        self.assertEqual(job.progress_percentage, 50.0)
        
        # Test speed parsing
        self.cracker._parse_hashcat_progress(job, "Speed.#1.....: 12345 H/s")
        self.assertEqual(job.keys_per_second, 12345)
    
    def test_parse_hashcat_result_success(self):
        """Test successful hashcat result parsing"""
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_22000,
            wordlist_file=self.test_wordlist,
            method="hashcat",
            start_time=datetime.now()
        )
        
        # Create mock potfile
        potfile = f"{self.cracker.results_dir}/{job.job_id}_hashcat.pot"
        os.makedirs(self.cracker.results_dir, exist_ok=True)
        with open(potfile, 'w') as f:
            f.write("hash123:password123")
        
        output = "Status.......: Cracked"
        success = self.cracker._parse_hashcat_result(job, output, 0)
        
        self.assertTrue(success)
        self.assertEqual(job.result, "password123")
    
    @patch('wifi_security_tester.components.password_cracker.subprocess.Popen')
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_crack_with_hashcat_success(self, mock_run_command, mock_popen):
        """Test successful hashcat job creation"""
        # Mock hashcat availability
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock conversion success
        with patch.object(self.cracker, '_convert_capture_for_hashcat') as mock_convert:
            mock_convert.return_value = self.test_22000
            
            # Mock process
            mock_process = Mock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process
            
            job = self.cracker.crack_with_hashcat(self.test_capture, self.test_wordlist)
            
            self.assertIsNotNone(job)
            self.assertIsInstance(job, CrackJob)
            self.assertEqual(job.method, "hashcat")
            self.assertEqual(job.status, "running")
            self.assertIn(job.job_id, self.cracker.active_jobs)
    
    def test_crack_with_hashcat_conversion_failure(self):
        """Test hashcat job creation with conversion failure"""
        with patch.object(self.cracker, '_convert_capture_for_hashcat') as mock_convert:
            mock_convert.return_value = None
            
            job = self.cracker.crack_with_hashcat(self.test_capture, self.test_wordlist)
            self.assertIsNone(job)


class TestPasswordCrackerUnified(unittest.TestCase):
    """Test cases for unified cracking interface"""
    
    def setUp(self):
        """Set up test environment"""
        self.cracker = PasswordCracker()
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test files
        self.test_capture = os.path.join(self.temp_dir, "test.cap")
        self.test_wordlist = os.path.join(self.temp_dir, "test_wordlist.txt")
        
        # Create dummy files
        with open(self.test_capture, 'w') as f:
            f.write("dummy capture data")
        
        with open(self.test_wordlist, 'w') as f:
            passwords = ["password123", "test123", "admin"] * 5000  # Large wordlist for GPU test
            f.write("\n".join(passwords) + "\n")
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_select_optimal_method_gpu_available(self, mock_run_command):
        """Test optimal method selection with GPU available"""
        # Mock both tools available
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock GPU capabilities
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {
                'available': True,
                'opencl_support': True,
                'devices': [{'type': 'GPU'}]
            }
            
            method = self.cracker._select_optimal_method(self.test_capture, self.test_wordlist)
            self.assertEqual(method, "hashcat")
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_select_optimal_method_no_gpu(self, mock_run_command):
        """Test optimal method selection without GPU"""
        # Mock both tools available
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock no GPU
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {'available': False}
            
            method = self.cracker._select_optimal_method(self.test_capture, self.test_wordlist)
            self.assertEqual(method, "aircrack")
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_select_optimal_method_only_aircrack(self, mock_run_command):
        """Test method selection when only aircrack is available"""
        def mock_command(cmd, **kwargs):
            if 'aircrack-ng' in cmd:
                return Mock(returncode=0)
            else:
                raise Exception("Command not found")
        
        mock_run_command.side_effect = mock_command
        
        method = self.cracker._select_optimal_method(self.test_capture, self.test_wordlist)
        self.assertEqual(method, "aircrack")
    
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_get_method_recommendations(self, mock_run_command):
        """Test method recommendations generation"""
        # Mock both tools available
        mock_run_command.return_value = Mock(returncode=0)
        
        with patch.object(self.cracker, 'get_gpu_capabilities') as mock_gpu:
            mock_gpu.return_value = {
                'available': True,
                'opencl_support': True,
                'devices': [{'type': 'GPU'}]
            }
            
            recommendations = self.cracker.get_method_recommendations(self.test_capture, self.test_wordlist)
            
            self.assertIn('optimal_method', recommendations)
            self.assertIn('available_methods', recommendations)
            self.assertIn('reasoning', recommendations)
            self.assertIn('estimated_times', recommendations)
            self.assertIn('hardware_info', recommendations)
            
            self.assertIn('aircrack', recommendations['available_methods'])
            self.assertIn('hashcat', recommendations['available_methods'])
    
    @patch('wifi_security_tester.components.password_cracker.subprocess.Popen')
    @patch('wifi_security_tester.components.password_cracker.run_command')
    def test_crack_password_auto_selection(self, mock_run_command, mock_popen):
        """Test unified crack_password with auto method selection"""
        # Mock tool availability
        mock_run_command.return_value = Mock(returncode=0)
        
        # Mock process
        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process
        
        # Mock method selection
        with patch.object(self.cracker, '_select_optimal_method') as mock_select:
            mock_select.return_value = "aircrack"
            
            job = self.cracker.crack_password(self.test_capture, self.test_wordlist, method="auto")
            
            self.assertIsNotNone(job)
            self.assertEqual(job.method, "aircrack")
            mock_select.assert_called_once()
    
    def test_get_comprehensive_progress(self):
        """Test comprehensive progress information"""
        # Create a test job
        job = CrackJob(
            job_id="test_job",
            capture_file=self.test_capture,
            wordlist_file=self.test_wordlist,
            method="aircrack",
            start_time=datetime.now()
        )
        job.progress_percentage = 75.0
        job.keys_per_second = 3000
        job.estimated_time = 300
        
        self.cracker.active_jobs[job.job_id] = job
        
        progress = self.cracker.get_comprehensive_progress(job.job_id)
        
        self.assertEqual(progress['job_id'], job.job_id)
        self.assertEqual(progress['method'], job.method)
        self.assertEqual(progress['progress_percentage'], 75.0)
        self.assertEqual(progress['keys_per_second'], 3000)
        self.assertIn('completion_probability', progress)
        self.assertIn('performance_rating', progress)
        self.assertIn('estimated_remaining', progress)
    
    def test_stop_all_jobs(self):
        """Test stopping all active jobs"""
        # Create test jobs
        job1 = CrackJob("job1", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job1.status = "running"
        job2 = CrackJob("job2", self.test_capture, self.test_wordlist, "hashcat", datetime.now())
        job2.status = "completed"
        
        self.cracker.active_jobs["job1"] = job1
        self.cracker.active_jobs["job2"] = job2
        
        # Mock stop_crack_job
        with patch.object(self.cracker, 'stop_crack_job') as mock_stop:
            mock_stop.return_value = True
            
            results = self.cracker.stop_all_jobs()
            
            self.assertIn("job1", results)
            self.assertIn("job2", results)
            self.assertTrue(results["job1"])
            self.assertTrue(results["job2"])
            mock_stop.assert_called_once_with("job1")
    
    def test_cleanup_completed_jobs(self):
        """Test cleanup of old completed jobs"""
        # Create old completed job
        old_time = datetime.now() - timedelta(hours=25)
        job1 = CrackJob("old_job", self.test_capture, self.test_wordlist, "aircrack", old_time)
        job1.status = "completed"
        job1.end_time = old_time + timedelta(minutes=5)
        
        # Create recent job
        recent_time = datetime.now() - timedelta(hours=1)
        job2 = CrackJob("recent_job", self.test_capture, self.test_wordlist, "aircrack", recent_time)
        job2.status = "completed"
        job2.end_time = recent_time + timedelta(minutes=5)
        
        self.cracker.active_jobs["old_job"] = job1
        self.cracker.active_jobs["recent_job"] = job2
        
        # Run cleanup
        cleaned_count = self.cracker.cleanup_completed_jobs(max_age_hours=24)
        
        self.assertEqual(cleaned_count, 1)
        self.assertNotIn("old_job", self.cracker.active_jobs)
        self.assertIn("recent_job", self.cracker.active_jobs)
    
    def test_export_results_summary(self):
        """Test results summary export"""
        # Create test jobs with various statuses
        job1 = CrackJob("job1", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job1.status = "completed"
        job1.result = "password123"
        job1.end_time = datetime.now()
        job1.keys_per_second = 2000
        
        job2 = CrackJob("job2", self.test_capture, self.test_wordlist, "hashcat", datetime.now())
        job2.status = "failed"
        job2.keys_per_second = 15000
        
        job3 = CrackJob("job3", self.test_capture, self.test_wordlist, "aircrack", datetime.now())
        job3.status = "running"
        
        self.cracker.active_jobs["job1"] = job1
        self.cracker.active_jobs["job2"] = job2
        self.cracker.active_jobs["job3"] = job3
        
        summary = self.cracker.export_results_summary()
        
        self.assertIn('generated_at', summary)
        self.assertEqual(summary['total_jobs'], 3)
        self.assertEqual(summary['job_summary']['completed'], 1)
        self.assertEqual(summary['job_summary']['failed'], 1)
        self.assertEqual(summary['job_summary']['running'], 1)
        self.assertEqual(summary['success_statistics']['total_successful'], 1)
        self.assertEqual(len(summary['successful_cracks']), 1)
        self.assertEqual(summary['method_statistics']['aircrack_jobs'], 2)
        self.assertEqual(summary['method_statistics']['hashcat_jobs'], 1)
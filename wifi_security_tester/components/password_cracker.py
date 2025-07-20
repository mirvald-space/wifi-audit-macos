"""
Password Cracker - WiFi password cracking with aircrack-ng and hashcat support
Implements unified interface for password cracking operations on macOS

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import os
import signal
import time
import re
import json
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread, Event
import tempfile

from ..core.logger import get_logger, log_operation, log_security_event
from ..utils.common import run_command, ensure_directory, validate_file_path
from .wordlist_manager import WordlistManager


@dataclass
class CrackJob:
    """Data model for password cracking job information"""
    job_id: str
    capture_file: str
    wordlist_file: str
    method: str  # aircrack, hashcat
    start_time: datetime
    estimated_time: Optional[int] = None  # seconds
    progress_percentage: float = 0.0
    keys_per_second: int = 0
    result: Optional[str] = None  # cracked password
    status: str = "running"  # running, completed, failed, stopped
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert datetime objects to strings
        data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


class PasswordCracker:
    """Unified password cracking interface with aircrack-ng and hashcat support"""
    
    def __init__(self, wordlist_manager: WordlistManager = None):
        self.logger = get_logger("password_cracker")
        self.wordlist_manager = wordlist_manager or WordlistManager()
        
        # Job management
        self.active_jobs: Dict[str, CrackJob] = {}
        self.crack_processes: Dict[str, subprocess.Popen] = {}
        self.stop_events: Dict[str, Event] = {}
        
        # Results directory
        self.results_dir = Path("results")
        ensure_directory(self.results_dir)
        
        # Progress callbacks
        self.progress_callbacks: Dict[str, Callable] = {}
        
    def crack_with_aircrack(self, capture_file: str, wordlist_file: str, 
                           progress_callback: Callable = None) -> Optional[CrackJob]:
        """
        Start password cracking using aircrack-ng
        
        Args:
            capture_file: Path to capture file (.cap format)
            wordlist_file: Path to wordlist file
            progress_callback: Optional callback for progress updates
            
        Returns:
            CrackJob object if started successfully, None otherwise
        """
        try:
            # Log security event
            log_security_event("CRACK_START", 
                             f"Method: aircrack-ng, Capture: {os.path.basename(capture_file)}")
            
            # Validate inputs
            if not validate_file_path(capture_file):
                self.logger.error(f"Capture file not found: {capture_file}")
                return None
                
            if not validate_file_path(wordlist_file):
                self.logger.error(f"Wordlist file not found: {wordlist_file}")
                return None
            
            # Check aircrack-ng availability
            if not self._check_aircrack_availability():
                self.logger.error("aircrack-ng is not available")
                return None
            
            # Create crack job
            job_id = f"aircrack_{int(time.time())}"
            job = CrackJob(
                job_id=job_id,
                capture_file=capture_file,
                wordlist_file=wordlist_file,
                method="aircrack",
                start_time=datetime.now()
            )
            
            # Estimate cracking time
            job.estimated_time = self._estimate_aircrack_time(wordlist_file)
            
            # Start cracking process
            success = self._start_aircrack_process(job)
            
            if success:
                self.active_jobs[job_id] = job
                if progress_callback:
                    self.progress_callbacks[job_id] = progress_callback
                
                log_operation("CRACK_STARTED", 
                            os.path.basename(capture_file), 
                            f"Method: aircrack-ng")
                return job
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to start aircrack-ng: {e}")
            return None
    
    def _check_aircrack_availability(self) -> bool:
        """Check if aircrack-ng is available and functional"""
        try:
            result = run_command(['aircrack-ng', '--help'], timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _estimate_aircrack_time(self, wordlist_file: str) -> int:
        """
        Estimate cracking time for aircrack-ng based on wordlist size
        
        Args:
            wordlist_file: Path to wordlist file
            
        Returns:
            Estimated time in seconds
        """
        try:
            # Count lines in wordlist
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            # Rough estimate: aircrack-ng processes ~1000-5000 keys/second on average
            # This varies greatly based on hardware and capture complexity
            estimated_kps = 2000  # Conservative estimate
            estimated_seconds = line_count / estimated_kps
            
            # Add some buffer time
            return int(estimated_seconds * 1.2)
            
        except Exception as e:
            self.logger.debug(f"Could not estimate aircrack time: {e}")
            return 0
    
    def _start_aircrack_process(self, job: CrackJob) -> bool:
        """
        Start aircrack-ng process for password cracking
        
        Args:
            job: CrackJob object
            
        Returns:
            True if process started successfully, False otherwise
        """
        try:
            # Build aircrack-ng command
            cmd = [
                'aircrack-ng',
                '-w', job.wordlist_file,  # wordlist
                '-l', f"{self.results_dir}/{job.job_id}_result.txt",  # output file for key
                job.capture_file
            ]
            
            self.logger.info(f"Starting aircrack-ng: {' '.join(cmd)}")
            
            # Start process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Store process and create stop event
            self.crack_processes[job.job_id] = process
            self.stop_events[job.job_id] = Event()
            
            # Start monitoring thread
            monitor_thread = Thread(
                target=self._monitor_aircrack_process,
                args=(job, process),
                daemon=True
            )
            monitor_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start aircrack-ng process: {e}")
            return False
    
    def _monitor_aircrack_process(self, job: CrackJob, process: subprocess.Popen):
        """
        Monitor aircrack-ng process and parse progress
        
        Args:
            job: CrackJob object
            process: aircrack-ng process
        """
        try:
            stop_event = self.stop_events[job.job_id]
            output_buffer = []
            
            while not stop_event.is_set():
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Read output line by line
                try:
                    line = process.stdout.readline()
                    if line:
                        output_buffer.append(line.strip())
                        self._parse_aircrack_progress(job, line.strip())
                        
                        # Call progress callback if available
                        if job.job_id in self.progress_callbacks:
                            self.progress_callbacks[job.job_id](job)
                    else:
                        time.sleep(0.1)
                        
                except Exception as e:
                    self.logger.debug(f"Error reading aircrack output: {e}")
                    time.sleep(0.5)
            
            # Process completed, get final result
            process.wait()
            
            # Parse final output
            stdout, stderr = process.communicate() if process.poll() is None else ("", "")
            all_output = "\n".join(output_buffer) + stdout
            
            # Check for successful crack
            success = self._parse_aircrack_result(job, all_output, process.returncode)
            
            if success:
                job.status = "completed"
                self.logger.info(f"Password cracked successfully: {job.result}")
                log_operation("CRACK_SUCCESS", 
                            os.path.basename(job.capture_file),
                            f"Password: {job.result}")
            else:
                job.status = "failed"
                if process.returncode != 0:
                    job.error_message = stderr or "aircrack-ng process failed"
                else:
                    job.error_message = "Password not found in wordlist"
                
                self.logger.info(f"Cracking failed for job {job.job_id}: {job.error_message}")
                log_operation("CRACK_FAILED", 
                            os.path.basename(job.capture_file),
                            job.error_message)
            
        except Exception as e:
            job.status = "failed"
            job.error_message = f"Monitoring error: {e}"
            self.logger.error(f"Error monitoring aircrack process: {e}")
        finally:
            self._finalize_crack_job(job)
    
    def _parse_aircrack_progress(self, job: CrackJob, line: str):
        """
        Parse progress information from aircrack-ng output
        
        Args:
            job: CrackJob object
            line: Output line from aircrack-ng
        """
        try:
            # Look for key rate information
            # Example: "Tested 12345 keys (got 1234 IVs)"
            key_match = re.search(r'Tested\s+(\d+)\s+keys', line)
            if key_match:
                tested_keys = int(key_match.group(1))
                
                # Calculate progress if we have wordlist size
                try:
                    with open(job.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        total_keys = sum(1 for _ in f)
                    
                    if total_keys > 0:
                        job.progress_percentage = min((tested_keys / total_keys) * 100, 100.0)
                except Exception:
                    pass
            
            # Look for keys per second information
            # This is less common in aircrack-ng output but may appear
            kps_match = re.search(r'(\d+)\s+k/s', line)
            if kps_match:
                job.keys_per_second = int(kps_match.group(1)) * 1000
            
        except Exception as e:
            self.logger.debug(f"Error parsing aircrack progress: {e}")
    
    def _parse_aircrack_result(self, job: CrackJob, output: str, return_code: int) -> bool:
        """
        Parse final result from aircrack-ng output
        
        Args:
            job: CrackJob object
            output: Complete output from aircrack-ng
            return_code: Process return code
            
        Returns:
            True if password was found, False otherwise
        """
        try:
            # Look for successful crack patterns
            success_patterns = [
                r'KEY FOUND!\s*\[\s*([^\]]+)\s*\]',
                r'Current passphrase:\s*([^\n\r]+)',
                r'Master Key\s*:\s*([A-Fa-f0-9\s]+)'
            ]
            
            for pattern in success_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    password = match.group(1).strip()
                    if password and password != "":
                        job.result = password
                        return True
            
            # Check result file if it was created
            result_file = f"{self.results_dir}/{job.job_id}_result.txt"
            if validate_file_path(result_file):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            job.result = content
                            return True
                except Exception:
                    pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error parsing aircrack result: {e}")
            return False
    
    def stop_crack_job(self, job_id: str) -> bool:
        """
        Stop an active cracking job
        
        Args:
            job_id: ID of the job to stop
            
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            if job_id not in self.active_jobs:
                self.logger.warning(f"Job {job_id} not found")
                return False
            
            job = self.active_jobs[job_id]
            
            # Signal stop to monitoring thread
            if job_id in self.stop_events:
                self.stop_events[job_id].set()
            
            # Stop process
            self._stop_crack_process(job_id)
            
            # Update job status
            job.status = "stopped"
            job.end_time = datetime.now()
            
            log_operation("CRACK_STOPPED", os.path.basename(job.capture_file))
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop job {job_id}: {e}")
            return False
    
    def _stop_crack_process(self, job_id: str):
        """Stop the cracking process for a job"""
        try:
            if job_id in self.crack_processes:
                process = self.crack_processes[job_id]
                
                if process.poll() is None:  # Process still running
                    # Try graceful termination first
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        process.wait(timeout=5)
                    except (subprocess.TimeoutExpired, ProcessLookupError):
                        # Force kill if graceful termination fails
                        try:
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                
                del self.crack_processes[job_id]
            
            # Clean up stop event
            if job_id in self.stop_events:
                del self.stop_events[job_id]
                
        except Exception as e:
            self.logger.error(f"Error stopping crack process: {e}")
    
    def _finalize_crack_job(self, job: CrackJob):
        """Finalize crack job and clean up resources"""
        try:
            job.end_time = datetime.now()
            
            # Calculate actual duration
            duration = (job.end_time - job.start_time).total_seconds()
            
            # Clean up progress callback
            if job.job_id in self.progress_callbacks:
                del self.progress_callbacks[job.job_id]
            
            # Save job results to file
            self._save_job_results(job)
            
            self.logger.info(f"Crack job {job.job_id} finalized in {duration:.1f}s")
            
        except Exception as e:
            self.logger.error(f"Error finalizing crack job: {e}")
    
    def _save_job_results(self, job: CrackJob):
        """Save job results to JSON file"""
        try:
            results_file = self.results_dir / f"{job.job_id}_job.json"
            
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(job.to_dict(), f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"Error saving job results: {e}")
    
    def get_active_jobs(self) -> List[CrackJob]:
        """Get list of active cracking jobs"""
        return [job for job in self.active_jobs.values() 
                if job.status == "running"]
    
    def get_job(self, job_id: str) -> Optional[CrackJob]:
        """Get crack job by ID"""
        return self.active_jobs.get(job_id)
    
    def get_all_jobs(self) -> List[CrackJob]:
        """Get all crack jobs"""
        return list(self.active_jobs.values())
    
    def get_job_progress(self, job_id: str) -> Dict[str, Any]:
        """
        Get detailed progress information for a job
        
        Args:
            job_id: ID of the job
            
        Returns:
            Dictionary with progress information
        """
        try:
            if job_id not in self.active_jobs:
                return {'error': 'Job not found'}
            
            job = self.active_jobs[job_id]
            
            # Calculate elapsed time
            elapsed = (datetime.now() - job.start_time).total_seconds()
            
            # Calculate ETA if we have progress
            eta = None
            if job.progress_percentage > 0:
                total_estimated = elapsed / (job.progress_percentage / 100)
                eta = max(0, total_estimated - elapsed)
            
            return {
                'job_id': job.job_id,
                'status': job.status,
                'progress_percentage': job.progress_percentage,
                'keys_per_second': job.keys_per_second,
                'elapsed_seconds': int(elapsed),
                'estimated_remaining': int(eta) if eta else None,
                'result': job.result,
                'error_message': job.error_message
            }
            
        except Exception as e:
            return {'error': f'Progress query failed: {e}'}
    
    def validate_capture_for_cracking(self, capture_file: str) -> Dict[str, Any]:
        """
        Validate if capture file is suitable for password cracking
        
        Args:
            capture_file: Path to capture file
            
        Returns:
            Dictionary with validation results
        """
        try:
            if not validate_file_path(capture_file):
                return {
                    'valid': False,
                    'error': 'Capture file not found',
                    'details': {}
                }
            
            # Use aircrack-ng to analyze the capture
            result = run_command(['aircrack-ng', capture_file], timeout=15)
            
            validation_result = {
                'valid': False,
                'error': None,
                'details': {
                    'file_size': os.path.getsize(capture_file),
                    'networks_found': 0,
                    'handshakes_found': 0,
                    'crackable_networks': []
                }
            }
            
            output = result.stdout
            
            # Parse networks and handshakes
            network_matches = re.findall(r'(\d+)\s+([A-Fa-f0-9:]{17})\s+([^\s]+)', output)
            handshake_matches = re.findall(r'(\d+)\s+handshake', output.lower())
            
            validation_result['details']['networks_found'] = len(network_matches)
            
            if handshake_matches:
                validation_result['details']['handshakes_found'] = int(handshake_matches[0])
                validation_result['valid'] = True
                
                # Extract crackable networks
                for match in network_matches:
                    if 'wpa' in output.lower():
                        validation_result['details']['crackable_networks'].append({
                            'index': match[0],
                            'bssid': match[1],
                            'ssid': match[2] if len(match) > 2 else 'Hidden'
                        })
            else:
                validation_result['error'] = 'No handshakes found in capture file'
            
            return validation_result
            
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation failed: {e}',
                'details': {}
            }
    
    def get_crack_statistics(self) -> Dict[str, Any]:
        """
        Get overall cracking statistics
        
        Returns:
            Dictionary with statistics
        """
        try:
            stats = {
                'total_jobs': len(self.active_jobs),
                'active_jobs': len(self.get_active_jobs()),
                'completed_jobs': 0,
                'failed_jobs': 0,
                'success_rate': 0.0,
                'total_passwords_cracked': 0
            }
            
            for job in self.active_jobs.values():
                if job.status == 'completed':
                    stats['completed_jobs'] += 1
                    if job.result:
                        stats['total_passwords_cracked'] += 1
                elif job.status == 'failed':
                    stats['failed_jobs'] += 1
            
            # Calculate success rate
            total_finished = stats['completed_jobs'] + stats['failed_jobs']
            if total_finished > 0:
                stats['success_rate'] = (stats['total_passwords_cracked'] / total_finished) * 100
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting crack statistics: {e}")
            return {'error': f'Statistics query failed: {e}'}
    
    def crack_with_hashcat(self, capture_file: str, wordlist_file: str, 
                          progress_callback: Callable = None) -> Optional[CrackJob]:
        """
        Start password cracking using hashcat with GPU acceleration
        
        Args:
            capture_file: Path to capture file (will be converted to hashcat format)
            wordlist_file: Path to wordlist file
            progress_callback: Optional callback for progress updates
            
        Returns:
            CrackJob object if started successfully, None otherwise
        """
        try:
            # Log security event
            log_security_event("CRACK_START", 
                             f"Method: hashcat, Capture: {os.path.basename(capture_file)}")
            
            # Validate inputs
            if not validate_file_path(capture_file):
                self.logger.error(f"Capture file not found: {capture_file}")
                return None
                
            if not validate_file_path(wordlist_file):
                self.logger.error(f"Wordlist file not found: {wordlist_file}")
                return None
            
            # Check hashcat availability
            if not self._check_hashcat_availability():
                self.logger.error("hashcat is not available")
                return None
            
            # Convert capture file to hashcat format
            hashcat_file = self._convert_capture_for_hashcat(capture_file)
            if not hashcat_file:
                self.logger.error("Failed to convert capture file for hashcat")
                return None
            
            # Create crack job
            job_id = f"hashcat_{int(time.time())}"
            job = CrackJob(
                job_id=job_id,
                capture_file=hashcat_file,  # Use converted file
                wordlist_file=wordlist_file,
                method="hashcat",
                start_time=datetime.now()
            )
            
            # Estimate cracking time
            job.estimated_time = self._estimate_hashcat_time(wordlist_file)
            
            # Start cracking process
            success = self._start_hashcat_process(job)
            
            if success:
                self.active_jobs[job_id] = job
                if progress_callback:
                    self.progress_callbacks[job_id] = progress_callback
                
                log_operation("CRACK_STARTED", 
                            os.path.basename(capture_file), 
                            f"Method: hashcat")
                return job
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to start hashcat: {e}")
            return None
    
    def _check_hashcat_availability(self) -> bool:
        """Check if hashcat is available and functional"""
        try:
            result = run_command(['hashcat', '--version'], timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_gpu_capabilities(self) -> Dict[str, Any]:
        """
        Detect and validate GPU capabilities for hashcat
        
        Returns:
            Dictionary with GPU information and capabilities
        """
        try:
            gpu_info = {
                'available': False,
                'devices': [],
                'opencl_support': False,
                'metal_support': False,  # For macOS
                'recommended_workload': 1024
            }
            
            # Check hashcat device list
            try:
                result = run_command(['hashcat', '-I'], timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Parse device information
                    devices = self._parse_hashcat_devices(output)
                    gpu_info['devices'] = devices
                    gpu_info['available'] = len(devices) > 0
                    
                    # Check for OpenCL support
                    if 'opencl' in output.lower():
                        gpu_info['opencl_support'] = True
                    
                    # Check for Metal support (macOS)
                    if 'metal' in output.lower():
                        gpu_info['metal_support'] = True
                        
            except Exception as e:
                self.logger.debug(f"Could not get hashcat device info: {e}")
            
            # If no GPU detected, check system info for fallback
            if not gpu_info['available']:
                gpu_info.update(self._detect_system_gpu())
            
            return gpu_info
            
        except Exception as e:
            self.logger.error(f"Error detecting GPU capabilities: {e}")
            return {'available': False, 'error': str(e)}
    
    def _parse_hashcat_devices(self, output: str) -> List[Dict[str, Any]]:
        """Parse hashcat device list output"""
        devices = []
        try:
            lines = output.split('\n')
            current_device = None
            
            for line in lines:
                line = line.strip()
                
                # Look for device entries
                if line.startswith('* Device #'):
                    if current_device:
                        devices.append(current_device)
                    
                    # Extract device number
                    device_match = re.search(r'Device #(\d+)', line)
                    current_device = {
                        'id': int(device_match.group(1)) if device_match else len(devices),
                        'name': '',
                        'type': 'unknown',
                        'memory': 0,
                        'compute_units': 0
                    }
                
                elif current_device:
                    # Parse device properties
                    if 'Name' in line:
                        name_match = re.search(r'Name[:\s]+(.+)', line)
                        if name_match:
                            current_device['name'] = name_match.group(1).strip()
                    
                    elif 'Type' in line:
                        if 'GPU' in line:
                            current_device['type'] = 'GPU'
                        elif 'CPU' in line:
                            current_device['type'] = 'CPU'
                    
                    elif 'Global Memory' in line:
                        memory_match = re.search(r'(\d+)', line)
                        if memory_match:
                            current_device['memory'] = int(memory_match.group(1))
                    
                    elif 'Compute Units' in line:
                        cu_match = re.search(r'(\d+)', line)
                        if cu_match:
                            current_device['compute_units'] = int(cu_match.group(1))
            
            # Add the last device
            if current_device:
                devices.append(current_device)
                
        except Exception as e:
            self.logger.debug(f"Error parsing hashcat devices: {e}")
        
        return devices
    
    def _detect_system_gpu(self) -> Dict[str, Any]:
        """Detect GPU using system tools (macOS specific)"""
        try:
            gpu_info = {
                'available': False,
                'system_gpu': None,
                'metal_support': False
            }
            
            # Use system_profiler to get GPU info on macOS
            result = run_command(['system_profiler', 'SPDisplaysDataType'], timeout=10)
            if result.returncode == 0:
                output = result.stdout
                
                # Look for GPU information
                if 'Metal' in output:
                    gpu_info['metal_support'] = True
                
                # Extract GPU names
                gpu_matches = re.findall(r'Chipset Model:\s*(.+)', output)
                if gpu_matches:
                    gpu_info['system_gpu'] = gpu_matches[0].strip()
                    gpu_info['available'] = True
            
            return gpu_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting system GPU: {e}")
            return {'available': False}
    
    def _convert_capture_for_hashcat(self, capture_file: str) -> Optional[str]:
        """
        Convert capture file to hashcat-compatible format
        
        Args:
            capture_file: Path to original capture file
            
        Returns:
            Path to converted file if successful, None otherwise
        """
        try:
            input_path = Path(capture_file)
            
            # Determine target format based on hashcat version and capabilities
            # Try 22000 format first (newer), then hccapx (legacy)
            target_formats = ['22000', 'hccapx']
            
            for format_type in target_formats:
                output_file = input_path.with_suffix(f'.{format_type}')
                
                if format_type == '22000':
                    success = self._convert_to_22000_format(capture_file, str(output_file))
                elif format_type == 'hccapx':
                    success = self._convert_to_hccapx_format(capture_file, str(output_file))
                else:
                    continue
                
                if success:
                    self.logger.info(f"Converted capture to {format_type} format: {output_file}")
                    return str(output_file)
            
            self.logger.error("Failed to convert capture to any hashcat format")
            return None
            
        except Exception as e:
            self.logger.error(f"Capture conversion error: {e}")
            return None
    
    def _convert_to_22000_format(self, input_file: str, output_file: str) -> bool:
        """Convert capture to hashcat 22000 format (WPA*01/WPA*02)"""
        try:
            # Try using hcxpcapngtool (preferred method)
            try:
                result = run_command([
                    'hcxpcapngtool',
                    '-o', output_file,
                    input_file
                ], timeout=30)
                
                if result.returncode == 0 and validate_file_path(output_file):
                    return True
            except Exception:
                pass
            
            # Fallback: try cap2hashcat if available
            try:
                result = run_command([
                    'cap2hashcat',
                    input_file,
                    output_file
                ], timeout=30)
                
                if result.returncode == 0 and validate_file_path(output_file):
                    return True
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            self.logger.debug(f"22000 format conversion error: {e}")
            return False
    
    def _convert_to_hccapx_format(self, input_file: str, output_file: str) -> bool:
        """Convert capture to hashcat hccapx format (legacy)"""
        try:
            # Use cap2hccapx tool
            result = run_command([
                'cap2hccapx',
                input_file,
                output_file
            ], timeout=30)
            
            if result.returncode == 0 and validate_file_path(output_file):
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"hccapx format conversion error: {e}")
            return False
    
    def _estimate_hashcat_time(self, wordlist_file: str) -> int:
        """
        Estimate cracking time for hashcat based on wordlist size and GPU capabilities
        
        Args:
            wordlist_file: Path to wordlist file
            
        Returns:
            Estimated time in seconds
        """
        try:
            # Count lines in wordlist
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)
            
            # Get GPU capabilities to estimate speed
            gpu_info = self.get_gpu_capabilities()
            
            # Estimate keys per second based on hardware
            if gpu_info['available'] and gpu_info.get('opencl_support'):
                # GPU acceleration available - much faster
                estimated_kps = 50000  # Conservative GPU estimate
            elif gpu_info['available'] and gpu_info.get('metal_support'):
                # Metal support on macOS
                estimated_kps = 30000  # Metal performance estimate
            else:
                # CPU only - slower
                estimated_kps = 5000
            
            estimated_seconds = line_count / estimated_kps
            
            # Add buffer time and ensure minimum time
            result = int(estimated_seconds * 1.3)
            return max(result, 1)  # Ensure at least 1 second
            
        except Exception as e:
            self.logger.debug(f"Could not estimate hashcat time: {e}")
            return 0
        except Exception as e:
            self.logger.debug(f"Could not estimate hashcat time: {e}")
            return 0
    
    def _start_hashcat_process(self, job: CrackJob) -> bool:
        """
        Start hashcat process for password cracking
        
        Args:
            job: CrackJob object
            
        Returns:
            True if process started successfully, False otherwise
        """
        try:
            # Determine hash mode based on file format
            hash_mode = self._get_hashcat_mode(job.capture_file)
            if not hash_mode:
                self.logger.error("Could not determine hashcat mode for capture file")
                return False
            
            # Build hashcat command
            cmd = [
                'hashcat',
                '-m', str(hash_mode),  # Hash mode
                '-a', '0',  # Attack mode: dictionary
                job.capture_file,  # Hash file
                job.wordlist_file,  # Wordlist
                '--status',  # Enable status output
                '--status-timer=2',  # Status every 2 seconds
                '--quiet'  # Reduce output noise
            ]
            
            # Add GPU optimization if available
            gpu_info = self.get_gpu_capabilities()
            if gpu_info['available']:
                # Optimize workload for GPU
                cmd.extend(['-w', '3'])  # Workload profile: high
                
                # Use specific devices if multiple available
                gpu_devices = [d for d in gpu_info['devices'] if d['type'] == 'GPU']
                if gpu_devices:
                    device_ids = [str(d['id']) for d in gpu_devices]
                    cmd.extend(['-d', ','.join(device_ids)])
            
            # Add output file for cracked passwords
            potfile = f"{self.results_dir}/{job.job_id}_hashcat.pot"
            cmd.extend(['--potfile-path', potfile])
            
            self.logger.info(f"Starting hashcat: {' '.join(cmd)}")
            
            # Start process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Store process and create stop event
            self.crack_processes[job.job_id] = process
            self.stop_events[job.job_id] = Event()
            
            # Start monitoring thread
            monitor_thread = Thread(
                target=self._monitor_hashcat_process,
                args=(job, process),
                daemon=True
            )
            monitor_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start hashcat process: {e}")
            return False
    
    def _get_hashcat_mode(self, capture_file: str) -> Optional[int]:
        """
        Determine appropriate hashcat mode based on capture file format
        
        Args:
            capture_file: Path to capture file
            
        Returns:
            Hashcat mode number if determined, None otherwise
        """
        try:
            file_path = Path(capture_file)
            
            if file_path.suffix == '.22000':
                return 22000  # WPA-PBKDF2-PMKID+EAPOL
            elif file_path.suffix == '.hccapx':
                return 2500   # WPA-EAPOL-PBKDF2 (legacy)
            elif file_path.suffix == '.16800':
                return 16800  # WPA-PMKID-PBKDF2
            else:
                # Try to detect format by content
                try:
                    with open(capture_file, 'rb') as f:
                        header = f.read(16)
                        
                    # Check for known format signatures
                    if header.startswith(b'HCPX'):
                        return 2500  # hccapx format
                    elif b'WPA*01' in header or b'WPA*02' in header:
                        return 22000  # 22000 format
                        
                except Exception:
                    pass
            
            # Default to 22000 for modern format
            return 22000
            
        except Exception as e:
            self.logger.debug(f"Error determining hashcat mode: {e}")
            return None
    
    def _monitor_hashcat_process(self, job: CrackJob, process: subprocess.Popen):
        """
        Monitor hashcat process and parse progress
        
        Args:
            job: CrackJob object
            process: hashcat process
        """
        try:
            stop_event = self.stop_events[job.job_id]
            output_buffer = []
            
            while not stop_event.is_set():
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Read output line by line
                try:
                    line = process.stdout.readline()
                    if line:
                        output_buffer.append(line.strip())
                        self._parse_hashcat_progress(job, line.strip())
                        
                        # Call progress callback if available
                        if job.job_id in self.progress_callbacks:
                            self.progress_callbacks[job.job_id](job)
                    else:
                        time.sleep(0.1)
                        
                except Exception as e:
                    self.logger.debug(f"Error reading hashcat output: {e}")
                    time.sleep(0.5)
            
            # Process completed, get final result
            process.wait()
            
            # Parse final output
            stdout, stderr = process.communicate() if process.poll() is None else ("", "")
            all_output = "\n".join(output_buffer) + stdout
            
            # Check for successful crack
            success = self._parse_hashcat_result(job, all_output, process.returncode)
            
            if success:
                job.status = "completed"
                self.logger.info(f"Password cracked successfully with hashcat: {job.result}")
                log_operation("CRACK_SUCCESS", 
                            os.path.basename(job.capture_file),
                            f"Password: {job.result}")
            else:
                job.status = "failed"
                if process.returncode != 0:
                    job.error_message = stderr or "hashcat process failed"
                else:
                    job.error_message = "Password not found in wordlist"
                
                self.logger.info(f"Hashcat cracking failed for job {job.job_id}: {job.error_message}")
                log_operation("CRACK_FAILED", 
                            os.path.basename(job.capture_file),
                            job.error_message)
            
        except Exception as e:
            job.status = "failed"
            job.error_message = f"Monitoring error: {e}"
            self.logger.error(f"Error monitoring hashcat process: {e}")
        finally:
            self._finalize_crack_job(job)
    
    def _parse_hashcat_progress(self, job: CrackJob, line: str):
        """
        Parse progress information from hashcat output
        
        Args:
            job: CrackJob object
            line: Output line from hashcat
        """
        try:
            # Look for status line with progress information
            # Example: "Status.......: Running"
            # Example: "Progress.....: 12345/67890 (18.12%)"
            # Example: "Speed.#1.....: 12345 H/s"
            
            if 'Progress' in line:
                # Extract progress percentage
                progress_match = re.search(r'\((\d+\.?\d*)%\)', line)
                if progress_match:
                    job.progress_percentage = float(progress_match.group(1))
            
            elif 'Speed' in line:
                # Extract hash rate
                speed_match = re.search(r'(\d+)\s*H/s', line)
                if speed_match:
                    job.keys_per_second = int(speed_match.group(1))
            
        except Exception as e:
            self.logger.debug(f"Error parsing hashcat progress: {e}")
    
    def _parse_hashcat_result(self, job: CrackJob, output: str, return_code: int) -> bool:
        """
        Parse final result from hashcat output
        
        Args:
            job: CrackJob object
            output: Complete output from hashcat
            return_code: Process return code
            
        Returns:
            True if password was found, False otherwise
        """
        try:
            # Check for successful crack in output
            if 'Cracked' in output or return_code == 0:
                # Look for the actual password in potfile
                potfile = f"{self.results_dir}/{job.job_id}_hashcat.pot"
                
                if validate_file_path(potfile):
                    try:
                        with open(potfile, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                            
                        # Parse potfile format: hash:password
                        if ':' in content:
                            lines = content.split('\n')
                            for line in lines:
                                if ':' in line:
                                    password = line.split(':', 1)[1]
                                    if password:
                                        job.result = password
                                        return True
                    except Exception:
                        pass
                
                # Fallback: look for password in output
                password_patterns = [
                    r'Recovered\.+:\s*(.+)',
                    r'Cracked:\s*(.+)',
                    r'Password:\s*(.+)'
                ]
                
                for pattern in password_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        password = match.group(1).strip()
                        if password:
                            job.result = password
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error parsing hashcat result: {e}")
            return False
    
    def crack_password(self, capture_file: str, wordlist_file: str, 
                      method: str = "auto", progress_callback: Callable = None) -> Optional[CrackJob]:
        """
        Unified interface for password cracking with automatic method selection
        
        Args:
            capture_file: Path to capture file
            wordlist_file: Path to wordlist file
            method: Cracking method ('auto', 'aircrack', 'hashcat')
            progress_callback: Optional callback for progress updates
            
        Returns:
            CrackJob object if started successfully, None otherwise
        """
        try:
            # Log security event
            log_security_event("CRACK_REQUEST", 
                             f"Method: {method}, Capture: {os.path.basename(capture_file)}")
            
            # Validate inputs
            if not validate_file_path(capture_file):
                self.logger.error(f"Capture file not found: {capture_file}")
                return None
                
            if not validate_file_path(wordlist_file):
                self.logger.error(f"Wordlist file not found: {wordlist_file}")
                return None
            
            # Determine optimal method if auto
            if method == "auto":
                method = self._select_optimal_method(capture_file, wordlist_file)
                self.logger.info(f"Auto-selected cracking method: {method}")
            
            # Execute with selected method
            if method == "aircrack":
                return self.crack_with_aircrack(capture_file, wordlist_file, progress_callback)
            elif method == "hashcat":
                return self.crack_with_hashcat(capture_file, wordlist_file, progress_callback)
            else:
                self.logger.error(f"Unsupported cracking method: {method}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to start password cracking: {e}")
            return None
    
    def _select_optimal_method(self, capture_file: str, wordlist_file: str) -> str:
        """
        Select optimal cracking method based on available hardware and file characteristics
        
        Args:
            capture_file: Path to capture file
            wordlist_file: Path to wordlist file
            
        Returns:
            Optimal method name ('aircrack' or 'hashcat')
        """
        try:
            # Check tool availability
            hashcat_available = self._check_hashcat_availability()
            aircrack_available = self._check_aircrack_availability()
            
            if not hashcat_available and not aircrack_available:
                self.logger.error("Neither hashcat nor aircrack-ng is available")
                return "aircrack"  # Default fallback
            
            # If only one is available, use it
            if hashcat_available and not aircrack_available:
                return "hashcat"
            elif aircrack_available and not hashcat_available:
                return "aircrack"
            
            # Both available - make intelligent choice
            
            # Check GPU capabilities
            gpu_info = self.get_gpu_capabilities()
            has_gpu = gpu_info['available'] and (
                gpu_info.get('opencl_support') or gpu_info.get('metal_support')
            )
            
            # Check wordlist size
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist_size = sum(1 for _ in f)
            except Exception:
                wordlist_size = 0
            
            # Decision logic
            if has_gpu and wordlist_size > 10000:
                # Large wordlist + GPU = hashcat is better
                self.logger.info("Selecting hashcat: GPU available and large wordlist")
                return "hashcat"
            elif wordlist_size < 1000:
                # Small wordlist = aircrack is sufficient and simpler
                self.logger.info("Selecting aircrack-ng: small wordlist")
                return "aircrack"
            elif has_gpu:
                # GPU available = prefer hashcat for speed
                self.logger.info("Selecting hashcat: GPU acceleration available")
                return "hashcat"
            else:
                # No GPU, moderate wordlist = aircrack is reliable
                self.logger.info("Selecting aircrack-ng: no GPU acceleration")
                return "aircrack"
                
        except Exception as e:
            self.logger.error(f"Error selecting optimal method: {e}")
            return "aircrack"  # Safe fallback
    
    def get_method_recommendations(self, capture_file: str, wordlist_file: str) -> Dict[str, Any]:
        """
        Get recommendations for cracking methods based on system capabilities
        
        Args:
            capture_file: Path to capture file
            wordlist_file: Path to wordlist file
            
        Returns:
            Dictionary with method recommendations and reasoning
        """
        try:
            recommendations = {
                'optimal_method': 'aircrack',
                'available_methods': [],
                'reasoning': [],
                'estimated_times': {},
                'hardware_info': {}
            }
            
            # Check tool availability
            if self._check_aircrack_availability():
                recommendations['available_methods'].append('aircrack')
                recommendations['estimated_times']['aircrack'] = self._estimate_aircrack_time(wordlist_file)
            
            if self._check_hashcat_availability():
                recommendations['available_methods'].append('hashcat')
                recommendations['estimated_times']['hashcat'] = self._estimate_hashcat_time(wordlist_file)
            
            # Get hardware info
            gpu_info = self.get_gpu_capabilities()
            recommendations['hardware_info'] = {
                'gpu_available': gpu_info['available'],
                'gpu_devices': len(gpu_info.get('devices', [])),
                'opencl_support': gpu_info.get('opencl_support', False),
                'metal_support': gpu_info.get('metal_support', False)
            }
            
            # Get wordlist info
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist_size = sum(1 for _ in f)
                recommendations['wordlist_size'] = wordlist_size
            except Exception:
                recommendations['wordlist_size'] = 0
            
            # Generate recommendations
            if not recommendations['available_methods']:
                recommendations['reasoning'].append("No cracking tools available - install aircrack-ng or hashcat")
                return recommendations
            
            # Select optimal method
            recommendations['optimal_method'] = self._select_optimal_method(capture_file, wordlist_file)
            
            # Generate reasoning
            if recommendations['optimal_method'] == 'hashcat':
                if recommendations['hardware_info']['gpu_available']:
                    recommendations['reasoning'].append("GPU acceleration available - hashcat recommended for speed")
                if recommendations['wordlist_size'] > 10000:
                    recommendations['reasoning'].append("Large wordlist - hashcat handles better with GPU")
            else:
                if not recommendations['hardware_info']['gpu_available']:
                    recommendations['reasoning'].append("No GPU acceleration - aircrack-ng is sufficient")
                if recommendations['wordlist_size'] < 1000:
                    recommendations['reasoning'].append("Small wordlist - aircrack-ng is simpler and effective")
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            return {'error': f'Recommendation generation failed: {e}'}
    
    def get_comprehensive_progress(self, job_id: str) -> Dict[str, Any]:
        """
        Get comprehensive progress information with time estimation and success prediction
        
        Args:
            job_id: ID of the job
            
        Returns:
            Dictionary with comprehensive progress information
        """
        try:
            if job_id not in self.active_jobs:
                return {'error': 'Job not found'}
            
            job = self.active_jobs[job_id]
            
            # Calculate elapsed time
            elapsed = (datetime.now() - job.start_time).total_seconds()
            
            # Calculate ETA and completion prediction
            eta = None
            completion_probability = 0.0
            
            if job.progress_percentage > 0:
                total_estimated = elapsed / (job.progress_percentage / 100)
                eta = max(0, total_estimated - elapsed)
                
                # Simple completion probability based on progress
                if job.progress_percentage > 80:
                    completion_probability = 0.9
                elif job.progress_percentage > 50:
                    completion_probability = 0.7
                elif job.progress_percentage > 20:
                    completion_probability = 0.5
                else:
                    completion_probability = 0.3
            
            # Performance metrics
            performance_rating = "unknown"
            if job.keys_per_second > 0:
                if job.method == "hashcat":
                    if job.keys_per_second > 20000:
                        performance_rating = "excellent"
                    elif job.keys_per_second > 10000:
                        performance_rating = "good"
                    elif job.keys_per_second > 5000:
                        performance_rating = "fair"
                    else:
                        performance_rating = "poor"
                else:  # aircrack
                    if job.keys_per_second > 5000:
                        performance_rating = "excellent"
                    elif job.keys_per_second > 2000:
                        performance_rating = "good"
                    elif job.keys_per_second > 1000:
                        performance_rating = "fair"
                    else:
                        performance_rating = "poor"
            
            return {
                'job_id': job.job_id,
                'method': job.method,
                'status': job.status,
                'progress_percentage': job.progress_percentage,
                'keys_per_second': job.keys_per_second,
                'elapsed_seconds': int(elapsed),
                'estimated_remaining': int(eta) if eta else None,
                'completion_probability': completion_probability,
                'performance_rating': performance_rating,
                'result': job.result,
                'error_message': job.error_message,
                'start_time': job.start_time.isoformat(),
                'estimated_total_time': job.estimated_time
            }
            
        except Exception as e:
            return {'error': f'Progress query failed: {e}'}
    
    def stop_all_jobs(self) -> Dict[str, bool]:
        """
        Stop all active cracking jobs
        
        Returns:
            Dictionary mapping job IDs to stop success status
        """
        try:
            results = {}
            active_job_ids = list(self.active_jobs.keys())
            
            for job_id in active_job_ids:
                job = self.active_jobs[job_id]
                if job.status == "running":
                    success = self.stop_crack_job(job_id)
                    results[job_id] = success
                else:
                    results[job_id] = True  # Already stopped
            
            log_operation("ALL_JOBS_STOPPED", f"Stopped {len(results)} jobs")
            return results
            
        except Exception as e:
            self.logger.error(f"Error stopping all jobs: {e}")
            return {'error': f'Stop all failed: {e}'}
    
    def cleanup_completed_jobs(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed jobs and their files
        
        Args:
            max_age_hours: Maximum age in hours for completed jobs
            
        Returns:
            Number of jobs cleaned up
        """
        try:
            cleanup_count = 0
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=max_age_hours)
            
            jobs_to_remove = []
            
            for job_id, job in self.active_jobs.items():
                if job.status in ["completed", "failed", "stopped"] and job.end_time:
                    if job.end_time < cutoff_time:
                        jobs_to_remove.append(job_id)
            
            # Remove old jobs
            for job_id in jobs_to_remove:
                job = self.active_jobs[job_id]
                
                # Clean up result files
                try:
                    if job.method == "aircrack":
                        result_file = f"{self.results_dir}/{job_id}_result.txt"
                        if validate_file_path(result_file):
                            os.remove(result_file)
                    elif job.method == "hashcat":
                        potfile = f"{self.results_dir}/{job_id}_hashcat.pot"
                        if validate_file_path(potfile):
                            os.remove(potfile)
                    
                    # Clean up job JSON
                    job_file = f"{self.results_dir}/{job_id}_job.json"
                    if validate_file_path(job_file):
                        os.remove(job_file)
                        
                except Exception as e:
                    self.logger.debug(f"Error cleaning up files for job {job_id}: {e}")
                
                # Remove from active jobs
                del self.active_jobs[job_id]
                cleanup_count += 1
            
            if cleanup_count > 0:
                log_operation("JOBS_CLEANED", f"Cleaned up {cleanup_count} old jobs")
                self.logger.info(f"Cleaned up {cleanup_count} completed jobs older than {max_age_hours} hours")
            
            return cleanup_count
            
        except Exception as e:
            self.logger.error(f"Error during job cleanup: {e}")
            return 0
    
    def export_results_summary(self) -> Dict[str, Any]:
        """
        Export comprehensive summary of all cracking results
        
        Returns:
            Dictionary with results summary
        """
        try:
            summary = {
                'generated_at': datetime.now().isoformat(),
                'total_jobs': len(self.active_jobs),
                'job_summary': {
                    'running': 0,
                    'completed': 0,
                    'failed': 0,
                    'stopped': 0
                },
                'success_statistics': {
                    'total_successful': 0,
                    'success_rate': 0.0,
                    'average_time_to_crack': 0.0
                },
                'method_statistics': {
                    'aircrack_jobs': 0,
                    'hashcat_jobs': 0,
                    'aircrack_success_rate': 0.0,
                    'hashcat_success_rate': 0.0
                },
                'successful_cracks': [],
                'performance_metrics': {
                    'fastest_crack_time': None,
                    'slowest_crack_time': None,
                    'average_keys_per_second': 0.0
                }
            }
            
            successful_times = []
            all_kps = []
            
            for job in self.active_jobs.values():
                # Count by status
                summary['job_summary'][job.status] += 1
                
                # Count by method
                if job.method == 'aircrack':
                    summary['method_statistics']['aircrack_jobs'] += 1
                elif job.method == 'hashcat':
                    summary['method_statistics']['hashcat_jobs'] += 1
                
                # Successful cracks
                if job.status == 'completed' and job.result:
                    summary['success_statistics']['total_successful'] += 1
                    
                    # Calculate crack time
                    if job.end_time:
                        crack_time = (job.end_time - job.start_time).total_seconds()
                        successful_times.append(crack_time)
                        
                        summary['successful_cracks'].append({
                            'job_id': job.job_id,
                            'method': job.method,
                            'password': job.result,
                            'crack_time_seconds': crack_time,
                            'capture_file': os.path.basename(job.capture_file),
                            'wordlist_file': os.path.basename(job.wordlist_file)
                        })
                
                # Performance metrics
                if job.keys_per_second > 0:
                    all_kps.append(job.keys_per_second)
            
            # Calculate success rates
            total_finished = (summary['job_summary']['completed'] + 
                            summary['job_summary']['failed'] + 
                            summary['job_summary']['stopped'])
            
            if total_finished > 0:
                summary['success_statistics']['success_rate'] = (
                    summary['success_statistics']['total_successful'] / total_finished * 100
                )
            
            # Method-specific success rates
            aircrack_total = summary['method_statistics']['aircrack_jobs']
            hashcat_total = summary['method_statistics']['hashcat_jobs']
            
            if aircrack_total > 0:
                aircrack_successful = len([j for j in self.active_jobs.values() 
                                         if j.method == 'aircrack' and j.status == 'completed' and j.result])
                summary['method_statistics']['aircrack_success_rate'] = (aircrack_successful / aircrack_total * 100)
            
            if hashcat_total > 0:
                hashcat_successful = len([j for j in self.active_jobs.values() 
                                        if j.method == 'hashcat' and j.status == 'completed' and j.result])
                summary['method_statistics']['hashcat_success_rate'] = (hashcat_successful / hashcat_total * 100)
            
            # Time statistics
            if successful_times:
                summary['success_statistics']['average_time_to_crack'] = sum(successful_times) / len(successful_times)
                summary['performance_metrics']['fastest_crack_time'] = min(successful_times)
                summary['performance_metrics']['slowest_crack_time'] = max(successful_times)
            
            # Performance statistics
            if all_kps:
                summary['performance_metrics']['average_keys_per_second'] = sum(all_kps) / len(all_kps)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error exporting results summary: {e}")
            return {'error': f'Export failed: {e}'}
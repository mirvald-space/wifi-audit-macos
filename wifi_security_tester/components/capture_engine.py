"""
Capture Engine - WiFi packet capture and handshake detection for macOS
Implements airodump-ng with tcpdump fallback for handshake capture

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import os
import signal
import time
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
import tempfile

from ..core.logger import get_logger, log_operation, log_security_event
from ..utils.common import run_command, ensure_directory, validate_file_path
from .network_scanner import NetworkInfo
from .interface_manager import InterfaceManager


@dataclass
class CaptureSession:
    """Data model for capture session information"""
    session_id: str
    target_network: NetworkInfo
    interface: str
    start_time: datetime
    end_time: Optional[datetime] = None
    capture_file: str = ""
    handshake_found: bool = False
    packet_count: int = 0
    status: str = "active"  # active, completed, failed, stopped
    method: str = "airodump"  # airodump, tcpdump
    
    def __post_init__(self):
        if not self.capture_file:
            timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
            safe_ssid = re.sub(r'[^\w\-_]', '_', self.target_network.ssid)
            self.capture_file = f"capture_{safe_ssid}_{timestamp}"


class CaptureEngine:
    """WiFi packet capture engine with handshake detection"""
    
    def __init__(self, interface_manager: InterfaceManager = None):
        self.logger = get_logger("capture_engine")
        self.interface_manager = interface_manager or InterfaceManager()
        self.active_sessions: Dict[str, CaptureSession] = {}
        self.capture_dir = Path("captures")
        ensure_directory(self.capture_dir)
        
        # Capture process management
        self.capture_processes: Dict[str, subprocess.Popen] = {}
        self.stop_events: Dict[str, Event] = {}
        
    def start_capture(self, target_network: NetworkInfo, interface: str = None, 
                     duration: int = 300, method: str = "auto") -> Optional[CaptureSession]:
        """
        Start packet capture for target network
        
        Args:
            target_network: NetworkInfo object for target network
            interface: WiFi interface to use (auto-detect if None)
            duration: Maximum capture duration in seconds
            method: Capture method ('airodump', 'tcpdump', 'auto')
            
        Returns:
            CaptureSession object if successful, None otherwise
        """
        try:
            # Log security event
            log_security_event("CAPTURE_START", 
                             f"Target: {target_network.ssid} ({target_network.bssid})")
            
            # Determine interface
            if not interface:
                available_interfaces = self.interface_manager.get_available_interfaces()
                if not available_interfaces:
                    self.logger.error("No WiFi interface available")
                    return None
                interface = available_interfaces[0]  # Use first available interface
            
            # Validate interface
            status = self.interface_manager.validate_interface_status(interface)
            if not status['exists']:
                self.logger.error(f"Interface {interface} is not valid")
                return None
            
            # Create capture session
            session_id = f"capture_{int(time.time())}"
            session = CaptureSession(
                session_id=session_id,
                target_network=target_network,
                interface=interface,
                start_time=datetime.now(),
                method=method if method != "auto" else "airodump"
            )
            
            # Determine capture method
            if method == "auto":
                if self._check_airodump_availability():
                    session.method = "airodump"
                else:
                    session.method = "tcpdump"
                    self.logger.warning("airodump-ng not available, using tcpdump fallback")
            
            # Set interface to monitor mode
            success, message = self.interface_manager.set_monitor_mode(interface)
            if not success:
                self.logger.error(f"Failed to set {interface} to monitor mode: {message}")
                return None
            
            # Start capture based on method
            success = False
            if session.method == "airodump":
                success = self._start_airodump_capture(session, duration)
            elif session.method == "tcpdump":
                success = self._start_tcpdump_capture(session, duration)
            
            if success:
                self.active_sessions[session_id] = session
                log_operation("CAPTURE_STARTED", 
                            f"{target_network.ssid}", 
                            f"Method: {session.method}")
                return session
            else:
                # Restore interface on failure
                self.interface_manager.restore_managed_mode(interface)
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            return None
    
    def _check_airodump_availability(self) -> bool:
        """Check if airodump-ng is available and functional"""
        try:
            result = run_command(['airodump-ng', '--help'], timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _start_airodump_capture(self, session: CaptureSession, duration: int) -> bool:
        """
        Start packet capture using airodump-ng
        
        Args:
            session: CaptureSession object
            duration: Maximum capture duration in seconds
            
        Returns:
            True if capture started successfully, False otherwise
        """
        try:
            # Prepare capture file paths
            capture_base = self.capture_dir / session.capture_file
            cap_file = f"{capture_base}-01.cap"
            
            # Build airodump-ng command
            cmd = [
                'airodump-ng',
                '--bssid', session.target_network.bssid,
                '--channel', str(session.target_network.channel),
                '--write', str(capture_base),
                '--output-format', 'cap',
                session.interface
            ]
            
            self.logger.info(f"Starting airodump-ng capture: {' '.join(cmd)}")
            
            # Start capture process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Store process and create stop event
            self.capture_processes[session.session_id] = process
            self.stop_events[session.session_id] = Event()
            
            # Start monitoring thread
            monitor_thread = Thread(
                target=self._monitor_airodump_capture,
                args=(session, process, duration),
                daemon=True
            )
            monitor_thread.start()
            
            # Update session
            session.capture_file = cap_file
            session.status = "active"
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start airodump-ng capture: {e}")
            return False
    
    def _start_tcpdump_capture(self, session: CaptureSession, duration: int) -> bool:
        """
        Start packet capture using tcpdump with 802.11 filters
        
        Args:
            session: CaptureSession object
            duration: Maximum capture duration in seconds
            
        Returns:
            True if capture started successfully, False otherwise
        """
        try:
            # Prepare capture file
            capture_file = self.capture_dir / f"{session.capture_file}.pcap"
            
            # Build tcpdump command with 802.11 filters
            # Filter for EAPOL frames (handshake packets)
            cmd = [
                'tcpdump',
                '-i', session.interface,
                '-w', str(capture_file),
                '-s', '0',  # Capture full packets
                f'ether host {session.target_network.bssid} and (ether[0] & 8 = 8)'
            ]
            
            self.logger.info(f"Starting tcpdump capture: {' '.join(cmd)}")
            
            # Start capture process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )
            
            # Store process and create stop event
            self.capture_processes[session.session_id] = process
            self.stop_events[session.session_id] = Event()
            
            # Start monitoring thread
            monitor_thread = Thread(
                target=self._monitor_tcpdump_capture,
                args=(session, process, duration),
                daemon=True
            )
            monitor_thread.start()
            
            # Update session
            session.capture_file = str(capture_file)
            session.status = "active"
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start tcpdump capture: {e}")
            return False
    
    def _monitor_airodump_capture(self, session: CaptureSession, 
                                process: subprocess.Popen, duration: int):
        """
        Monitor airodump-ng capture process and detect handshakes
        
        Args:
            session: CaptureSession object
            process: airodump-ng process
            duration: Maximum capture duration
        """
        try:
            start_time = time.time()
            stop_event = self.stop_events[session.session_id]
            
            while not stop_event.is_set():
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Check timeout
                if time.time() - start_time > duration:
                    self.logger.info(f"Capture timeout reached for session {session.session_id}")
                    break
                
                # Check for handshake in capture file
                if self._check_handshake_airodump(session):
                    session.handshake_found = True
                    self.logger.info(f"Handshake detected for {session.target_network.ssid}")
                    log_operation("HANDSHAKE_CAPTURED", session.target_network.ssid)
                    break
                
                time.sleep(2)  # Check every 2 seconds
            
            # Stop capture
            self._stop_capture_process(session.session_id)
            
        except Exception as e:
            self.logger.error(f"Error monitoring airodump capture: {e}")
        finally:
            self._finalize_capture_session(session)
    
    def _monitor_tcpdump_capture(self, session: CaptureSession, 
                               process: subprocess.Popen, duration: int):
        """
        Monitor tcpdump capture process
        
        Args:
            session: CaptureSession object
            process: tcpdump process
            duration: Maximum capture duration
        """
        try:
            start_time = time.time()
            stop_event = self.stop_events[session.session_id]
            
            while not stop_event.is_set():
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Check timeout
                if time.time() - start_time > duration:
                    self.logger.info(f"Capture timeout reached for session {session.session_id}")
                    break
                
                # For tcpdump, we'll validate handshake after capture completes
                time.sleep(5)  # Check every 5 seconds
            
            # Stop capture
            self._stop_capture_process(session.session_id)
            
            # Check for handshake in captured file
            if self._check_handshake_tcpdump(session):
                session.handshake_found = True
                self.logger.info(f"Handshake detected in tcpdump capture for {session.target_network.ssid}")
                log_operation("HANDSHAKE_CAPTURED", session.target_network.ssid)
            
        except Exception as e:
            self.logger.error(f"Error monitoring tcpdump capture: {e}")
        finally:
            self._finalize_capture_session(session)
    
    def _check_handshake_airodump(self, session: CaptureSession) -> bool:
        """
        Check if handshake was captured using airodump-ng output
        
        Args:
            session: CaptureSession object
            
        Returns:
            True if handshake detected, False otherwise
        """
        try:
            # Check if capture file exists
            if not validate_file_path(session.capture_file):
                return False
            
            # Use aircrack-ng to check for handshake
            result = run_command([
                'aircrack-ng',
                session.capture_file
            ], timeout=10)
            
            # Look for handshake indicators in output
            output = result.stdout.lower()
            if 'handshake' in output or 'wpa' in output:
                # More detailed check
                if any(indicator in output for indicator in [
                    'handshake found',
                    'wpa (1 handshake)',
                    'wpa2 (1 handshake)'
                ]):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking handshake: {e}")
            return False
    
    def _check_handshake_tcpdump(self, session: CaptureSession) -> bool:
        """
        Check if handshake was captured in tcpdump file
        
        Args:
            session: CaptureSession object
            
        Returns:
            True if handshake detected, False otherwise
        """
        try:
            # Check if capture file exists
            if not validate_file_path(session.capture_file):
                return False
            
            # Use tshark to analyze the capture for EAPOL frames
            try:
                result = run_command([
                    'tshark',
                    '-r', session.capture_file,
                    '-Y', 'eapol',
                    '-c', '4'  # Look for 4-way handshake
                ], timeout=15)
                
                if result.returncode == 0 and result.stdout.strip():
                    # Count EAPOL frames
                    eapol_count = len(result.stdout.strip().split('\n'))
                    if eapol_count >= 4:
                        return True
                        
            except Exception:
                # Fallback: use tcpdump to check for EAPOL frames
                result = run_command([
                    'tcpdump',
                    '-r', session.capture_file,
                    '-c', '4',
                    'ether proto 0x888e'  # EAPOL protocol
                ], timeout=15)
                
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    return len(lines) >= 4
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking tcpdump handshake: {e}")
            return False
    
    def stop_capture(self, session_id: str) -> bool:
        """
        Stop an active capture session
        
        Args:
            session_id: ID of the capture session to stop
            
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            if session_id not in self.active_sessions:
                self.logger.warning(f"Session {session_id} not found")
                return False
            
            session = self.active_sessions[session_id]
            
            # Signal stop to monitoring thread
            if session_id in self.stop_events:
                self.stop_events[session_id].set()
            
            # Stop capture process
            self._stop_capture_process(session_id)
            
            log_operation("CAPTURE_STOPPED", session.target_network.ssid)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop capture {session_id}: {e}")
            return False
    
    def _stop_capture_process(self, session_id: str):
        """Stop the capture process for a session"""
        try:
            if session_id in self.capture_processes:
                process = self.capture_processes[session_id]
                
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
                
                del self.capture_processes[session_id]
            
            # Clean up stop event
            if session_id in self.stop_events:
                del self.stop_events[session_id]
                
        except Exception as e:
            self.logger.error(f"Error stopping capture process: {e}")
    
    def _finalize_capture_session(self, session: CaptureSession):
        """Finalize capture session and restore interface"""
        try:
            session.end_time = datetime.now()
            session.status = "completed" if session.handshake_found else "failed"
            
            # Get packet count if possible
            session.packet_count = self._get_packet_count(session)
            
            # Restore interface to managed mode
            self.interface_manager.restore_managed_mode(session.interface)
            
            # Log completion
            duration = (session.end_time - session.start_time).total_seconds()
            self.logger.info(f"Capture session {session.session_id} completed in {duration:.1f}s")
            
            log_operation("CAPTURE_COMPLETED", 
                        session.target_network.ssid,
                        f"Handshake: {'Yes' if session.handshake_found else 'No'}")
            
        except Exception as e:
            self.logger.error(f"Error finalizing capture session: {e}")
    
    def _get_packet_count(self, session: CaptureSession) -> int:
        """Get packet count from capture file"""
        try:
            if not validate_file_path(session.capture_file):
                return 0
            
            if session.method == "airodump":
                # For airodump files, use aircrack-ng
                result = run_command(['aircrack-ng', session.capture_file], timeout=10)
                # Parse packet count from output (simplified)
                return 0  # Would need more sophisticated parsing
            
            elif session.method == "tcpdump":
                # For pcap files, use tcpdump or tshark
                try:
                    result = run_command(['tcpdump', '-r', session.capture_file, '-c', '0'], timeout=10)
                    # Parse packet count from stderr
                    if 'packets captured' in result.stderr:
                        match = re.search(r'(\d+) packets captured', result.stderr)
                        if match:
                            return int(match.group(1))
                except Exception:
                    pass
            
            return 0
            
        except Exception:
            return 0
    
    def get_active_sessions(self) -> List[CaptureSession]:
        """Get list of active capture sessions"""
        return [session for session in self.active_sessions.values() 
                if session.status == "active"]
    
    def get_session(self, session_id: str) -> Optional[CaptureSession]:
        """Get capture session by ID"""
        return self.active_sessions.get(session_id)
    
    def get_all_sessions(self) -> List[CaptureSession]:
        """Get all capture sessions"""
        return list(self.active_sessions.values())
    
    def validate_handshake(self, capture_file: str) -> Dict[str, Any]:
        """
        Validate captured handshake quality and completeness
        
        Args:
            capture_file: Path to capture file
            
        Returns:
            Dictionary with validation results
        """
        try:
            if not validate_file_path(capture_file):
                return {
                    'valid': False,
                    'error': 'Capture file not found or not readable',
                    'details': {}
                }
            
            # Determine file type and validation method
            if capture_file.endswith('.cap'):
                return self._validate_airodump_handshake(capture_file)
            elif capture_file.endswith('.pcap'):
                return self._validate_tcpdump_handshake(capture_file)
            else:
                return {
                    'valid': False,
                    'error': 'Unsupported capture file format',
                    'details': {}
                }
                
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation error: {e}',
                'details': {}
            }
    
    def _validate_airodump_handshake(self, capture_file: str) -> Dict[str, Any]:
        """Validate handshake in airodump capture file"""
        try:
            # Use aircrack-ng to analyze the handshake
            result = run_command(['aircrack-ng', capture_file], timeout=15)
            
            validation_result = {
                'valid': False,
                'error': None,
                'details': {
                    'method': 'airodump',
                    'file_size': os.path.getsize(capture_file),
                    'handshake_count': 0,
                    'networks_found': 0
                }
            }
            
            output = result.stdout.lower()
            
            # Check for handshake presence
            if 'handshake' in output:
                validation_result['valid'] = True
                
                # Extract handshake count
                handshake_matches = re.findall(r'(\d+)\s+handshake', output)
                if handshake_matches:
                    validation_result['details']['handshake_count'] = int(handshake_matches[0])
            
            # Extract network count
            network_matches = re.findall(r'(\d+)\s+network', output)
            if network_matches:
                validation_result['details']['networks_found'] = int(network_matches[0])
            
            if not validation_result['valid']:
                validation_result['error'] = 'No valid handshake found in capture'
            
            return validation_result
            
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation failed: {e}',
                'details': {'method': 'airodump'}
            }
    
    def _validate_tcpdump_handshake(self, capture_file: str) -> Dict[str, Any]:
        """Validate handshake in tcpdump capture file"""
        try:
            validation_result = {
                'valid': False,
                'error': None,
                'details': {
                    'method': 'tcpdump',
                    'file_size': os.path.getsize(capture_file),
                    'eapol_frames': 0,
                    'total_packets': 0
                }
            }
            
            # Count total packets
            try:
                result = run_command(['tcpdump', '-r', capture_file, '-c', '0'], timeout=10)
                if 'packets captured' in result.stderr:
                    match = re.search(r'(\d+) packets captured', result.stderr)
                    if match:
                        validation_result['details']['total_packets'] = int(match.group(1))
            except Exception:
                pass
            
            # Count EAPOL frames
            try:
                result = run_command([
                    'tcpdump', '-r', capture_file,
                    'ether proto 0x888e'
                ], timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    eapol_count = len(result.stdout.strip().split('\n'))
                    validation_result['details']['eapol_frames'] = eapol_count
                    
                    # Need at least 4 EAPOL frames for complete handshake
                    if eapol_count >= 4:
                        validation_result['valid'] = True
                    else:
                        validation_result['error'] = f'Incomplete handshake: only {eapol_count} EAPOL frames found'
                else:
                    validation_result['error'] = 'No EAPOL frames found in capture'
                    
            except Exception as e:
                validation_result['error'] = f'EAPOL analysis failed: {e}'
            
            return validation_result
            
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation failed: {e}',
                'details': {'method': 'tcpdump'}
            }
    
    def convert_capture_format(self, input_file: str, output_format: str) -> Optional[str]:
        """
        Convert capture file to different format
        
        Args:
            input_file: Path to input capture file
            output_format: Target format ('hccapx', '22000', 'pcap')
            
        Returns:
            Path to converted file if successful, None otherwise
        """
        try:
            if not validate_file_path(input_file):
                self.logger.error(f"Input file not found: {input_file}")
                return None
            
            input_path = Path(input_file)
            output_file = input_path.with_suffix(f'.{output_format}')
            
            if output_format == 'hccapx':
                return self._convert_to_hccapx(input_file, str(output_file))
            elif output_format == '22000':
                return self._convert_to_22000(input_file, str(output_file))
            elif output_format == 'pcap':
                return self._convert_to_pcap(input_file, str(output_file))
            else:
                self.logger.error(f"Unsupported output format: {output_format}")
                return None
                
        except Exception as e:
            self.logger.error(f"Format conversion failed: {e}")
            return None
    
    def _convert_to_hccapx(self, input_file: str, output_file: str) -> Optional[str]:
        """Convert capture to hccapx format for hashcat"""
        try:
            # Use cap2hccapx tool if available
            result = run_command(['cap2hccapx', input_file, output_file], timeout=30)
            
            if result.returncode == 0 and validate_file_path(output_file):
                self.logger.info(f"Converted to hccapx: {output_file}")
                return output_file
            else:
                self.logger.error(f"cap2hccapx conversion failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"hccapx conversion error: {e}")
            return None
    
    def _convert_to_22000(self, input_file: str, output_file: str) -> Optional[str]:
        """Convert capture to hashcat 22000 format"""
        try:
            # Use hcxpcapngtool if available
            result = run_command([
                'hcxpcapngtool',
                '-o', output_file,
                input_file
            ], timeout=30)
            
            if result.returncode == 0 and validate_file_path(output_file):
                self.logger.info(f"Converted to 22000 format: {output_file}")
                return output_file
            else:
                self.logger.error(f"22000 conversion failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"22000 conversion error: {e}")
            return None
    
    def _convert_to_pcap(self, input_file: str, output_file: str) -> Optional[str]:
        """Convert capture to pcap format"""
        try:
            # If already pcap, just copy
            if input_file.endswith('.pcap'):
                import shutil
                shutil.copy2(input_file, output_file)
                return output_file
            
            # Convert cap to pcap using editcap or similar
            result = run_command(['editcap', input_file, output_file], timeout=30)
            
            if result.returncode == 0 and validate_file_path(output_file):
                self.logger.info(f"Converted to pcap: {output_file}")
                return output_file
            else:
                self.logger.error(f"pcap conversion failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"pcap conversion error: {e}")
            return None
    
    def cleanup_old_captures(self, days_old: int = 7) -> int:
        """
        Clean up old capture files
        
        Args:
            days_old: Remove files older than this many days
            
        Returns:
            Number of files removed
        """
        try:
            removed_count = 0
            cutoff_time = time.time() - (days_old * 24 * 3600)
            
            for file_path in self.capture_dir.glob('*'):
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    try:
                        file_path.unlink()
                        removed_count += 1
                        self.logger.debug(f"Removed old capture file: {file_path}")
                    except Exception as e:
                        self.logger.warning(f"Failed to remove {file_path}: {e}")
            
            if removed_count > 0:
                self.logger.info(f"Cleaned up {removed_count} old capture files")
            
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
            return 0
    
    def organize_capture_files(self) -> Dict[str, Any]:
        """
        Organize capture files by date and network
        
        Returns:
            Dictionary with organization results
        """
        try:
            organization_result = {
                'organized_files': 0,
                'created_directories': 0,
                'errors': []
            }
            
            # Create date-based subdirectories
            today = datetime.now()
            date_dir = self.capture_dir / today.strftime("%Y-%m-%d")
            
            if not date_dir.exists():
                date_dir.mkdir(parents=True, exist_ok=True)
                organization_result['created_directories'] += 1
                self.logger.info(f"Created date directory: {date_dir}")
            
            # Move files to organized structure
            for file_path in self.capture_dir.glob('*'):
                if file_path.is_file() and file_path.parent == self.capture_dir:
                    try:
                        # Extract network name from filename
                        filename = file_path.name
                        if 'capture_' in filename:
                            # Move to date directory
                            new_path = date_dir / filename
                            file_path.rename(new_path)
                            organization_result['organized_files'] += 1
                            self.logger.debug(f"Moved {filename} to {date_dir}")
                    except Exception as e:
                        error_msg = f"Failed to organize {file_path}: {e}"
                        organization_result['errors'].append(error_msg)
                        self.logger.warning(error_msg)
            
            self.logger.info(f"Organized {organization_result['organized_files']} capture files")
            return organization_result
            
        except Exception as e:
            self.logger.error(f"File organization failed: {e}")
            return {'organized_files': 0, 'created_directories': 0, 'errors': [str(e)]}
    
    def get_capture_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get detailed information about a capture file
        
        Args:
            file_path: Path to capture file
            
        Returns:
            Dictionary with file information
        """
        try:
            if not validate_file_path(file_path):
                return {'error': 'File not found or not readable'}
            
            file_path_obj = Path(file_path)
            file_info = {
                'filename': file_path_obj.name,
                'size_bytes': file_path_obj.stat().st_size,
                'size_human': self._format_file_size(file_path_obj.stat().st_size),
                'created': datetime.fromtimestamp(file_path_obj.stat().st_ctime),
                'modified': datetime.fromtimestamp(file_path_obj.stat().st_mtime),
                'format': file_path_obj.suffix.lower(),
                'validation': None,
                'handshake_info': None
            }
            
            # Validate the capture file
            validation_result = self.validate_handshake(file_path)
            file_info['validation'] = validation_result
            
            # Extract handshake information if valid
            if validation_result.get('valid', False):
                file_info['handshake_info'] = {
                    'handshake_count': validation_result.get('details', {}).get('handshake_count', 0),
                    'networks_found': validation_result.get('details', {}).get('networks_found', 0),
                    'eapol_frames': validation_result.get('details', {}).get('eapol_frames', 0),
                    'total_packets': validation_result.get('details', {}).get('total_packets', 0)
                }
            
            return file_info
            
        except Exception as e:
            return {'error': f'Failed to get file info: {e}'}
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def list_capture_files(self, include_subdirs: bool = True) -> List[Dict[str, Any]]:
        """
        List all capture files with their information
        
        Args:
            include_subdirs: Whether to include files in subdirectories
            
        Returns:
            List of file information dictionaries
        """
        try:
            files_info = []
            
            # Define file patterns to look for
            patterns = ['*.cap', '*.pcap', '*.hccapx']
            
            for pattern in patterns:
                if include_subdirs:
                    files = self.capture_dir.rglob(pattern)
                else:
                    files = self.capture_dir.glob(pattern)
                
                for file_path in files:
                    if file_path.is_file():
                        file_info = self.get_capture_file_info(str(file_path))
                        if 'error' not in file_info:
                            file_info['full_path'] = str(file_path)
                            file_info['relative_path'] = str(file_path.relative_to(self.capture_dir))
                            files_info.append(file_info)
            
            # Sort by modification time (newest first)
            files_info.sort(key=lambda x: x.get('modified', datetime.min), reverse=True)
            
            self.logger.info(f"Listed {len(files_info)} capture files")
            return files_info
            
        except Exception as e:
            self.logger.error(f"Failed to list capture files: {e}")
            return []
    
    def archive_old_captures(self, days_old: int = 30, archive_format: str = 'zip') -> Dict[str, Any]:
        """
        Archive old capture files instead of deleting them
        
        Args:
            days_old: Archive files older than this many days
            archive_format: Archive format ('zip' or 'tar')
            
        Returns:
            Dictionary with archive results
        """
        try:
            import zipfile
            import tarfile
            
            archive_result = {
                'archived_files': 0,
                'archive_path': None,
                'archive_size': 0,
                'errors': []
            }
            
            cutoff_time = time.time() - (days_old * 24 * 3600)
            old_files = []
            
            # Find old files
            for file_path in self.capture_dir.rglob('*'):
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    old_files.append(file_path)
            
            if not old_files:
                self.logger.info("No old files to archive")
                return archive_result
            
            # Create archive
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if archive_format == 'zip':
                archive_path = self.capture_dir / f"archive_{timestamp}.zip"
                
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
                    for file_path in old_files:
                        try:
                            # Add file to archive with relative path
                            arcname = str(file_path.relative_to(self.capture_dir))
                            archive.write(file_path, arcname)
                            archive_result['archived_files'] += 1
                        except Exception as e:
                            error_msg = f"Failed to archive {file_path}: {e}"
                            archive_result['errors'].append(error_msg)
                            self.logger.warning(error_msg)
            
            elif archive_format == 'tar':
                archive_path = self.capture_dir / f"archive_{timestamp}.tar.gz"
                
                with tarfile.open(archive_path, 'w:gz') as archive:
                    for file_path in old_files:
                        try:
                            # Add file to archive with relative path
                            arcname = str(file_path.relative_to(self.capture_dir))
                            archive.add(file_path, arcname)
                            archive_result['archived_files'] += 1
                        except Exception as e:
                            error_msg = f"Failed to archive {file_path}: {e}"
                            archive_result['errors'].append(error_msg)
                            self.logger.warning(error_msg)
            
            # Remove original files after successful archiving
            if archive_result['archived_files'] > 0:
                for file_path in old_files:
                    try:
                        if file_path.exists():
                            file_path.unlink()
                    except Exception as e:
                        error_msg = f"Failed to remove {file_path} after archiving: {e}"
                        archive_result['errors'].append(error_msg)
                        self.logger.warning(error_msg)
                
                archive_result['archive_path'] = str(archive_path)
                archive_result['archive_size'] = archive_path.stat().st_size
                
                self.logger.info(f"Archived {archive_result['archived_files']} files to {archive_path}")
            
            return archive_result
            
        except Exception as e:
            self.logger.error(f"Archive operation failed: {e}")
            return {'archived_files': 0, 'archive_path': None, 'archive_size': 0, 'errors': [str(e)]}
    
    def cleanup_all_sessions(self) -> Dict[str, Any]:
        """
        Cleanup all active sessions and restore interfaces
        
        Returns:
            Dictionary with cleanup results
        """
        try:
            cleanup_result = {
                'stopped_sessions': 0,
                'restored_interfaces': 0,
                'errors': []
            }
            
            # Stop all active capture processes
            for session_id in list(self.capture_processes.keys()):
                try:
                    self._stop_capture_process(session_id)
                    cleanup_result['stopped_sessions'] += 1
                except Exception as e:
                    error_msg = f"Failed to stop session {session_id}: {e}"
                    cleanup_result['errors'].append(error_msg)
                    self.logger.warning(error_msg)
            
            # Restore all interfaces that were in monitor mode
            restored_interfaces = set()
            for session in self.active_sessions.values():
                if session.interface not in restored_interfaces:
                    try:
                        success, message = self.interface_manager.restore_managed_mode(session.interface)
                        if success:
                            cleanup_result['restored_interfaces'] += 1
                            restored_interfaces.add(session.interface)
                        else:
                            error_msg = f"Failed to restore interface {session.interface}: {message}"
                            cleanup_result['errors'].append(error_msg)
                            self.logger.warning(error_msg)
                    except Exception as e:
                        error_msg = f"Exception restoring interface {session.interface}: {e}"
                        cleanup_result['errors'].append(error_msg)
                        self.logger.warning(error_msg)
            
            # Clear session data
            self.active_sessions.clear()
            self.capture_processes.clear()
            self.stop_events.clear()
            
            log_operation("CLEANUP_ALL_SESSIONS", 
                        f"Stopped: {cleanup_result['stopped_sessions']}, Restored: {cleanup_result['restored_interfaces']}")
            
            return cleanup_result
            
        except Exception as e:
            self.logger.error(f"Session cleanup failed: {e}")
            return {'stopped_sessions': 0, 'restored_interfaces': 0, 'errors': [str(e)]}
    
    def validate_handshake_quality(self, capture_file: str) -> Dict[str, Any]:
        """
        Perform detailed handshake quality validation
        
        Args:
            capture_file: Path to capture file
            
        Returns:
            Dictionary with detailed quality assessment
        """
        try:
            if not validate_file_path(capture_file):
                return {
                    'quality_score': 0,
                    'issues': ['File not found or not readable'],
                    'recommendations': ['Check file path and permissions'],
                    'details': {}
                }
            
            # Start with basic validation
            basic_validation = self.validate_handshake(capture_file)
            
            quality_result = {
                'quality_score': 0,  # 0-100 score
                'issues': [],
                'recommendations': [],
                'details': basic_validation.get('details', {}),
                'basic_valid': basic_validation.get('valid', False)
            }
            
            if not quality_result['basic_valid']:
                quality_result['issues'].append('No valid handshake found')
                quality_result['recommendations'].append('Recapture handshake with better signal strength')
                return quality_result
            
            # Quality scoring based on various factors
            score = 0
            
            # Factor 1: Handshake completeness (40 points max)
            if capture_file.endswith('.cap'):
                handshake_count = quality_result['details'].get('handshake_count', 0)
                if handshake_count >= 1:
                    score += 40
                    quality_result['details']['completeness'] = 'Complete'
                else:
                    quality_result['issues'].append('Incomplete handshake')
                    quality_result['details']['completeness'] = 'Incomplete'
            
            elif capture_file.endswith('.pcap'):
                eapol_frames = quality_result['details'].get('eapol_frames', 0)
                if eapol_frames >= 4:
                    score += 40
                    quality_result['details']['completeness'] = 'Complete (4-way handshake)'
                elif eapol_frames >= 2:
                    score += 20
                    quality_result['details']['completeness'] = 'Partial (2 frames)'
                    quality_result['issues'].append('Incomplete 4-way handshake')
                else:
                    quality_result['issues'].append('Insufficient EAPOL frames')
                    quality_result['details']['completeness'] = 'Incomplete'
            
            # Factor 2: File size (20 points max)
            file_size = Path(capture_file).stat().st_size
            if file_size > 1024 * 1024:  # > 1MB
                score += 20
                quality_result['details']['size_assessment'] = 'Good size'
            elif file_size > 100 * 1024:  # > 100KB
                score += 10
                quality_result['details']['size_assessment'] = 'Adequate size'
            else:
                quality_result['issues'].append('Small capture file size')
                quality_result['details']['size_assessment'] = 'Small size'
                quality_result['recommendations'].append('Capture for longer duration')
            
            # Factor 3: Packet count (20 points max)
            total_packets = quality_result['details'].get('total_packets', 0)
            if total_packets > 1000:
                score += 20
                quality_result['details']['packet_assessment'] = 'Good packet count'
            elif total_packets > 100:
                score += 10
                quality_result['details']['packet_assessment'] = 'Adequate packet count'
            else:
                quality_result['issues'].append('Low packet count')
                quality_result['details']['packet_assessment'] = 'Low packet count'
            
            # Factor 4: Network diversity (10 points max)
            networks_found = quality_result['details'].get('networks_found', 0)
            if networks_found >= 1:
                score += 10
                quality_result['details']['network_assessment'] = 'Target network found'
            else:
                quality_result['issues'].append('Target network not clearly identified')
            
            # Factor 5: File integrity (10 points max)
            try:
                # Try to read the file with appropriate tools
                if capture_file.endswith('.cap'):
                    result = run_command(['aircrack-ng', '-c', capture_file], timeout=5)
                    if result.returncode == 0:
                        score += 10
                        quality_result['details']['integrity'] = 'Good'
                    else:
                        quality_result['issues'].append('File integrity issues')
                        quality_result['details']['integrity'] = 'Questionable'
                elif capture_file.endswith('.pcap'):
                    result = run_command(['tcpdump', '-r', capture_file, '-c', '1'], timeout=5)
                    if result.returncode == 0:
                        score += 10
                        quality_result['details']['integrity'] = 'Good'
                    else:
                        quality_result['issues'].append('File integrity issues')
                        quality_result['details']['integrity'] = 'Questionable'
            except Exception:
                quality_result['issues'].append('Cannot verify file integrity')
                quality_result['details']['integrity'] = 'Unknown'
            
            quality_result['quality_score'] = min(score, 100)
            
            # Generate recommendations based on score
            if quality_result['quality_score'] >= 80:
                quality_result['recommendations'].append('Excellent capture quality - ready for cracking')
            elif quality_result['quality_score'] >= 60:
                quality_result['recommendations'].append('Good capture quality - should work for cracking')
            elif quality_result['quality_score'] >= 40:
                quality_result['recommendations'].append('Moderate quality - may work but consider recapturing')
            else:
                quality_result['recommendations'].append('Poor quality - recommend recapturing')
            
            return quality_result
            
        except Exception as e:
            return {
                'quality_score': 0,
                'issues': [f'Quality validation failed: {e}'],
                'recommendations': ['Check file and try again'],
                'details': {},
                'basic_valid': False
            }
    
    def get_capture_statistics(self) -> Dict[str, Any]:
        """Get statistics about capture sessions"""
        try:
            all_sessions = list(self.active_sessions.values())
            
            stats = {
                'total_sessions': len(all_sessions),
                'active_sessions': len([s for s in all_sessions if s.status == "active"]),
                'completed_sessions': len([s for s in all_sessions if s.status == "completed"]),
                'failed_sessions': len([s for s in all_sessions if s.status == "failed"]),
                'successful_handshakes': len([s for s in all_sessions if s.handshake_found]),
                'methods_used': {},
                'capture_files_size': 0
            }
            
            # Method breakdown
            for session in all_sessions:
                method = session.method
                stats['methods_used'][method] = stats['methods_used'].get(method, 0) + 1
            
            # Calculate total capture files size
            try:
                for file_path in self.capture_dir.glob('*'):
                    if file_path.is_file():
                        stats['capture_files_size'] += file_path.stat().st_size
            except Exception:
                pass
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get capture statistics: {e}")
            return {}
    
    def emergency_cleanup(self) -> bool:
        """
        Emergency cleanup function to restore system state
        Use this if normal cleanup fails
        
        Returns:
            True if cleanup successful, False otherwise
        """
        try:
            self.logger.warning("Performing emergency cleanup")
            
            # Kill all capture processes forcefully
            try:
                subprocess.run(['sudo', 'pkill', '-f', 'airodump'], timeout=10)
                subprocess.run(['sudo', 'pkill', '-f', 'tcpdump'], timeout=10)
            except Exception as e:
                self.logger.warning(f"Failed to kill capture processes: {e}")
            
            # Reset all known WiFi interfaces
            try:
                interfaces = self.interface_manager.get_available_interfaces()
                for interface in interfaces:
                    try:
                        # Force interface cleanup
                        self.interface_manager.cleanup_interface(interface)
                    except Exception as e:
                        self.logger.warning(f"Failed to cleanup interface {interface}: {e}")
            except Exception as e:
                self.logger.warning(f"Failed to get interfaces for cleanup: {e}")
            
            # Clear all session data
            self.active_sessions.clear()
            self.capture_processes.clear()
            self.stop_events.clear()
            
            # Log the emergency cleanup
            log_security_event("EMERGENCY_CLEANUP", "System state forcefully restored")
            
            self.logger.info("Emergency cleanup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Emergency cleanup failed: {e}")
            return False
    
    def __del__(self):
        """Destructor to ensure cleanup on object deletion"""
        try:
            if hasattr(self, 'active_sessions') and self.active_sessions:
                self.cleanup_all_sessions()
        except Exception:
            pass  # Ignore errors during destruction
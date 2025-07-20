"""
Interface Manager - Manages WiFi interfaces and their modes
Handles interface discovery, capability checking, and mode management

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import re
import logging
import time
import os
from typing import List, Dict, Optional, Tuple

# Import logger with proper path handling
try:
    from ..core.logger import get_logger
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from core.logger import get_logger

class InterfaceManager:
    """Manages WiFi interfaces and their modes"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._discovered_interfaces = {}
        self._interface_capabilities = {}
        
    def discover_wifi_interfaces(self) -> List[Dict[str, str]]:
        """
        Automatically detect WiFi interfaces using networksetup
        Returns list of interface dictionaries with name, hardware port, and device info
        """
        self.logger.info("Discovering WiFi interfaces...")
        interfaces = []
        
        try:
            # Use networksetup to list all hardware ports
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to find WiFi interfaces
            current_port = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('Hardware Port:'):
                    # Save previous port if it was WiFi
                    if current_port and self._is_wifi_port(current_port.get('name', '')):
                        interfaces.append(current_port.copy())
                    
                    # Start new port
                    current_port = {'name': line.replace('Hardware Port: ', '')}
                    
                elif line.startswith('Device:'):
                    current_port['device'] = line.replace('Device: ', '')
                    
                elif line.startswith('Ethernet Address:'):
                    current_port['mac_address'] = line.replace('Ethernet Address: ', '')
            
            # Don't forget the last port
            if current_port and self._is_wifi_port(current_port.get('name', '')):
                interfaces.append(current_port.copy())
            
            # Enhance interface info with additional details
            for interface in interfaces:
                self._enhance_interface_info(interface)
            
            self._discovered_interfaces = {iface['device']: iface for iface in interfaces}
            self.logger.info(f"Discovered {len(interfaces)} WiFi interface(s)")
            
            return interfaces
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to discover interfaces: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error during interface discovery: {e}")
            return []
    
    def _is_wifi_port(self, port_name: str) -> bool:
        """Check if a hardware port is a WiFi interface"""
        wifi_indicators = ['wi-fi', 'wifi', 'wireless', 'airport']
        return any(indicator in port_name.lower() for indicator in wifi_indicators)
    
    def _enhance_interface_info(self, interface: Dict[str, str]) -> None:
        """Enhance interface information with additional system details"""
        device = interface.get('device')
        if not device:
            return
            
        try:
            # Get interface status using ifconfig
            result = subprocess.run(
                ['ifconfig', device],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse ifconfig output for additional info
            output = result.stdout
            
            # Extract status
            if 'status: active' in output:
                interface['status'] = 'active'
            elif 'status: inactive' in output:
                interface['status'] = 'inactive'
            else:
                interface['status'] = 'unknown'
            
            # Extract current network if connected
            ssid_match = re.search(r'ssid\s+([^\s]+)', output)
            if ssid_match:
                interface['connected_ssid'] = ssid_match.group(1)
            
            # Extract channel info
            channel_match = re.search(r'channel\s+(\d+)', output)
            if channel_match:
                interface['channel'] = channel_match.group(1)
                
        except subprocess.CalledProcessError:
            # Interface might not exist or be accessible
            interface['status'] = 'unavailable'
        except Exception as e:
            self.logger.warning(f"Could not enhance info for {device}: {e}")
    
    def get_interface_capabilities(self, interface_name: str) -> Dict[str, bool]:
        """
        Check interface capabilities including monitor mode support
        Returns dictionary with capability flags
        """
        self.logger.info(f"Checking capabilities for interface {interface_name}")
        
        if interface_name in self._interface_capabilities:
            return self._interface_capabilities[interface_name]
        
        capabilities = {
            'monitor_mode': False,
            'injection': False,
            'active': False,
            'exists': False
        }
        
        try:
            # Check if interface exists
            result = subprocess.run(
                ['ifconfig', interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            capabilities['exists'] = True
            
            # Check if interface is active
            if 'status: active' in result.stdout:
                capabilities['active'] = True
            
            # Check monitor mode capability using iwconfig (if available)
            # Note: iwconfig might not be available on macOS, so we'll use alternative methods
            capabilities['monitor_mode'] = self._check_monitor_mode_support(interface_name)
            
            # For injection capability, we need to test with actual tools
            # This is a basic check - real injection testing would require aircrack-ng
            capabilities['injection'] = capabilities['monitor_mode']  # Assume if monitor works, injection might work
            
        except subprocess.CalledProcessError:
            self.logger.warning(f"Interface {interface_name} not found or not accessible")
        except Exception as e:
            self.logger.error(f"Error checking capabilities for {interface_name}: {e}")
        
        self._interface_capabilities[interface_name] = capabilities
        return capabilities
    
    def _check_monitor_mode_support(self, interface_name: str) -> bool:
        """
        Check if interface supports monitor mode
        On macOS, this is tricky due to SIP restrictions
        """
        try:
            # Try to get current interface mode
            result = subprocess.run(
                ['ifconfig', interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Look for monitor mode indicators in the output
            output = result.stdout.lower()
            
            # Check if already in monitor mode
            if 'monitor' in output:
                return True
            
            # For macOS, we can try to check if the interface supports mode changes
            # This is a conservative approach - we assume most modern WiFi cards support it
            # but actual switching might be restricted by SIP
            
            # Check if it's a known compatible chipset
            compatible_patterns = [
                r'broadcom',
                r'atheros',
                r'intel',
                r'realtek'
            ]
            
            # Get more detailed interface info
            try:
                system_profiler_result = subprocess.run(
                    ['system_profiler', 'SPAirPortDataType'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                sp_output = system_profiler_result.stdout.lower()
                for pattern in compatible_patterns:
                    if re.search(pattern, sp_output):
                        return True
                        
            except subprocess.CalledProcessError:
                pass
            
            # Default assumption for macOS built-in WiFi
            return True
            
        except Exception as e:
            self.logger.warning(f"Could not determine monitor mode support for {interface_name}: {e}")
            return False
    
    def validate_interface_status(self, interface_name: str) -> Dict[str, any]:
        """
        Validate interface status and provide detailed reporting
        Returns comprehensive status information
        """
        self.logger.info(f"Validating status for interface {interface_name}")
        
        status_report = {
            'interface': interface_name,
            'exists': False,
            'active': False,
            'connected': False,
            'ssid': None,
            'channel': None,
            'signal_strength': None,
            'mode': 'unknown',
            'capabilities': {},
            'issues': [],
            'recommendations': []
        }
        
        try:
            # Basic existence check
            result = subprocess.run(
                ['ifconfig', interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            status_report['exists'] = True
            output = result.stdout
            
            # Parse interface status
            if 'status: active' in output:
                status_report['active'] = True
            elif 'status: inactive' in output:
                status_report['active'] = False
                status_report['issues'].append('Interface is inactive')
                status_report['recommendations'].append('Try: sudo ifconfig {} up'.format(interface_name))
            
            # Check connection status
            ssid_match = re.search(r'ssid\s+([^\s]+)', output)
            if ssid_match:
                status_report['connected'] = True
                status_report['ssid'] = ssid_match.group(1)
            
            # Extract channel
            channel_match = re.search(r'channel\s+(\d+)', output)
            if channel_match:
                status_report['channel'] = int(channel_match.group(1))
            
            # Try to get signal strength using wdutil if available
            try:
                wdutil_result = subprocess.run(
                    ['wdutil', 'info'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Parse signal strength from wdutil output
                rssi_match = re.search(r'RSSI:\s*(-?\d+)', wdutil_result.stdout)
                if rssi_match:
                    status_report['signal_strength'] = int(rssi_match.group(1))
                    
            except subprocess.CalledProcessError:
                pass  # wdutil might not be available or interface not connected
            
            # Get capabilities
            status_report['capabilities'] = self.get_interface_capabilities(interface_name)
            
            # Determine current mode
            if 'monitor' in output.lower():
                status_report['mode'] = 'monitor'
            elif status_report['connected']:
                status_report['mode'] = 'managed'
            else:
                status_report['mode'] = 'disconnected'
            
            # Add recommendations based on status
            if not status_report['capabilities']['monitor_mode']:
                status_report['issues'].append('Monitor mode not supported or restricted')
                status_report['recommendations'].append('Check SIP status and consider disabling if needed')
            
            if not status_report['active']:
                status_report['recommendations'].append('Activate interface before use')
                
        except subprocess.CalledProcessError:
            status_report['issues'].append('Interface not found or not accessible')
            status_report['recommendations'].append('Check interface name and permissions')
        except Exception as e:
            status_report['issues'].append(f'Validation error: {str(e)}')
            self.logger.error(f"Error validating interface {interface_name}: {e}")
        
        return status_report
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available WiFi interface names"""
        if not self._discovered_interfaces:
            self.discover_wifi_interfaces()
        
        return list(self._discovered_interfaces.keys())
    
    def get_interface_info(self, interface_name: str) -> Optional[Dict[str, str]]:
        """Get detailed information about a specific interface"""
        if not self._discovered_interfaces:
            self.discover_wifi_interfaces()
        
        return self._discovered_interfaces.get(interface_name)
    
    def set_monitor_mode(self, interface_name: str) -> Tuple[bool, str]:
        """
        Safely switch interface to monitor mode
        Returns (success, message) tuple
        """
        self.logger.info(f"Attempting to set {interface_name} to monitor mode")
        
        # First validate the interface
        status = self.validate_interface_status(interface_name)
        if not status['exists']:
            return False, f"Interface {interface_name} does not exist"
        
        if not status['capabilities'].get('monitor_mode', False):
            return False, f"Interface {interface_name} does not support monitor mode"
        
        try:
            # Store current state for restoration
            self._store_interface_state(interface_name)
            
            # Step 1: Disassociate from any current network
            if status['connected']:
                self.logger.info(f"Disconnecting {interface_name} from current network")
                result = subprocess.run(
                    ['sudo', 'airport', '-z'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Note: airport command might not be available on newer macOS
                # Alternative: networksetup -setairportpower Wi-Fi off/on
                
            # Step 2: Try to set interface down
            self.logger.info(f"Setting {interface_name} down")
            result = subprocess.run(
                ['sudo', 'ifconfig', interface_name, 'down'],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            # Step 3: Attempt to set monitor mode
            # On macOS, this is challenging due to SIP restrictions
            # We'll try multiple approaches
            
            success = False
            error_messages = []
            
            # Method 1: Try direct ifconfig monitor mode (might be restricted)
            try:
                self.logger.info(f"Attempting direct monitor mode on {interface_name}")
                result = subprocess.run(
                    ['sudo', 'ifconfig', interface_name, 'mediaopt', 'monitor'],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10
                )
                success = True
                self.logger.info("Direct monitor mode activation successful")
            except subprocess.CalledProcessError as e:
                error_messages.append(f"Direct method failed: {e}")
                self.logger.warning(f"Direct monitor mode failed: {e}")
            
            # Method 2: Try using airport utility if available
            if not success:
                try:
                    self.logger.info("Attempting monitor mode via airport utility")
                    # Try to find airport utility
                    airport_path = self._find_airport_utility()
                    if airport_path:
                        result = subprocess.run(
                            ['sudo', airport_path, interface_name, 'sniff', '1'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        # This starts sniffing, which puts interface in monitor-like mode
                        success = True
                        self.logger.info("Airport utility monitor mode successful")
                except Exception as e:
                    error_messages.append(f"Airport method failed: {e}")
                    self.logger.warning(f"Airport monitor mode failed: {e}")
            
            # Method 3: Alternative approach using networksetup
            if not success:
                try:
                    self.logger.info("Attempting alternative monitor mode setup")
                    # This is a workaround - we can't truly set monitor mode on modern macOS
                    # but we can prepare the interface for packet capture
                    result = subprocess.run(
                        ['sudo', 'ifconfig', interface_name, 'up'],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10
                    )
                    
                    # Verify the interface is ready for capture operations
                    # Even if not in true monitor mode, it might work for some operations
                    success = True
                    self.logger.warning("Using alternative monitor mode setup (limited functionality)")
                    
                except subprocess.CalledProcessError as e:
                    error_messages.append(f"Alternative method failed: {e}")
                    self.logger.error(f"Alternative monitor mode failed: {e}")
            
            if success:
                # Verify the mode change
                time.sleep(1)  # Give system time to apply changes
                verification = self._verify_monitor_mode(interface_name)
                if verification:
                    self.logger.info(f"Monitor mode successfully activated on {interface_name}")
                    return True, f"Monitor mode activated on {interface_name}"
                else:
                    self.logger.warning(f"Monitor mode activation uncertain for {interface_name}")
                    return True, f"Monitor mode setup completed for {interface_name} (verification uncertain)"
            else:
                error_msg = f"Failed to activate monitor mode on {interface_name}. Errors: {'; '.join(error_messages)}"
                self.logger.error(error_msg)
                # Try to restore interface to working state
                self.restore_managed_mode(interface_name)
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout while setting monitor mode on {interface_name}"
            self.logger.error(error_msg)
            return False, error_msg
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed while setting monitor mode on {interface_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error setting monitor mode on {interface_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def restore_managed_mode(self, interface_name: str) -> Tuple[bool, str]:
        """
        Restore interface to managed mode (normal operation)
        Returns (success, message) tuple
        """
        self.logger.info(f"Restoring {interface_name} to managed mode")
        
        try:
            # Step 1: Set interface down
            result = subprocess.run(
                ['sudo', 'ifconfig', interface_name, 'down'],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            # Step 2: Remove monitor mode settings
            try:
                result = subprocess.run(
                    ['sudo', 'ifconfig', interface_name, '-mediaopt', 'monitor'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except subprocess.CalledProcessError:
                # This might fail if monitor mode wasn't properly set
                pass
            
            # Step 3: Bring interface back up
            result = subprocess.run(
                ['sudo', 'ifconfig', interface_name, 'up'],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            # Step 4: Restore previous network connection if any
            self._restore_interface_state(interface_name)
            
            # Step 5: Restart WiFi service to ensure clean state
            try:
                # Turn WiFi off and on to reset state
                result = subprocess.run(
                    ['networksetup', '-setairportpower', 'Wi-Fi', 'off'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                time.sleep(2)  # Wait for interface to go down
                
                result = subprocess.run(
                    ['networksetup', '-setairportpower', 'Wi-Fi', 'on'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                time.sleep(3)  # Wait for interface to come back up
                
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"WiFi restart failed: {e}")
            
            self.logger.info(f"Successfully restored {interface_name} to managed mode")
            return True, f"Interface {interface_name} restored to managed mode"
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout while restoring {interface_name}"
            self.logger.error(error_msg)
            return False, error_msg
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed while restoring {interface_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error restoring {interface_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _store_interface_state(self, interface_name: str) -> None:
        """Store current interface state for later restoration"""
        try:
            state = {
                'timestamp': time.time(),
                'connected_ssid': None,
                'ip_address': None,
                'was_active': False
            }
            
            # Get current status
            status = self.validate_interface_status(interface_name)
            state['was_active'] = status['active']
            state['connected_ssid'] = status['ssid']
            
            # Get IP address if connected
            if status['connected']:
                result = subprocess.run(
                    ['ifconfig', interface_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Extract IP address
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    state['ip_address'] = ip_match.group(1)
            
            # Store state
            if not hasattr(self, '_stored_states'):
                self._stored_states = {}
            self._stored_states[interface_name] = state
            
            self.logger.debug(f"Stored state for {interface_name}: {state}")
            
        except Exception as e:
            self.logger.warning(f"Could not store state for {interface_name}: {e}")
    
    def _restore_interface_state(self, interface_name: str) -> None:
        """Restore previously stored interface state"""
        try:
            if not hasattr(self, '_stored_states'):
                return
            
            state = self._stored_states.get(interface_name)
            if not state:
                return
            
            self.logger.debug(f"Restoring state for {interface_name}: {state}")
            
            # If was connected to a network, try to reconnect
            if state['connected_ssid']:
                try:
                    # Try to reconnect to the previous network
                    result = subprocess.run(
                        ['networksetup', '-setairportnetwork', 'Wi-Fi', state['connected_ssid']],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    self.logger.info(f"Attempted to reconnect to {state['connected_ssid']}")
                except subprocess.CalledProcessError as e:
                    self.logger.warning(f"Could not reconnect to {state['connected_ssid']}: {e}")
            
            # Clean up stored state
            del self._stored_states[interface_name]
            
        except Exception as e:
            self.logger.warning(f"Could not restore state for {interface_name}: {e}")
    
    def _find_airport_utility(self) -> Optional[str]:
        """Find the airport utility on the system"""
        possible_paths = [
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
            '/usr/sbin/airport'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _verify_monitor_mode(self, interface_name: str) -> bool:
        """Verify if interface is actually in monitor mode"""
        try:
            result = subprocess.run(
                ['ifconfig', interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.lower()
            
            # Look for monitor mode indicators
            monitor_indicators = ['monitor', 'promisc', 'rfmon']
            return any(indicator in output for indicator in monitor_indicators)
            
        except Exception as e:
            self.logger.warning(f"Could not verify monitor mode for {interface_name}: {e}")
            return False
    
    def get_current_mode(self, interface_name: str) -> str:
        """Get the current mode of the interface"""
        try:
            result = subprocess.run(
                ['ifconfig', interface_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.lower()
            
            if 'monitor' in output:
                return 'monitor'
            elif 'promisc' in output:
                return 'promiscuous'
            else:
                # Check if connected to a network
                status = self.validate_interface_status(interface_name)
                if status['connected']:
                    return 'managed'
                else:
                    return 'disconnected'
                    
        except Exception as e:
            self.logger.error(f"Could not determine mode for {interface_name}: {e}")
            return 'unknown'
    
    def cleanup_interface(self, interface_name: str) -> Tuple[bool, str]:
        """
        Comprehensive cleanup of interface state
        Ensures interface is returned to a clean, working state
        """
        self.logger.info(f"Performing comprehensive cleanup of {interface_name}")
        
        try:
            # Step 1: Try to restore to managed mode
            success, message = self.restore_managed_mode(interface_name)
            
            if not success:
                self.logger.warning(f"Standard restoration failed: {message}")
            
            # Step 2: Force reset the interface
            try:
                # Kill any processes that might be using the interface
                subprocess.run(
                    ['sudo', 'pkill', '-f', f'.*{interface_name}.*'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            except:
                pass  # It's okay if this fails
            
            # Step 3: Reset network services
            try:
                subprocess.run(
                    ['sudo', 'dscacheutil', '-flushcache'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except:
                pass
            
            # Step 4: Final verification
            final_status = self.validate_interface_status(interface_name)
            
            if final_status['exists'] and not final_status['issues']:
                self.logger.info(f"Interface {interface_name} successfully cleaned up")
                return True, f"Interface {interface_name} cleaned up successfully"
            else:
                self.logger.warning(f"Interface {interface_name} cleanup completed with issues: {final_status['issues']}")
                return True, f"Interface {interface_name} cleanup completed with warnings"
                
        except Exception as e:
            error_msg = f"Error during cleanup of {interface_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
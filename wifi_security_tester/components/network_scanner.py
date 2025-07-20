"""
Network Scanner - Modern WiFi network scanning for macOS
Implements wdutil-based scanning with fallback methods

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import json
import re
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.logger import get_logger
from utils.common import run_command


@dataclass
class NetworkInfo:
    """Data model for WiFi network information"""
    ssid: str
    bssid: str
    channel: int
    frequency: str
    signal_strength: int
    encryption_type: str
    cipher: str
    authentication: str
    vendor: str = ""
    first_seen: datetime = None
    last_seen: datetime = None
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()


class NetworkScanner:
    """Modern WiFi network scanner for macOS"""
    
    def __init__(self):
        self.logger = get_logger("network_scanner")
        self.networks: Dict[str, NetworkInfo] = {}
        self.last_scan_time: Optional[datetime] = None
        
    def scan_networks(self) -> List[NetworkInfo]:
        """
        Scan for available WiFi networks using modern macOS methods
        
        Returns:
            List of NetworkInfo objects representing discovered networks
        """
        self.logger.info("Starting network scan")
        
        # Try wdutil first (modern method)
        networks = self._scan_with_wdutil()
        
        # Fallback to system_profiler if wdutil fails
        if not networks:
            self.logger.warning("wdutil scan failed, trying system_profiler fallback")
            networks = self._scan_with_system_profiler()
        
        # Update internal network database
        self._update_network_database(networks)
        
        self.last_scan_time = datetime.now()
        self.logger.info(f"Network scan completed, found {len(networks)} networks")
        
        return networks
    
    def _scan_with_wdutil(self) -> List[NetworkInfo]:
        """
        Scan networks using wdutil (modern macOS WiFi diagnostics tool)
        
        Returns:
            List of NetworkInfo objects
        """
        try:
            self.logger.debug("Attempting wdutil scan")
            
            # Run wdutil scan command
            result = run_command(['wdutil', 'scan'], timeout=30)
            
            if result.returncode != 0:
                self.logger.error(f"wdutil scan failed: {result.stderr}")
                return []
            
            # Parse wdutil output
            networks = self._parse_wdutil_output(result.stdout)
            self.logger.debug(f"wdutil found {len(networks)} networks")
            
            return networks
            
        except Exception as e:
            self.logger.error(f"wdutil scan error: {e}")
            return []
    
    def _scan_with_system_profiler(self) -> List[NetworkInfo]:
        """
        Fallback scanning using system_profiler
        
        Returns:
            List of NetworkInfo objects
        """
        try:
            self.logger.debug("Attempting system_profiler scan")
            
            # Run system_profiler command
            result = run_command(['system_profiler', 'SPAirPortDataType', '-json'], timeout=30)
            
            if result.returncode != 0:
                self.logger.error(f"system_profiler scan failed: {result.stderr}")
                return []
            
            # Parse system_profiler output
            networks = self._parse_system_profiler_output(result.stdout)
            self.logger.debug(f"system_profiler found {len(networks)} networks")
            
            return networks
            
        except Exception as e:
            self.logger.error(f"system_profiler scan error: {e}")
            return []
    
    def _parse_wdutil_output(self, output: str) -> List[NetworkInfo]:
        """
        Parse wdutil scan output into NetworkInfo objects
        
        Args:
            output: Raw wdutil output string
            
        Returns:
            List of NetworkInfo objects
        """
        networks = []
        
        try:
            # wdutil output format parsing
            lines = output.strip().split('\n')
            current_network = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Look for network entries
                if 'SSID:' in line:
                    if current_network:
                        network = self._create_network_from_wdutil_data(current_network)
                        if network:
                            networks.append(network)
                    current_network = {'ssid': line.split('SSID:')[1].strip()}
                
                elif 'BSSID:' in line:
                    current_network['bssid'] = line.split('BSSID:')[1].strip()
                
                elif 'Channel:' in line:
                    try:
                        channel_str = line.split('Channel:')[1].strip()
                        current_network['channel'] = int(re.search(r'\d+', channel_str).group())
                    except (ValueError, AttributeError):
                        current_network['channel'] = 0
                
                elif 'RSSI:' in line:
                    try:
                        rssi_str = line.split('RSSI:')[1].strip()
                        current_network['signal_strength'] = int(re.search(r'-?\d+', rssi_str).group())
                    except (ValueError, AttributeError):
                        current_network['signal_strength'] = -100
                
                elif 'Security:' in line:
                    current_network['encryption_type'] = line.split('Security:')[1].strip()
            
            # Process last network
            if current_network:
                network = self._create_network_from_wdutil_data(current_network)
                if network:
                    networks.append(network)
                    
        except Exception as e:
            self.logger.error(f"Error parsing wdutil output: {e}")
        
        return networks
    
    def _parse_system_profiler_output(self, output: str) -> List[NetworkInfo]:
        """
        Parse system_profiler JSON output into NetworkInfo objects
        
        Args:
            output: Raw system_profiler JSON output
            
        Returns:
            List of NetworkInfo objects
        """
        networks = []
        
        try:
            data = json.loads(output)
            
            # Navigate through system_profiler JSON structure
            for item in data.get('SPAirPortDataType', []):
                interfaces = item.get('spairport_airport_interfaces', [])
                
                for interface in interfaces:
                    scan_results = interface.get('spairport_scan_results', [])
                    
                    for network_data in scan_results:
                        network = self._create_network_from_profiler_data(network_data)
                        if network:
                            networks.append(network)
                            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"Error parsing system_profiler output: {e}")
        
        return networks
    
    def _create_network_from_wdutil_data(self, data: Dict[str, Any]) -> Optional[NetworkInfo]:
        """Create NetworkInfo from wdutil parsed data"""
        try:
            # Extract required fields with defaults
            ssid = data.get('ssid', 'Unknown')
            bssid = data.get('bssid', '00:00:00:00:00:00')
            channel = data.get('channel', 0)
            signal_strength = data.get('signal_strength', -100)
            encryption_type = data.get('encryption_type', 'Unknown')
            
            # Skip networks with invalid data
            if ssid == 'Unknown' or bssid == '00:00:00:00:00:00':
                return None
            
            # Calculate frequency from channel
            frequency = self._channel_to_frequency(channel)
            
            # Parse encryption details
            cipher, auth = self._parse_encryption_details(encryption_type)
            
            return NetworkInfo(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                frequency=frequency,
                signal_strength=signal_strength,
                encryption_type=encryption_type,
                cipher=cipher,
                authentication=auth,
                vendor=self._get_vendor_from_bssid(bssid)
            )
            
        except Exception as e:
            self.logger.error(f"Error creating network from wdutil data: {e}")
            return None
    
    def _create_network_from_profiler_data(self, data: Dict[str, Any]) -> Optional[NetworkInfo]:
        """Create NetworkInfo from system_profiler data"""
        try:
            ssid = data.get('_name', 'Unknown')
            bssid = data.get('spairport_network_bssid', '00:00:00:00:00:00')
            channel = int(data.get('spairport_network_channel', 0))
            signal_strength = int(data.get('spairport_signal_noise', {}).get('spairport_signal', -100))
            encryption_type = data.get('spairport_security_mode', 'Unknown')
            
            # Skip networks with invalid data
            if ssid == 'Unknown' or bssid == '00:00:00:00:00:00':
                return None
            
            frequency = self._channel_to_frequency(channel)
            cipher, auth = self._parse_encryption_details(encryption_type)
            
            return NetworkInfo(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                frequency=frequency,
                signal_strength=signal_strength,
                encryption_type=encryption_type,
                cipher=cipher,
                authentication=auth,
                vendor=self._get_vendor_from_bssid(bssid)
            )
            
        except Exception as e:
            self.logger.error(f"Error creating network from profiler data: {e}")
            return None
    
    def _channel_to_frequency(self, channel: int) -> str:
        """Convert WiFi channel to frequency"""
        if 1 <= channel <= 14:
            # 2.4 GHz band
            if channel == 14:
                return "2484 MHz"
            else:
                return f"{2412 + (channel - 1) * 5} MHz"
        elif 36 <= channel <= 165:
            # 5 GHz band
            return f"{5000 + channel * 5} MHz"
        else:
            return "Unknown"
    
    def _parse_encryption_details(self, encryption_type: str) -> tuple:
        """Parse encryption type into cipher and authentication"""
        encryption_lower = encryption_type.lower()
        
        if 'wpa3' in encryption_lower:
            return 'AES', 'WPA3'
        elif 'wpa2' in encryption_lower:
            if 'aes' in encryption_lower:
                return 'AES', 'WPA2'
            elif 'tkip' in encryption_lower:
                return 'TKIP', 'WPA2'
            else:
                return 'AES', 'WPA2'
        elif 'wpa' in encryption_lower:
            return 'TKIP', 'WPA'
        elif 'wep' in encryption_lower:
            return 'WEP', 'WEP'
        elif 'none' in encryption_lower or 'open' in encryption_lower:
            return 'None', 'Open'
        else:
            return 'Unknown', 'Unknown'
    
    def _get_vendor_from_bssid(self, bssid: str) -> str:
        """Get vendor information from BSSID (simplified implementation)"""
        # This is a simplified implementation
        # In a full implementation, you'd use an OUI database
        oui = bssid[:8].upper()
        
        vendor_map = {
            '00:1B:63': 'Apple',
            '00:23:DF': 'Apple',
            '00:26:BB': 'Apple',
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '08:00:27': 'VirtualBox',
        }
        
        return vendor_map.get(oui, 'Unknown')
    
    def _update_network_database(self, networks: List[NetworkInfo]):
        """Update internal network database with scan results"""
        current_time = datetime.now()
        
        for network in networks:
            key = f"{network.ssid}_{network.bssid}"
            
            if key in self.networks:
                # Update existing network
                existing = self.networks[key]
                existing.last_seen = current_time
                existing.signal_strength = network.signal_strength
            else:
                # Add new network
                network.first_seen = current_time
                network.last_seen = current_time
                self.networks[key] = network
    
    def get_network_details(self, ssid: str) -> Optional[NetworkInfo]:
        """
        Get detailed information about a specific network
        
        Args:
            ssid: Network SSID to look up
            
        Returns:
            NetworkInfo object if found, None otherwise
        """
        for network in self.networks.values():
            if network.ssid == ssid:
                return network
        return None
    
    def get_all_networks(self) -> List[NetworkInfo]:
        """Get all discovered networks"""
        return list(self.networks.values())
    
    def clear_network_database(self):
        """Clear the internal network database"""
        self.networks.clear()
        self.logger.info("Network database cleared")
    
    def sort_networks_by_signal_strength(self, networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Sort networks by signal strength (strongest first)
        
        Args:
            networks: List of networks to sort, uses all networks if None
            
        Returns:
            Sorted list of NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        sorted_networks = sorted(networks, key=lambda n: n.signal_strength, reverse=True)
        self.logger.debug(f"Sorted {len(sorted_networks)} networks by signal strength")
        
        return sorted_networks
    
    def filter_networks_by_encryption(self, encryption_types: List[str], 
                                    networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Filter networks by encryption type
        
        Args:
            encryption_types: List of encryption types to include (e.g., ['WPA2', 'WPA3'])
            networks: List of networks to filter, uses all networks if None
            
        Returns:
            Filtered list of NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        # Normalize encryption types for comparison
        normalized_types = [enc.lower() for enc in encryption_types]
        
        filtered_networks = []
        for network in networks:
            network_enc = network.encryption_type.lower()
            if any(enc_type in network_enc for enc_type in normalized_types):
                filtered_networks.append(network)
        
        self.logger.debug(f"Filtered to {len(filtered_networks)} networks with encryption types: {encryption_types}")
        return filtered_networks
    
    def filter_networks_by_signal_strength(self, min_strength: int = -70, 
                                         networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Filter networks by minimum signal strength
        
        Args:
            min_strength: Minimum signal strength in dBm (default: -70)
            networks: List of networks to filter, uses all networks if None
            
        Returns:
            Filtered list of NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        filtered_networks = [n for n in networks if n.signal_strength >= min_strength]
        self.logger.debug(f"Filtered to {len(filtered_networks)} networks with signal >= {min_strength} dBm")
        
        return filtered_networks
    
    def filter_networks_by_channel(self, channels: List[int], 
                                 networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Filter networks by channel numbers
        
        Args:
            channels: List of channel numbers to include
            networks: List of networks to filter, uses all networks if None
            
        Returns:
            Filtered list of NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        filtered_networks = [n for n in networks if n.channel in channels]
        self.logger.debug(f"Filtered to {len(filtered_networks)} networks on channels: {channels}")
        
        return filtered_networks
    
    def filter_networks_by_band(self, band: str, networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Filter networks by frequency band
        
        Args:
            band: Frequency band ('2.4GHz' or '5GHz')
            networks: List of networks to filter, uses all networks if None
            
        Returns:
            Filtered list of NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        filtered_networks = []
        for network in networks:
            if band == '2.4GHz' and 1 <= network.channel <= 14:
                filtered_networks.append(network)
            elif band == '5GHz' and 36 <= network.channel <= 165:
                filtered_networks.append(network)
        
        self.logger.debug(f"Filtered to {len(filtered_networks)} networks in {band} band")
        return filtered_networks
    
    def search_networks_by_ssid(self, ssid_pattern: str, 
                               networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        """
        Search networks by SSID pattern (case-insensitive)
        
        Args:
            ssid_pattern: Pattern to search for in SSID
            networks: List of networks to search, uses all networks if None
            
        Returns:
            List of matching NetworkInfo objects
        """
        if networks is None:
            networks = list(self.networks.values())
        
        pattern_lower = ssid_pattern.lower()
        matching_networks = [n for n in networks if pattern_lower in n.ssid.lower()]
        
        self.logger.debug(f"Found {len(matching_networks)} networks matching SSID pattern: {ssid_pattern}")
        return matching_networks
    
    def get_networks_by_criteria(self, 
                               encryption_types: List[str] = None,
                               min_signal_strength: int = None,
                               channels: List[int] = None,
                               band: str = None,
                               ssid_pattern: str = None,
                               sort_by_signal: bool = True) -> List[NetworkInfo]:
        """
        Get networks filtered by multiple criteria
        
        Args:
            encryption_types: List of encryption types to include
            min_signal_strength: Minimum signal strength in dBm
            channels: List of channel numbers to include
            band: Frequency band ('2.4GHz' or '5GHz')
            ssid_pattern: Pattern to search for in SSID
            sort_by_signal: Whether to sort by signal strength
            
        Returns:
            Filtered and optionally sorted list of NetworkInfo objects
        """
        networks = list(self.networks.values())
        
        # Apply filters sequentially
        if encryption_types:
            networks = self.filter_networks_by_encryption(encryption_types, networks)
        
        if min_signal_strength is not None:
            networks = self.filter_networks_by_signal_strength(min_signal_strength, networks)
        
        if channels:
            networks = self.filter_networks_by_channel(channels, networks)
        
        if band:
            networks = self.filter_networks_by_band(band, networks)
        
        if ssid_pattern:
            networks = self.search_networks_by_ssid(ssid_pattern, networks)
        
        # Sort if requested
        if sort_by_signal:
            networks = self.sort_networks_by_signal_strength(networks)
        
        self.logger.info(f"Applied filters, returning {len(networks)} networks")
        return networks
    
    def save_scan_results(self, file_path: str, networks: List[NetworkInfo] = None) -> bool:
        """
        Save scan results to a JSON file
        
        Args:
            file_path: Path to save the results
            networks: List of networks to save, uses all networks if None
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if networks is None:
                networks = list(self.networks.values())
            
            # Convert networks to serializable format
            data = {
                'scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
                'total_networks': len(networks),
                'networks': []
            }
            
            for network in networks:
                network_data = asdict(network)
                # Convert datetime objects to ISO format
                network_data['first_seen'] = network.first_seen.isoformat()
                network_data['last_seen'] = network.last_seen.isoformat()
                data['networks'].append(network_data)
            
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved {len(networks)} networks to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save scan results: {e}")
            return False
    
    def load_scan_results(self, file_path: str) -> bool:
        """
        Load scan results from a JSON file
        
        Args:
            file_path: Path to load the results from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Clear existing networks
            self.networks.clear()
            
            # Load networks
            for network_data in data.get('networks', []):
                # Convert datetime strings back to datetime objects
                network_data['first_seen'] = datetime.fromisoformat(network_data['first_seen'])
                network_data['last_seen'] = datetime.fromisoformat(network_data['last_seen'])
                
                network = NetworkInfo(**network_data)
                key = f"{network.ssid}_{network.bssid}"
                self.networks[key] = network
            
            # Update last scan time
            if data.get('scan_time'):
                self.last_scan_time = datetime.fromisoformat(data['scan_time'])
            
            self.logger.info(f"Loaded {len(self.networks)} networks from {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load scan results: {e}")
            return False
    
    def export_networks_csv(self, file_path: str, networks: List[NetworkInfo] = None) -> bool:
        """
        Export networks to CSV format
        
        Args:
            file_path: Path to save the CSV file
            networks: List of networks to export, uses all networks if None
            
        Returns:
            True if successful, False otherwise
        """
        try:
            import csv
            
            if networks is None:
                networks = list(self.networks.values())
            
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'SSID', 'BSSID', 'Channel', 'Frequency', 'Signal Strength (dBm)',
                    'Encryption Type', 'Cipher', 'Authentication', 'Vendor',
                    'First Seen', 'Last Seen'
                ])
                
                # Write network data
                for network in networks:
                    writer.writerow([
                        network.ssid,
                        network.bssid,
                        network.channel,
                        network.frequency,
                        network.signal_strength,
                        network.encryption_type,
                        network.cipher,
                        network.authentication,
                        network.vendor,
                        network.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                        network.last_seen.strftime('%Y-%m-%d %H:%M:%S')
                    ])
            
            self.logger.info(f"Exported {len(networks)} networks to CSV: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export networks to CSV: {e}")
            return False
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about discovered networks
        
        Returns:
            Dictionary with network statistics
        """
        networks = list(self.networks.values())
        
        if not networks:
            return {
                'total_networks': 0,
                'encryption_breakdown': {},
                'channel_distribution': {},
                'signal_strength_ranges': {},
                'band_distribution': {}
            }
        
        # Encryption type breakdown
        encryption_count = {}
        for network in networks:
            enc_type = network.authentication
            encryption_count[enc_type] = encryption_count.get(enc_type, 0) + 1
        
        # Channel distribution
        channel_count = {}
        for network in networks:
            channel = network.channel
            channel_count[channel] = channel_count.get(channel, 0) + 1
        
        # Signal strength ranges
        signal_ranges = {
            'Excellent (>= -30 dBm)': 0,
            'Good (-30 to -50 dBm)': 0,
            'Fair (-50 to -70 dBm)': 0,
            'Poor (< -70 dBm)': 0
        }
        
        for network in networks:
            signal = network.signal_strength
            if signal >= -30:
                signal_ranges['Excellent (>= -30 dBm)'] += 1
            elif signal >= -50:
                signal_ranges['Good (-30 to -50 dBm)'] += 1
            elif signal >= -70:
                signal_ranges['Fair (-50 to -70 dBm)'] += 1
            else:
                signal_ranges['Poor (< -70 dBm)'] += 1
        
        # Band distribution
        band_count = {'2.4GHz': 0, '5GHz': 0, 'Unknown': 0}
        for network in networks:
            if 1 <= network.channel <= 14:
                band_count['2.4GHz'] += 1
            elif 36 <= network.channel <= 165:
                band_count['5GHz'] += 1
            else:
                band_count['Unknown'] += 1
        
        return {
            'total_networks': len(networks),
            'encryption_breakdown': encryption_count,
            'channel_distribution': channel_count,
            'signal_strength_ranges': signal_ranges,
            'band_distribution': band_count,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None
        }
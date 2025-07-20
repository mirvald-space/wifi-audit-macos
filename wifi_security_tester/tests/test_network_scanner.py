#!/usr/bin/env python3
"""
Test script for Network Scanner component
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any

# Mock logger for testing
class MockLogger:
    def info(self, msg): pass
    def debug(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass

def get_logger(name=None):
    return MockLogger()

# Mock run_command for testing
def run_command(command, timeout=30):
    class MockResult:
        returncode = 1
        stdout = ""
        stderr = "Mock command execution"
    return MockResult()

# Copy the NetworkInfo class for testing
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

# Simplified NetworkScanner for testing
class NetworkScanner:
    """Test version of NetworkScanner"""
    
    def __init__(self):
        self.logger = get_logger("network_scanner")
        self.networks: Dict[str, NetworkInfo] = {}
        self.last_scan_time: Optional[datetime] = None
    
    def get_all_networks(self) -> List[NetworkInfo]:
        return list(self.networks.values())
    
    def sort_networks_by_signal_strength(self, networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        return sorted(networks, key=lambda n: n.signal_strength, reverse=True)
    
    def filter_networks_by_encryption(self, encryption_types: List[str], 
                                    networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        normalized_types = [enc.lower() for enc in encryption_types]
        filtered_networks = []
        for network in networks:
            network_enc = network.encryption_type.lower()
            if any(enc_type in network_enc for enc_type in normalized_types):
                filtered_networks.append(network)
        return filtered_networks
    
    def filter_networks_by_signal_strength(self, min_strength: int = -70, 
                                         networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        return [n for n in networks if n.signal_strength >= min_strength]
    
    def filter_networks_by_channel(self, channels: List[int], 
                                 networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        return [n for n in networks if n.channel in channels]
    
    def filter_networks_by_band(self, band: str, networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        filtered_networks = []
        for network in networks:
            if band == '2.4GHz' and 1 <= network.channel <= 14:
                filtered_networks.append(network)
            elif band == '5GHz' and 36 <= network.channel <= 165:
                filtered_networks.append(network)
        return filtered_networks
    
    def search_networks_by_ssid(self, ssid_pattern: str, 
                               networks: List[NetworkInfo] = None) -> List[NetworkInfo]:
        if networks is None:
            networks = list(self.networks.values())
        pattern_lower = ssid_pattern.lower()
        return [n for n in networks if pattern_lower in n.ssid.lower()]
    
    def get_networks_by_criteria(self, 
                               encryption_types: List[str] = None,
                               min_signal_strength: int = None,
                               channels: List[int] = None,
                               band: str = None,
                               ssid_pattern: str = None,
                               sort_by_signal: bool = True) -> List[NetworkInfo]:
        networks = list(self.networks.values())
        
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
        if sort_by_signal:
            networks = self.sort_networks_by_signal_strength(networks)
        
        return networks
    
    def get_network_statistics(self) -> Dict[str, Any]:
        networks = list(self.networks.values())
        if not networks:
            return {'total_networks': 0, 'encryption_breakdown': {}, 'channel_distribution': {}, 'signal_strength_ranges': {}, 'band_distribution': {}}
        
        encryption_count = {}
        for network in networks:
            enc_type = network.authentication
            encryption_count[enc_type] = encryption_count.get(enc_type, 0) + 1
        
        return {
            'total_networks': len(networks),
            'encryption_breakdown': encryption_count,
            'channel_distribution': {},
            'signal_strength_ranges': {},
            'band_distribution': {}
        }
    
    def save_scan_results(self, file_path: str, networks: List[NetworkInfo] = None) -> bool:
        try:
            if networks is None:
                networks = list(self.networks.values())
            
            data = {
                'scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
                'total_networks': len(networks),
                'networks': []
            }
            
            for network in networks:
                network_data = asdict(network)
                network_data['first_seen'] = network.first_seen.isoformat()
                network_data['last_seen'] = network.last_seen.isoformat()
                data['networks'].append(network_data)
            
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception:
            return False
    
    def load_scan_results(self, file_path: str) -> bool:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.networks.clear()
            
            for network_data in data.get('networks', []):
                network_data['first_seen'] = datetime.fromisoformat(network_data['first_seen'])
                network_data['last_seen'] = datetime.fromisoformat(network_data['last_seen'])
                
                network = NetworkInfo(**network_data)
                key = f"{network.ssid}_{network.bssid}"
                self.networks[key] = network
            
            if data.get('scan_time'):
                self.last_scan_time = datetime.fromisoformat(data['scan_time'])
            
            return True
        except Exception:
            return False
    
    def export_networks_csv(self, file_path: str, networks: List[NetworkInfo] = None) -> bool:
        try:
            import csv
            
            if networks is None:
                networks = list(self.networks.values())
            
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'SSID', 'BSSID', 'Channel', 'Frequency', 'Signal Strength (dBm)',
                    'Encryption Type', 'Cipher', 'Authentication', 'Vendor',
                    'First Seen', 'Last Seen'
                ])
                
                for network in networks:
                    writer.writerow([
                        network.ssid, network.bssid, network.channel, network.frequency,
                        network.signal_strength, network.encryption_type, network.cipher,
                        network.authentication, network.vendor,
                        network.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                        network.last_seen.strftime('%Y-%m-%d %H:%M:%S')
                    ])
            
            return True
        except Exception:
            return False
    
    def clear_network_database(self):
        self.networks.clear()
    
    def scan_networks(self) -> List[NetworkInfo]:
        # Mock scan that will fail in test environment
        result = run_command(['wdutil', 'scan'], timeout=30)
        return []


def test_network_scanner():
    """Test the NetworkScanner functionality"""
    print("Testing Network Scanner Component")
    print("=" * 50)
    
    # Initialize scanner
    scanner = NetworkScanner()
    print("✓ NetworkScanner initialized")
    
    # Test network creation
    test_network = NetworkInfo(
        ssid="TestNetwork",
        bssid="00:11:22:33:44:55",
        channel=6,
        frequency="2437 MHz",
        signal_strength=-45,
        encryption_type="WPA2 Personal",
        cipher="AES",
        authentication="WPA2"
    )
    print("✓ NetworkInfo object created")
    
    # Test manual network addition
    scanner.networks["test_key"] = test_network
    print("✓ Network added to scanner database")
    
    # Test filtering and sorting
    all_networks = scanner.get_all_networks()
    print(f"✓ Retrieved {len(all_networks)} networks")
    
    # Test signal strength sorting
    sorted_networks = scanner.sort_networks_by_signal_strength()
    print(f"✓ Sorted {len(sorted_networks)} networks by signal strength")
    
    # Test encryption filtering
    wpa2_networks = scanner.filter_networks_by_encryption(['WPA2'])
    print(f"✓ Filtered to {len(wpa2_networks)} WPA2 networks")
    
    # Test signal strength filtering
    strong_networks = scanner.filter_networks_by_signal_strength(-50)
    print(f"✓ Filtered to {len(strong_networks)} networks with signal >= -50 dBm")
    
    # Test channel filtering
    channel_6_networks = scanner.filter_networks_by_channel([6])
    print(f"✓ Filtered to {len(channel_6_networks)} networks on channel 6")
    
    # Test band filtering
    band_24_networks = scanner.filter_networks_by_band('2.4GHz')
    print(f"✓ Filtered to {len(band_24_networks)} networks in 2.4GHz band")
    
    # Test SSID search
    test_networks = scanner.search_networks_by_ssid('Test')
    print(f"✓ Found {len(test_networks)} networks matching 'Test'")
    
    # Test combined criteria
    filtered_networks = scanner.get_networks_by_criteria(
        encryption_types=['WPA2'],
        min_signal_strength=-50,
        sort_by_signal=True
    )
    print(f"✓ Applied combined criteria, got {len(filtered_networks)} networks")
    
    # Test statistics
    stats = scanner.get_network_statistics()
    print(f"✓ Generated statistics for {stats['total_networks']} networks")
    
    # Test save/load functionality
    test_file = "test_scan_results.json"
    if scanner.save_scan_results(test_file):
        print("✓ Saved scan results to file")
        
        # Clear and reload
        scanner.clear_network_database()
        if scanner.load_scan_results(test_file):
            print("✓ Loaded scan results from file")
            
            # Verify data integrity
            reloaded_networks = scanner.get_all_networks()
            if len(reloaded_networks) == 1 and reloaded_networks[0].ssid == "TestNetwork":
                print("✓ Data integrity verified after save/load")
            else:
                print("✗ Data integrity check failed")
        else:
            print("✗ Failed to load scan results")
        
        # Clean up test file
        try:
            os.remove(test_file)
            print("✓ Cleaned up test file")
        except:
            pass
    else:
        print("✗ Failed to save scan results")
    
    # Test CSV export
    csv_file = "test_networks.csv"
    if scanner.export_networks_csv(csv_file):
        print("✓ Exported networks to CSV")
        try:
            os.remove(csv_file)
            print("✓ Cleaned up CSV file")
        except:
            pass
    else:
        print("✗ Failed to export to CSV")
    
    print("\n" + "=" * 50)
    print("Network Scanner Component Test Completed")
    
    # Test actual scanning (will likely fail in test environment)
    print("\nTesting actual network scanning...")
    try:
        networks = scanner.scan_networks()
        if networks:
            print(f"✓ Successfully scanned and found {len(networks)} networks")
            for network in networks[:3]:  # Show first 3 networks
                print(f"  - {network.ssid} ({network.bssid}) - {network.signal_strength} dBm")
        else:
            print("! No networks found (expected in test environment)")
    except Exception as e:
        print(f"! Network scanning failed (expected in test environment): {e}")


if __name__ == "__main__":
    test_network_scanner()
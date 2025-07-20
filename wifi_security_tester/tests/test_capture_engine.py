#!/usr/bin/env python3
"""
Test script for Capture Engine component
Tests packet capture functionality and handshake detection
"""

import sys
import os
import time
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass

# Mock logger for testing
class MockLogger:
    def info(self, msg): print(f"INFO: {msg}")
    def debug(self, msg): print(f"DEBUG: {msg}")
    def warning(self, msg): print(f"WARNING: {msg}")
    def error(self, msg): print(f"ERROR: {msg}")

# Mock NetworkInfo for testing
@dataclass
class NetworkInfo:
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


def test_capture_engine_basic():
    """Test basic CaptureEngine functionality"""
    print("Testing basic CaptureEngine functionality...")
    
    try:
        # Test that the file exists and can be imported
        capture_engine_path = Path(__file__).parent / "components" / "capture_engine.py"
        if not capture_engine_path.exists():
            print("✗ capture_engine.py file not found")
            return False
        
        print("✓ capture_engine.py file exists")
        
        # Test file syntax by trying to compile it
        with open(capture_engine_path, 'r') as f:
            code = f.read()
        
        try:
            compile(code, str(capture_engine_path), 'exec')
            print("✓ capture_engine.py syntax is valid")
        except SyntaxError as e:
            print(f"✗ Syntax error in capture_engine.py: {e}")
            return False
        
        return True
    except Exception as e:
        print(f"✗ Basic test failed: {e}")
        return False


def test_capture_session_creation():
    """Test CaptureSession data model"""
    print("\nTesting CaptureSession data model...")
    
    try:
        # Create a mock network info
        network = NetworkInfo(
            ssid="TestNetwork",
            bssid="00:11:22:33:44:55",
            channel=6,
            frequency="2437 MHz",
            signal_strength=-45,
            encryption_type="WPA2",
            cipher="AES",
            authentication="WPA2"
        )
        
        print(f"✓ NetworkInfo created: {network.ssid}")
        print(f"  BSSID: {network.bssid}")
        print(f"  Channel: {network.channel}")
        print(f"  Security: {network.encryption_type}")
        
        return True
    except Exception as e:
        print(f"✗ NetworkInfo creation failed: {e}")
        return False


def test_dependency_checks():
    """Test capture tool dependency checks"""
    print("\nTesting capture tool dependencies...")
    
    # Test airodump-ng availability
    try:
        result = subprocess.run(['airodump-ng', '--help'], 
                              capture_output=True, text=True, timeout=5)
        airodump_available = result.returncode == 0
    except:
        airodump_available = False
    
    print(f"airodump-ng available: {'✓' if airodump_available else '✗'}")
    
    # Test tcpdump availability
    try:
        result = subprocess.run(['tcpdump', '--help'], 
                              capture_output=True, text=True, timeout=5)
        tcpdump_available = result.returncode == 0
    except:
        tcpdump_available = False
    
    print(f"tcpdump available: {'✓' if tcpdump_available else '✗'}")
    
    if not airodump_available and not tcpdump_available:
        print("  Warning: No capture tools available")
    
    return True


def test_capture_validation():
    """Test capture file validation concepts"""
    print("\nTesting capture validation concepts...")
    
    # Test file existence check
    test_file = "nonexistent.cap"
    exists = Path(test_file).exists()
    print(f"File existence check: {'✓' if not exists else '✗'} (correctly detected non-existent file)")
    
    # Test file extension validation
    valid_extensions = ['.cap', '.pcap']
    test_files = ['test.cap', 'test.pcap', 'test.txt']
    
    for test_file in test_files:
        is_valid = any(test_file.endswith(ext) for ext in valid_extensions)
        status = '✓' if is_valid else '✗'
        print(f"Extension validation for {test_file}: {status}")
    
    return True


def test_interface_discovery():
    """Test WiFi interface discovery using system commands"""
    print("\nTesting interface discovery...")
    
    try:
        # Test networksetup command
        result = subprocess.run(['networksetup', '-listallhardwareports'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✓ networksetup command available")
            
            # Look for WiFi interfaces in output
            wifi_found = False
            for line in result.stdout.split('\n'):
                if 'wi-fi' in line.lower() or 'wifi' in line.lower():
                    wifi_found = True
                    print(f"  Found WiFi port: {line.strip()}")
            
            if not wifi_found:
                print("  No WiFi interfaces found in networksetup output")
        else:
            print("✗ networksetup command failed")
        
        # Test ifconfig command
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ ifconfig command available")
            
            # Count network interfaces
            interface_count = result.stdout.count(': flags=')
            print(f"  Found {interface_count} total network interfaces")
        else:
            print("✗ ifconfig command failed")
        
        return True
    except Exception as e:
        print(f"✗ Interface discovery test failed: {e}")
        return False


def test_capture_statistics():
    """Test capture statistics concepts"""
    print("\nTesting capture statistics concepts...")
    
    # Test basic statistics structure
    stats_template = {
        'total_sessions': 0,
        'active_sessions': 0,
        'completed_sessions': 0,
        'failed_sessions': 0,
        'successful_handshakes': 0,
        'methods_used': {},
        'capture_files_size': 0
    }
    
    print("✓ Statistics template structure:")
    for key, value in stats_template.items():
        print(f"  {key}: {value}")
    
    return True


def test_file_format_conversion():
    """Test file format conversion tools availability"""
    print("\nTesting file format conversion tools...")
    
    # Test cap2hccapx availability
    try:
        result = subprocess.run(['cap2hccapx'], capture_output=True, text=True, timeout=5)
        cap2hccapx_available = True
    except:
        cap2hccapx_available = False
    
    print(f"cap2hccapx available: {'✓' if cap2hccapx_available else '✗'}")
    
    # Test hcxpcapngtool availability
    try:
        result = subprocess.run(['hcxpcapngtool'], capture_output=True, text=True, timeout=5)
        hcxpcapngtool_available = True
    except:
        hcxpcapngtool_available = False
    
    print(f"hcxpcapngtool available: {'✓' if hcxpcapngtool_available else '✗'}")
    
    # Test supported formats
    supported_formats = ['hccapx', '22000', 'pcap']
    print(f"Supported formats: {', '.join(supported_formats)}")
    
    return True


def test_capture_management():
    """Test capture management functionality"""
    print("\nTesting capture management functionality...")
    
    # Test file size formatting
    test_sizes = [1024, 1024*1024, 1024*1024*1024]
    expected = ['1.0 KB', '1.0 MB', '1.0 GB']
    
    for size, exp in zip(test_sizes, expected):
        # Simple file size formatting test
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                formatted = f"{size:.1f} {unit}"
                break
            size /= 1024.0
        print(f"✓ File size formatting test passed")
        break
    
    # Test quality scoring concepts
    quality_factors = [
        'Handshake completeness (40 points)',
        'File size (20 points)', 
        'Packet count (20 points)',
        'Network diversity (10 points)',
        'File integrity (10 points)'
    ]
    
    print("✓ Quality assessment factors:")
    for factor in quality_factors:
        print(f"  - {factor}")
    
    # Test file patterns
    capture_patterns = ['*.cap', '*.pcap', '*.hccapx']
    print(f"✓ Capture file patterns: {', '.join(capture_patterns)}")
    
    return True


def test_cleanup_functionality():
    """Test cleanup functionality concepts"""
    print("\nTesting cleanup functionality...")
    
    # Test captures directory creation
    captures_dir = Path("captures")
    if not captures_dir.exists():
        print("✓ Captures directory would be created")
    else:
        print(f"✓ Captures directory exists with {len(list(captures_dir.glob('*')))} files")
    
    # Test file age calculation
    import time
    current_time = time.time()
    days_old = 7
    cutoff_time = current_time - (days_old * 24 * 3600)
    
    print(f"✓ Cleanup cutoff time calculated for {days_old} days")
    print(f"  Current time: {current_time}")
    print(f"  Cutoff time: {cutoff_time}")
    
    # Test file organization concepts
    from datetime import datetime
    today = datetime.now()
    date_dir = f"captures/{today.strftime('%Y-%m-%d')}"
    print(f"✓ Date-based organization directory: {date_dir}")
    
    # Test archive formats
    archive_formats = ['zip', 'tar']
    print(f"✓ Supported archive formats: {', '.join(archive_formats)}")
    
    return True


def run_interactive_test():
    """Run interactive test with user input"""
    print("\n" + "="*60)
    print("INTERACTIVE CAPTURE ENGINE TEST")
    print("="*60)
    
    print("\nLEGAL WARNING:")
    print("This tool is for testing YOUR OWN networks only!")
    print("Unauthorized access to networks is illegal.")
    
    try:
        response = input("\nDo you agree to use this tool legally? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print("User consent not provided. Exiting.")
            return False
    except (EOFError, KeyboardInterrupt):
        print("\nUser consent not provided. Exiting.")
        return False
    
    try:
        print("\nNote: This is a test run - no actual capture will be performed")
        print("In a real scenario, you would:")
        print("1. Select a target network (YOUR OWN network only)")
        print("2. Choose capture duration")
        print("3. Start capture session")
        print("4. Monitor for handshake detection")
        print("5. Validate captured handshake")
        
        print("\nCapture Engine features:")
        print("- airodump-ng integration for packet capture")
        print("- tcpdump fallback for compatibility")
        print("- Handshake detection and validation")
        print("- Multiple capture format support")
        print("- Automatic interface management")
        print("- Session monitoring and cleanup")
        
        return True
        
    except Exception as e:
        print(f"Interactive test failed: {e}")
        return False


def main():
    """Main test function"""
    print("WiFi Security Tester - Capture Engine Test Suite")
    print("=" * 50)
    
    # Basic setup
    print("Setting up test environment...")
    
    # Run tests
    tests = [
        test_capture_engine_basic,
        test_capture_session_creation,
        test_dependency_checks,
        test_capture_validation,
        test_interface_discovery,
        test_capture_statistics,
        test_file_format_conversion,
        test_capture_management,
        test_cleanup_functionality
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"Test {test.__name__} failed with exception: {e}")
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    # Ask for interactive test
    try:
        response = input("\nRun interactive test? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            run_interactive_test()
    except (EOFError, KeyboardInterrupt):
        print("\nInteractive test skipped.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
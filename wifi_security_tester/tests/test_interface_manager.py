#!/usr/bin/env python3
"""
Test script for Interface Manager functionality
Tests interface discovery and validation without requiring sudo
"""

import sys
import json
from components.interface_manager import InterfaceManager

def test_interface_discovery():
    """Test WiFi interface discovery"""
    print("=== Testing WiFi Interface Discovery ===")
    
    im = InterfaceManager()
    interfaces = im.discover_wifi_interfaces()
    
    print(f"Found {len(interfaces)} WiFi interface(s):")
    for i, iface in enumerate(interfaces, 1):
        print(f"\n{i}. Interface: {iface['name']}")
        print(f"   Device: {iface['device']}")
        print(f"   MAC: {iface['mac_address']}")
        print(f"   Status: {iface['status']}")
    
    return interfaces

def test_interface_capabilities(interfaces):
    """Test interface capability checking"""
    print("\n=== Testing Interface Capabilities ===")
    
    im = InterfaceManager()
    
    for iface in interfaces:
        device = iface['device']
        print(f"\nCapabilities for {device}:")
        
        capabilities = im.get_interface_capabilities(device)
        for cap, value in capabilities.items():
            status = "✓" if value else "✗"
            print(f"  {status} {cap}: {value}")

def test_interface_validation(interfaces):
    """Test interface status validation"""
    print("\n=== Testing Interface Status Validation ===")
    
    im = InterfaceManager()
    
    for iface in interfaces:
        device = iface['device']
        print(f"\nStatus validation for {device}:")
        
        status = im.validate_interface_status(device)
        
        print(f"  Exists: {status['exists']}")
        print(f"  Active: {status['active']}")
        print(f"  Connected: {status['connected']}")
        print(f"  Mode: {status['mode']}")
        
        if status['ssid']:
            print(f"  SSID: {status['ssid']}")
        if status['channel']:
            print(f"  Channel: {status['channel']}")
        if status['signal_strength']:
            print(f"  Signal: {status['signal_strength']} dBm")
        
        if status['issues']:
            print("  Issues:")
            for issue in status['issues']:
                print(f"    - {issue}")
        
        if status['recommendations']:
            print("  Recommendations:")
            for rec in status['recommendations']:
                print(f"    - {rec}")

def test_mode_detection(interfaces):
    """Test current mode detection"""
    print("\n=== Testing Mode Detection ===")
    
    im = InterfaceManager()
    
    for iface in interfaces:
        device = iface['device']
        current_mode = im.get_current_mode(device)
        print(f"  {device}: {current_mode}")

def main():
    """Run all tests"""
    print("WiFi Security Tester - Interface Manager Test Suite")
    print("=" * 60)
    
    try:
        # Test interface discovery
        interfaces = test_interface_discovery()
        
        if not interfaces:
            print("\nNo WiFi interfaces found. Cannot continue with tests.")
            return
        
        # Test capabilities
        test_interface_capabilities(interfaces)
        
        # Test validation
        test_interface_validation(interfaces)
        
        # Test mode detection
        test_mode_detection(interfaces)
        
        print("\n" + "=" * 60)
        print("All tests completed successfully!")
        print("\nNote: Monitor mode activation tests require sudo privileges")
        print("and may be restricted by System Integrity Protection (SIP).")
        
    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
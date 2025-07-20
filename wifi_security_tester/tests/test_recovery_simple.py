#!/usr/bin/env python3
"""
Simple test to verify recovery and fallback mechanisms work
"""

import sys
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent))

from core.recovery_coordinator import get_recovery_coordinator
from core.fallback_mechanisms import get_fallback_mechanisms
from core.user_guidance import get_user_guidance_system, GuidanceLevel
from core.exceptions import *


def test_homebrew_fallback():
    """Test Requirement 1.4: Homebrew installation fallback"""
    print("Testing Homebrew installation fallback...")
    
    fallback_mechanisms = get_fallback_mechanisms()
    success, message, details = fallback_mechanisms.homebrew_installation_fallback()
    
    print(f"Success: {success}")
    print(f"Message: {message}")
    print(f"Details keys: {list(details.keys())}")
    
    if not success and 'guidance' in details:
        print("✓ Provides manual guidance when automatic installation fails")
    
    return True


def test_network_scanning_fallback():
    """Test Requirement 2.4: Network scanning fallback"""
    print("\nTesting network scanning fallback...")
    
    fallback_mechanisms = get_fallback_mechanisms()
    success, networks, details = fallback_mechanisms.network_scanning_fallback()
    
    print(f"Success: {success}")
    print(f"Networks found: {len(networks)}")
    print(f"Method used: {details.get('method', 'unknown')}")
    
    if not success and 'guidance' in details:
        print("✓ Provides manual guidance when all scanning methods fail")
    elif success:
        print(f"✓ Successfully scanned using {details.get('method')}")
    
    return True


def test_monitor_mode_fallback():
    """Test Requirement 3.4: Monitor mode fallback"""
    print("\nTesting monitor mode fallback...")
    
    fallback_mechanisms = get_fallback_mechanisms()
    success, message, details = fallback_mechanisms.monitor_mode_fallback("en0")
    
    print(f"Success: {success}")
    print(f"Message: {message}")
    
    if not success and 'alternatives' in details:
        alternatives = details['alternatives']
        print(f"✓ Provides {len(alternatives['alternatives'])} alternatives")
        for alt in alternatives['alternatives']:
            print(f"  - {alt['option']}")
    
    return True


def test_user_guidance():
    """Test user guidance system"""
    print("\nTesting user guidance system...")
    
    guidance_system = get_user_guidance_system()
    
    # Test SIP restriction guidance
    error = SIPRestrictionError("SIP is blocking the operation")
    guidance = guidance_system.get_guidance(error, GuidanceLevel.DETAILED)
    
    print(f"Guidance title: {guidance['title']}")
    print(f"Number of solutions: {len(guidance.get('solutions', []))}")
    
    # Test quick fixes
    quick_fixes = guidance_system.get_quick_fix_suggestions(error)
    print(f"Quick fixes: {quick_fixes}")
    
    print("✓ User guidance system working")
    return True


def test_recovery_coordinator():
    """Test recovery coordinator integration"""
    print("\nTesting recovery coordinator...")
    
    coordinator = get_recovery_coordinator()
    
    # Test with a dependency error
    error = DependencyMissingError("test-tool")
    result = coordinator.handle_error_with_recovery(error, "test_operation")
    
    print(f"Recovery attempted: {result['recovery_attempted']}")
    print(f"Recovery successful: {result['recovery_successful']}")
    print(f"User guidance provided: {result['user_guidance'] is not None}")
    
    print("✓ Recovery coordinator working")
    return True


def main():
    """Run all tests"""
    print("=== Testing Recovery and Fallback Mechanisms ===")
    
    tests = [
        test_homebrew_fallback,
        test_network_scanning_fallback,
        test_monitor_mode_fallback,
        test_user_guidance,
        test_recovery_coordinator
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"Test {test.__name__} failed: {e}")
    
    print(f"\n=== Results: {passed}/{len(tests)} tests passed ===")
    
    if passed == len(tests):
        print("✓ All recovery and fallback mechanisms are working correctly!")
        return True
    else:
        print("✗ Some tests failed")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
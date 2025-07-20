# WiFi Security Tester - Usage Examples

This document provides comprehensive examples of how to use the WiFi Security Test Tool for various security testing scenarios.

## Table of Contents

1. [Basic Usage Examples](#basic-usage-examples)
2. [Advanced Scenarios](#advanced-scenarios)
3. [Performance Optimization Examples](#performance-optimization-examples)
4. [Error Handling Examples](#error-handling-examples)
5. [Automation Examples](#automation-examples)
6. [Best Practices](#best-practices)

## Basic Usage Examples

### Example 1: First-Time Setup and Basic Network Test

```bash
# 1. Start the application
python3 wifi_security_tester/main.py

# 2. Accept legal agreement
# Read and accept the terms of use

# 3. Check dependencies
Select option: 1
# The tool will automatically install missing dependencies

# 4. Scan for networks
Select option: 2
# Review the list of discovered networks

# 5. Test your own network
# Select your network from the list
# Follow the guided workflow
```

### Example 2: Quick Security Assessment

```python
#!/usr/bin/env python3
"""
Quick security assessment script
"""
import sys
from pathlib import Path

# Add project to path
sys.path.append(str(Path(__file__).parent))

from components.network_scanner import NetworkScanner
from components.wordlist_manager import WordlistManager
from components.password_cracker import PasswordCracker

def quick_assessment(target_ssid):
    """Perform quick security assessment of target network"""
    
    # 1. Scan for the target network
    scanner = NetworkScanner()
    networks = scanner.scan_networks()
    
    target_network = None
    for network in networks:
        if network['ssid'] == target_ssid:
            target_network = network
            break
    
    if not target_network:
        print(f"Network '{target_ssid}' not found")
        return
    
    print(f"Found target network: {target_network}")
    
    # 2. Create a basic wordlist
    wm = WordlistManager()
    common_passwords = wm.generate_builtin_wordlist('common')
    wordlist_path = wm.create_custom_wordlist('quick_test', common_passwords)
    
    print(f"Created wordlist with {len(common_passwords)} passwords")
    
    # 3. Note: In real scenario, you would capture handshake first
    print("Note: Handshake capture required before password testing")
    print("Use the main application menu for complete workflow")

if __name__ == "__main__":
    # Replace with your network name
    quick_assessment("YourNetworkName")
```

### Example 3: Custom Wordlist Creation

```python
#!/usr/bin/env python3
"""
Create custom wordlist for specific target
"""
from components.wordlist_manager import WordlistManager

def create_targeted_wordlist():
    """Create wordlist targeted for specific organization"""
    
    wm = WordlistManager()
    
    # Company-specific passwords
    company_passwords = [
        "CompanyName123",
        "CompanyName2024",
        "CompanyWiFi",
        "CompanyGuest",
        "Office123",
        "Reception2024"
    ]
    
    # Personal information (for authorized testing only)
    personal_passwords = [
        "JohnSmith123",
        "JaneSmith2024",
        "Birthday1990",
        "Anniversary2020"
    ]
    
    # Combine with common patterns
    common_passwords = wm.generate_builtin_wordlist('common')
    
    # Create comprehensive wordlist
    all_passwords = company_passwords + personal_passwords + common_passwords
    
    success, wordlist_path = wm.create_custom_wordlist(
        'targeted_test',
        all_passwords,
        'Custom wordlist for authorized security testing'
    )
    
    if success:
        print(f"Created targeted wordlist: {wordlist_path}")
        
        # Analyze wordlist
        analysis = wm.analyze_wordlist_size(wordlist_path)
        print(f"Wordlist analysis: {analysis}")
    else:
        print(f"Failed to create wordlist: {wordlist_path}")

if __name__ == "__main__":
    create_targeted_wordlist()
```

## Advanced Scenarios

### Example 4: Multi-Interface Testing

```python
#!/usr/bin/env python3
"""
Advanced multi-interface testing scenario
"""
from components.interface_manager import InterfaceManager
from components.network_scanner import NetworkScanner

def multi_interface_test():
    """Test using multiple WiFi interfaces"""
    
    im = InterfaceManager()
    scanner = NetworkScanner()
    
    # Discover all available interfaces
    interfaces = im.discover_wifi_interfaces()
    print(f"Found {len(interfaces)} WiFi interfaces:")
    
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface['name']} ({interface['device']})")
        
        # Check capabilities
        capabilities = im.get_interface_capabilities(interface['device'])
        print(f"   Monitor mode: {'✓' if capabilities['monitor_mode'] else '✗'}")
        print(f"   Active: {'✓' if capabilities['active'] else '✗'}")
        
        # Scan networks with this interface
        try:
            networks = scanner.scan_networks_with_interface(interface['device'])
            print(f"   Networks found: {len(networks)}")
        except Exception as e:
            print(f"   Scan failed: {e}")
        
        print()

if __name__ == "__main__":
    multi_interface_test()
```

### Example 5: Automated Security Assessment

```python
#!/usr/bin/env python3
"""
Automated security assessment with reporting
"""
import json
import time
from datetime import datetime
from pathlib import Path

from components.network_scanner import NetworkScanner
from components.wordlist_manager import WordlistManager
from components.security_manager import SecurityManager

def automated_assessment(target_networks):
    """Perform automated security assessment"""
    
    # Initialize components
    scanner = NetworkScanner()
    wm = WordlistManager()
    sm = SecurityManager()
    
    # Check system security status
    security_status = sm.check_system_security()
    print(f"System security status: {security_status}")
    
    # Create assessment report
    report = {
        'timestamp': datetime.now().isoformat(),
        'system_info': security_status,
        'networks_assessed': [],
        'recommendations': []
    }
    
    # Scan networks
    print("Scanning for networks...")
    networks = scanner.scan_networks()
    
    for target_ssid in target_networks:
        print(f"\nAssessing network: {target_ssid}")
        
        # Find target network
        target_network = None
        for network in networks:
            if network['ssid'] == target_ssid:
                target_network = network
                break
        
        if not target_network:
            print(f"Network '{target_ssid}' not found")
            continue
        
        # Analyze network security
        network_assessment = {
            'ssid': target_ssid,
            'bssid': target_network.get('bssid', 'Unknown'),
            'encryption': target_network.get('encryption', 'Unknown'),
            'signal_strength': target_network.get('signal_strength', 0),
            'security_level': 'Unknown',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Assess encryption type
        encryption = target_network.get('encryption', '').upper()
        if 'WEP' in encryption:
            network_assessment['security_level'] = 'Very Low'
            network_assessment['vulnerabilities'].append('WEP encryption is easily broken')
            network_assessment['recommendations'].append('Upgrade to WPA3 immediately')
        elif 'WPA ' in encryption or 'WPA2' in encryption:
            network_assessment['security_level'] = 'Medium'
            network_assessment['recommendations'].append('Consider upgrading to WPA3')
        elif 'WPA3' in encryption:
            network_assessment['security_level'] = 'High'
        else:
            network_assessment['security_level'] = 'Unknown'
            network_assessment['vulnerabilities'].append('Unknown encryption type')
        
        # Check for common weak passwords (simulation)
        if network_assessment['security_level'] in ['Very Low', 'Medium']:
            weak_passwords = wm.generate_builtin_wordlist('common')[:100]  # Top 100
            network_assessment['weak_password_risk'] = 'High'
            network_assessment['recommendations'].append('Use strong, unique password')
        
        report['networks_assessed'].append(network_assessment)
    
    # Generate overall recommendations
    report['recommendations'] = [
        'Regularly update WiFi passwords',
        'Use WPA3 encryption when available',
        'Disable WPS if not needed',
        'Monitor for unauthorized access',
        'Implement network segmentation'
    ]
    
    # Save report
    report_path = Path('security_assessment_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nAssessment complete. Report saved to: {report_path}")
    return report

if __name__ == "__main__":
    # Replace with your network names
    target_networks = ["YourNetwork1", "YourNetwork2"]
    automated_assessment(target_networks)
```

## Performance Optimization Examples

### Example 6: Large Wordlist Optimization

```python
#!/usr/bin/env python3
"""
Optimize performance for large wordlist processing
"""
from core.performance_optimizer import get_performance_optimizer
from components.wordlist_manager import WordlistManager

def optimize_large_wordlist_processing():
    """Demonstrate large wordlist optimization"""
    
    # Get performance optimizer
    optimizer = get_performance_optimizer()
    
    # Start performance monitoring
    optimizer.start_performance_monitoring(interval_seconds=10)
    
    # Simulate large wordlist processing
    wm = WordlistManager()
    
    # Create large wordlist
    print("Creating large wordlist...")
    large_wordlist = []
    
    # Generate multiple categories
    for category in ['common', 'numeric', 'keyboard', 'dates']:
        passwords = wm.generate_builtin_wordlist(category)
        large_wordlist.extend(passwords)
    
    print(f"Generated {len(large_wordlist)} passwords")
    
    # Optimize for large wordlist operation
    optimization_config = optimizer.optimize_for_operation(
        'large_wordlist_crack',
        {'wordlist_size': len(large_wordlist)}
    )
    
    print(f"Optimization config: {optimization_config}")
    
    # Create optimized wordlist
    success, wordlist_path = wm.create_custom_wordlist(
        'large_optimized',
        large_wordlist,
        'Large optimized wordlist for performance testing'
    )
    
    if success:
        print(f"Created optimized wordlist: {wordlist_path}")
        
        # Optimize the wordlist file
        optimize_result = wm.optimize_wordlist(wordlist_path)
        print(f"Optimization result: {optimize_result}")
    
    # Get performance report
    time.sleep(5)  # Let monitoring collect some data
    report = optimizer.get_performance_report()
    print(f"Performance report: {report}")
    
    # Stop monitoring
    optimizer.stop_performance_monitoring()

if __name__ == "__main__":
    optimize_large_wordlist_processing()
```

### Example 7: Memory-Efficient Processing

```python
#!/usr/bin/env python3
"""
Memory-efficient processing for resource-constrained systems
"""
from core.performance_optimizer import MemoryManager, WordlistOptimizer

def memory_efficient_processing(wordlist_path):
    """Process large wordlist with minimal memory usage"""
    
    # Initialize memory management
    memory_manager = MemoryManager(max_memory_mb=512)  # Limit to 512MB
    wordlist_optimizer = WordlistOptimizer(memory_manager)
    
    print("Processing wordlist with memory optimization...")
    
    # Get memory usage before processing
    initial_memory = memory_manager.get_memory_usage()
    print(f"Initial memory usage: {initial_memory['percent']:.1f}%")
    
    # Create memory-efficient iterator
    chunk_size = 10000  # Process 10K passwords at a time
    processed_count = 0
    
    for password_chunk in wordlist_optimizer.create_optimized_wordlist_iterator(
        wordlist_path, chunk_size
    ):
        # Process chunk
        processed_count += len(password_chunk)
        
        # Check memory pressure
        if memory_manager.check_memory_pressure():
            print("Memory pressure detected, triggering garbage collection...")
            gc_stats = memory_manager.trigger_garbage_collection()
            print(f"Freed {gc_stats['memory_freed_mb']} MB")
        
        # Progress update
        if processed_count % 50000 == 0:
            current_memory = memory_manager.get_memory_usage()
            print(f"Processed {processed_count:,} passwords, "
                  f"Memory usage: {current_memory['percent']:.1f}%")
    
    print(f"Processing complete. Total passwords processed: {processed_count:,}")

if __name__ == "__main__":
    # Replace with actual wordlist path
    wordlist_path = "wifi_security_tester/wordlists/large_test_wordlist.txt"
    memory_efficient_processing(wordlist_path)
```

## Error Handling Examples

### Example 8: Comprehensive Error Handling

```python
#!/usr/bin/env python3
"""
Comprehensive error handling and recovery examples
"""
from core.error_handler import handle_error, get_error_handler
from core.exceptions import *
from components.interface_manager import InterfaceManager

def demonstrate_error_handling():
    """Demonstrate comprehensive error handling"""
    
    error_handler = get_error_handler()
    im = InterfaceManager()
    
    # Example 1: Handle interface errors with automatic recovery
    try:
        interfaces = im.discover_wifi_interfaces()
        if not interfaces:
            raise InterfaceNotFoundError("No WiFi interfaces available")
        
        # Try to set monitor mode
        interface = interfaces[0]['device']
        success, message = im.set_monitor_mode(interface)
        
        if not success:
            raise MonitorModeError(f"Failed to set monitor mode: {message}")
            
    except Exception as e:
        # Handle error with automatic recovery
        error_result = handle_error(e, 
                                  context={'interface': interface},
                                  operation='interface_management')
        
        print(f"Error handled: {error_result}")
        
        if error_result['recovery_successful']:
            print("Recovery successful, continuing with fallback method")
        else:
            print("Recovery failed, user intervention required")
            if error_result.get('user_action_required'):
                print("User guidance:")
                print(error_result.get('user_guidance', 'No specific guidance available'))
    
    # Example 2: Handle dependency errors
    try:
        # Simulate missing dependency
        raise DependencyMissingError("aircrack-ng", "aircrack-ng not found in PATH")
        
    except DependencyMissingError as e:
        error_result = handle_error(e, operation='dependency_check')
        
        if error_result['recovery_successful']:
            print("Dependency automatically installed")
        else:
            print("Manual installation required:")
            print("Run: brew install aircrack-ng")
    
    # Example 3: Handle SIP restrictions
    try:
        # Simulate SIP restriction
        raise SIPRestrictionError("Operation blocked by System Integrity Protection")
        
    except SIPRestrictionError as e:
        error_result = handle_error(e, operation='system_access')
        
        print("SIP restriction detected:")
        print("Recommendations:")
        for suggestion in error_result.get('recovery_suggestions', []):
            print(f"  - {suggestion}")
    
    # Get error statistics
    stats = error_handler.get_error_statistics()
    print(f"\nError handling statistics: {stats}")

if __name__ == "__main__":
    demonstrate_error_handling()
```

### Example 9: Custom Error Recovery

```python
#!/usr/bin/env python3
"""
Custom error recovery strategies
"""
from core.error_handler import get_error_handler, RecoveryStrategy
from core.recovery_manager import RecoveryManager, FallbackMethod

def setup_custom_recovery():
    """Setup custom error recovery strategies"""
    
    error_handler = get_error_handler()
    recovery_manager = RecoveryManager()
    
    # Custom fallback method for network scanning
    def custom_network_scan(*args, **kwargs):
        """Custom network scanning fallback"""
        print("Using custom network scanning method...")
        # Implement custom scanning logic
        return [{'ssid': 'CustomScan', 'bssid': '00:00:00:00:00:00'}]
    
    # Register custom fallback
    custom_fallback = FallbackMethod(
        'custom_scan',
        custom_network_scan,
        priority=4,  # Lower priority than built-in methods
        requirements=[]
    )
    
    recovery_manager.register_fallback_method('network_scan', custom_fallback)
    
    # Custom recovery strategy for specific error type
    class CustomNetworkError(Exception):
        pass
    
    error_handler.register_recovery_strategy(
        CustomNetworkError,
        RecoveryStrategy.FALLBACK
    )
    
    print("Custom recovery strategies registered")
    
    # Test custom recovery
    try:
        raise CustomNetworkError("Custom network error for testing")
    except CustomNetworkError as e:
        # Use fallback execution
        success, result, method = recovery_manager.execute_with_fallback(
            'network_scan',
            lambda: None  # Primary method that will fail
        )
        
        if success:
            print(f"Custom recovery successful using method: {method}")
            print(f"Result: {result}")
        else:
            print("Custom recovery failed")

if __name__ == "__main__":
    setup_custom_recovery()
```

## Automation Examples

### Example 10: Scheduled Security Monitoring

```python
#!/usr/bin/env python3
"""
Scheduled security monitoring script
"""
import schedule
import time
import json
from datetime import datetime
from pathlib import Path

from components.network_scanner import NetworkScanner
from components.security_manager import SecurityManager

class SecurityMonitor:
    """Automated security monitoring system"""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.security_manager = SecurityManager()
        self.baseline_networks = set()
        self.alerts = []
    
    def establish_baseline(self):
        """Establish baseline of known networks"""
        print("Establishing network baseline...")
        networks = self.scanner.scan_networks()
        
        for network in networks:
            self.baseline_networks.add(network['bssid'])
        
        print(f"Baseline established with {len(self.baseline_networks)} networks")
    
    def monitor_networks(self):
        """Monitor for network changes"""
        print(f"[{datetime.now()}] Monitoring networks...")
        
        current_networks = self.scanner.scan_networks()
        current_bssids = {network['bssid'] for network in current_networks}
        
        # Check for new networks
        new_networks = current_bssids - self.baseline_networks
        if new_networks:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'type': 'new_networks',
                'details': list(new_networks),
                'severity': 'medium'
            }
            self.alerts.append(alert)
            print(f"ALERT: {len(new_networks)} new networks detected")
        
        # Check for suspicious networks
        for network in current_networks:
            if self.is_suspicious_network(network):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'suspicious_network',
                    'details': network,
                    'severity': 'high'
                }
                self.alerts.append(alert)
                print(f"ALERT: Suspicious network detected: {network['ssid']}")
        
        # Save monitoring report
        self.save_monitoring_report()
    
    def is_suspicious_network(self, network):
        """Check if network appears suspicious"""
        suspicious_indicators = [
            # Hidden SSID
            not network.get('ssid') or network['ssid'].strip() == '',
            
            # Weak encryption
            'WEP' in network.get('encryption', '').upper(),
            
            # Common evil twin names
            any(evil_name in network.get('ssid', '').lower() 
                for evil_name in ['free wifi', 'public', 'guest', 'open']),
            
            # Very strong signal (possible close proximity attack)
            network.get('signal_strength', 0) > -20
        ]
        
        return any(suspicious_indicators)
    
    def save_monitoring_report(self):
        """Save monitoring report to file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'baseline_count': len(self.baseline_networks),
            'recent_alerts': self.alerts[-10:],  # Last 10 alerts
            'total_alerts': len(self.alerts)
        }
        
        report_path = Path('security_monitoring_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

def setup_monitoring():
    """Setup automated monitoring schedule"""
    monitor = SecurityMonitor()
    
    # Establish baseline
    monitor.establish_baseline()
    
    # Schedule monitoring
    schedule.every(5).minutes.do(monitor.monitor_networks)
    schedule.every().hour.do(monitor.save_monitoring_report)
    
    print("Security monitoring started...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped")

if __name__ == "__main__":
    setup_monitoring()
```

## Best Practices

### Example 11: Security Testing Best Practices

```python
#!/usr/bin/env python3
"""
Security testing best practices implementation
"""
from components.security_manager import SecurityManager
from core.logger import get_logger

class SecurityTestingBestPractices:
    """Implements security testing best practices"""
    
    def __init__(self):
        self.logger = get_logger("best_practices")
        self.security_manager = SecurityManager()
    
    def pre_test_checklist(self):
        """Pre-testing security checklist"""
        checklist = {
            'legal_authorization': False,
            'network_ownership': False,
            'backup_created': False,
            'monitoring_disabled': False,
            'documentation_ready': False
        }
        
        print("Pre-Testing Security Checklist:")
        print("=" * 40)
        
        # Check legal authorization
        response = input("Do you have legal authorization to test this network? (y/N): ")
        checklist['legal_authorization'] = response.lower() in ['y', 'yes']
        
        # Check network ownership
        response = input("Do you own this network or have written permission? (y/N): ")
        checklist['network_ownership'] = response.lower() in ['y', 'yes']
        
        # Check backup status
        response = input("Have you created a backup of network configuration? (y/N): ")
        checklist['backup_created'] = response.lower() in ['y', 'yes']
        
        # Check monitoring
        response = input("Have you disabled network monitoring/IDS during testing? (y/N): ")
        checklist['monitoring_disabled'] = response.lower() in ['y', 'yes']
        
        # Check documentation
        response = input("Do you have documentation plan for findings? (y/N): ")
        checklist['documentation_ready'] = response.lower() in ['y', 'yes']
        
        # Evaluate checklist
        passed_checks = sum(checklist.values())
        total_checks = len(checklist)
        
        print(f"\nChecklist Results: {passed_checks}/{total_checks} passed")
        
        if passed_checks < total_checks:
            print("⚠️  WARNING: Not all checklist items passed")
            print("Please address the following before proceeding:")
            
            for item, passed in checklist.items():
                if not passed:
                    print(f"  - {item.replace('_', ' ').title()}")
            
            return False
        
        print("✅ All checklist items passed - proceeding with testing")
        return True
    
    def secure_testing_environment(self):
        """Setup secure testing environment"""
        print("Setting up secure testing environment...")
        
        # Check system security
        security_status = self.security_manager.check_system_security()
        
        # Log security event
        self.security_manager.log_security_event(
            "TESTING_SESSION_START",
            "Security testing session initiated"
        )
        
        # Setup isolated environment recommendations
        recommendations = [
            "Use dedicated testing machine",
            "Disconnect from production networks",
            "Enable comprehensive logging",
            "Use VPN for remote testing",
            "Implement time limits for testing"
        ]
        
        print("Security recommendations:")
        for rec in recommendations:
            print(f"  - {rec}")
        
        return security_status
    
    def post_test_cleanup(self):
        """Post-testing cleanup and reporting"""
        print("Performing post-test cleanup...")
        
        # Reset interfaces
        print("- Resetting network interfaces")
        
        # Clear temporary files
        print("- Cleaning temporary files")
        
        # Generate security report
        print("- Generating security report")
        
        # Log completion
        self.security_manager.log_security_event(
            "TESTING_SESSION_END",
            "Security testing session completed"
        )
        
        print("✅ Post-test cleanup completed")

def demonstrate_best_practices():
    """Demonstrate security testing best practices"""
    
    best_practices = SecurityTestingBestPractices()
    
    # Pre-test checklist
    if not best_practices.pre_test_checklist():
        print("Exiting due to incomplete checklist")
        return
    
    # Setup secure environment
    security_status = best_practices.secure_testing_environment()
    print(f"Security status: {security_status}")
    
    # Simulate testing
    print("\n[Simulating security testing...]")
    time.sleep(2)
    
    # Post-test cleanup
    best_practices.post_test_cleanup()

if __name__ == "__main__":
    import time
    demonstrate_best_practices()
```

### Example 12: Comprehensive Testing Workflow

```python
#!/usr/bin/env python3
"""
Comprehensive security testing workflow
"""
import json
from datetime import datetime
from pathlib import Path

from components.network_scanner import NetworkScanner
from components.wordlist_manager import WordlistManager
from components.interface_manager import InterfaceManager
from components.security_manager import SecurityManager

class ComprehensiveSecurityTest:
    """Complete security testing workflow"""
    
    def __init__(self, target_ssid):
        self.target_ssid = target_ssid
        self.scanner = NetworkScanner()
        self.wordlist_manager = WordlistManager()
        self.interface_manager = InterfaceManager()
        self.security_manager = SecurityManager()
        
        self.test_results = {
            'target': target_ssid,
            'timestamp': datetime.now().isoformat(),
            'phases': {}
        }
    
    def run_comprehensive_test(self):
        """Run complete security testing workflow"""
        
        print(f"Starting comprehensive security test for: {self.target_ssid}")
        print("=" * 60)
        
        # Phase 1: Reconnaissance
        self.phase_reconnaissance()
        
        # Phase 2: Interface Setup
        self.phase_interface_setup()
        
        # Phase 3: Network Analysis
        self.phase_network_analysis()
        
        # Phase 4: Wordlist Preparation
        self.phase_wordlist_preparation()
        
        # Phase 5: Security Assessment
        self.phase_security_assessment()
        
        # Phase 6: Reporting
        self.phase_reporting()
        
        print("\n" + "=" * 60)
        print("Comprehensive security test completed")
    
    def phase_reconnaissance(self):
        """Phase 1: Network reconnaissance"""
        print("\nPhase 1: Network Reconnaissance")
        print("-" * 30)
        
        # Scan for networks
        networks = self.scanner.scan_networks()
        target_network = None
        
        for network in networks:
            if network['ssid'] == self.target_ssid:
                target_network = network
                break
        
        if not target_network:
            raise ValueError(f"Target network '{self.target_ssid}' not found")
        
        # Analyze target network
        network_details = self.scanner.get_network_details(self.target_ssid)
        
        self.test_results['phases']['reconnaissance'] = {
            'target_found': True,
            'network_details': target_network,
            'extended_details': network_details,
            'nearby_networks': len(networks)
        }
        
        print(f"✅ Target network found: {target_network}")
    
    def phase_interface_setup(self):
        """Phase 2: Interface configuration"""
        print("\nPhase 2: Interface Setup")
        print("-" * 25)
        
        # Discover interfaces
        interfaces = self.interface_manager.discover_wifi_interfaces()
        
        if not interfaces:
            raise RuntimeError("No WiFi interfaces available")
        
        # Select best interface
        best_interface = interfaces[0]  # Simplified selection
        
        # Check capabilities
        capabilities = self.interface_manager.get_interface_capabilities(
            best_interface['device']
        )
        
        self.test_results['phases']['interface_setup'] = {
            'interfaces_found': len(interfaces),
            'selected_interface': best_interface,
            'capabilities': capabilities
        }
        
        print(f"✅ Interface configured: {best_interface['device']}")
    
    def phase_network_analysis(self):
        """Phase 3: Network security analysis"""
        print("\nPhase 3: Network Analysis")
        print("-" * 25)
        
        target_network = self.test_results['phases']['reconnaissance']['network_details']
        
        # Analyze encryption
        encryption = target_network.get('encryption', 'Unknown')
        security_level = self.analyze_encryption_strength(encryption)
        
        # Check for common vulnerabilities
        vulnerabilities = self.check_common_vulnerabilities(target_network)
        
        self.test_results['phases']['network_analysis'] = {
            'encryption_type': encryption,
            'security_level': security_level,
            'vulnerabilities': vulnerabilities,
            'signal_strength': target_network.get('signal_strength', 0)
        }
        
        print(f"✅ Network analysis complete - Security level: {security_level}")
    
    def phase_wordlist_preparation(self):
        """Phase 4: Wordlist preparation"""
        print("\nPhase 4: Wordlist Preparation")
        print("-" * 30)
        
        # Create targeted wordlist
        wordlist_categories = ['common', 'wifi_specific']
        all_passwords = []
        
        for category in wordlist_categories:
            passwords = self.wordlist_manager.generate_builtin_wordlist(category)
            all_passwords.extend(passwords)
        
        # Create custom wordlist
        success, wordlist_path = self.wordlist_manager.create_custom_wordlist(
            f'test_{self.target_ssid}',
            all_passwords,
            f'Wordlist for testing {self.target_ssid}'
        )
        
        if success:
            # Optimize wordlist
            optimization_result = self.wordlist_manager.optimize_wordlist(wordlist_path)
            
            self.test_results['phases']['wordlist_preparation'] = {
                'wordlist_created': True,
                'wordlist_path': wordlist_path,
                'password_count': len(all_passwords),
                'optimization_result': optimization_result
            }
            
            print(f"✅ Wordlist prepared: {len(all_passwords)} passwords")
        else:
            print(f"❌ Wordlist creation failed: {wordlist_path}")
    
    def phase_security_assessment(self):
        """Phase 5: Security assessment"""
        print("\nPhase 5: Security Assessment")
        print("-" * 28)
        
        # Note: This is a simulation - actual password cracking would require
        # proper handshake capture and ethical authorization
        
        assessment_results = {
            'password_strength': 'Unknown',
            'estimated_crack_time': 'Unknown',
            'recommendations': []
        }
        
        # Simulate assessment based on network analysis
        network_analysis = self.test_results['phases']['network_analysis']
        
        if network_analysis['security_level'] == 'Low':
            assessment_results['password_strength'] = 'Weak'
            assessment_results['estimated_crack_time'] = 'Minutes to Hours'
            assessment_results['recommendations'].extend([
                'Change to strong password immediately',
                'Upgrade encryption to WPA3',
                'Enable additional security features'
            ])
        elif network_analysis['security_level'] == 'Medium':
            assessment_results['password_strength'] = 'Moderate'
            assessment_results['estimated_crack_time'] = 'Hours to Days'
            assessment_results['recommendations'].extend([
                'Consider stronger password',
                'Upgrade to WPA3 if available',
                'Regular password rotation'
            ])
        else:
            assessment_results['password_strength'] = 'Strong'
            assessment_results['estimated_crack_time'] = 'Impractical'
            assessment_results['recommendations'].append('Maintain current security level')
        
        self.test_results['phases']['security_assessment'] = assessment_results
        
        print(f"✅ Security assessment complete")
    
    def phase_reporting(self):
        """Phase 6: Generate comprehensive report"""
        print("\nPhase 6: Report Generation")
        print("-" * 26)
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary()
        
        # Generate technical details
        technical_details = self.generate_technical_details()
        
        # Generate recommendations
        recommendations = self.generate_recommendations()
        
        # Complete report
        final_report = {
            'executive_summary': executive_summary,
            'technical_details': technical_details,
            'recommendations': recommendations,
            'test_results': self.test_results
        }
        
        # Save report
        report_path = Path(f'security_test_report_{self.target_ssid}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        with open(report_path, 'w') as f:
            json.dump(final_report, f, indent=2)
        
        print(f"✅ Report generated: {report_path}")
        
        # Display summary
        print(f"\nExecutive Summary:")
        print(f"Network: {executive_summary['network_name']}")
        print(f"Security Level: {executive_summary['overall_security_level']}")
        print(f"Risk Level: {executive_summary['risk_level']}")
        print(f"Priority Recommendations: {len(executive_summary['priority_recommendations'])}")
    
    def analyze_encryption_strength(self, encryption):
        """Analyze encryption strength"""
        encryption_upper = encryption.upper()
        
        if 'WEP' in encryption_upper:
            return 'Very Low'
        elif 'WPA ' in encryption_upper:
            return 'Low'
        elif 'WPA2' in encryption_upper:
            return 'Medium'
        elif 'WPA3' in encryption_upper:
            return 'High'
        else:
            return 'Unknown'
    
    def check_common_vulnerabilities(self, network):
        """Check for common network vulnerabilities"""
        vulnerabilities = []
        
        encryption = network.get('encryption', '').upper()
        
        if 'WEP' in encryption:
            vulnerabilities.append('WEP encryption is easily broken')
        
        if 'WPS' in encryption:
            vulnerabilities.append('WPS may be vulnerable to PIN attacks')
        
        if network.get('signal_strength', 0) > -30:
            vulnerabilities.append('Very strong signal may indicate close proximity threat')
        
        return vulnerabilities
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        network_analysis = self.test_results['phases']['network_analysis']
        security_assessment = self.test_results['phases']['security_assessment']
        
        return {
            'network_name': self.target_ssid,
            'test_date': self.test_results['timestamp'],
            'overall_security_level': network_analysis['security_level'],
            'risk_level': self.calculate_risk_level(),
            'priority_recommendations': security_assessment['recommendations'][:3]
        }
    
    def generate_technical_details(self):
        """Generate technical details section"""
        return {
            'methodology': 'Comprehensive WiFi Security Assessment',
            'tools_used': ['Network Scanner', 'Wordlist Manager', 'Security Analyzer'],
            'test_phases': list(self.test_results['phases'].keys()),
            'detailed_findings': self.test_results['phases']
        }
    
    def generate_recommendations(self):
        """Generate comprehensive recommendations"""
        recommendations = {
            'immediate': [],
            'short_term': [],
            'long_term': []
        }
        
        security_level = self.test_results['phases']['network_analysis']['security_level']
        
        if security_level in ['Very Low', 'Low']:
            recommendations['immediate'].extend([
                'Change WiFi password immediately',
                'Upgrade encryption protocol',
                'Disable WPS if enabled'
            ])
        
        recommendations['short_term'].extend([
            'Implement regular password rotation',
            'Enable network monitoring',
            'Update router firmware'
        ])
        
        recommendations['long_term'].extend([
            'Consider enterprise-grade security',
            'Implement network segmentation',
            'Regular security assessments'
        ])
        
        return recommendations
    
    def calculate_risk_level(self):
        """Calculate overall risk level"""
        security_level = self.test_results['phases']['network_analysis']['security_level']
        vulnerabilities = self.test_results['phases']['network_analysis']['vulnerabilities']
        
        if security_level in ['Very Low', 'Low'] or len(vulnerabilities) > 2:
            return 'High'
        elif security_level == 'Medium' or len(vulnerabilities) > 0:
            return 'Medium'
        else:
            return 'Low'

if __name__ == "__main__":
    # Replace with your network name
    target_network = "YourNetworkName"
    
    try:
        test = ComprehensiveSecurityTest(target_network)
        test.run_comprehensive_test()
    except Exception as e:
        print(f"Test failed: {e}")
```

---

These examples demonstrate the full capabilities of the WiFi Security Test Tool, from basic usage to advanced automation and comprehensive security testing workflows. Remember to always use these tools ethically and only on networks you own or have explicit permission to test.
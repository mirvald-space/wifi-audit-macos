"""
User Guidance System - Provides clear instructions for manual error resolution
Offers step-by-step guidance for resolving common issues in WiFi Security Tester
"""

import sys
from typing import Dict, List, Optional, Any
from pathlib import Path
from enum import Enum

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.exceptions import *
from core.logger import get_logger
from utils.common import get_system_info, check_admin_privileges


class GuidanceLevel(Enum):
    """Guidance detail levels"""
    BASIC = "basic"
    DETAILED = "detailed"
    EXPERT = "expert"


class UserGuidanceSystem:
    """Provides user-friendly guidance for error resolution"""
    
    def __init__(self):
        self.logger = get_logger("user_guidance")
        self.guidance_templates = {}
        self.system_info = get_system_info()
        
        # Initialize guidance templates
        self._initialize_guidance_templates()
    
    def _initialize_guidance_templates(self) -> None:
        """Initialize guidance templates for different error types"""
        
        # System Error Guidance
        self.guidance_templates[SIPRestrictionError] = {
            'title': 'System Integrity Protection (SIP) Restriction',
            'description': 'macOS System Integrity Protection is blocking the operation.',
            'severity': 'HIGH',
            'solutions': [
                {
                    'title': 'Use External WiFi Adapter (Recommended)',
                    'difficulty': 'Easy',
                    'steps': [
                        'Purchase a USB WiFi adapter that supports monitor mode',
                        'Popular options: Alfa AWUS036ACS, Panda PAU09',
                        'Connect the adapter to your Mac',
                        'Select the external adapter in the interface menu'
                    ],
                    'pros': ['No system modifications needed', 'Safer approach'],
                    'cons': ['Requires additional hardware purchase']
                },
                {
                    'title': 'Disable SIP Temporarily (Advanced)',
                    'difficulty': 'Advanced',
                    'warning': 'This reduces system security. Only use on test systems.',
                    'steps': [
                        'Restart your Mac and hold Command+R to enter Recovery Mode',
                        'Open Terminal from Utilities menu',
                        'Run: csrutil disable',
                        'Restart your Mac',
                        'After testing, re-enable SIP: csrutil enable'
                    ],
                    'pros': ['Uses built-in WiFi adapter'],
                    'cons': ['Reduces system security', 'Requires restart', 'Advanced procedure']
                }
            ],
            'prevention': [
                'Consider using external WiFi adapters for security testing',
                'Keep SIP enabled for production systems'
            ]
        }
        
        self.guidance_templates[DependencyMissingError] = {
            'title': 'Required Tool Missing',
            'description': 'A required tool is not installed or not found in PATH.',
            'severity': 'HIGH',
            'solutions': [
                {
                    'title': 'Install via Homebrew (Recommended)',
                    'difficulty': 'Easy',
                    'steps': [
                        'Open Terminal',
                        'Install Homebrew if not installed: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
                        'Install the missing tool: brew install [tool-name]',
                        'Verify installation: [tool-name] --version'
                    ]
                },
                {
                    'title': 'Manual Installation',
                    'difficulty': 'Advanced',
                    'steps': [
                        'Visit the official website of the tool',
                        'Download the macOS version',
                        'Follow the installation instructions',
                        'Add to PATH if necessary'
                    ]
                }
            ],
            'common_tools': {
                'aircrack-ng': 'brew install aircrack-ng',
                'hashcat': 'brew install hashcat',
                'wireshark': 'brew install --cask wireshark'
            }
        }
        
        self.guidance_templates[MonitorModeError] = {
            'title': 'Monitor Mode Not Supported',
            'description': 'The WiFi interface does not support monitor mode.',
            'severity': 'HIGH',
            'solutions': [
                {
                    'title': 'Use External WiFi Adapter',
                    'difficulty': 'Easy',
                    'steps': [
                        'Purchase a USB WiFi adapter with monitor mode support',
                        'Recommended: Alfa AWUS036ACS, Panda PAU09',
                        'Connect the adapter to your Mac',
                        'Select the external adapter in the application'
                    ],
                    'pros': ['Full monitor mode support', 'Better for security testing'],
                    'cons': ['Additional hardware cost']
                },
                {
                    'title': 'Use Alternative Capture Methods',
                    'difficulty': 'Intermediate',
                    'steps': [
                        'Use passive scanning instead of monitor mode',
                        'Try tcpdump with specific filters',
                        'Use built-in packet capture tools',
                        'Consider Wireshark in promiscuous mode'
                    ],
                    'limitations': ['May not capture all packets', 'Limited handshake capture']
                }
            ]
        }
    
    def get_guidance(self, error: Exception, level: GuidanceLevel = GuidanceLevel.DETAILED) -> Dict[str, Any]:
        """Get guidance for a specific error"""
        error_type = type(error)
        
        # Check for specific error type guidance
        if error_type in self.guidance_templates:
            guidance = self.guidance_templates[error_type].copy()
        else:
            # Check parent classes
            guidance = None
            for parent_type in error_type.__mro__[1:]:
                if parent_type in self.guidance_templates:
                    guidance = self.guidance_templates[parent_type].copy()
                    break
            
            if not guidance:
                guidance = self._get_generic_guidance(error)
        
        # Add error-specific information
        guidance['error_message'] = str(error)
        guidance['error_type'] = error_type.__name__
        
        # Add recovery suggestions from error if available
        if hasattr(error, 'recovery_suggestions'):
            guidance['error_suggestions'] = error.recovery_suggestions
        
        # Filter guidance based on level
        if level == GuidanceLevel.BASIC:
            guidance = self._filter_basic_guidance(guidance)
        elif level == GuidanceLevel.EXPERT:
            guidance = self._add_expert_guidance(guidance, error)
        
        return guidance
    
    def _get_generic_guidance(self, error: Exception) -> Dict[str, Any]:
        """Get generic guidance for unknown error types"""
        return {
            'title': 'Unknown Error',
            'description': f'An unexpected error occurred: {str(error)}',
            'severity': 'MEDIUM',
            'solutions': [
                {
                    'title': 'Basic Troubleshooting',
                    'difficulty': 'Easy',
                    'steps': [
                        'Restart the application',
                        'Check your internet connection',
                        'Verify all required tools are installed',
                        'Try running with administrator privileges'
                    ]
                }
            ]
        }
    
    def _filter_basic_guidance(self, guidance: Dict[str, Any]) -> Dict[str, Any]:
        """Filter guidance to show only basic information"""
        filtered = guidance.copy()
        
        # Keep only easy solutions
        if 'solutions' in filtered:
            filtered['solutions'] = [
                sol for sol in filtered['solutions'] 
                if sol.get('difficulty', '').lower() == 'easy'
            ]
        
        return filtered
    
    def _add_expert_guidance(self, guidance: Dict[str, Any], error: Exception) -> Dict[str, Any]:
        """Add expert-level guidance and technical details"""
        expert_guidance = guidance.copy()
        
        # Add technical details
        expert_guidance['technical_details'] = {
            'error_class': type(error).__name__,
            'error_module': type(error).__module__,
            'system_info': self.system_info,
            'admin_privileges': check_admin_privileges()
        }
        
        return expert_guidance
    
    def format_guidance_text(self, guidance: Dict[str, Any]) -> str:
        """Format guidance as readable text"""
        text_parts = []
        
        # Title and description
        text_parts.append(f"=== {guidance.get('title', 'Error Guidance')} ===")
        text_parts.append(f"Description: {guidance.get('description', 'No description available')}")
        text_parts.append(f"Severity: {guidance.get('severity', 'UNKNOWN')}")
        text_parts.append("")
        
        # Error message
        if 'error_message' in guidance:
            text_parts.append(f"Error: {guidance['error_message']}")
            text_parts.append("")
        
        # Solutions
        solutions = guidance.get('solutions', [])
        if solutions:
            text_parts.append("SOLUTIONS:")
            for i, solution in enumerate(solutions, 1):
                text_parts.append(f"\n{i}. {solution.get('title', 'Solution')}")
                text_parts.append(f"   Difficulty: {solution.get('difficulty', 'Unknown')}")
                
                if 'warning' in solution:
                    text_parts.append(f"   ⚠️  WARNING: {solution['warning']}")
                
                steps = solution.get('steps', [])
                if steps:
                    text_parts.append("   Steps:")
                    for j, step in enumerate(steps, 1):
                        text_parts.append(f"      {j}. {step}")
                
                if 'pros' in solution:
                    text_parts.append(f"   Pros: {', '.join(solution['pros'])}")
                if 'cons' in solution:
                    text_parts.append(f"   Cons: {', '.join(solution['cons'])}")
        
        return "\n".join(text_parts)
    
    def get_quick_fix_suggestions(self, error: Exception) -> List[str]:
        """Get quick fix suggestions for common errors"""
        error_type = type(error)
        
        quick_fixes = {
            DependencyMissingError: [
                "Install missing tool with Homebrew",
                "Check if tool is in PATH",
                "Restart terminal after installation"
            ],
            SIPRestrictionError: [
                "Use external WiFi adapter",
                "Try alternative methods",
                "Consider disabling SIP temporarily (advanced)"
            ],
            MonitorModeError: [
                "Use external WiFi adapter with monitor mode support",
                "Try alternative capture methods",
                "Check if interface supports monitor mode"
            ]
        }
        
        # Check for specific error type
        if error_type in quick_fixes:
            return quick_fixes[error_type]
        
        # Check parent classes
        for parent_type in error_type.__mro__[1:]:
            if parent_type in quick_fixes:
                return quick_fixes[parent_type]
        
        # Generic quick fixes
        return [
            "Restart the application",
            "Check system requirements",
            "Verify all dependencies are installed",
            "Try running with administrator privileges"
        ]
    
    def generate_troubleshooting_report(self, errors: List[Exception]) -> str:
        """Generate a comprehensive troubleshooting report"""
        import time
        
        report_parts = []
        
        report_parts.append("=== TROUBLESHOOTING REPORT ===")
        report_parts.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_parts.append(f"System: {self.system_info.get('system', 'Unknown')}")
        report_parts.append(f"Total Errors: {len(errors)}")
        report_parts.append("")
        
        # Group errors by type
        error_groups = {}
        for error in errors:
            error_type = type(error).__name__
            if error_type not in error_groups:
                error_groups[error_type] = []
            error_groups[error_type].append(error)
        
        # Report each error group
        for error_type, error_list in error_groups.items():
            report_parts.append(f"--- {error_type} ({len(error_list)} occurrences) ---")
            
            # Get guidance for first error of this type
            guidance = self.get_guidance(error_list[0], GuidanceLevel.DETAILED)
            
            report_parts.append(f"Description: {guidance.get('description', 'No description')}")
            report_parts.append(f"Severity: {guidance.get('severity', 'UNKNOWN')}")
            
            # Quick fixes
            quick_fixes = self.get_quick_fix_suggestions(error_list[0])
            if quick_fixes:
                report_parts.append("Quick Fixes:")
                for fix in quick_fixes:
                    report_parts.append(f"  • {fix}")
            
            report_parts.append("")
        
        return "\n".join(report_parts)


# Global user guidance system instance
_global_user_guidance_system = None


def get_user_guidance_system() -> UserGuidanceSystem:
    """Get the global user guidance system instance"""
    global _global_user_guidance_system
    if _global_user_guidance_system is None:
        _global_user_guidance_system = UserGuidanceSystem()
    return _global_user_guidance_system
"""
Dependency Manager - Manages system dependencies and tool installations
Handles checking, installing, and validating required tools for WiFi security testing

Author: @mirvaId
Contact: Telegram @mirvaId
License: MIT License
"""

import subprocess
import platform
import shutil
import os
from typing import Dict, List, Tuple, Optional
import sys
from pathlib import Path

# Add the parent directory to sys.path to enable imports
sys.path.append(str(Path(__file__).parent.parent))
from core.logger import get_logger


class DependencyManager:
    """Manages system dependencies and tool installations"""
    
    def __init__(self):
        self.logger = get_logger("dependency_manager")
        self.required_tools = {
            'homebrew': '/opt/homebrew/bin/brew',  # Apple Silicon path
            'aircrack-ng': 'aircrack-ng',
            'hashcat': 'hashcat',
            'wdutil': '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/wdutil'
        }
        self.homebrew_fallback_path = '/usr/local/bin/brew'  # Intel Mac path
        self.min_macos_version = (10, 15)  # Catalina minimum
    
    def check_homebrew_installation(self) -> bool:
        """
        Check if Homebrew is installed on the system
        
        Returns:
            bool: True if Homebrew is installed, False otherwise
        """
        try:
            # Check Apple Silicon path first
            if os.path.exists(self.required_tools['homebrew']):
                self.logger.info("Homebrew found at Apple Silicon path")
                return True
            
            # Check Intel Mac path
            if os.path.exists(self.homebrew_fallback_path):
                self.logger.info("Homebrew found at Intel Mac path")
                self.required_tools['homebrew'] = self.homebrew_fallback_path
                return True
            
            # Try to find brew in PATH
            if shutil.which('brew'):
                brew_path = shutil.which('brew')
                self.logger.info(f"Homebrew found in PATH: {brew_path}")
                self.required_tools['homebrew'] = brew_path
                return True
            
            self.logger.warning("Homebrew not found on system")
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking Homebrew installation: {e}")
            return False
    
    def check_tool_availability(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a specific tool is available on the system
        
        Args:
            tool_name (str): Name of the tool to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_available, path_or_error)
        """
        try:
            if tool_name == 'homebrew':
                is_available = self.check_homebrew_installation()
                path = self.required_tools['homebrew'] if is_available else None
                return is_available, path
            
            elif tool_name == 'wdutil':
                # wdutil is a built-in macOS tool
                wdutil_path = self.required_tools['wdutil']
                if os.path.exists(wdutil_path):
                    self.logger.info(f"wdutil found at: {wdutil_path}")
                    return True, wdutil_path
                else:
                    self.logger.warning("wdutil not found - may not be available on this macOS version")
                    return False, "wdutil not found in expected location"
            
            elif tool_name in ['aircrack-ng', 'hashcat']:
                # Check if tool is in PATH
                tool_path = shutil.which(tool_name)
                if tool_path:
                    self.logger.info(f"{tool_name} found at: {tool_path}")
                    return True, tool_path
                else:
                    self.logger.warning(f"{tool_name} not found in PATH")
                    return False, f"{tool_name} not found in PATH"
            
            else:
                return False, f"Unknown tool: {tool_name}"
                
        except Exception as e:
            error_msg = f"Error checking {tool_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def check_macos_compatibility(self) -> Tuple[bool, str]:
        """
        Check if the current macOS version is compatible
        
        Returns:
            Tuple[bool, str]: (is_compatible, version_info)
        """
        try:
            # Get macOS version
            mac_version = platform.mac_ver()[0]
            if not mac_version:
                return False, "Unable to determine macOS version"
            
            # Parse version numbers
            version_parts = mac_version.split('.')
            major = int(version_parts[0])
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            
            current_version = (major, minor)
            min_version = self.min_macos_version
            
            is_compatible = current_version >= min_version
            
            version_info = f"Current: macOS {mac_version}, Minimum: macOS {min_version[0]}.{min_version[1]}"
            
            if is_compatible:
                self.logger.info(f"macOS version compatible: {version_info}")
            else:
                self.logger.warning(f"macOS version may be incompatible: {version_info}")
            
            return is_compatible, version_info
            
        except Exception as e:
            error_msg = f"Error checking macOS compatibility: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_system_architecture(self) -> str:
        """
        Get the system architecture (Intel or Apple Silicon)
        
        Returns:
            str: System architecture information
        """
        try:
            machine = platform.machine()
            processor = platform.processor()
            
            if machine == 'arm64':
                arch_info = "Apple Silicon (M1/M2)"
            elif machine == 'x86_64':
                arch_info = "Intel x86_64"
            else:
                arch_info = f"Unknown architecture: {machine}"
            
            self.logger.info(f"System architecture: {arch_info}")
            return arch_info
            
        except Exception as e:
            error_msg = f"Error getting system architecture: {e}"
            self.logger.error(error_msg)
            return error_msg
    
    def check_all_dependencies(self) -> Dict[str, Dict[str, any]]:
        """
        Check all required dependencies and system compatibility
        
        Returns:
            Dict: Comprehensive dependency status report
        """
        dependency_status = {
            'system_info': {},
            'tools': {},
            'overall_status': True
        }
        
        try:
            # Check system compatibility
            is_compatible, version_info = self.check_macos_compatibility()
            dependency_status['system_info']['macos_compatible'] = is_compatible
            dependency_status['system_info']['version_info'] = version_info
            dependency_status['system_info']['architecture'] = self.get_system_architecture()
            
            if not is_compatible:
                dependency_status['overall_status'] = False
            
            # Check each required tool
            for tool_name in self.required_tools.keys():
                is_available, path_or_error = self.check_tool_availability(tool_name)
                
                dependency_status['tools'][tool_name] = {
                    'available': is_available,
                    'path': path_or_error if is_available else None,
                    'error': path_or_error if not is_available else None
                }
                
                if not is_available:
                    dependency_status['overall_status'] = False
            
            # Log overall status
            if dependency_status['overall_status']:
                self.logger.info("All dependencies check passed")
            else:
                self.logger.warning("Some dependencies are missing or incompatible")
            
            return dependency_status
            
        except Exception as e:
            self.logger.error(f"Error during dependency check: {e}")
            dependency_status['overall_status'] = False
            dependency_status['error'] = str(e)
            return dependency_status
    
    def install_homebrew(self) -> Tuple[bool, str]:
        """
        Install Homebrew if it's not present on the system
        
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            self.logger.info("Starting Homebrew installation...")
            
            # Homebrew installation command
            install_cmd = [
                '/bin/bash', '-c',
                '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
            ]
            
            # Run installation with progress tracking
            process = subprocess.Popen(
                install_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            stdout_lines = []
            stderr_lines = []
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    stdout_lines.append(output.strip())
                    self.logger.info(f"Homebrew install: {output.strip()}")
            
            # Get any remaining stderr
            stderr_output = process.stderr.read()
            if stderr_output:
                stderr_lines.extend(stderr_output.strip().split('\n'))
            
            return_code = process.poll()
            
            if return_code == 0:
                success_msg = "Homebrew installation completed successfully"
                self.logger.info(success_msg)
                
                # Update Homebrew path after installation
                if not self.check_homebrew_installation():
                    return False, "Homebrew installed but not found in expected locations"
                
                return True, success_msg
            else:
                error_msg = f"Homebrew installation failed with code {return_code}"
                if stderr_lines:
                    error_msg += f": {'; '.join(stderr_lines)}"
                self.logger.error(error_msg)
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Error installing Homebrew: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def install_tool_via_brew(self, tool_name: str) -> Tuple[bool, str]:
        """
        Install a specific tool using Homebrew
        
        Args:
            tool_name (str): Name of the tool to install
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Check if Homebrew is available
            if not self.check_homebrew_installation():
                return False, "Homebrew not available for tool installation"
            
            brew_path = self.required_tools['homebrew']
            
            # Map tool names to Homebrew packages
            brew_packages = {
                'aircrack-ng': 'aircrack-ng',
                'hashcat': 'hashcat'
            }
            
            if tool_name not in brew_packages:
                return False, f"Tool {tool_name} cannot be installed via Homebrew"
            
            package_name = brew_packages[tool_name]
            self.logger.info(f"Installing {tool_name} via Homebrew...")
            
            # Install command
            install_cmd = [brew_path, 'install', package_name]
            
            # Run installation with progress tracking
            process = subprocess.Popen(
                install_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            stdout_lines = []
            stderr_lines = []
            
            # Read output in real-time
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    stdout_lines.append(output.strip())
                    self.logger.info(f"brew install {package_name}: {output.strip()}")
            
            # Get any remaining stderr
            stderr_output = process.stderr.read()
            if stderr_output:
                stderr_lines.extend(stderr_output.strip().split('\n'))
                for line in stderr_lines:
                    if line.strip():
                        self.logger.warning(f"brew install {package_name} stderr: {line}")
            
            return_code = process.poll()
            
            if return_code == 0:
                success_msg = f"{tool_name} installation completed successfully"
                self.logger.info(success_msg)
                
                # Verify installation
                is_available, _ = self.check_tool_availability(tool_name)
                if not is_available:
                    return False, f"{tool_name} installed but not found in PATH"
                
                return True, success_msg
            else:
                error_msg = f"{tool_name} installation failed with code {return_code}"
                if stderr_lines:
                    error_msg += f": {'; '.join([line for line in stderr_lines if line.strip()])}"
                self.logger.error(error_msg)
                return False, error_msg
                
        except Exception as e:
            error_msg = f"Error installing {tool_name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def install_missing_dependencies(self) -> Dict[str, Dict[str, any]]:
        """
        Automatically install missing dependencies
        
        Returns:
            Dict: Installation results for each dependency
        """
        installation_results = {
            'homebrew': {'attempted': False, 'success': False, 'message': ''},
            'tools': {},
            'overall_success': True
        }
        
        try:
            # First check current status
            dependency_status = self.check_all_dependencies()
            
            # Install Homebrew if missing
            if not dependency_status['tools']['homebrew']['available']:
                self.logger.info("Homebrew missing - attempting installation...")
                installation_results['homebrew']['attempted'] = True
                
                success, message = self.install_homebrew()
                installation_results['homebrew']['success'] = success
                installation_results['homebrew']['message'] = message
                
                if not success:
                    installation_results['overall_success'] = False
                    self.logger.error("Cannot proceed with tool installation - Homebrew installation failed")
                    return installation_results
            else:
                installation_results['homebrew']['success'] = True
                installation_results['homebrew']['message'] = "Homebrew already available"
            
            # Install missing tools
            installable_tools = ['aircrack-ng', 'hashcat']
            
            for tool_name in installable_tools:
                if not dependency_status['tools'][tool_name]['available']:
                    self.logger.info(f"{tool_name} missing - attempting installation...")
                    
                    success, message = self.install_tool_via_brew(tool_name)
                    installation_results['tools'][tool_name] = {
                        'attempted': True,
                        'success': success,
                        'message': message
                    }
                    
                    if not success:
                        installation_results['overall_success'] = False
                else:
                    installation_results['tools'][tool_name] = {
                        'attempted': False,
                        'success': True,
                        'message': f"{tool_name} already available"
                    }
            
            # Handle wdutil (built-in tool)
            if not dependency_status['tools']['wdutil']['available']:
                installation_results['tools']['wdutil'] = {
                    'attempted': False,
                    'success': False,
                    'message': "wdutil is a built-in macOS tool - cannot be installed separately"
                }
                installation_results['overall_success'] = False
            else:
                installation_results['tools']['wdutil'] = {
                    'attempted': False,
                    'success': True,
                    'message': "wdutil available (built-in macOS tool)"
                }
            
            # Log overall result
            if installation_results['overall_success']:
                self.logger.info("All missing dependencies installed successfully")
            else:
                self.logger.warning("Some dependencies could not be installed")
            
            return installation_results
            
        except Exception as e:
            error_msg = f"Error during dependency installation: {e}"
            self.logger.error(error_msg)
            installation_results['overall_success'] = False
            installation_results['error'] = error_msg
            return installation_results
    
    def track_installation_progress(self, process: subprocess.Popen, tool_name: str) -> Tuple[List[str], List[str]]:
        """
        Track installation progress and log output in real-time
        
        Args:
            process: The subprocess running the installation
            tool_name: Name of the tool being installed
            
        Returns:
            Tuple[List[str], List[str]]: (stdout_lines, stderr_lines)
        """
        stdout_lines = []
        stderr_lines = []
        
        try:
            while True:
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Read stdout
                stdout_line = process.stdout.readline()
                if stdout_line:
                    line = stdout_line.strip()
                    stdout_lines.append(line)
                    self.logger.info(f"{tool_name} install: {line}")
                
                # Read stderr
                stderr_line = process.stderr.readline()
                if stderr_line:
                    line = stderr_line.strip()
                    stderr_lines.append(line)
                    self.logger.warning(f"{tool_name} install stderr: {line}")
            
            # Get any remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            
            if remaining_stdout:
                for line in remaining_stdout.strip().split('\n'):
                    if line.strip():
                        stdout_lines.append(line.strip())
                        self.logger.info(f"{tool_name} install: {line.strip()}")
            
            if remaining_stderr:
                for line in remaining_stderr.strip().split('\n'):
                    if line.strip():
                        stderr_lines.append(line.strip())
                        self.logger.warning(f"{tool_name} install stderr: {line.strip()}")
            
        except Exception as e:
            self.logger.error(f"Error tracking installation progress for {tool_name}: {e}")
        
        return stdout_lines, stderr_lines
    
    def get_tool_version(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """
        Get version information for a specific tool
        
        Args:
            tool_name (str): Name of the tool
            
        Returns:
            Tuple[bool, Optional[str]]: (success, version_string)
        """
        try:
            version_commands = {
                'homebrew': [self.required_tools.get('homebrew', 'brew'), '--version'],
                'aircrack-ng': ['aircrack-ng', '--help'],  # aircrack-ng shows version in help
                'hashcat': ['hashcat', '--version'],
                'wdutil': [self.required_tools['wdutil'], 'version']
            }
            
            if tool_name not in version_commands:
                return False, f"Version check not implemented for {tool_name}"
            
            cmd = version_commands[tool_name]
            
            # Special handling for tools that might not be in PATH
            if tool_name in ['homebrew', 'wdutil']:
                if not os.path.exists(cmd[0]):
                    return False, f"{tool_name} executable not found"
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                
                # Extract version from output
                if tool_name == 'homebrew':
                    # Homebrew version is in first line
                    version = output.split('\n')[0] if output else "Unknown"
                elif tool_name == 'aircrack-ng':
                    # Look for version in help output
                    for line in output.split('\n'):
                        if 'Aircrack-ng' in line and ('v' in line or '.' in line):
                            version = line.strip()
                            break
                    else:
                        version = "Version found in help output"
                elif tool_name == 'hashcat':
                    # Hashcat version is usually in first line
                    version = output.split('\n')[0] if output else "Unknown"
                elif tool_name == 'wdutil':
                    # wdutil version output
                    version = output if output else "Built-in macOS tool"
                else:
                    version = output.split('\n')[0] if output else "Unknown"
                
                self.logger.info(f"{tool_name} version: {version}")
                return True, version
            else:
                error_msg = result.stderr.strip() if result.stderr else f"Command failed with code {result.returncode}"
                self.logger.warning(f"Could not get {tool_name} version: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout getting {tool_name} version"
            self.logger.warning(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error getting {tool_name} version: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def validate_tool_compatibility(self, tool_name: str, version: str) -> Tuple[bool, str]:
        """
        Validate if a tool version is compatible with the system
        
        Args:
            tool_name (str): Name of the tool
            version (str): Version string
            
        Returns:
            Tuple[bool, str]: (is_compatible, compatibility_message)
        """
        try:
            # Define minimum compatible versions
            min_versions = {
                'aircrack-ng': '1.6',
                'hashcat': '6.0.0',
                'homebrew': '3.0.0'
            }
            
            if tool_name not in min_versions:
                return True, f"{tool_name} compatibility check not implemented"
            
            min_version = min_versions[tool_name]
            
            # Simple version comparison (works for most cases)
            # Extract numeric version from version string
            import re
            version_match = re.search(r'(\d+\.[\d\.]+)', version)
            
            if not version_match:
                return True, f"Could not parse version for {tool_name}: {version}"
            
            current_version = version_match.group(1)
            
            # Compare versions (simple string comparison works for most cases)
            if current_version >= min_version:
                compatibility_msg = f"{tool_name} version {current_version} is compatible (min: {min_version})"
                self.logger.info(compatibility_msg)
                return True, compatibility_msg
            else:
                compatibility_msg = f"{tool_name} version {current_version} may be outdated (min: {min_version})"
                self.logger.warning(compatibility_msg)
                return False, compatibility_msg
                
        except Exception as e:
            error_msg = f"Error validating {tool_name} compatibility: {e}"
            self.logger.error(error_msg)
            return True, error_msg  # Default to compatible if we can't check
    
    def generate_dependency_report(self) -> Dict[str, any]:
        """
        Generate comprehensive dependency status report
        
        Returns:
            Dict: Detailed dependency report with recommendations
        """
        report = {
            'timestamp': subprocess.run(['date'], capture_output=True, text=True).stdout.strip(),
            'system_info': {},
            'dependencies': {},
            'recommendations': [],
            'overall_status': 'unknown'
        }
        
        try:
            # Get system information
            is_compatible, version_info = self.check_macos_compatibility()
            architecture = self.get_system_architecture()
            
            report['system_info'] = {
                'macos_compatible': is_compatible,
                'version_info': version_info,
                'architecture': architecture,
                'platform': platform.platform()
            }
            
            # Check each dependency
            dependency_status = self.check_all_dependencies()
            
            for tool_name in self.required_tools.keys():
                tool_info = {
                    'available': False,
                    'path': None,
                    'version': None,
                    'compatible': False,
                    'status': 'unknown',
                    'recommendations': []
                }
                
                # Check availability
                is_available, path_or_error = self.check_tool_availability(tool_name)
                tool_info['available'] = is_available
                
                if is_available:
                    tool_info['path'] = path_or_error
                    tool_info['status'] = 'available'
                    
                    # Get version
                    version_success, version_info = self.get_tool_version(tool_name)
                    if version_success:
                        tool_info['version'] = version_info
                        
                        # Check compatibility
                        is_compatible, compat_msg = self.validate_tool_compatibility(tool_name, version_info)
                        tool_info['compatible'] = is_compatible
                        tool_info['compatibility_message'] = compat_msg
                        
                        if is_compatible:
                            tool_info['status'] = 'ready'
                        else:
                            tool_info['status'] = 'outdated'
                            tool_info['recommendations'].append(f"Consider updating {tool_name}")
                    else:
                        tool_info['version'] = f"Could not determine version: {version_info}"
                        tool_info['compatible'] = True  # Assume compatible if we can't check
                        tool_info['status'] = 'available_unknown_version'
                else:
                    tool_info['status'] = 'missing'
                    tool_info['error'] = path_or_error
                    
                    # Add installation recommendations
                    if tool_name == 'homebrew':
                        tool_info['recommendations'].append("Install Homebrew from https://brew.sh")
                    elif tool_name in ['aircrack-ng', 'hashcat']:
                        tool_info['recommendations'].append(f"Install via Homebrew: brew install {tool_name}")
                    elif tool_name == 'wdutil':
                        tool_info['recommendations'].append("wdutil is built-in to macOS - may not be available on older versions")
                
                report['dependencies'][tool_name] = tool_info
            
            # Generate overall recommendations
            missing_tools = [name for name, info in report['dependencies'].items() 
                           if not info['available']]
            
            if missing_tools:
                if 'homebrew' in missing_tools:
                    report['recommendations'].append("Install Homebrew first, then install missing tools")
                else:
                    report['recommendations'].append(f"Install missing tools: {', '.join(missing_tools)}")
            
            if not report['system_info']['macos_compatible']:
                report['recommendations'].append("Consider upgrading macOS for better compatibility")
            
            # Determine overall status
            if not missing_tools and report['system_info']['macos_compatible']:
                report['overall_status'] = 'ready'
            elif missing_tools:
                report['overall_status'] = 'missing_dependencies'
            else:
                report['overall_status'] = 'system_incompatible'
            
            self.logger.info(f"Dependency report generated - Status: {report['overall_status']}")
            return report
            
        except Exception as e:
            error_msg = f"Error generating dependency report: {e}"
            self.logger.error(error_msg)
            report['error'] = error_msg
            report['overall_status'] = 'error'
            return report
    
    def print_user_friendly_report(self, report: Dict[str, any] = None) -> str:
        """
        Generate user-friendly dependency report
        
        Args:
            report (Dict): Optional pre-generated report
            
        Returns:
            str: Formatted report string
        """
        if report is None:
            report = self.generate_dependency_report()
        
        output_lines = []
        
        try:
            # Header
            output_lines.append("=" * 60)
            output_lines.append("WiFi Security Tester - Dependency Report")
            output_lines.append("=" * 60)
            output_lines.append(f"Generated: {report.get('timestamp', 'Unknown')}")
            output_lines.append("")
            
            # System Information
            output_lines.append("System Information:")
            output_lines.append("-" * 20)
            sys_info = report.get('system_info', {})
            output_lines.append(f"macOS Version: {sys_info.get('version_info', 'Unknown')}")
            output_lines.append(f"Architecture: {sys_info.get('architecture', 'Unknown')}")
            output_lines.append(f"Compatible: {'✓' if sys_info.get('macos_compatible') else '✗'}")
            output_lines.append("")
            
            # Dependencies
            output_lines.append("Dependencies:")
            output_lines.append("-" * 15)
            
            dependencies = report.get('dependencies', {})
            for tool_name, tool_info in dependencies.items():
                status_icon = "✓" if tool_info.get('available') else "✗"
                status_text = tool_info.get('status', 'unknown').replace('_', ' ').title()
                
                output_lines.append(f"{status_icon} {tool_name.title()}: {status_text}")
                
                if tool_info.get('version'):
                    output_lines.append(f"    Version: {tool_info['version']}")
                
                if tool_info.get('path'):
                    output_lines.append(f"    Path: {tool_info['path']}")
                
                if tool_info.get('error'):
                    output_lines.append(f"    Error: {tool_info['error']}")
                
                if tool_info.get('recommendations'):
                    for rec in tool_info['recommendations']:
                        output_lines.append(f"    → {rec}")
                
                output_lines.append("")
            
            # Overall Status
            overall_status = report.get('overall_status', 'unknown')
            status_messages = {
                'ready': '✓ All dependencies are ready!',
                'missing_dependencies': '⚠ Some dependencies are missing',
                'system_incompatible': '✗ System compatibility issues detected',
                'error': '✗ Error occurred during check'
            }
            
            output_lines.append("Overall Status:")
            output_lines.append("-" * 15)
            output_lines.append(status_messages.get(overall_status, f"Status: {overall_status}"))
            output_lines.append("")
            
            # Recommendations
            recommendations = report.get('recommendations', [])
            if recommendations:
                output_lines.append("Recommendations:")
                output_lines.append("-" * 15)
                for i, rec in enumerate(recommendations, 1):
                    output_lines.append(f"{i}. {rec}")
                output_lines.append("")
            
            output_lines.append("=" * 60)
            
            formatted_report = "\n".join(output_lines)
            self.logger.info("User-friendly dependency report generated")
            return formatted_report
            
        except Exception as e:
            error_msg = f"Error formatting dependency report: {e}"
            self.logger.error(error_msg)
            return f"Error generating report: {error_msg}"
    
    def get_installation_guidance(self, missing_tools: List[str] = None) -> Dict[str, str]:
        """
        Provide step-by-step installation guidance for missing tools
        
        Args:
            missing_tools (List[str]): List of missing tools, if None will check automatically
            
        Returns:
            Dict[str, str]: Installation guidance for each tool
        """
        if missing_tools is None:
            dependency_status = self.check_all_dependencies()
            missing_tools = [name for name, info in dependency_status['tools'].items() 
                           if not info['available']]
        
        guidance = {}
        
        try:
            for tool in missing_tools:
                if tool == 'homebrew':
                    guidance[tool] = """
1. Open Terminal application
2. Run the following command:
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
3. Follow the on-screen instructions
4. After installation, restart Terminal
5. Verify installation: brew --version
"""
                
                elif tool == 'aircrack-ng':
                    guidance[tool] = """
1. Ensure Homebrew is installed first
2. Open Terminal application
3. Run: brew install aircrack-ng
4. Wait for installation to complete
5. Verify installation: aircrack-ng --help
"""
                
                elif tool == 'hashcat':
                    guidance[tool] = """
1. Ensure Homebrew is installed first
2. Open Terminal application
3. Run: brew install hashcat
4. Wait for installation to complete
5. Verify installation: hashcat --version
"""
                
                elif tool == 'wdutil':
                    guidance[tool] = """
wdutil is a built-in macOS tool that should be available on macOS 10.15+
If not available:
1. Check your macOS version: About This Mac
2. Consider updating macOS if running an older version
3. wdutil may not be available on some macOS configurations
"""
                
                else:
                    guidance[tool] = f"Installation guidance not available for {tool}"
            
            self.logger.info(f"Installation guidance generated for {len(guidance)} tools")
            return guidance
            
        except Exception as e:
            error_msg = f"Error generating installation guidance: {e}"
            self.logger.error(error_msg)
            return {'error': error_msg}
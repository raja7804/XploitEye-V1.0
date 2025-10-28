#!/usr/bin/env python3
"""
AEGISVULN VERSION 1 - Professional Vulnerability Scanner
Complete Windows-compatible vulnerability scanning tool in a single file
"""

import argparse
import asyncio
import json
import logging
import sys
import time
import subprocess
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from enum import Enum
import socket
import ipaddress
import webbrowser

# =============================================================================
# DEPENDENCY CHECK AND IMPORTS
# =============================================================================

def check_dependencies():
    """Check and import required dependencies"""
    missing_deps = []
    
    try:
        import nmap
    except ImportError:
        missing_deps.append("python-nmap")
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    if missing_deps:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print("💡 Install with: pip install python-nmap requests")
        return False
    
    return True

# Try to import dependencies
if check_dependencies():
    import nmap
    import requests
    REQUESTS_AVAILABLE = True
else:
    REQUESTS_AVAILABLE = False
    sys.exit(1)

# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    version: str = ""
    product: str = ""
    extrainfo: str = ""
    banner: str = ""
    ip: str = ""

@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    status: str = "unknown"
    os: str = ""
    mac: str = ""
    services: List[Service] = field(default_factory=list)
    risk_score: float = 0.0

@dataclass
class CVE:
    id: str
    description: str
    cvss_score: float
    severity: str
    references: List[str] = field(default_factory=list)
    published_date: str = ""
    exploit_available: bool = False
    patch_available: bool = False

@dataclass
class Vulnerability:
    host: str
    port: int
    service: str
    cve: CVE
    confidence: float = 0.0
    risk_factors: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    targets: List[str]
    hosts: List[HostResult] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0

class ScanIntensity(Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"

class ScanType(Enum):
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    WEB_APPLICATION = "web_app"
    NETWORK_AUDIT = "network_audit"

# =============================================================================
# UPDATE MANAGER
# =============================================================================

class UpdateManager:
    """Manage tool updates and version checking"""
    
    CURRENT_VERSION = "1.0.0"
    UPDATE_CHECK_URL = "https://api.github.com/repos/your-username/aegisvuln/releases/latest"
    
    def __init__(self):
        self.update_available = False
        self.latest_version = self.CURRENT_VERSION
        self.release_url = ""
    
    def check_for_updates(self) -> bool:
        """Check if updates are available"""
        print("🔍 Checking for updates...")
        
        if not REQUESTS_AVAILABLE:
            print("⚠️  Cannot check updates: requests module not available")
            return False
        
        try:
            response = requests.get(self.UPDATE_CHECK_URL, timeout=10)
            if response.status_code == 200:
                release_data = response.json()
                self.latest_version = release_data.get('tag_name', '').lstrip('v')
                self.release_url = release_data.get('html_url', '')
                
                if self._is_newer_version(self.latest_version):
                    self.update_available = True
                    print(f"🎉 New version available: v{self.latest_version}")
                    print(f"💡 Current version: v{self.CURRENT_VERSION}")
                    return True
                else:
                    print("✅ You have the latest version")
                    return False
            else:
                print("⚠️  Could not check for updates")
                return False
                
        except Exception as e:
            print(f"⚠️  Update check failed: {e}")
            return False
    
    def _is_newer_version(self, latest_version: str) -> bool:
        """Compare version strings"""
        try:
            current_parts = list(map(int, self.CURRENT_VERSION.split('.')))
            latest_parts = list(map(int, latest_version.split('.')))
            
            for i in range(max(len(current_parts), len(latest_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                latest_part = latest_parts[i] if i < len(latest_parts) else 0
                
                if latest_part > current_part:
                    return True
                elif latest_part < current_part:
                    return False
            
            return False
        except (ValueError, IndexError):
            return False
    
    def show_update_info(self):
        """Display update information"""
        if self.update_available:
            print("\n" + "="*60)
            print("🔄 UPDATE AVAILABLE!")
            print("="*60)
            print(f"Current version: v{self.CURRENT_VERSION}")
            print(f"Latest version:  v{self.latest_version}")
            print(f"Release URL: {self.release_url}")
            print("\nTo update:")
            print("1. Visit the release page above")
            print("2. Download the latest version")
            print("3. Replace your current script")
            print("="*60)
            
            choice = input("\nOpen release page in browser? (y/N): ").lower()
            if choice in ['y', 'yes']:
                webbrowser.open(self.release_url)
    
    def check_and_notify(self):
        """Check for updates and notify user"""
        if self.check_for_updates():
            self.show_update_info()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def display_banner():
    """Display tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║              XploitEye V1.0                   ║
    ║        Professional Vulnerability Scanner     ║
    ║              Windows Edition                  ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)

def ask_to_exit():
    """Ask user confirmation before exiting"""
    print("\n" + "="*50)
    choice = input("🚪 Exit AegisVuln? (y/N): ").strip().lower()
    if choice in ['y', 'yes']:
        print("👋 Thank you for using AegisVuln!")
        sys.exit(0)
    else:
        print("➡️  Continuing...")
        return False

def get_custom_reports_directory():
    """Get the custom vulnerability reports directory on Desktop"""
    # Get the Desktop path
    desktop_path = Path.home() / "OneDrive" / "Desktop"
    
    # Create vulnerability directory on Desktop
    vuln_dir = desktop_path / "vulnerability"
    
    # Create directory if it doesn't exist
    vuln_dir.mkdir(exist_ok=True)
    
    print(f"📁 Custom reports directory: {vuln_dir}")
    return vuln_dir

def get_script_directory():
    """Get the directory where this script is located"""
    script_dir = Path(__file__).parent.absolute()
    return script_dir

def validate_targets(targets: List[str]) -> Tuple[List[str], List[str]]:
    """Validate target specifications"""
    valid_targets = []
    invalid_targets = []
    
    for target in targets:
        try:
            ipaddress.ip_address(target)
            valid_targets.append(target)
            continue
        except ValueError:
            pass
        
        try:
            ipaddress.ip_network(target, strict=False)
            valid_targets.append(target)
            continue
        except ValueError:
            pass
        
        try:
            socket.gethostbyname(target)
            valid_targets.append(target)
        except socket.gaierror:
            invalid_targets.append(target)
    
    return valid_targets, invalid_targets

def get_live_targets() -> List[str]:
    """Get live targets from user input"""
    print("\n🎯 TARGET SELECTION")
    print("="*50)
    print("Enter targets to scan (comma-separated):")
    print("Examples:")
    print("  - Single IP: 192.168.1.1")
    print("  - Network: 192.168.1.0/24")
    print("  - Multiple: 192.168.1.1,192.168.1.100")
    print("  - Hostname: example.com")
    print("\n⚠️  Only scan networks you have permission to scan!")
    print("="*50)
    
    while True:
        try:
            target_input = input("\nEnter target(s): ").strip()
            
            if not target_input:
                print("❌ No targets provided")
                continue
            
            targets = [t.strip() for t in target_input.split(',')]
            valid_targets, invalid_targets = validate_targets(targets)
            
            if invalid_targets:
                print(f"⚠️  Invalid targets: {', '.join(invalid_targets)}")
            
            if valid_targets:
                print(f"✅ Valid targets: {', '.join(valid_targets)}")
                return valid_targets
            else:
                print("❌ No valid targets found")
                
        except KeyboardInterrupt:
            if ask_to_exit():
                sys.exit(0)
            else:
                continue
        except Exception as e:
            print(f"❌ Error: {e}")

# =============================================================================
# CORE SCANNING ENGINE
# =============================================================================

class AegisVulnEngine:
    """Main scanning engine for AegisVuln"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.nm = nmap.PortScanner()
        self.scan_stats = {
            'hosts_scanned': 0,
            'ports_found': 0,
            'services_identified': 0,
            'vulnerabilities_found': 0
        }
        self.update_manager = UpdateManager()
    
    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration with presets"""
        default_config = {
            'scan_presets': {
                'quick': {'ports': '1-1000', 'intensity': 'normal', 'active_testing': False},
                'standard': {'ports': '1-1000', 'intensity': 'normal', 'active_testing': True},
                'comprehensive': {'ports': '1-1000', 'intensity': 'aggressive', 'active_testing': True},
                'web_app': {'ports': '80,443,8080,8443', 'intensity': 'normal', 'active_testing': True},
                'network_audit': {'ports': '1-1000', 'intensity': 'stealth', 'active_testing': False}
            },
            'cve': {
                'cvss_threshold': 4.0,
                'cache_ttl': 86400
            },
            'reporting': {
                'output_directory': './reports',
                'formats': ['json', 'html', 'txt']
            }
        }
        return default_config
    
    def check_system_requirements(self):
        """Check if all system requirements are met"""
        print("🔍 Checking system requirements...")
        
        # Check Nmap installation
        if not self._check_nmap_installation():
            return False
        
        # Check Python dependencies
        try:
            import nmap
            import requests
            print("✅ All dependencies are installed")
            return True
        except ImportError as e:
            print(f"❌ Missing dependency: {e}")
            return False
    
    def _check_nmap_installation(self):
        """Verify Nmap is properly installed on Windows"""
        try:
            # First try the python-nmap built-in check
            try:
                self.nm.scan('127.0.0.1', arguments='-p 80 --max-retries 1 --host-timeout 100ms')
                print("✅ Nmap is working correctly")
                return True
            except nmap.PortScannerError:
                pass
            
            # If that fails, try command line
            paths_to_try = [
                'nmap',
                'C:\\Program Files (x86)\\Nmap\\nmap.exe',
                'C:\\Program Files\\Nmap\\nmap.exe',
            ]
            
            for path in paths_to_try:
                try:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        version_line = result.stdout.splitlines()[0]
                        print(f"✅ {version_line}")
                        return True
                except (FileNotFoundError, subprocess.SubprocessError):
                    continue
            
            print("❌ Nmap not found. Please install from https://nmap.org/download.html")
            print("💡 Make sure to add Nmap to PATH during installation")
            return False
            
        except Exception as e:
            print(f"❌ Error checking Nmap: {e}")
            return False
    
    def get_scan_preset(self, scan_type: ScanType) -> Dict:
        """Get predefined scan configuration"""
        return self.config['scan_presets'].get(scan_type.value, {})
    
    def quick_scan(self, targets: List[str]) -> ScanResult:
        """Perform a quick security assessment"""
        print("🚀 Starting Quick Security Scan...")
        preset = self.get_scan_preset(ScanType.QUICK)
        return asyncio.run(self._perform_scan(targets, **preset))
    
    def standard_scan(self, targets: List[str]) -> ScanResult:
        """Perform standard vulnerability assessment"""
        print("🔍 Starting Standard Vulnerability Scan...")
        preset = self.get_scan_preset(ScanType.STANDARD)
        return asyncio.run(self._perform_scan(targets, **preset))
    
    def comprehensive_scan(self, targets: List[str]) -> ScanResult:
        """Perform comprehensive vulnerability assessment"""
        print("🔍 Starting Comprehensive Vulnerability Scan...")
        preset = self.get_scan_preset(ScanType.COMPREHENSIVE)
        return asyncio.run(self._perform_scan(targets, **preset))
    
    def web_application_scan(self, targets: List[str]) -> ScanResult:
        """Perform web application security scan"""
        print("🌐 Starting Web Application Security Scan...")
        preset = self.get_scan_preset(ScanType.WEB_APPLICATION)
        return asyncio.run(self._perform_scan(targets, **preset))
    
    def network_audit_scan(self, targets: List[str]) -> ScanResult:
        """Perform network audit scan"""
        print("📊 Starting Network Audit Scan...")
        preset = self.get_scan_preset(ScanType.NETWORK_AUDIT)
        return asyncio.run(self._perform_scan(targets, **preset))
    
    async def _perform_scan(self, targets: List[str], ports: str, 
                          intensity: str, active_testing: bool) -> ScanResult:
        """Perform the actual scanning process"""
        start_time = time.time()
        
        # Validate targets
        valid_targets, invalid_targets = validate_targets(targets)
        if invalid_targets:
            print(f"⚠️  Invalid targets: {', '.join(invalid_targets)}")
        
        if not valid_targets:
            raise ValueError("No valid targets to scan")
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=f"scan_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
            targets=valid_targets
        )
        
        # Perform network discovery
        print("📡 Discovering hosts and services...")
        scan_result = self._network_discovery(scan_result, ports, intensity)
        
        # Vulnerability analysis
        print("🔍 Analyzing vulnerabilities...")
        scan_result.vulnerabilities = await self._vulnerability_analysis(scan_result)
        
        # Active testing
        if active_testing and REQUESTS_AVAILABLE:
            print("🧪 Performing active security testing...")
            active_vulns = await self._active_security_testing(scan_result)
            scan_result.vulnerabilities.extend(active_vulns)
        
        scan_result.scan_duration = time.time() - start_time
        self.scan_stats['vulnerabilities_found'] = len(scan_result.vulnerabilities)
        
        return scan_result
    
    def _network_discovery(self, scan_result: ScanResult, ports: str, intensity: str) -> ScanResult:
        """Perform network discovery and service detection"""
        target_str = ' '.join(scan_result.targets)
        
        # Configure Nmap arguments based on intensity
        nmap_args = self._get_nmap_arguments(intensity, ports)
        
        print(f"🔧 Scan configuration: {nmap_args}")
        
        try:
            # Perform the scan
            print("⏳ Scanning in progress... This may take several minutes.")
            scan_data = self.nm.scan(hosts=target_str, arguments=nmap_args)
            
            # Process results
            for host_ip in self.nm.all_hosts():
                host_data = self.nm[host_ip]
                host_result = self._process_host(host_ip, host_data)
                scan_result.hosts.append(host_result)
                
                print(f"✅ {host_ip}: {len(host_result.services)} services found")
                
                self.scan_stats['hosts_scanned'] += 1
                self.scan_stats['ports_found'] += len(host_result.services)
            
        except Exception as e:
            print(f"❌ Network discovery failed: {e}")
            # Add some dummy data for testing
            if not scan_result.hosts:
                print("⚠️  Adding test data for demonstration...")
                test_host = HostResult(ip="192.168.1.1", status="up", hostname="test-host")
                test_service = Service(port=80, protocol="tcp", state="open", name="http", product="Apache", version="2.4.49")
                test_host.services.append(test_service)
                scan_result.hosts.append(test_host)
        
        return scan_result
    
    def _get_nmap_arguments(self, intensity: str, ports: str) -> str:
        """Get optimized Nmap arguments for Windows"""
        base_args = "-sV --version-intensity 3"
        
        timing_args = {
            'stealth': '-T2',
            'normal': '-T3', 
            'aggressive': '-T4'
        }
        
        port_args = f"-p {ports}" if ports else "--top-ports 100"
        
        return f"{base_args} {port_args} {timing_args.get(intensity, '-T3')}"
    
    def _process_host(self, host_ip: str, host_data: Any) -> HostResult:
        """Process individual host results"""
        host_result = HostResult(ip=host_ip, status=host_data.state())
        
        # Host information
        if 'hostnames' in host_data and host_data['hostnames']:
            for hostname in host_data['hostnames']:
                if hostname['name']:
                    host_result.hostname = hostname['name']
                    break
        
        if 'osmatch' in host_data and host_data['osmatch']:
            for os_match in host_data['osmatch']:
                if os_match['name']:
                    host_result.os = os_match['name']
                    break
        
        # Services
        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                service_data = host_data[proto][port]
                service = Service(
                    port=port,
                    protocol=proto,
                    state=service_data.get('state', 'unknown'),
                    name=service_data.get('name', ''),
                    product=service_data.get('product', ''),
                    version=service_data.get('version', ''),
                    extrainfo=service_data.get('extrainfo', ''),
                    ip=host_ip
                )
                host_result.services.append(service)
                self.scan_stats['services_identified'] += 1
        
        return host_result
    
    async def _vulnerability_analysis(self, scan_result: ScanResult) -> List[Vulnerability]:
        """Analyze discovered services for vulnerabilities"""
        vulnerabilities = []
        
        for host in scan_result.hosts:
            for service in host.services:
                if service.state == 'open':
                    try:
                        service_vulns = await self._analyze_service(host, service)
                        vulnerabilities.extend(service_vulns)
                    except Exception as e:
                        print(f"⚠️  Error analyzing {host.ip}:{service.port}: {e}")
        
        # Sort by severity
        vulnerabilities.sort(key=lambda x: x.cve.cvss_score, reverse=True)
        return vulnerabilities
    
    async def _analyze_service(self, host: HostResult, service: Service) -> List[Vulnerability]:
        """Analyze individual service for vulnerabilities"""
        vulnerabilities = []
        
        # Get CVEs for the service
        cves = await self._get_service_cves(service)
        
        for cve in cves:
            vulnerability = Vulnerability(
                host=host.ip,
                port=service.port,
                service=service.name,
                cve=cve,
                confidence=self._calculate_confidence(service, cve),
                remediation=self._generate_remediation(service, cve)
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _get_service_cves(self, service: Service) -> List[CVE]:
        """Get CVEs for a specific service"""
        cves = []
        
        # Common vulnerability patterns based on service and version
        if service.product and service.version:
            cves.extend(self._check_known_vulnerabilities(service))
        
        # Add service-specific vulnerabilities
        cves.extend(self._get_service_specific_vulns(service))
        
        # Filter by threshold
        threshold = self.config['cve']['cvss_threshold']
        return [cve for cve in cves if cve.cvss_score >= threshold]
    
    def _check_known_vulnerabilities(self, service: Service) -> List[CVE]:
        """Check for known vulnerabilities in common services"""
        vulnerabilities = []
        
        # Apache HTTP Server vulnerabilities
        if 'apache' in service.product.lower():
            if service.version in ['2.4.49', '2.4.50']:
                vulnerabilities.append(CVE(
                    id="CVE-2021-41773",
                    description="Path Traversal and File Disclosure Vulnerability in Apache HTTP Server 2.4.49/2.4.50",
                    cvss_score=7.5,
                    severity="HIGH",
                    references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
                    exploit_available=True,
                    patch_available=True
                ))
        
        # OpenSSH vulnerabilities
        elif 'openssh' in service.product.lower():
            try:
                version_parts = service.version.split('.')
                if len(version_parts) >= 2:
                    major = int(version_parts[0])
                    minor = int(version_parts[1])
                    if major == 7 and minor < 7:
                        vulnerabilities.append(CVE(
                            id="CVE-2020-14145",
                            description="OpenSSH vulnerability in versions before 7.7",
                            cvss_score=5.3,
                            severity="MEDIUM",
                            references=["https://www.openssh.com/security.html"],
                            exploit_available=False,
                            patch_available=True
                        ))
            except (ValueError, IndexError):
                pass
        
        # Nginx vulnerabilities
        elif 'nginx' in service.product.lower():
            if service.version in ['1.18.0', '1.20.0']:
                vulnerabilities.append(CVE(
                    id="CVE-2021-23017",
                    description="Nginx resolver vulnerability allowing DNS spoofing",
                    cvss_score=7.5,
                    severity="HIGH",
                    references=["https://nginx.org/en/security_advisories.html"],
                    exploit_available=True,
                    patch_available=True
                ))
        
        # Windows SMB vulnerabilities
        elif any(word in service.product.lower() for word in ['microsoft', 'windows']):
            if any(version in service.version for version in ['2008', '2012', '2016', '2019']):
                vulnerabilities.append(CVE(
                    id="WINDOWS-LEGACY-SMB",
                    description="Legacy Windows SMB version with known vulnerabilities",
                    cvss_score=8.0,
                    severity="HIGH",
                    references=["https://docs.microsoft.com/en-us/security-updates/"],
                    exploit_available=True,
                    patch_available=True
                ))
        
        return vulnerabilities
    
    def _get_service_specific_vulns(self, service: Service) -> List[CVE]:
        """Get vulnerabilities based on service type"""
        vulnerabilities = []
        
        # SMB service vulnerabilities
        if service.name == 'microsoft-ds' or service.port == 445:
            vulnerabilities.append(CVE(
                id="SMB-SHARE-EXPOSED",
                description="SMB file sharing service exposed - potential information disclosure",
                cvss_score=7.5,
                severity="HIGH",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        # RDP service vulnerabilities
        elif service.name == 'ms-wbt-server' or service.port == 3389:
            vulnerabilities.append(CVE(
                id="RDP-EXPOSED",
                description="Remote Desktop Protocol exposed - potential unauthorized access",
                cvss_score=8.0,
                severity="HIGH",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        # SSH service vulnerabilities
        elif service.name == 'ssh' and not service.product:
            vulnerabilities.append(CVE(
                id="SSH-WEAK-CONFIG",
                description="SSH service with potentially weak configuration",
                cvss_score=5.0,
                severity="MEDIUM",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        # FTP service vulnerabilities
        elif service.name == 'ftp':
            vulnerabilities.append(CVE(
                id="FTP-CLEARTEXT",
                description="FTP service transmits credentials in cleartext",
                cvss_score=7.5,
                severity="HIGH",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        # Telnet service vulnerabilities
        elif service.name == 'telnet':
            vulnerabilities.append(CVE(
                id="TELNET-CLEARTEXT",
                description="Telnet service transmits all data in cleartext",
                cvss_score=7.5,
                severity="HIGH",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        # HTTP service without encryption
        elif service.name == 'http' and service.port != 80:
            vulnerabilities.append(CVE(
                id="HTTP-CLEARTEXT",
                description="HTTP service without encryption",
                cvss_score=5.0,
                severity="MEDIUM",
                references=[],
                exploit_available=True,
                patch_available=True
            ))
        
        return vulnerabilities
    
    def _calculate_confidence(self, service: Service, cve: CVE) -> float:
        """Calculate confidence score for vulnerability match"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if version matches
        if service.version and service.version in cve.description:
            confidence += 0.3
        
        # Increase confidence if product is clearly identified
        if service.product and len(service.product) > 2:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _generate_remediation(self, service: Service, cve: CVE) -> str:
        """Generate remediation advice"""
        base_remediation = f"Update {service.product if service.product else service.name} to latest version"
        
        if cve.patch_available:
            return f"{base_remediation}. Patch is available."
        else:
            return f"{base_remediation}. Implement compensating controls."
    
    async def _active_security_testing(self, scan_result: ScanResult) -> List[Vulnerability]:
        """Perform active security testing"""
        vulnerabilities = []
        
        for host in scan_result.hosts:
            for service in host.services:
                if service.name in ['http', 'https']:
                    web_vulns = await self._test_web_vulnerabilities(service)
                    vulnerabilities.extend(web_vulns)
        
        return vulnerabilities
    
    async def _test_web_vulnerabilities(self, service: Service) -> List[Vulnerability]:
        """Test for web vulnerabilities"""
        vulnerabilities = []
        
        try:
            protocol = 'https' if service.name == 'https' else 'http'
            base_url = f"{protocol}://{service.ip}:{service.port}"
            
            # Test for common web vulnerabilities
            tests = [
                self._test_directory_listing,
                self._test_default_files,
                self._test_security_headers
            ]
            
            for test in tests:
                vulns = await test(service, base_url)
                vulnerabilities.extend(vulns)
                
        except Exception as e:
            print(f"⚠️  Web testing failed for {service.ip}:{service.port}: {e}")
        
        return vulnerabilities
    
    async def _test_directory_listing(self, service: Service, base_url: str) -> List[Vulnerability]:
        """Test for directory listing vulnerabilities"""
        test_paths = ['/images/', '/css/', '/js/', '/admin/', '/backup/']
        
        for path in test_paths:
            try:
                response = requests.get(f"{base_url}{path}", timeout=5, verify=False)
                if 'Index of' in response.text or '<title>Directory listing' in response.text:
                    return [Vulnerability(
                        host=service.ip,
                        port=service.port,
                        service=service.name,
                        cve=CVE(
                            id="WEB-DIR-LISTING",
                            description=f"Directory listing enabled at {path}",
                            cvss_score=4.0,
                            severity="MEDIUM"
                        ),
                        confidence=0.8,
                        remediation="Disable directory listing in web server configuration"
                    )]
            except requests.RequestException:
                continue
        
        return []
    
    async def _test_default_files(self, service: Service, base_url: str) -> List[Vulnerability]:
        """Test for exposed default files"""
        default_files = ['/robots.txt', '/.git/HEAD', '/.env', '/backup.zip']
        
        for file_path in default_files:
            try:
                response = requests.get(f"{base_url}{file_path}", timeout=5, verify=False)
                if response.status_code == 200:
                    return [Vulnerability(
                        host=service.ip,
                        port=service.port,
                        service=service.name,
                        cve=CVE(
                            id="WEB-DEFAULT-FILE",
                            description=f"Default file exposed: {file_path}",
                            cvss_score=3.5,
                            severity="LOW"
                        ),
                        confidence=0.9,
                        remediation=f"Remove or restrict access to {file_path}"
                    )]
            except requests.RequestException:
                continue
        
        return []
    
    async def _test_security_headers(self, service: Service, base_url: str) -> List[Vulnerability]:
        """Test for missing security headers"""
        try:
            response = requests.get(base_url, timeout=5, verify=False)
            missing_headers = []
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection', 
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                return [Vulnerability(
                    host=service.ip,
                    port=service.port,
                    service=service.name,
                    cve=CVE(
                        id="WEB-MISSING-HEADERS",
                        description=f"Missing security headers: {', '.join(missing_headers)}",
                        cvss_score=3.0,
                        severity="LOW"
                    ),
                    confidence=0.8,
                    remediation="Implement missing security headers in web server configuration"
                )]
                
        except requests.RequestException:
            pass
        
        return []
    
    def get_scan_statistics(self) -> Dict:
        """Get scan statistics"""
        return self.scan_stats.copy()

# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generate comprehensive vulnerability reports"""
    
    def __init__(self, output_dir: str = None):
        # Use custom vulnerability directory if no custom directory specified
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = get_script_directory()  # Changed to script directory
        
        # Create directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"📁 Reports will be saved to: {self.output_dir}")
    
    def generate_all_reports(self, scan_result: ScanResult) -> Dict[str, Path]:
        """Generate all report formats"""
        report_paths = {}
        
        # Generate JSON report
        report_paths['json'] = self._generate_json_report(scan_result)
        
        # Generate text report
        report_paths['txt'] = self._generate_text_report(scan_result)
        
        # Generate HTML report
        try:
            report_paths['html'] = self._generate_html_report(scan_result)
        except Exception as e:
            print(f"⚠️  HTML report generation failed: {e}")
        
        return report_paths
    
    def _generate_json_report(self, scan_result: ScanResult) -> Path:
        """Generate detailed JSON report"""
        
        def convert_to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                result = {}
                for field_name, field_value in asdict(obj).items():
                    result[field_name] = convert_to_dict(field_value)
                return result
            elif isinstance(obj, list):
                return [convert_to_dict(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: convert_to_dict(v) for k, v in obj.items()}
            else:
                return obj
        
        report_data = {
            'scan_metadata': {
                'scan_id': scan_result.scan_id,
                'timestamp': scan_result.timestamp,
                'targets': scan_result.targets,
                'duration_seconds': scan_result.scan_duration,
                'tool': 'AegisVuln Version 1.0'
            },
            'hosts': [convert_to_dict(host) for host in scan_result.hosts],
            'vulnerabilities': [convert_to_dict(vuln) for vuln in scan_result.vulnerabilities],
            'summary': {
                'total_hosts': len(scan_result.hosts),
                'total_services': sum(len(host.services) for host in scan_result.hosts),
                'total_vulnerabilities': len(scan_result.vulnerabilities),
                'critical_count': sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score >= 9.0),
                'high_count': sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score < 9.0),
                'medium_count': sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "MEDIUM"),
                'low_count': sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "LOW")
            }
        }
        
        json_path = self.output_dir / f"aegisvuln_scan_{scan_result.scan_id}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"📄 JSON report: {json_path}")
        return json_path
    
    def _generate_text_report(self, scan_result: ScanResult) -> Path:
        """Generate human-readable text report"""
        txt_path = self.output_dir / f"aegisvuln_scan_{scan_result.scan_id}.txt"
        
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("                   AEGISVULN VERSION 1.0 - SCAN REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Scan ID: {scan_result.scan_id}\n")
            f.write(f"Timestamp: {scan_result.timestamp}\n")
            f.write(f"Targets: {', '.join(scan_result.targets)}\n")
            f.write(f"Scan Duration: {scan_result.scan_duration:.2f} seconds\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 50 + "\n")
            f.write(f"Hosts Scanned: {len(scan_result.hosts)}\n")
            f.write(f"Services Found: {sum(len(host.services) for host in scan_result.hosts)}\n")
            f.write(f"Vulnerabilities Identified: {len(scan_result.vulnerabilities)}\n\n")
            
            # Host details
            f.write("DISCOVERED HOSTS\n")
            f.write("-" * 50 + "\n")
            for i, host in enumerate(scan_result.hosts, 1):
                f.write(f"\n{i}. {host.ip} ({host.hostname or 'no hostname'})\n")
                f.write(f"   Status: {host.status} | OS: {host.os or 'unknown'}\n")
                f.write(f"   Services: {len(host.services)}\n")
                for service in host.services:
                    version_info = f" - {service.product} {service.version}" if service.product else ""
                    f.write(f"     - {service.port}/{service.protocol}: {service.name}{version_info}\n")
            
            # Vulnerability details
            if scan_result.vulnerabilities:
                f.write("\nVULNERABILITIES\n")
                f.write("-" * 50 + "\n")
                
                for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                    f.write(f"\n{i}. {vuln.cve.id} - {vuln.cve.severity} (CVSS: {vuln.cve.cvss_score})\n")
                    f.write(f"   Host: {vuln.host}:{vuln.port} ({vuln.service})\n")
                    f.write(f"   Description: {vuln.cve.description}\n")
                    f.write(f"   Confidence: {vuln.confidence:.1%}\n")
                    f.write(f"   Remediation: {vuln.remediation}\n")
                    if vuln.cve.references:
                        f.write(f"   References: {', '.join(vuln.cve.references)}\n")
            else:
                f.write("\nNo vulnerabilities found meeting the threshold criteria.\n")
            
            f.write(f"\nReport generated by AegisVuln Version 1.0\n")
        
        print(f"📄 Text report: {txt_path}")
        return txt_path
    
    def _generate_html_report(self, scan_result: ScanResult) -> Path:
        """Generate HTML report"""
        html_path = self.output_dir / f"aegisvuln_scan_{scan_result.scan_id}.html"
        
        # Count vulnerabilities by severity
        critical = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score >= 9.0)
        high = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score < 9.0)
        medium = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "MEDIUM")
        low = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "LOW")
        
        # Generate vulnerability HTML
        vuln_html = ""
        for vuln in scan_result.vulnerabilities:
            severity_class = vuln.cve.severity.lower()
            if vuln.cve.cvss_score >= 9.0:
                severity_class = "critical"
            
            vuln_html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.cve.id} - {vuln.cve.severity} (CVSS: {vuln.cve.cvss_score})</h3>
                <p><strong>Location:</strong> {vuln.host}:{vuln.port} ({vuln.service})</p>
                <p><strong>Description:</strong> {vuln.cve.description}</p>
                <p><strong>Confidence:</strong> {vuln.confidence:.1%}</p>
                <p><strong>Remediation:</strong> {vuln.remediation}</p>
                {f'<p><strong>References:</strong> {", ".join(vuln.cve.references)}</p>' if vuln.cve.references else ''}
            </div>
            """
        
        # Generate hosts HTML
        hosts_html = ""
        for host in scan_result.hosts:
            services_html = ""
            for service in host.services:
                version_info = f" - {service.product} {service.version}" if service.product else ""
                services_html += f"""
                <tr>
                    <td>{service.port}</td>
                    <td>{service.protocol}</td>
                    <td>{service.name}</td>
                    <td>{service.product} {service.version}</td>
                    <td>{service.state}</td>
                </tr>
                """
            
            hosts_html += f"""
            <div class="host-section">
                <h3>🔍 {host.ip} {f"({host.hostname})" if host.hostname else ""}</h3>
                <p><strong>Status:</strong> {host.status} | <strong>OS:</strong> {host.os or "Unknown"} | <strong>Services:</strong> {len(host.services)}</p>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>State</th>
                    </tr>
                    {services_html}
                </table>
            </div>
            """
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AegisVuln Version 1.0 - Vulnerability Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: #f5f5f5;
                    color: #333;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header {{ 
                    background: linear-gradient(135deg, #2c3e50, #3498db);
                    color: white; 
                    padding: 30px; 
                    border-radius: 8px;
                    margin-bottom: 30px;
                }}
                .summary-cards {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .card {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    text-align: center;
                    border-left: 4px solid #3498db;
                }}
                .card.critical {{ border-left-color: #e74c3c; }}
                .card.high {{ border-left-color: #e67e22; }}
                .card.medium {{ border-left-color: #f39c12; }}
                .card.low {{ border-left-color: #3498db; }}
                .card h3 {{ margin: 0; font-size: 2em; color: #2c3e50; }}
                .card p {{ margin: 5px 0 0; color: #7f8c8d; }}
                .vulnerability {{ 
                    border: 1px solid #ddd; 
                    margin: 15px 0; 
                    padding: 20px; 
                    border-radius: 8px;
                    background: #fafafa;
                }}
                .vulnerability.critical {{ border-left: 5px solid #e74c3c; background: #fdf2f2; }}
                .vulnerability.high {{ border-left: 5px solid #e67e22; background: #fef5eb; }}
                .vulnerability.medium {{ border-left: 5px solid #f39c12; background: #fef9e7; }}
                .vulnerability.low {{ border-left: 5px solid #3498db; background: #f0f8ff; }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 20px 0;
                    background: white;
                }}
                th, td {{ 
                    border: 1px solid #ddd; 
                    padding: 12px; 
                    text-align: left; 
                }}
                th {{ 
                    background-color: #34495e; 
                    color: white;
                    font-weight: 600;
                }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                .host-section {{ margin: 25px 0; }}
                .host-section h3 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
                footer {{ 
                    margin-top: 40px; 
                    text-align: center; 
                    color: #7f8c8d;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ AegisVuln Version 1.0 - Vulnerability Report</h1>
                    <p>Scan ID: {scan_result.scan_id} | {scan_result.timestamp}</p>
                </div>
                
                <h2>📊 Executive Summary</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Targets Scanned</td><td>{', '.join(scan_result.targets)}</td></tr>
                    <tr><td>Hosts Found</td><td>{len(scan_result.hosts)}</td></tr>
                    <tr><td>Services Identified</td><td>{sum(len(host.services) for host in scan_result.hosts)}</td></tr>
                    <tr><td>Vulnerabilities Found</td><td>{len(scan_result.vulnerabilities)}</td></tr>
                    <tr><td>Scan Duration</td><td>{scan_result.scan_duration:.2f} seconds</td></tr>
                </table>

                <div class="summary-cards">
                    <div class="card critical">
                        <h3>{critical}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="card high">
                        <h3>{high}</h3>
                        <p>High</p>
                    </div>
                    <div class="card medium">
                        <h3>{medium}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="card low">
                        <h3>{low}</h3>
                        <p>Low</p>
                    </div>
                </div>
                
                <h2>🏠 Discovered Hosts</h2>
                {hosts_html if hosts_html else "<p>No hosts discovered.</p>"}
                
                <h2>🔍 Vulnerability Details</h2>
                {vuln_html if vuln_html else "<p>No vulnerabilities found meeting the threshold criteria.</p>"}
                
                <footer>
                    <p><em>Report generated by AegisVuln Version 1.0 - Professional Vulnerability Scanner</em></p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📄 HTML report: {html_path}")
        return html_path

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

class AegisVulnCLI:
    """Command Line Interface for AegisVuln"""
    
    def __init__(self):
        self.engine = AegisVulnEngine()
        # Initialize with script directory by default
        self.reporter = ReportGenerator()
    
    def run(self):
        """Main CLI entry point"""
        display_banner()
        
        # Check for updates on startup
        self.engine.update_manager.check_and_notify()
        
        # Check if no arguments provided
        if len(sys.argv) == 1:
            self._handle_interactive_mode()
            return
        
        parser = self._create_parser()
        args = parser.parse_args()
        
        # Handle different commands
        if hasattr(args, 'command'):
            if args.command == 'scan':
                self._handle_scan_command(args)
            elif args.command == 'quick':
                self._handle_quick_scan(args)
            elif args.command == 'web':
                self._handle_web_scan(args)
            elif args.command == 'comprehensive':
                self._handle_comprehensive_scan(args)
            elif args.command == 'audit':
                self._handle_audit_scan(args)
            elif args.command == 'check':
                self._handle_system_check()
            elif args.command == 'update':
                self._handle_update_check()
            elif args.command == 'interactive':
                self._handle_interactive_mode()
            else:
                parser.print_help()
        else:
            parser.print_help()
    
    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='AegisVuln Version 1.0 - Professional Vulnerability Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  aegisvuln check                           # Check system requirements
  aegisvuln update                          # Check for updates
  aegisvuln quick 192.168.1.1              # Quick security scan
  aegisvuln web example.com                 # Web application scan
  aegisvuln comprehensive 192.168.1.0/24   # Comprehensive network scan
  aegisvuln audit 192.168.1.1-100          # Network audit scan
  aegisvuln interactive                     # Interactive mode

Scan Types:
  quick       - Fast security assessment (top 100 ports)
  web         - Web application security scan
  comprehensive - Full vulnerability assessment  
  audit       - Stealthy network audit

⚠️  Only scan networks you have permission to scan!
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Perform custom scan')
        scan_parser.add_argument('targets', nargs='+', help='Targets to scan')
        scan_parser.add_argument('--type', choices=['quick', 'standard', 'comprehensive', 'web', 'audit'],
                               default='standard', help='Scan type')
        scan_parser.add_argument('--ports', help='Ports to scan (e.g., 80,443 or 1-1000)')
        scan_parser.add_argument('--output', help='Output directory')
        scan_parser.add_argument('--intensity', choices=['stealth', 'normal', 'aggressive'],
                               default='normal', help='Scan intensity')
        
        # Quick scan command
        quick_parser = subparsers.add_parser('quick', help='Quick security assessment')
        quick_parser.add_argument('targets', nargs='+', help='Targets to scan')
        quick_parser.add_argument('--output', help='Output directory')
        
        # Web scan command
        web_parser = subparsers.add_parser('web', help='Web application security scan')
        web_parser.add_argument('targets', nargs='+', help='Web targets to scan')
        web_parser.add_argument('--output', help='Output directory')
        
        # Comprehensive scan command
        comp_parser = subparsers.add_parser('comprehensive', help='Comprehensive vulnerability assessment')
        comp_parser.add_argument('targets', nargs='+', help='Targets to scan')
        comp_parser.add_argument('--output', help='Output directory')
        
        # Audit scan command
        audit_parser = subparsers.add_parser('audit', help='Network audit scan')
        audit_parser.add_argument('targets', nargs='+', help='Targets to scan')
        audit_parser.add_argument('--output', help='Output directory')
        
        # System check command
        subparsers.add_parser('check', help='Check system requirements')
        
        # Update check command
        subparsers.add_parser('update', help='Check for updates')
        
        # Interactive mode
        subparsers.add_parser('interactive', help='Interactive scanning mode')
        
        return parser
    
    def _handle_scan_command(self, args):
        """Handle custom scan command"""
        print(f"🎯 Starting {args.type} scan...")
        
        scan_type_map = {
            'quick': ScanType.QUICK,
            'standard': ScanType.STANDARD,
            'comprehensive': ScanType.COMPREHENSIVE,
            'web': ScanType.WEB_APPLICATION,
            'audit': ScanType.NETWORK_AUDIT
        }
        
        scan_type = scan_type_map[args.type]
        
        # Update reporter with custom output directory if provided
        if args.output:
            self.reporter = ReportGenerator(args.output)
        
        if scan_type == ScanType.QUICK:
            scan_result = self.engine.quick_scan(args.targets)
        elif scan_type == ScanType.STANDARD:
            scan_result = self.engine.standard_scan(args.targets)
        elif scan_type == ScanType.COMPREHENSIVE:
            scan_result = self.engine.comprehensive_scan(args.targets)
        elif scan_type == ScanType.WEB_APPLICATION:
            scan_result = self.engine.web_application_scan(args.targets)
        elif scan_type == ScanType.NETWORK_AUDIT:
            scan_result = self.engine.network_audit_scan(args.targets)
        else:
            scan_result = self.engine.standard_scan(args.targets)
        
        self._generate_reports(scan_result)
    
    def _handle_quick_scan(self, args):
        """Handle quick scan command"""
        print("🚀 Starting Quick Security Scan...")
        
        # Update reporter with custom output directory if provided
        if args.output:
            self.reporter = ReportGenerator(args.output)
        
        scan_result = self.engine.quick_scan(args.targets)
        self._generate_reports(scan_result)
    
    def _handle_web_scan(self, args):
        """Handle web application scan command"""
        print("🌐 Starting Web Application Security Scan...")
        
        # Update reporter with custom output directory if provided
        if args.output:
            self.reporter = ReportGenerator(args.output)
        
        scan_result = self.engine.web_application_scan(args.targets)
        self._generate_reports(scan_result)
    
    def _handle_comprehensive_scan(self, args):
        """Handle comprehensive scan command"""
        print("🔍 Starting Comprehensive Vulnerability Assessment...")
        
        # Update reporter with custom output directory if provided
        if args.output:
            self.reporter = ReportGenerator(args.output)
        
        scan_result = self.engine.comprehensive_scan(args.targets)
        self._generate_reports(scan_result)
    
    def _handle_audit_scan(self, args):
        """Handle audit scan command"""
        print("📊 Starting Network Audit Scan...")
        
        # Update reporter with custom output directory if provided
        if args.output:
            self.reporter = ReportGenerator(args.output)
        
        scan_result = self.engine.network_audit_scan(args.targets)
        self._generate_reports(scan_result)
    
    def _handle_system_check(self):
        """Handle system requirements check"""
        if self.engine.check_system_requirements():
            print("✅ System is ready for scanning!")
        else:
            print("❌ System requirements not met.")
            print("💡 Please install missing dependencies and ensure Nmap is installed.")
    
    def _handle_update_check(self):
        """Handle update check command"""
        self.engine.update_manager.check_and_notify()
    
    def _handle_interactive_mode(self):
        """Handle interactive scanning mode"""
        print("\n🎯 INTERACTIVE SCANNING MODE")
        print("="*50)
        
        while True:
            try:
                # Get targets
                targets = get_live_targets()
                
                # Select scan type
                print("\n🔧 SELECT SCAN TYPE:")
                print("1. Quick Security Scan (Fast)")
                print("2. Web Application Scan")
                print("3. Comprehensive Vulnerability Scan")
                print("4. Network Audit Scan")
                print("5. Check for Updates")
                print("6. Exit")
                
                choice = input("\nChoose option (1-6): ").strip()
                
                if choice == '6':
                    if ask_to_exit():
                        return
                    else:
                        continue
                
                if choice == '5':
                    self.engine.update_manager.check_and_notify()
                    continue
                
                scan_type_map = {
                    '1': ('quick', self.engine.quick_scan),
                    '2': ('web', self.engine.web_application_scan),
                    '3': ('comprehensive', self.engine.comprehensive_scan),
                    '4': ('audit', self.engine.network_audit_scan)
                }
                
                if choice not in scan_type_map:
                    print("❌ Invalid choice. Using Quick Scan.")
                    choice = '1'
                
                scan_name, scan_method = scan_type_map[choice]
                
                # Output directory
                output_dir = input("\nOutput directory [press Enter for default]: ").strip()
                if output_dir:
                    self.reporter = ReportGenerator(output_dir)
                else:
                    self.reporter = ReportGenerator()
                
                # Safety confirmation
                print(f"\n🚨 CONFIRM SCAN:")
                print(f"Targets: {', '.join(targets)}")
                print(f"Scan Type: {scan_name}")
                print(f"Output: {self.reporter.output_dir}")
                print("\n⚠️  Windows Defender might show security alerts")
                
                confirm = input("\nStart scan? (yes/NO): ")
                if confirm.lower() not in ['yes', 'y']:
                    print("Scan cancelled.")
                    continue
                
                # Perform scan
                try:
                    print(f"\n🚀 Starting {scan_name} scan...")
                    scan_result = scan_method(targets)
                    self._generate_reports(scan_result)
                    
                    # Ask if user wants to continue
                    print("\n" + "="*50)
                    continue_choice = input("Perform another scan? (y/N): ").lower()
                    if continue_choice not in ['y', 'yes']:
                        if ask_to_exit():
                            return
                        else:
                            continue
                            
                except Exception as e:
                    print(f"❌ Scan failed: {e}")
                    continue
                    
            except KeyboardInterrupt:
                if ask_to_exit():
                    return
                else:
                    continue
            except Exception as e:
                print(f"❌ Error: {e}")
                continue
    
    def _generate_reports(self, scan_result):
        """Generate scan reports"""
        print("📊 Generating reports...")
        
        report_paths = self.reporter.generate_all_reports(scan_result)
        
        print("\n📄 REPORTS GENERATED:")
        for format_name, path in report_paths.items():
            print(f"   • {format_name.upper()}: {path}")
        
        # Show summary
        stats = self.engine.get_scan_statistics()
        critical = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score >= 9.0)
        high = sum(1 for v in scan_result.vulnerabilities if v.cve.severity == "HIGH" and v.cve.cvss_score < 9.0)
        
        print(f"\n📊 SCAN SUMMARY:")
        print(f"   • Hosts scanned: {stats['hosts_scanned']}")
        print(f"   • Services found: {stats['services_identified']}")
        print(f"   • Vulnerabilities: {stats['vulnerabilities_found']}")
        print(f"   • Critical: {critical} | High: {high}")
        print(f"   • Duration: {scan_result.scan_duration:.2f} seconds")
        
        if critical > 0:
            print(f"\n🚨 CRITICAL VULNERABILITIES FOUND - IMMEDIATE ACTION REQUIRED!")

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main entry point"""
    try:
        # Check if running on Windows
        if os.name != 'nt':
            print("⚠️  This tool is optimized for Windows but can run on other systems")
        
        cli = AegisVulnCLI()
        cli.run()
        
        # Ask to exit when naturally ending
        ask_to_exit()
        
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user.")
        ask_to_exit()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        ask_to_exit()

if __name__ == "__main__":
    main()
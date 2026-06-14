#!/usr/bin/env python3
"""
Privilege Escalation Agent - System privilege elevation
"""

import json
import logging
from typing import Dict, List
from core.llm_manager import LLMManager
from tools.privesc import (
    LinuxPrivEsc,
    WindowsPrivEsc,
    KernelExploiter,
    MisconfigFinder,
    CredentialHarvester,
    SudoExploiter
)

logger = logging.getLogger(__name__)


class PrivEscAgent:
    """Agent responsible for privilege escalation"""
    
    def __init__(self, config: Dict):
        """Initialize privilege escalation agent"""
        self.config = config
        self.llm = LLMManager(config)
        self.linux_privesc = LinuxPrivEsc(config)
        self.windows_privesc = WindowsPrivEsc(config)
        self.kernel_exploiter = KernelExploiter(config)
        self.misconfig_finder = MisconfigFinder(config)
        self.cred_harvester = CredentialHarvester(config)
        self.sudo_exploiter = SudoExploiter(config)
        
        logger.info("PrivEscAgent initialized")
    
    def execute(self, target: str, context: Dict) -> Dict:
        """Execute privilege escalation phase"""
        logger.info(f"Starting privilege escalation on {target}")
        
        results = {
            "target": target,
            "status": "running",
            "escalation_paths": [],
            "successful_escalations": [],
            "credentials_harvested": [],
            "system_info": {},
            "ai_analysis": {}
        }
        
        try:
            # Get exploitation data from context
            exploit_data = context.get("phases", {}).get("exploitation", {})
            
            if not exploit_data.get("successful_exploits"):
                logger.warning("No successful exploits found. Limited privilege escalation options.")
                results["status"] = "skipped"
                results["message"] = "No initial access obtained"
                return results
            
            # Phase 1: System Enumeration
            logger.info("Phase 1: System enumeration")
            results["system_info"] = self._enumerate_system(exploit_data)
            
            # Phase 2: Identify Escalation Paths
            logger.info("Phase 2: Identifying escalation paths")
            results["escalation_paths"] = self._identify_escalation_paths(
                results["system_info"]
            )
            
            # Phase 3: AI-Powered Path Selection
            logger.info("Phase 3: AI escalation strategy")
            strategy = self._ai_escalation_strategy(
                results["system_info"],
                results["escalation_paths"]
            )
            results["ai_analysis"] = strategy
            
            # Phase 4: Execute Escalation Attempts
            logger.info("Phase 4: Executing escalation attempts")
            for path in results["escalation_paths"][:5]:
                escalation_result = self._attempt_escalation(path, results["system_info"])
                
                if escalation_result.get("success"):
                    results["successful_escalations"].append(escalation_result)
                    logger.info(f"Successful escalation: {path.get('technique')}")
                    break  # Stop after first successful escalation
            
            # Phase 5: Credential Harvesting
            if results["successful_escalations"]:
                logger.info("Phase 5: Harvesting credentials")
                results["credentials_harvested"] = self._harvest_credentials(
                    results["system_info"]
                )
            
            results["status"] = "completed"
            logger.info("Privilege escalation phase completed")
            
        except Exception as e:
            logger.error(f"Error during privilege escalation: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _enumerate_system(self, exploit_data: Dict) -> Dict:
        """Enumerate system for privilege escalation opportunities"""
        system_info = {
            "os": "unknown",
            "kernel_version": "unknown",
            "architecture": "unknown",
            "users": [],
            "groups": [],
            "sudo_permissions": [],
            "suid_binaries": [],
            "writable_paths": [],
            "scheduled_tasks": [],
            "services": [],
            "environment_variables": {}
        }
        
        # Determine OS type from exploit data
        os_type = self._detect_os_type(exploit_data)
        system_info["os"] = os_type
        
        if os_type == "linux":
            system_info.update(self.linux_privesc.enumerate())
        elif os_type == "windows":
            system_info.update(self.windows_privesc.enumerate())
        
        return system_info
    
    def _detect_os_type(self, exploit_data: Dict) -> str:
        """Detect operating system type"""
        # Placeholder - would analyze exploit data to determine OS
        return "linux"  # Default assumption
    
    def _identify_escalation_paths(self, system_info: Dict) -> List[Dict]:
        """Identify possible privilege escalation paths"""
        paths = []
        os_type = system_info.get("os")
        
        if os_type == "linux":
            # SUID exploitation
            for binary in system_info.get("suid_binaries", []):
                paths.append({
                    "technique": "suid_exploitation",
                    "target": binary,
                    "difficulty": "medium",
                    "likelihood": 0.6
                })
            
            # Sudo exploitation
            for permission in system_info.get("sudo_permissions", []):
                paths.append({
                    "technique": "sudo_exploitation",
                    "target": permission,
                    "difficulty": "low",
                    "likelihood": 0.8
                })
            
            # Kernel exploitation
            if system_info.get("kernel_version"):
                paths.append({
                    "technique": "kernel_exploit",
                    "target": system_info["kernel_version"],
                    "difficulty": "high",
                    "likelihood": 0.4
                })
            
            # Writable path exploitation
            for path in system_info.get("writable_paths", []):
                if "bin" in path or "sbin" in path:
                    paths.append({
                        "technique": "path_hijacking",
                        "target": path,
                        "difficulty": "medium",
                        "likelihood": 0.5
                    })
        
        elif os_type == "windows":
            # Service exploitation
            for service in system_info.get("services", []):
                if service.get("unquoted_path") or service.get("weak_permissions"):
                    paths.append({
                        "technique": "service_exploitation",
                        "target": service,
                        "difficulty": "medium",
                        "likelihood": 0.7
                    })
            
            # AlwaysInstallElevated
            if system_info.get("always_install_elevated"):
                paths.append({
                    "technique": "always_install_elevated",
                    "target": "MSI",
                    "difficulty": "low",
                    "likelihood": 0.9
                })
            
            # Token impersonation
            paths.append({
                "technique": "token_impersonation",
                "target": "SeImpersonatePrivilege",
                "difficulty": "medium",
                "likelihood": 0.6
            })
        
        # Sort by likelihood
        paths.sort(key=lambda x: x.get("likelihood", 0), reverse=True)
        return paths
    
    def _ai_escalation_strategy(self, system_info: Dict, escalation_paths: List[Dict]) -> Dict:
        """Use AI to optimize escalation strategy"""
        prompt = self.llm.get_prompt(
            "privesc",
            "ai_escalation_strategy_user",
            default=f"""
Analyze the system and recommend optimal privilege escalation strategy:

System Information:
{json.dumps(system_info, indent=2)}

Identified Escalation Paths:
{json.dumps(escalation_paths, indent=2)}

Provide:
1. Recommended escalation path (with justification)
2. Step-by-step execution plan
3. Required tools and commands
4. Detection likelihood and evasion techniques
5. Fallback options
6. Post-escalation actions

Response in JSON format with actionable recommendations.
"""
        )
        
        system_prompt = self.llm.get_prompt(
            "privesc",
            "ai_escalation_strategy_system",
            default="""You are an expert in privilege escalation techniques.
Analyze systems and recommend the most effective, stealthy escalation paths.
Consider Windows, Linux, and Active Directory environments.
Prioritize reliability and minimal detection."""
        )
        
        try:
            formatted_prompt = prompt.format(
                system_info_json=json.dumps(system_info, indent=2),
                escalation_paths_json=json.dumps(escalation_paths, indent=2)
            )
            response = self.llm.generate(formatted_prompt, system_prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"AI escalation strategy error: {e}")
            return {"error": str(e)}
    
    def _attempt_escalation(self, path: Dict, system_info: Dict) -> Dict:
        """Attempt privilege escalation using specified path"""
        technique = path.get("technique")
        os_type = system_info.get("os")
        
        result = {
            "technique": technique,
            "success": False,
            "details": {}
        }
        
        try:
            if os_type == "linux":
                if technique == "suid_exploitation":
                    result = self.linux_privesc.exploit_suid(path.get("target"))
                elif technique == "sudo_exploitation":
                    result = self.sudo_exploiter.exploit(path.get("target"))
                elif technique == "kernel_exploit":
                    result = self.kernel_exploiter.exploit_linux(path.get("target"))
                elif technique == "path_hijacking":
                    result = self.linux_privesc.exploit_path_hijacking(path.get("target"))
            
            elif os_type == "windows":
                if technique == "service_exploitation":
                    result = self.windows_privesc.exploit_service(path.get("target"))
                elif technique == "always_install_elevated":
                    result = self.windows_privesc.exploit_msi()
                elif technique == "token_impersonation":
                    result = self.windows_privesc.impersonate_token()
        
        except Exception as e:
            logger.error(f"Escalation error for {technique}: {e}")
            result["error"] = str(e)
        
        return result
    
    def _harvest_credentials(self, system_info: Dict) -> List[Dict]:
        """Harvest credentials after privilege escalation"""
        os_type = system_info.get("os")
        
        if os_type == "linux":
            return self.cred_harvester.harvest_linux()
        elif os_type == "windows":
            return self.cred_harvester.harvest_windows()
        
        return []

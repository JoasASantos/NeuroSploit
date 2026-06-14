#!/usr/bin/env python3
"""
Lateral Movement Agent - Move through the network
"""

import json
import logging
from typing import Dict, List
from core.llm_manager import LLMManager

logger = logging.getLogger(__name__)


class LateralMovementAgent:
    """Agent responsible for lateral movement"""
    
    def __init__(self, config: Dict):
        """Initialize lateral movement agent"""
        self.config = config
        self.llm = LLMManager(config)
        logger.info("LateralMovementAgent initialized")
    
    def execute(self, target: str, context: Dict) -> Dict:
        """Execute lateral movement phase"""
        logger.info(f"Starting lateral movement from {target}")
        
        results = {
            "target": target,
            "status": "running",
            "discovered_hosts": [],
            "compromised_hosts": [],
            "credentials_used": [],
            "movement_paths": [],
            "ai_analysis": {}
        }
        
        try:
            # Get previous phase data
            recon_data = context.get("phases", {}).get("recon", {})
            privesc_data = context.get("phases", {}).get("privilege_escalation", {})
            
            # Phase 1: Network Discovery
            logger.info("Phase 1: Internal network discovery")
            results["discovered_hosts"] = self._discover_internal_network(recon_data)
            
            # Phase 2: AI-Powered Movement Strategy
            logger.info("Phase 2: AI lateral movement strategy")
            strategy = self._ai_movement_strategy(context, results["discovered_hosts"])
            results["ai_analysis"] = strategy
            
            # Phase 3: Credential Reuse
            logger.info("Phase 3: Credential reuse attacks")
            credentials = privesc_data.get("credentials_harvested", [])
            results["credentials_used"] = self._attempt_credential_reuse(
                results["discovered_hosts"],
                credentials
            )
            
            # Phase 4: Pass-the-Hash/Pass-the-Ticket
            logger.info("Phase 4: Pass-the-Hash/Ticket attacks")
            results["movement_paths"].extend(
                self._pass_the_hash_attacks(results["discovered_hosts"])
            )
            
            # Phase 5: Exploit Trust Relationships
            logger.info("Phase 5: Exploiting trust relationships")
            results["movement_paths"].extend(
                self._exploit_trust_relationships(results["discovered_hosts"])
            )
            
            results["status"] = "completed"
            logger.info("Lateral movement phase completed")
            
        except Exception as e:
            logger.error(f"Error during lateral movement: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _discover_internal_network(self, recon_data: Dict) -> List[Dict]:
        """Discover internal network hosts"""
        hosts = []
        
        # Extract hosts from recon data
        network_scan = recon_data.get("network_scan", {})
        for ip, data in network_scan.get("hosts", {}).items():
            hosts.append({
                "ip": ip,
                "ports": data.get("open_ports", []),
                "os": data.get("os", "unknown")
            })
        
        # Simulate additional internal discovery
        hosts.extend([
            {"ip": "192.168.1.10", "role": "domain_controller", "status": "discovered"},
            {"ip": "192.168.1.20", "role": "file_server", "status": "discovered"},
            {"ip": "192.168.1.30", "role": "workstation", "status": "discovered"}
        ])
        
        return hosts
    
    def _ai_movement_strategy(self, context: Dict, hosts: List[Dict]) -> Dict:
        """Use AI to plan lateral movement"""
        prompt = self.llm.get_prompt(
            "lateral_movement",
            "ai_movement_strategy_user",
            default=f"""
Plan a lateral movement strategy based on the following:

Current Context:
{json.dumps(context, indent=2)}

Discovered Hosts:
{json.dumps(hosts, indent=2)}

Provide:
1. Target prioritization (high-value targets first)
2. Movement techniques for each target
3. Credential strategies
4. Evasion techniques
5. Attack path optimization
6. Fallback options

Response in JSON format with detailed attack paths.
"""
        )
        
        system_prompt = self.llm.get_prompt(
            "lateral_movement",
            "ai_movement_strategy_system",
            default="""You are an expert in lateral movement and Active Directory attacks.
Plan sophisticated movement strategies that minimize detection and maximize impact.
Consider Pass-the-Hash, Pass-the-Ticket, RDP, WMI, PSExec, and other techniques.
Prioritize domain controllers and critical infrastructure."""
        )
        
        try:
            formatted_prompt = prompt.format(
                context_json=json.dumps(context, indent=2),
                hosts_json=json.dumps(hosts, indent=2)
            )
            response = self.llm.generate(formatted_prompt, system_prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"AI movement strategy error: {e}")
            return {"error": str(e)}
    
    def _attempt_credential_reuse(self, hosts: List[Dict], credentials: List[Dict]) -> List[Dict]:
        """Attempt credential reuse across hosts"""
        attempts = []
        
        for host in hosts[:5]:  # Limit attempts
            for cred in credentials[:3]:
                attempts.append({
                    "host": host.get("ip"),
                    "credential": "***hidden***",
                    "protocol": "SMB",
                    "success": False,  # Simulated
                    "status": "simulated"
                })
        
        return attempts
    
    def _pass_the_hash_attacks(self, hosts: List[Dict]) -> List[Dict]:
        """Perform Pass-the-Hash attacks"""
        attacks = []
        
        for host in hosts:
            if host.get("role") in ["domain_controller", "file_server"]:
                attacks.append({
                    "type": "pass_the_hash",
                    "target": host.get("ip"),
                    "technique": "SMB relay",
                    "success": False,  # Simulated
                    "status": "simulated"
                })
        
        return attacks
    
    def _exploit_trust_relationships(self, hosts: List[Dict]) -> List[Dict]:
        """Exploit trust relationships"""
        exploits = []
        
        # Domain trust exploitation
        exploits.append({
            "type": "domain_trust",
            "description": "Cross-domain exploitation",
            "status": "simulated"
        })
        
        # Kerberos delegation
        exploits.append({
            "type": "kerberos_delegation",
            "description": "Unconstrained delegation abuse",
            "status": "simulated"
        })
        
        return exploits

#!/usr/bin/env python3
"""
Network Reconnaissance Agent - Network-focused information gathering and enumeration
"""

import os
import json
import subprocess
from typing import Dict, List
import logging
from core.llm_manager import LLMManager
from tools.recon import (
    NetworkScanner, 
    OSINTCollector,
    DNSEnumerator,
    SubdomainFinder
)
from urllib.parse import urlparse # Added import

logger = logging.getLogger(__name__)


class NetworkReconAgent:
    """Agent responsible for network-focused reconnaissance and information gathering"""
    
    def __init__(self, config: Dict):
        """Initialize network reconnaissance agent"""
        self.config = config
        self.llm = LLMManager(config)
        self.network_scanner = NetworkScanner(config)
        self.osint = OSINTCollector(config)
        self.dns_enum = DNSEnumerator(config)
        self.subdomain_finder = SubdomainFinder(config)
        
        logger.info("NetworkReconAgent initialized")
    
    def execute(self, target: str, context: Dict) -> Dict:
        """Execute network reconnaissance phase"""
        logger.info(f"Starting network reconnaissance on {target}")
        
        results = {
            "target": target,
            "status": "running",
            "findings": [],
            "network_scan": {},
            "osint": {},
            "dns": {},
            "subdomains": [],
            "ai_analysis": {}
        }
        
        # Parse target to extract hostname if it's a URL
        parsed_target = urlparse(target)
        target_host = parsed_target.hostname or target # Use hostname if exists, otherwise original target
        logger.info(f"Target for network tools: {target_host}")

        try:
            # Phase 1: Network Scanning
            logger.info("Phase 1: Network scanning")
            results["network_scan"] = self.network_scanner.scan(target_host) # Use target_host
            
            # Phase 2: DNS Enumeration
            logger.info("Phase 2: DNS enumeration")
            results["dns"] = self.dns_enum.enumerate(target_host) # Use target_host
            
            # Phase 3: Subdomain Discovery
            logger.info("Phase 3: Subdomain discovery")
            results["subdomains"] = self.subdomain_finder.find(target_host) # Use target_host
            
            # Phase 4: OSINT Collection
            logger.info("Phase 4: OSINT collection")
            results["osint"] = self.osint.collect(target_host) # Use target_host
            
            # Phase 5: AI Analysis
            logger.info("Phase 5: AI-powered analysis")
            results["ai_analysis"] = self._ai_analysis(results)
            
            results["status"] = "completed"
            logger.info("Network reconnaissance phase completed")
            
        except Exception as e:
            logger.error(f"Error during network reconnaissance: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def _ai_analysis(self, recon_data: Dict) -> Dict:
        """Use AI to analyze reconnaissance data"""
        prompt = self.llm.get_prompt(
            "network_recon",
            "ai_analysis_user",
            default=f"""
Analyze the following network reconnaissance data and provide insights:

{json.dumps(recon_data, indent=2)}

Provide:
1. Attack surface summary
2. Prioritized network target list
3. Identified network vulnerabilities or misconfigurations
4. Recommended next steps for network exploitation
5. Network risk assessment
6. Stealth considerations for network activities

Response in JSON format with actionable recommendations.
"""
        )
        
        system_prompt = self.llm.get_prompt(
            "network_recon",
            "ai_analysis_system",
            default="""You are an expert network penetration tester analyzing reconnaissance data.
Identify network security weaknesses, network attack vectors, and provide strategic recommendations.
Consider both technical and operational security aspects."""
        )

        try:
            # Format the user prompt with recon_data
            formatted_prompt = prompt.format(recon_data_json=json.dumps(recon_data, indent=2))
            response = self.llm.generate(formatted_prompt, system_prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {"error": str(e), "raw_response": response if 'response' in locals() else None}
    
    def passive_recon(self, target: str) -> Dict:
        """Perform passive reconnaissance only"""
        # Parse target to extract hostname if it's a URL
        parsed_target = urlparse(target)
        target_host = parsed_target.hostname or target
        
        return {
            "osint": self.osint.collect(target_host), # Use target_host
            "dns": self.dns_enum.enumerate(target_host), # Use target_host
            "subdomains": self.subdomain_finder.find(target_host) # Use target_host
        }
    
    def active_recon(self, target: str) -> Dict:
        """Perform active reconnaissance"""
        # Parse target to extract hostname if it's a URL
        parsed_target = urlparse(target)
        target_host = parsed_target.hostname or target

        return {
            "network_scan": self.network_scanner.scan(target_host) # Use target_host
        }


#!/usr/bin/env python3
"""
NeuroSploitv2 - AI-Powered Penetration Testing Framework
Author: Security Research Team
License: MIT
Version: 2.0.0
"""

import os
import sys
import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
import logging
from datetime import datetime
import readline
import mistune

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/neurosploit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

from core.llm_manager import LLMManager
from core.tool_installer import ToolInstaller, run_installer_menu, PENTEST_TOOLS
from core.pentest_executor import PentestExecutor
from core.report_generator import ReportGenerator
from core.context_builder import ReconContextBuilder
from agents.base_agent import BaseAgent
from tools.recon.recon_tools import FullReconRunner

# Import AI Agents
try:
    from backend.core.ai_pentest_agent import AIPentestAgent
except ImportError:
    AIPentestAgent = None

try:
    from backend.core.autonomous_agent import AutonomousAgent, OperationMode
    from backend.core.task_library import get_task_library, Task, TaskCategory
except ImportError:
    AutonomousAgent = None
    OperationMode = None
    get_task_library = None
    Task = None
    TaskCategory = None


class Completer:
    def __init__(self, neurosploit):
        self.neurosploit = neurosploit
        self.commands = [
            "help", "run_agent", "config", "list_roles", "list_profiles",
            "set_profile", "set_agent", "discover_ollama", "install_tools",
            "scan", "quick_scan", "recon", "full_recon", "check_tools",
            "experience", "wizard", "analyze", "agent", "ai_agent",
            # Autonomous agent modes
            "pentest", "full_auto", "recon_only", "prompt_only", "analyze_only",
            # Task library
            "tasks", "task", "list_tasks", "create_task", "run_task",
            # Flags (for inline completion)
            "--kali", "--vpn", "--vpn-user", "--vpn-pass",
            "--researcher", "--multi-agent", "--custom-prompts",
            "exit", "quit"
        ]
        self.agent_roles = list(self.neurosploit.config.get('agent_roles', {}).keys())
        self.llm_profiles = list(self.neurosploit.config.get('llm', {}).get('profiles', {}).keys())

    def complete(self, text, state):
        line = readline.get_line_buffer()
        parts = line.split()

        options = []
        if state == 0:
            if not parts or (len(parts) == 1 and not line.endswith(' ')):
                options = [c + ' ' for c in self.commands if c.startswith(text)]
            elif len(parts) > 0:
                if parts[0] == 'run_agent':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles if a.startswith(parts[1])]
                elif parts[0] == 'set_agent':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [a + ' ' for a in self.agent_roles if a.startswith(parts[1])]
                elif parts[0] == 'set_profile':
                    if len(parts) == 1 and line.endswith(' '):
                        options = [p + ' ' for p in self.llm_profiles]
                    elif len(parts) == 2 and not line.endswith(' '):
                        options = [p + ' ' for p in self.llm_profiles if p.startswith(parts[1])]

        if state < len(options):
            return options[state]
        else:
            return None


class NeuroSploitv2:
    """Main framework class for NeuroSploitv2"""

    def __init__(self, config_path: str = "config/config.json"):
        """Initialize the framework"""
        self.config_path = config_path
        self.config = self._load_config()
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._setup_directories()

        # LLMManager instance will be created dynamically per agent role to select specific profiles
        self.llm_manager_instance: Optional[LLMManager] = None
        self.selected_agent_role: Optional[str] = None

        # Initialize tool installer
        self.tool_installer = ToolInstaller()

        logger.info(f"NeuroSploitv2 initialized - Session: {self.session_id}")

    def experience_mode(self):
        """
        Experience/Wizard Mode - Guided step-by-step configuration.
        Navigate through options to build your pentest configuration.
        """
        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║       NEUROSPLOIT - EXPERIENCE MODE (WIZARD)              ║
        ║           Step-by-step Configuration                      ║
        ╚═══════════════════════════════════════════════════════════╝
        """)

        config = {
            "target": None,
            "context_file": None,
            "llm_profile": None,
            "agent_role": None,
            "prompt": None,
            "mode": None
        }

        # Step 1: Choose Mode
        print("\n[STEP 1/6] Choose Operation Mode")
        print("-" * 50)
        print("  1. AI Analysis   - Analyze recon context with LLM (no tools)")
        print("  2. Full Scan     - Run real pentest tools + AI analysis")
        print("  3. Quick Scan    - Fast essential checks + AI analysis")
        print("  4. Recon Only    - Run reconnaissance tools, save context")
        print("  0. Cancel")

        while True:
            choice = input("\n  Select mode [1-4]: ").strip()
            if choice == "0":
                print("\n[!] Cancelled.")
                return
            if choice in ["1", "2", "3", "4"]:
                config["mode"] = {"1": "analysis", "2": "full_scan", "3": "quick_scan", "4": "recon"}[choice]
                break
            print("  Invalid choice. Enter 1-4 or 0 to cancel.")

        # Step 2: Target
        print(f"\n[STEP 2/6] Set Target")
        print("-" * 50)
        target = input("  Enter target URL or domain: ").strip()
        if not target:
            print("\n[!] Target is required. Cancelled.")
            return
        config["target"] = target

        # Step 3: Context File (for analysis mode)
        if config["mode"] == "analysis":
            print(f"\n[STEP 3/6] Context File")
            print("-" * 50)
            print("  Context file contains recon data collected previously.")

            # List available context files
            context_files = list(Path("results").glob("context_*.json"))
            if context_files:
                print("\n  Available context files:")
                for i, f in enumerate(context_files[-10:], 1):
                    print(f"    {i}. {f.name}")
                print(f"    {len(context_files[-10:])+1}. Enter custom path")

                choice = input(f"\n  Select file [1-{len(context_files[-10:])+1}]: ").strip()
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(context_files[-10:]):
                        config["context_file"] = str(context_files[-10:][idx])
                    else:
                        custom = input("  Enter context file path: ").strip()
                        if custom:
                            config["context_file"] = custom
                except ValueError:
                    custom = input("  Enter context file path: ").strip()
                    if custom:
                        config["context_file"] = custom
            else:
                custom = input("  Enter context file path (or press Enter to skip): ").strip()
                if custom:
                    config["context_file"] = custom

            if not config["context_file"]:
                print("\n[!] Analysis mode requires a context file. Cancelled.")
                return
        else:
            print(f"\n[STEP 3/6] Context File (Optional)")
            print("-" * 50)
            use_context = input("  Load existing context file? [y/N]: ").strip().lower()
            if use_context == 'y':
                context_files = list(Path("results").glob("context_*.json"))
                if context_files:
                    print("\n  Available context files:")
                    for i, f in enumerate(context_files[-10:], 1):
                        print(f"    {i}. {f.name}")
                    choice = input(f"\n  Select file [1-{len(context_files[-10:])}] or path: ").strip()
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(context_files[-10:]):
                            config["context_file"] = str(context_files[-10:][idx])
                    except ValueError:
                        if choice:
                            config["context_file"] = choice

        # Step 4: LLM Profile
        print(f"\n[STEP 4/6] LLM Profile")
        print("-" * 50)
        profiles = list(self.config.get('llm', {}).get('profiles', {}).keys())
        default_profile = self.config.get('llm', {}).get('default_profile', '')

        if profiles:
            print("  Available LLM profiles:")
            for i, p in enumerate(profiles, 1):
                marker = " (default)" if p == default_profile else ""
                print(f"    {i}. {p}{marker}")

            choice = input(f"\n  Select profile [1-{len(profiles)}] or Enter for default: ").strip()
            if choice:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(profiles):
                        config["llm_profile"] = profiles[idx]
                except ValueError:
                    pass

            if not config["llm_profile"]:
                config["llm_profile"] = default_profile
        else:
            print("  No LLM profiles configured. Using default.")
            config["llm_profile"] = default_profile

        # Step 5: Agent Role (optional)
        print(f"\n[STEP 5/6] Agent Role (Optional)")
        print("-" * 50)
        roles = list(self.config.get('agent_roles', {}).keys())

        if roles:
            print("  Available agent roles:")
            for i, r in enumerate(roles, 1):
                desc = self.config['agent_roles'][r].get('description', '')[:50]
                print(f"    {i}. {r} - {desc}")
            print(f"    {len(roles)+1}. None (use default)")

            choice = input(f"\n  Select role [1-{len(roles)+1}]: ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(roles):
                    config["agent_role"] = roles[idx]
            except ValueError:
                pass

        # Step 6: Custom Prompt
        if config["mode"] in ["analysis", "full_scan", "quick_scan"]:
            print(f"\n[STEP 6/6] Custom Prompt")
            print("-" * 50)
            print("  Enter your instructions for the AI agent.")
            print("  (What should it analyze, test, or look for?)")
            print("  Press Enter twice to finish.\n")

            lines = []
            while True:
                line = input("  > ")
                if line == "" and lines and lines[-1] == "":
                    break
                lines.append(line)

            config["prompt"] = "\n".join(lines).strip()

            if not config["prompt"]:
                config["prompt"] = f"Perform comprehensive security assessment on {config['target']}"
        else:
            print(f"\n[STEP 6/6] Skipped (Recon mode)")
            config["prompt"] = None

        # Summary and Confirmation
        print(f"\n{'='*60}")
        print("  CONFIGURATION SUMMARY")
        print(f"{'='*60}")
        print(f"  Mode:         {config['mode']}")
        print(f"  Target:       {config['target']}")
        print(f"  Context File: {config['context_file'] or 'None'}")
        print(f"  LLM Profile:  {config['llm_profile']}")
        print(f"  Agent Role:   {config['agent_role'] or 'default'}")
        if config["prompt"]:
            print(f"  Prompt:       {config['prompt'][:60]}...")
        print(f"{'='*60}")

        confirm = input("\n  Execute with this configuration? [Y/n]: ").strip().lower()
        if confirm == 'n':
            print("\n[!] Cancelled.")
            return

        # Execute based on mode
        print(f"\n[*] Starting execution...")

        context = None
        if config["context_file"]:
            from core.context_builder import load_context_from_file
            context = load_context_from_file(config["context_file"])
            if context:
                print(f"[+] Loaded context from: {config['context_file']}")

        if config["mode"] == "recon":
            self.run_full_recon(config["target"], with_ai_analysis=bool(config["agent_role"]))

        elif config["mode"] == "analysis":
            agent_role = config["agent_role"] or "bug_bounty_hunter"
            self.execute_agent_role(
                agent_role,
                config["prompt"],
                llm_profile_override=config["llm_profile"],
                recon_context=context
            )

        elif config["mode"] == "full_scan":
            self.execute_real_scan(
                config["target"],
                scan_type="full",
                agent_role=config["agent_role"],
                recon_context=context
            )

        elif config["mode"] == "quick_scan":
            self.execute_real_scan(
                config["target"],
                scan_type="quick",
                agent_role=config["agent_role"],
                recon_context=context
            )

        print(f"\n[+] Execution complete!")
        
    def _setup_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'reports', 'data', 'custom_agents', 'results']
        for d in dirs:
            Path(d).mkdir(exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            if os.path.exists("config/config-example.json"):
                import shutil
                shutil.copy("config/config-example.json", self.config_path)
                logger.info(f"Created default configuration at {self.config_path}")
            else:
                logger.error("config-example.json not found. Cannot create default configuration.")
                return {}
        
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    def _initialize_llm_manager(self, agent_llm_profile: Optional[str] = None):
        """Initializes LLMManager with a specific profile or default."""
        llm_config = self.config.get('llm', {})
        if agent_llm_profile:
            # Temporarily modify config to set the default profile for LLMManager init
            original_default = llm_config.get('default_profile')
            llm_config['default_profile'] = agent_llm_profile
            self.llm_manager_instance = LLMManager({"llm": llm_config})
            llm_config['default_profile'] = original_default # Restore original default
        else:
            self.llm_manager_instance = LLMManager({"llm": llm_config})

    def execute_agent_role(self, agent_role_name: str, user_input: str, additional_context: Optional[Dict] = None, llm_profile_override: Optional[str] = None, recon_context: Optional[Dict] = None):
        """
        Execute a specific agent role with a given input.

        Args:
            agent_role_name: Name of the agent role to use
            user_input: The prompt/task for the agent
            additional_context: Additional campaign data
            llm_profile_override: Override the default LLM profile
            recon_context: Pre-collected recon context (skips discovery if provided)
        """
        logger.info(f"Starting execution for agent role: {agent_role_name}")

        agent_roles_config = self.config.get('agent_roles', {})
        role_config = agent_roles_config.get(agent_role_name)

        # If role not in config, create a default config (allows dynamic roles from .md files)
        if not role_config:
            logger.info(f"Agent role '{agent_role_name}' not in config.json, using dynamic mode with prompt file.")
            role_config = {
                "enabled": True,
                "tools_allowed": [],
                "description": f"Dynamic agent role loaded from {agent_role_name}.md"
            }

        if not role_config.get('enabled', True):
            logger.warning(f"Agent role '{agent_role_name}' is disabled in configuration.")
            return {"warning": f"Agent role '{agent_role_name}' is disabled."}

        llm_profile_name = llm_profile_override or role_config.get('llm_profile', self.config['llm']['default_profile'])
        self._initialize_llm_manager(llm_profile_name)

        if not self.llm_manager_instance:
            logger.error("LLM Manager could not be initialized.")
            return {"error": "LLM Manager initialization failed."}

        # Get the prompts for the selected agent role
        # Assuming agent_role_name directly maps to the .md filename
        agent_prompts = self.llm_manager_instance.prompts.get("md_prompts", {}).get(agent_role_name)
        if not agent_prompts:
            logger.error(f"Prompts for agent role '{agent_role_name}' not found in MD library.")
            return {"error": f"Prompts for agent role '{agent_role_name}' not found."}

        # Instantiate and execute the BaseAgent
        agent_instance = BaseAgent(agent_role_name, self.config, self.llm_manager_instance, agent_prompts)

        # Execute with recon_context if provided (uses context-based flow)
        results = agent_instance.execute(user_input, additional_context, recon_context=recon_context)
        
        # Save results
        campaign_results = {
            "session_id": self.session_id,
            "agent_role": agent_role_name,
            "input": user_input,
            "timestamp": datetime.now().isoformat(),
            "results": results
        }
        self._save_results(campaign_results)
        return campaign_results
    
    def _save_results(self, results: Dict):
        """Save campaign results"""
        output_file = f"results/campaign_{self.session_id}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_file}")
        
        # Generate report
        self._generate_report(results)
    
    def _generate_report(self, results: Dict):
        """Generate professional HTML report with charts and modern CSS"""
        report_file = f"reports/report_{self.session_id}.html"

        # Get data
        llm_response = results.get('results', {}).get('llm_response', '')
        if isinstance(llm_response, dict):
            llm_response = json.dumps(llm_response, indent=2)

        report_content = mistune.html(llm_response)

        # Extract metrics from report
        targets = results.get('results', {}).get('targets', [results.get('input', 'N/A')])
        if isinstance(targets, str):
            targets = [targets]
        tools_executed = results.get('results', {}).get('tools_executed', 0)

        # Count severities from report text
        critical = len(re.findall(r'\[?Critical\]?', llm_response, re.IGNORECASE))
        high = len(re.findall(r'\[?High\]?', llm_response, re.IGNORECASE))
        medium = len(re.findall(r'\[?Medium\]?', llm_response, re.IGNORECASE))
        low = len(re.findall(r'\[?Low\]?', llm_response, re.IGNORECASE))
        info = len(re.findall(r'\[?Info\]?', llm_response, re.IGNORECASE))
        total_vulns = critical + high + medium + low

        # Risk score calculation
        risk_score = min(100, (critical * 25) + (high * 15) + (medium * 8) + (low * 3))
        risk_level = "Critical" if risk_score >= 70 else "High" if risk_score >= 50 else "Medium" if risk_score >= 25 else "Low"
        risk_color = "#e74c3c" if risk_score >= 70 else "#e67e22" if risk_score >= 50 else "#f1c40f" if risk_score >= 25 else "#27ae60"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {self.session_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a1f2e;
            --border-color: #2d3748;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #6366f1;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
            padding: 3rem 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}
        .header-content {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
        .logo {{ font-size: 2rem; font-weight: 800; background: linear-gradient(90deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .report-meta {{ text-align: right; color: var(--text-secondary); font-size: 0.9rem; }}

        /* Stats Grid */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .stat-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-critical .stat-value {{ color: var(--critical); }}
        .stat-high .stat-value {{ color: var(--high); }}
        .stat-medium .stat-value {{ color: var(--medium); }}
        .stat-low .stat-value {{ color: var(--low); }}

        /* Risk Score */
        .risk-section {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem; }}
        @media (max-width: 900px) {{ .risk-section {{ grid-template-columns: 1fr; }} }}
        .risk-card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid var(--border-color);
        }}
        .risk-score-circle {{
            width: 180px; height: 180px;
            border-radius: 50%;
            background: conic-gradient({risk_color} 0deg, {risk_color} {risk_score * 3.6}deg, #2d3748 {risk_score * 3.6}deg);
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 1rem;
        }}
        .risk-score-inner {{
            width: 140px; height: 140px;
            border-radius: 50%;
            background: var(--bg-card);
            display: flex; flex-direction: column; align-items: center; justify-content: center;
        }}
        .risk-score-value {{ font-size: 3rem; font-weight: 800; color: {risk_color}; }}
        .risk-score-label {{ color: var(--text-secondary); font-size: 0.875rem; }}
        .chart-container {{ height: 250px; }}

        /* Targets */
        .targets-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }}
        .target-tag {{
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid var(--accent);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-family: monospace;
        }}

        /* Main Report */
        .report-section {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
        }}
        .section-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid var(--accent);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .section-title::before {{
            content: '';
            width: 4px;
            height: 24px;
            background: var(--accent);
            border-radius: 2px;
        }}

        /* Vulnerability Cards */
        .report-content h2 {{
            background: linear-gradient(90deg, var(--bg-secondary), transparent);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin: 2rem 0 1rem;
            border-left: 4px solid var(--accent);
            font-size: 1.25rem;
        }}
        .report-content h2:has-text("Critical"), .report-content h2:contains("CRITICAL") {{ border-left-color: var(--critical); }}
        .report-content h3 {{ color: var(--accent); margin: 1.5rem 0 0.75rem; font-size: 1.1rem; }}
        .report-content table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}
        .report-content th, .report-content td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        .report-content th {{ background: rgba(59, 130, 246, 0.1); color: var(--accent); font-weight: 600; }}
        .report-content pre {{
            background: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        .report-content code {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.875rem;
        }}
        .report-content p {{ margin: 0.75rem 0; }}
        .report-content hr {{ border: none; border-top: 1px solid var(--border-color); margin: 2rem 0; }}
        .report-content ul, .report-content ol {{ margin: 1rem 0; padding-left: 1.5rem; }}
        .report-content li {{ margin: 0.5rem 0; }}

        /* Severity Badges */
        .report-content h2 {{ position: relative; }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            border-top: 1px solid var(--border-color);
            margin-top: 3rem;
        }}

        /* OHVR Structure */
        .ohvr-section {{
            margin: 1rem 0;
            padding: 1rem;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }}
        .ohvr-section h5 {{
            color: var(--accent);
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}
        .screenshot-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}
        .screenshot-card {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        .screenshot-card img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        .screenshot-caption {{
            padding: 0.5rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-align: center;
        }}

        /* Print Styles */
        @media print {{
            body {{ background: white; color: black; }}
            .stat-card, .risk-card, .report-section {{ border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div>
                    <div class="logo">NeuroSploit</div>
                    <p style="color: var(--text-secondary); margin-top: 0.5rem;">AI-Powered Security Assessment Report</p>
                </div>
                <div class="report-meta">
                    <div><strong>Report ID:</strong> {self.session_id}</div>
                    <div><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                    <div><strong>Agent:</strong> {results.get('agent_role', 'Security Analyst')}</div>
                </div>
            </div>
            <div class="targets-list">
                {''.join(f'<span class="target-tag">{t}</span>' for t in targets[:5])}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-value">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-value">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-value">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-value">{low}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent);">{tools_executed}</div>
                <div class="stat-label">Tests Run</div>
            </div>
        </div>

        <div class="risk-section">
            <div class="risk-card">
                <h3 style="text-align: center; margin-bottom: 1rem; color: var(--text-secondary);">Risk Score</h3>
                <div class="risk-score-circle">
                    <div class="risk-score-inner">
                        <div class="risk-score-value">{risk_score}</div>
                        <div class="risk-score-label">{risk_level}</div>
                    </div>
                </div>
            </div>
            <div class="risk-card">
                <h3 style="margin-bottom: 1rem; color: var(--text-secondary);">Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
        </div>

        <div class="report-section">
            <div class="section-title">Vulnerability Report</div>
            <div class="report-content">
                {report_content}
            </div>
        </div>

        <div class="footer">
            <p>Generated by <strong>NeuroSploit</strong> - AI-Powered Penetration Testing Framework</p>
            <p style="margin-top: 0.5rem;">Confidential - For authorized personnel only</p>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>
        hljs.highlightAll();

        // Severity Chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{critical}, {high}, {medium}, {low}, {info}],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'],
                    borderWidth: 0,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ color: '#94a3b8', padding: 15, font: {{ size: 12 }} }}
                    }}
                }},
                cutout: '60%'
            }}
        }});
    </script>
</body>
</html>"""
        
        with open(report_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Report generated: {report_file}")

    def execute_real_scan(self, target: str, scan_type: str = "full", agent_role: str = None, recon_context: Dict = None) -> Dict:
        """
        Execute a real penetration test with actual tools and generate professional report.

        Args:
            target: The target URL or IP to scan
            scan_type: "full" for comprehensive scan, "quick" for essential checks
            agent_role: Optional agent role for AI analysis of results
        """
        print(f"\n{'='*70}")
        print("    NeuroSploitv2 - Real Penetration Test Execution")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Scan Type: {scan_type}")
        print(f"[*] Session ID: {self.session_id}\n")

        # Check for required tools
        print("[*] Checking required tools...")
        missing_tools = []
        essential_tools = ["nmap", "curl"]
        for tool in essential_tools:
            installed, path = self.tool_installer.check_tool_installed(tool)
            if not installed:
                missing_tools.append(tool)
                print(f"    [-] {tool}: NOT INSTALLED")
            else:
                print(f"    [+] {tool}: {path}")

        if missing_tools:
            print(f"\n[!] Missing required tools: {', '.join(missing_tools)}")
            print("[!] Run 'install_tools' to install required tools.")
            return {"error": f"Missing tools: {missing_tools}"}

        # Execute the scan
        executor = PentestExecutor(target, self.config, recon_context=recon_context)
        if recon_context:
            print(f"[+] Using recon context with {recon_context.get('attack_surface', {}).get('total_subdomains', 0)} subdomains, {recon_context.get('attack_surface', {}).get('live_hosts', 0)} live hosts")

        if scan_type == "quick":
            scan_result = executor.run_quick_scan()
        else:
            scan_result = executor.run_full_scan()

        # Get results as dictionary
        results_dict = executor.to_dict()

        # Get AI analysis if agent role specified
        llm_analysis = ""
        if agent_role:
            print(f"\n[*] Running AI analysis with {agent_role}...")
            llm_profile = self.config.get('agent_roles', {}).get(agent_role, {}).get('llm_profile')
            self._initialize_llm_manager(llm_profile)

            if self.llm_manager_instance:
                agent_prompts = self.llm_manager_instance.prompts.get("md_prompts", {}).get(agent_role, {})
                if agent_prompts:
                    agent = BaseAgent(agent_role, self.config, self.llm_manager_instance, agent_prompts)
                    analysis_input = f"""
Analyze the following penetration test results and provide a detailed security assessment:

Target: {target}
Scan Type: {scan_type}

SCAN RESULTS:
{json.dumps(results_dict, indent=2)}

Provide:
1. Executive summary of findings
2. Risk assessment
3. Detailed analysis of each vulnerability
4. Prioritized remediation recommendations
5. Additional attack vectors to explore
"""
                    analysis_result = agent.execute(analysis_input, results_dict)
                    llm_analysis = analysis_result.get("llm_response", "")

        # Generate professional report
        print("\n[*] Generating professional report...")
        report_gen = ReportGenerator(results_dict, llm_analysis)
        html_report = report_gen.save_report("reports")
        json_report = report_gen.save_json_report("results")

        print(f"\n{'='*70}")
        print("[+] Scan Complete!")
        print(f"    - Vulnerabilities Found: {len(results_dict.get('vulnerabilities', []))}")
        print(f"    - HTML Report: {html_report}")
        print(f"    - JSON Results: {json_report}")
        print(f"{'='*70}\n")

        return {
            "session_id": self.session_id,
            "target": target,
            "scan_type": scan_type,
            "results": results_dict,
            "html_report": html_report,
            "json_report": json_report
        }

    def run_full_recon(self, target: str, with_ai_analysis: bool = True) -> Dict:
        """
        Run full advanced recon and consolidate all outputs.

        This command runs all recon tools:
        - Subdomain enumeration (subfinder, amass, assetfinder)
        - HTTP probing (httpx, httprobe)
        - URL collection (gau, waybackurls, waymore)
        - Web crawling (katana, gospider)
        - Port scanning (naabu, nmap)
        - DNS enumeration
        - Vulnerability scanning (nuclei)

        All results are consolidated into a single context file
        that will be used by the LLM to enhance testing.
        """
        print(f"\n{'='*70}")
        print("    NEUROSPLOIT - FULL ADVANCED RECON")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Session ID: {self.session_id}")
        print(f"[*] With AI analysis: {with_ai_analysis}\n")

        # Execute full recon
        recon_runner = FullReconRunner(self.config)

        # Determine target type
        target_type = "url" if target.startswith(('http://', 'https://')) else "domain"

        recon_results = recon_runner.run(target, target_type)

        # If requested, run AI analysis
        llm_analysis = ""
        if with_ai_analysis and self.selected_agent_role:
            print(f"\n[*] Running AI analysis with {self.selected_agent_role}...")
            llm_profile = self.config.get('agent_roles', {}).get(self.selected_agent_role, {}).get('llm_profile')
            self._initialize_llm_manager(llm_profile)

            if self.llm_manager_instance:
                agent_prompts = self.llm_manager_instance.prompts.get("md_prompts", {}).get(self.selected_agent_role, {})
                if agent_prompts:
                    agent = BaseAgent(self.selected_agent_role, self.config, self.llm_manager_instance, agent_prompts)

                    analysis_prompt = f"""
Analise o seguinte contexto de reconhecimento e identifique:
1. Vetores de ataque mais promissores
2. Vulnerabilidades potenciais baseadas nas tecnologias detectadas
3. Endpoints prioritarios para teste
4. Recomendacoes de proximos passos para o pentest

CONTEXTO DE RECON:
{recon_results.get('context_text', '')}
"""
                    analysis_result = agent.execute(analysis_prompt, recon_results.get('context', {}))
                    llm_analysis = analysis_result.get("llm_response", "")

        # Generate report if vulnerabilities found
        context = recon_results.get('context', {})
        vulns = context.get('vulnerabilities', {}).get('all', [])

        if vulns or llm_analysis:
            print("\n[*] Generating report...")
            from core.report_generator import ReportGenerator

            report_data = {
                "target": target,
                "scan_started": datetime.now().isoformat(),
                "scan_completed": datetime.now().isoformat(),
                "attack_surface": context.get('attack_surface', {}),
                "vulnerabilities": vulns,
                "technologies": context.get('data', {}).get('technologies', []),
                "open_ports": context.get('data', {}).get('open_ports', [])
            }

            report_gen = ReportGenerator(report_data, llm_analysis)
            html_report = report_gen.save_report("reports")
            print(f"[+] HTML Report: {html_report}")

        print(f"\n{'='*70}")
        print("[+] ADVANCED RECON COMPLETE!")
        print(f"[+] Consolidated context: {recon_results.get('context_file', '')}")
        print(f"[+] Text context: {recon_results.get('context_text_file', '')}")
        print(f"{'='*70}\n")

        return {
            "session_id": self.session_id,
            "target": target,
            "recon_results": recon_results,
            "llm_analysis": llm_analysis,
            "context_file": recon_results.get('context_file', ''),
            "context_text_file": recon_results.get('context_text_file', '')
        }

    def run_ai_agent(
        self,
        target: str,
        prompt_file: Optional[str] = None,
        context_file: Optional[str] = None,
        llm_profile: Optional[str] = None
    ) -> Dict:
        """
        Run the AI Offensive Security Agent.

        This is an autonomous agent that:
        - Uses LLM for intelligent vulnerability testing
        - Confirms vulnerabilities with AI (no false positives)
        - Uses recon data to inform testing
        - Accepts custom .md prompt files
        - Generates PoC code

        Args:
            target: Target URL to test
            prompt_file: Optional .md file with custom testing instructions
            context_file: Optional recon context JSON file
            llm_profile: Optional LLM profile to use
        """
        if not AIPentestAgent:
            print("[!] AI Agent not available. Check backend installation.")
            return {"error": "AI Agent not installed"}

        print(f"\n{'='*70}")
        print("    NEUROSPLOIT AI OFFENSIVE SECURITY AGENT")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        if prompt_file:
            print(f"[*] Prompt file: {prompt_file}")
        if context_file:
            print(f"[*] Context file: {context_file}")
        print(f"[*] Session ID: {self.session_id}")
        print()

        # Load recon context if provided
        recon_context = None
        if context_file:
            from core.context_builder import load_context_from_file
            recon_context = load_context_from_file(context_file)
            if recon_context:
                print(f"[+] Loaded recon context: {len(recon_context.get('data', {}).get('endpoints', []))} endpoints")

        # Initialize LLM manager
        profile = llm_profile or self.config.get('llm', {}).get('default_profile')
        self._initialize_llm_manager(profile)

        # Run the agent
        import asyncio

        async def run_agent():
            async def log_callback(level: str, message: str):
                prefix = {
                    "info": "[*]",
                    "warning": "[!]",
                    "error": "[X]",
                    "debug": "[D]",
                }.get(level, "[*]")
                print(f"{prefix} {message}")

            async with AIPentestAgent(
                target=target,
                llm_manager=self.llm_manager_instance,
                log_callback=log_callback,
                prompt_file=prompt_file,
                recon_context=recon_context,
                config=self.config,
                max_depth=5
            ) as agent:
                report = await agent.run()
                return report

        try:
            report = asyncio.run(run_agent())
        except Exception as e:
            logger.error(f"Agent error: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

        # Save results
        if report and report.get("findings"):
            result_file = f"results/agent_{self.session_id}.json"
            with open(result_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[+] Results saved: {result_file}")

            # Generate HTML report
            self._generate_agent_report(report)

        print(f"\n{'='*70}")
        print("[+] AI AGENT COMPLETE!")
        print(f"    Vulnerabilities found: {len(report.get('findings', []))}")
        print(f"{'='*70}\n")

        return report

    def run_autonomous_agent(
        self,
        target: str,
        mode: str = "full_auto",
        task_id: Optional[str] = None,
        prompt: Optional[str] = None,
        prompt_file: Optional[str] = None,
        context_file: Optional[str] = None,
        llm_profile: Optional[str] = None,
        enable_kali_sandbox: bool = False,
        vpn_file: Optional[str] = None,
        vpn_user: Optional[str] = None,
        vpn_pass: Optional[str] = None,
        enable_researcher: bool = False,
        enable_multi_agent: bool = False,
        scan_id: Optional[str] = None,
        custom_prompts: bool = False,
        generate_report: bool = True,
    ) -> Dict:
        """
        Run the Autonomous AI Security Agent.

        Modes:
        - recon_only: Just reconnaissance, no testing
        - full_auto: Complete workflow (Recon -> Analyze -> Test -> Report)
        - prompt_only: AI decides everything based on prompt (HIGH TOKEN USAGE!)
        - analyze_only: Analysis of provided data, no active testing

        Args:
            target: Target URL/domain
            mode: Operation mode
            task_id: Task from library to execute
            prompt: Custom prompt
            prompt_file: Path to .md prompt file
            context_file: Path to recon context JSON
            llm_profile: LLM profile to use
            enable_kali_sandbox: Use Kali Docker container
            vpn_file: Path to .ovpn file (requires enable_kali_sandbox)
            vpn_user: VPN username
            vpn_pass: VPN password
            enable_researcher: Enable AI Researcher agent
            enable_multi_agent: Enable multi-agent orchestration
            scan_id: Custom scan ID for tracking
            custom_prompts: Load custom prompts from data/custom_prompts/
            generate_report: Generate HTML report (default True)
        """
        if not AutonomousAgent:
            print("[!] Autonomous Agent not available. Check installation.")
            return {"error": "Agent not installed"}

        # Generate scan_id
        scan_id = scan_id or f"cli_{self.session_id}"

        print(f"\n{'='*70}")
        print("   NEUROSPLOIT AUTONOMOUS AI AGENT")
        print(f"{'='*70}")
        print(f"\n[*] Target: {target}")
        print(f"[*] Mode: {mode.upper()}")
        print(f"[*] Scan ID: {scan_id}")
        if enable_kali_sandbox:
            print(f"[*] Kali Sandbox: ENABLED")
        if vpn_file:
            print(f"[*] VPN: {vpn_file}")
        if enable_researcher:
            print(f"[*] AI Researcher: ENABLED")
        if enable_multi_agent:
            print(f"[*] Multi-Agent: ENABLED")

        # Warning for prompt_only mode
        if mode == "prompt_only":
            print("\n[!] WARNING: PROMPT-ONLY MODE")
            print("[!] This mode uses significantly more tokens than other modes.")
            print("[!] The AI will decide what tools to use based on your prompt.\n")

        # VPN requires Kali sandbox
        if vpn_file and not enable_kali_sandbox:
            print("[!] --vpn requires --kali flag. Enabling Kali sandbox automatically.")
            enable_kali_sandbox = True

        # Set env vars for sub-modules
        if enable_researcher:
            os.environ["ENABLE_RESEARCHER_AI"] = "true"
        if enable_multi_agent:
            os.environ["ENABLE_MULTI_AGENT"] = "true"

        # Load custom prompts from data/custom_prompts/
        loaded_custom_prompts = []
        if custom_prompts:
            prompts_dir = Path("data/custom_prompts")
            if prompts_dir.exists():
                for pf in sorted(prompts_dir.glob("*.json")):
                    try:
                        with open(pf) as f:
                            data = json.load(f)
                        if isinstance(data, list):
                            loaded_custom_prompts.extend(data)
                        elif isinstance(data, dict):
                            loaded_custom_prompts.append(data)
                        print(f"[+] Loaded custom prompt: {pf.name}")
                    except Exception as e:
                        print(f"[!] Error loading {pf.name}: {e}")
            else:
                print(f"[!] Custom prompts directory not found: {prompts_dir}")

        # Load task from library
        task = None
        if task_id and get_task_library:
            library = get_task_library()
            task = library.get_task(task_id)
            if task:
                print(f"[*] Task: {task.name}")
                prompt = task.prompt
            else:
                print(f"[!] Task not found: {task_id}")

        # Load prompt from file
        if prompt_file:
            print(f"[*] Prompt file: {prompt_file}")
            try:
                path = Path(prompt_file)
                for search in [path, Path("prompts") / path, Path("prompts/md_library") / path]:
                    if search.exists():
                        prompt = search.read_text()
                        break
            except Exception as e:
                print(f"[!] Error loading prompt file: {e}")

        # Load recon context
        recon_context = None
        if context_file:
            from core.context_builder import load_context_from_file
            recon_context = load_context_from_file(context_file)
            if recon_context:
                print(f"[+] Loaded context: {context_file}")

        # Get operation mode
        mode_map = {
            "recon_only": OperationMode.RECON_ONLY,
            "full_auto": OperationMode.FULL_AUTO,
            "prompt_only": OperationMode.PROMPT_ONLY,
            "analyze_only": OperationMode.ANALYZE_ONLY,
        }
        op_mode = mode_map.get(mode, OperationMode.FULL_AUTO)

        print(f"[*] Session: {self.session_id}\n")

        # Run agent
        import asyncio

        async def run():
            async def log_cb(level: str, message: str):
                prefix = {"info": "[*]", "warning": "[!]", "error": "[X]", "debug": "[D]"}.get(level, "[*]")
                print(f"{prefix} {message}")

            async def progress_cb(progress: int, message: str):
                filled = int(progress / 5)
                bar = "\u2588" * filled + "\u2591" * (20 - filled)
                phase = "RECON" if progress < 25 else "TEST" if progress < 50 else "DEEP" if progress < 75 else "REPORT"
                print(f"\r  [{bar}] {progress:3d}% [{phase:6s}] {message[:55]}", end="", flush=True)
                if progress == 100:
                    print()

            async def finding_cb(finding: dict):
                sev = finding.get('severity', 'info').upper()
                icons = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2", "INFO": "\U0001f535"}
                icon = icons.get(sev, "\u26aa")
                confidence = finding.get('confidence_score', 0)
                title = finding.get('title', 'Unknown')[:60]
                endpoint = finding.get('endpoint', '')[:50]
                print(f"\n  {icon} [{sev}] {title}")
                print(f"     Endpoint: {endpoint}")
                print(f"     Confidence: {confidence}/100")

            async with AutonomousAgent(
                target=target,
                mode=op_mode,
                log_callback=log_cb,
                progress_callback=progress_cb,
                finding_callback=finding_cb,
                task=task,
                custom_prompt=prompt,
                recon_context=recon_context,
                scan_id=scan_id,
                enable_kali_sandbox=enable_kali_sandbox,
                loaded_custom_prompts=loaded_custom_prompts if loaded_custom_prompts else None,
            ) as agent:
                # Connect VPN inside sandbox if requested
                if vpn_file and enable_kali_sandbox:
                    sandbox = getattr(agent, '_sandbox', None)
                    if sandbox and hasattr(sandbox, 'connect_vpn'):
                        try:
                            vpn_data = Path(vpn_file).read_bytes()
                            success, msg = await sandbox.connect_vpn(vpn_data, vpn_user, vpn_pass)
                            await log_cb("info" if success else "error", f"VPN: {msg}")
                        except Exception as e:
                            await log_cb("error", f"VPN connection failed: {e}")
                    else:
                        await log_cb("warning", "VPN requested but sandbox not available")

                return await agent.run()

        try:
            report = asyncio.run(run())
        except Exception as e:
            logger.error(f"Agent error: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

        # Save results
        result_file = f"results/autonomous_{scan_id}.json"
        with open(result_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Results saved: {result_file}")

        # Generate HTML report
        if generate_report and report.get("findings"):
            self._generate_autonomous_report(report)

        # Print summary
        findings = report.get("findings", [])
        if findings:
            print(f"\n{'='*70}")
            print(f"  FINDINGS SUMMARY ({len(findings)} total)")
            print(f"{'='*70}")
            severity_counts = {}
            for f in findings:
                s = f.get("severity", "info").upper()
                severity_counts[s] = severity_counts.get(s, 0) + 1
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = severity_counts.get(sev, 0)
                if count:
                    print(f"  {sev:10s}: {count}")
            avg_confidence = sum(f.get("confidence_score", 0) for f in findings) / len(findings)
            print(f"  {'AVG CONF':10s}: {avg_confidence:.0f}/100")
            print(f"{'='*70}\n")

        return report

    def list_tasks(self):
        """List all available tasks from library"""
        if not get_task_library:
            print("[!] Task library not available")
            return

        library = get_task_library()
        tasks = library.list_tasks()

        print(f"\n{'='*70}")
        print("   TASK LIBRARY")
        print(f"{'='*70}\n")

        # Group by category
        by_category = {}
        for task in tasks:
            cat = task.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(task)

        for category, cat_tasks in by_category.items():
            print(f"[{category.upper()}]")
            for task in cat_tasks:
                preset = " (preset)" if task.is_preset else ""
                print(f"  {task.id:<25} - {task.name}{preset}")
            print()

        print(f"Total: {len(tasks)} tasks")
        print("\nUse: run_task <task_id> <target>")

    def create_task(self, name: str, prompt: str, category: str = "custom"):
        """Create a new task in the library"""
        if not get_task_library or not Task:
            print("[!] Task library not available")
            return

        library = get_task_library()
        task = Task(
            id=f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name=name,
            description=prompt[:100],
            category=category,
            prompt=prompt,
            is_preset=False
        )
        library.create_task(task)
        print(f"[+] Task created: {task.id}")
        return task

    def _generate_autonomous_report(self, report: Dict):
        """Generate HTML report from autonomous agent results"""
        from core.report_generator import ReportGenerator

        # Convert to scan format
        scan_data = {
            "target": report.get("target", ""),
            "scan_started": report.get("scan_date", ""),
            "scan_completed": datetime.now().isoformat(),
            "vulnerabilities": [],
            "technologies": report.get("summary", {}).get("technologies", []),
        }

        for finding in report.get("findings", []):
            vuln = {
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "medium"),
                "description": finding.get("description", ""),
                "technical_details": finding.get("technical_details", ""),
                "affected_endpoint": finding.get("endpoint", ""),
                "payload": finding.get("payload", ""),
                "evidence": finding.get("evidence", ""),
                "impact": finding.get("impact", ""),
                "poc_code": finding.get("poc_code", ""),
                "exploitation_steps": finding.get("exploitation_steps", []),
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
            }

            # Add CVSS
            if finding.get("cvss"):
                cvss = finding["cvss"]
                vuln["cvss_score"] = cvss.get("score", 0)
                vuln["cvss_vector"] = cvss.get("vector", "")

            # Add CWE
            if finding.get("cwe_id"):
                vuln["cwe_id"] = finding["cwe_id"]

            # Add confidence data
            if finding.get("confidence_score") is not None:
                vuln["confidence_score"] = finding["confidence_score"]
                vuln["confidence_breakdown"] = finding.get("confidence_breakdown", {})
                vuln["proof_of_execution"] = finding.get("proof_of_execution", "")

            scan_data["vulnerabilities"].append(vuln)

        # Generate LLM analysis summary
        summary = report.get("summary", {})
        llm_analysis = f"""
## Autonomous AI Agent Assessment Report

**Target:** {report.get('target', '')}
**Mode:** {report.get('mode', 'full_auto').upper()}
**Scan Date:** {report.get('scan_date', '')}

### Executive Summary
Risk Level: **{summary.get('risk_level', 'UNKNOWN')}**

### Findings Summary
| Severity | Count |
|----------|-------|
| Critical | {summary.get('critical', 0)} |
| High | {summary.get('high', 0)} |
| Medium | {summary.get('medium', 0)} |
| Low | {summary.get('low', 0)} |
| Info | {summary.get('info', 0)} |

**Total Findings:** {summary.get('total_findings', 0)}
**Endpoints Tested:** {summary.get('endpoints_tested', 0)}

### Technologies Detected
{', '.join(summary.get('technologies', [])) or 'None detected'}

### Detailed Findings
"""
        for i, finding in enumerate(report.get("findings", []), 1):
            cvss_info = ""
            if finding.get("cvss"):
                cvss_info = f"**CVSS:** {finding['cvss'].get('score', 'N/A')} ({finding['cvss'].get('vector', '')})"

            confidence = finding.get('confidence_score', 0)
            conf_label = "Confirmed" if confidence >= 90 else "Likely" if confidence >= 60 else "Uncertain"
            proof = finding.get('proof_of_execution', '')

            llm_analysis += f"""
---
#### {i}. {finding.get('title', 'Unknown')} [{finding.get('severity', 'medium').upper()}]
{cvss_info}
**CWE:** {finding.get('cwe_id', 'N/A')}
**Endpoint:** `{finding.get('endpoint', 'N/A')}`
**Confidence:** {confidence}/100 ({conf_label})
{f'**Proof:** {proof}' if proof else ''}

**Description:**
{finding.get('description', 'No description')}

**Impact:**
{finding.get('impact', 'No impact assessment')}

**Evidence:**
```
{finding.get('evidence', 'No evidence')}
```

**Proof of Concept:**
```python
{finding.get('poc_code', '# No PoC available')}
```

**Remediation:**
{finding.get('remediation', 'No remediation provided')}

"""

        # Recommendations
        if report.get("recommendations"):
            llm_analysis += "\n### Recommendations\n"
            for rec in report["recommendations"]:
                llm_analysis += f"- {rec}\n"

        report_gen = ReportGenerator(scan_data, llm_analysis)
        html_report = report_gen.save_report("reports")
        print(f"[+] HTML Report: {html_report}")

    def _generate_agent_report(self, report: Dict):
        """Generate HTML report from AI agent results"""
        from core.report_generator import ReportGenerator

        # Convert agent report to scan format
        scan_data = {
            "target": report.get("target", ""),
            "scan_started": report.get("scan_date", ""),
            "scan_completed": datetime.now().isoformat(),
            "vulnerabilities": [],
            "technologies": report.get("summary", {}).get("technologies", []),
        }

        for finding in report.get("findings", []):
            scan_data["vulnerabilities"].append({
                "title": f"{finding['type'].upper()} - {finding['severity'].upper()}",
                "severity": finding["severity"],
                "description": finding.get("evidence", ""),
                "affected_endpoint": finding.get("endpoint", ""),
                "payload": finding.get("payload", ""),
                "poc_code": finding.get("poc_code", ""),
                "exploitation_steps": finding.get("exploitation_steps", []),
                "llm_analysis": finding.get("llm_analysis", ""),
            })

        # Generate LLM analysis summary
        llm_analysis = f"""
## AI Agent Analysis Summary

**Target:** {report.get('target', '')}
**Scan Date:** {report.get('scan_date', '')}
**LLM Enabled:** {report.get('llm_enabled', False)}

### Summary
- Total Endpoints: {report.get('summary', {}).get('total_endpoints', 0)}
- Total Parameters: {report.get('summary', {}).get('total_parameters', 0)}
- Vulnerabilities Found: {report.get('summary', {}).get('total_vulnerabilities', 0)}
  - Critical: {report.get('summary', {}).get('critical', 0)}
  - High: {report.get('summary', {}).get('high', 0)}
  - Medium: {report.get('summary', {}).get('medium', 0)}
  - Low: {report.get('summary', {}).get('low', 0)}

### Findings
"""
        for i, finding in enumerate(report.get("findings", []), 1):
            llm_analysis += f"""
#### {i}. {finding['type'].upper()} [{finding['severity'].upper()}]
- **Endpoint:** {finding.get('endpoint', '')}
- **Payload:** `{finding.get('payload', '')}`
- **Evidence:** {finding.get('evidence', '')}
- **Confidence:** {finding.get('confidence', 'medium')}
- **LLM Analysis:** {finding.get('llm_analysis', 'N/A')}
"""

        report_gen = ReportGenerator(scan_data, llm_analysis)
        html_report = report_gen.save_report("reports")
        print(f"[+] HTML Report: {html_report}")

    def check_tools_status(self):
        """Check and display status of all pentest tools"""
        print("\n" + "="*60)
        print("    PENTEST TOOLS STATUS")
        print("="*60 + "\n")

        status = self.tool_installer.get_tools_status()
        installed_count = 0
        missing_count = 0

        for tool_name, info in status.items():
            if info["installed"]:
                print(f"  [+] {tool_name:15} - INSTALLED ({info['path']})")
                installed_count += 1
            else:
                print(f"  [-] {tool_name:15} - NOT INSTALLED")
                missing_count += 1

        print("\n" + "-"*60)
        print(f"  Total: {installed_count} installed, {missing_count} missing")
        print("-"*60)

        if missing_count > 0:
            print("\n  [!] Run 'install_tools' to install missing tools")

        return status

    def update_tools_config(self):
        """Update config with found tool paths"""
        status = self.tool_installer.get_tools_status()

        for tool_name, info in status.items():
            if info["installed"] and info["path"]:
                self.config['tools'][tool_name] = info["path"]

        # Save updated config
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)

        logger.info("Tools configuration updated")

    def list_agent_roles(self):
        """List all available agent roles."""
        print("\nAvailable Agent Roles:")
        for role_name, role_details in self.config.get('agent_roles', {}).items():
            status = "Enabled" if role_details.get("enabled") else "Disabled"
            print(f"  - {role_name} ({status}): {role_details.get('description', 'No description.')}")

    def list_llm_profiles(self):
        """List all available LLM profiles."""
        print("\nAvailable LLM Profiles:")
        for profile_name in self.config.get('llm', {}).get('profiles', {}).keys():
            print(f"  - {profile_name}")
    
    def interactive_mode(self):
        """Start interactive mode"""
        
        completer = Completer(self)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")

        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║         NeuroSploitv2 - AI Offensive Security             ║
        ║                  Interactive Mode                         ║
        ╚═══════════════════════════════════════════════════════════╝
        """)
        
        while True:
            try:
                cmd = input("\nNeuroSploit> ").strip()
                
                if cmd.lower() in ['exit', 'quit']:
                    break
                elif cmd.lower() == 'help':
                    self._show_help()
                elif cmd.startswith('run_agent'):
                    parts = cmd.split(maxsplit=2) # e.g., run_agent red_team_agent "scan example.com"
                    if len(parts) >= 2:
                        if len(parts) == 2:
                            if self.selected_agent_role:
                                user_input = parts[1].strip('"')
                                self.execute_agent_role(self.selected_agent_role, user_input)
                            else:
                                print("No agent selected. Use 'set_agent <agent_name>' or 'run_agent <agent_name> \"<user_input>\"'")
                        else:
                            agent_role_name = parts[1]
                            user_input = parts[2].strip('"')
                            self.execute_agent_role(agent_role_name, user_input)
                    else:
                        print("Usage: run_agent <agent_role_name> \"<user_input>\"")

                elif cmd.startswith('config'):
                    print(json.dumps(self.config, indent=2))
                elif cmd.lower() == 'list_roles':
                    print("\nAvailable Agent Roles:")
                    for role_name, role_details in self.config.get('agent_roles', {}).items():
                        status = "Enabled" if role_details.get("enabled") else "Disabled"
                        marker = "*" if role_name == self.selected_agent_role else " "
                        print(f"  {marker} {role_name} ({status}): {role_details.get('description', 'No description.')}")
                elif cmd.lower() == 'list_profiles':
                    print("\nAvailable LLM Profiles:")
                    default_profile = self.config['llm']['default_profile']
                    for profile_name in self.config.get('llm', {}).get('profiles', {}).keys():
                        marker = "*" if profile_name == default_profile else " "
                        print(f"  {marker} {profile_name}")
                elif cmd.startswith('set_profile'):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        profile_name = parts[1].strip()
                        if profile_name in self.config.get('llm', {}).get('profiles', {}):
                            self.config['llm']['default_profile'] = profile_name
                            print(f"Default LLM profile set to: {profile_name}")
                        else:
                            print(f"Profile '{profile_name}' not found.")
                    else:
                        print("Usage: set_profile <profile_name>")
                elif cmd.startswith('set_agent'):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        agent_name = parts[1].strip()
                        if agent_name in self.config.get('agent_roles', {}):
                            self.selected_agent_role = agent_name
                            print(f"Default agent set to: {agent_name}")
                        else:
                            print(f"Agent '{agent_name}' not found.")
                    else:
                        print("Usage: set_agent <agent_name>")
                elif cmd.lower() == 'discover_ollama':
                    self.discover_ollama_models()
                elif cmd.lower() == 'install_tools':
                    run_installer_menu()
                    self.update_tools_config()
                elif cmd.lower() == 'check_tools':
                    self.check_tools_status()
                elif cmd.startswith('scan '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        target = parts[1].strip().strip('"')
                        agent_role = self.selected_agent_role or "bug_bounty_hunter"
                        self.execute_real_scan(target, scan_type="full", agent_role=agent_role)
                    else:
                        print("Usage: scan <target_url>")
                elif cmd.startswith('quick_scan '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        target = parts[1].strip().strip('"')
                        agent_role = self.selected_agent_role or "bug_bounty_hunter"
                        self.execute_real_scan(target, scan_type="quick", agent_role=agent_role)
                    else:
                        print("Usage: quick_scan <target_url>")
                elif cmd.startswith('recon ') or cmd.startswith('full_recon '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        target = parts[1].strip().strip('"')
                        with_ai = self.selected_agent_role is not None
                        self.run_full_recon(target, with_ai_analysis=with_ai)
                    else:
                        print("Usage: recon <target_domain_or_url>")
                        print("       full_recon <target_domain_or_url>")
                        print("\nThis command runs all recon tools:")
                        print("  - Subdomain enumeration (subfinder, amass, assetfinder)")
                        print("  - HTTP probing (httpx)")
                        print("  - URL collection (gau, waybackurls)")
                        print("  - Web crawling (katana, gospider)")
                        print("  - Port scanning (naabu, nmap)")
                        print("  - Vulnerability scanning (nuclei)")
                        print("\nAll outputs are consolidated into a single context file")
                        print("for use by the LLM.")
                elif cmd.lower() in ['experience', 'wizard']:
                    self.experience_mode()
                elif cmd.startswith('analyze '):
                    parts = cmd.split(maxsplit=1)
                    if len(parts) > 1:
                        context_file = parts[1].strip().strip('"')
                        if os.path.exists(context_file):
                            from core.context_builder import load_context_from_file
                            context = load_context_from_file(context_file)
                            if context:
                                prompt = input("Enter analysis prompt: ").strip()
                                if prompt:
                                    agent_role = self.selected_agent_role or "bug_bounty_hunter"
                                    self.execute_agent_role(agent_role, prompt, recon_context=context)
                        else:
                            print(f"Context file not found: {context_file}")
                    else:
                        print("Usage: analyze <context_file.json>")
                        print("       Then enter your analysis prompt")
                elif cmd.startswith('agent ') or cmd.startswith('ai_agent '):
                    # AI Agent command
                    # Format: agent <target> [--prompt <file.md>] [--context <context.json>]
                    parts = cmd.split()
                    if len(parts) >= 2:
                        target = parts[1].strip().strip('"')
                        prompt_file = None
                        context_file = None

                        # Parse optional arguments
                        i = 2
                        while i < len(parts):
                            if parts[i] in ['--prompt', '-p'] and i + 1 < len(parts):
                                prompt_file = parts[i + 1].strip().strip('"')
                                i += 2
                            elif parts[i] in ['--context', '-c'] and i + 1 < len(parts):
                                context_file = parts[i + 1].strip().strip('"')
                                i += 2
                            else:
                                i += 1

                        # Get LLM profile
                        llm_profile = self.config.get('llm', {}).get('default_profile')
                        self.run_ai_agent(target, prompt_file, context_file, llm_profile)
                    else:
                        print("Usage: agent <target_url> [--prompt <file.md>] [--context <context.json>]")
                        print("")
                        print("Examples:")
                        print("  agent https://example.com")
                        print("  agent https://example.com --prompt bug_bounty.md")
                        print("  agent https://example.com --context results/context_X.json")
                        print("")
                        print("The AI Agent will:")
                        print("  1. Use LLM for intelligent vulnerability testing")
                        print("  2. Confirm findings with AI (no false positives)")
                        print("  3. Generate PoC code for exploits")
                        print("  4. Use recon data if context file provided")

                # === NEW AUTONOMOUS AGENT MODES ===
                elif cmd.startswith('pentest ') or cmd.startswith('full_auto '):
                    # Full autonomous pentest mode
                    parts = cmd.split()
                    if len(parts) >= 2:
                        target = parts[1].strip().strip('"')
                        task_id = None
                        prompt_file = None
                        context_file = None
                        enable_kali = False
                        vpn_file = None
                        vpn_user = None
                        vpn_pass = None
                        enable_researcher = False
                        enable_multi_agent = False

                        i = 2
                        while i < len(parts):
                            if parts[i] in ['--task', '-t'] and i + 1 < len(parts):
                                task_id = parts[i + 1].strip()
                                i += 2
                            elif parts[i] in ['--prompt', '-p'] and i + 1 < len(parts):
                                prompt_file = parts[i + 1].strip().strip('"')
                                i += 2
                            elif parts[i] in ['--context', '-c'] and i + 1 < len(parts):
                                context_file = parts[i + 1].strip().strip('"')
                                i += 2
                            elif parts[i] == '--kali':
                                enable_kali = True
                                i += 1
                            elif parts[i] == '--vpn' and i + 1 < len(parts):
                                vpn_file = parts[i + 1].strip().strip('"')
                                i += 2
                            elif parts[i] == '--vpn-user' and i + 1 < len(parts):
                                vpn_user = parts[i + 1].strip()
                                i += 2
                            elif parts[i] == '--vpn-pass' and i + 1 < len(parts):
                                vpn_pass = parts[i + 1].strip()
                                i += 2
                            elif parts[i] == '--researcher':
                                enable_researcher = True
                                i += 1
                            elif parts[i] == '--multi-agent':
                                enable_multi_agent = True
                                i += 1
                            else:
                                i += 1

                        self.run_autonomous_agent(
                            target, "full_auto", task_id, None, prompt_file, context_file,
                            enable_kali_sandbox=enable_kali, vpn_file=vpn_file,
                            vpn_user=vpn_user, vpn_pass=vpn_pass,
                            enable_researcher=enable_researcher,
                            enable_multi_agent=enable_multi_agent,
                        )
                    else:
                        print("Usage: pentest <target> [options]")
                        print("")
                        print("Options:")
                        print("  --task <id>          Use preset task from library")
                        print("  --prompt <file.md>   Custom prompt file")
                        print("  --context <file.json> Recon context file")
                        print("  --kali               Enable Kali sandbox")
                        print("  --vpn <file.ovpn>    VPN config (requires --kali)")
                        print("  --vpn-user <user>    VPN username")
                        print("  --vpn-pass <pass>    VPN password")
                        print("  --researcher         Enable AI Researcher")
                        print("  --multi-agent        Enable multi-agent mode")

                elif cmd.startswith('recon_only '):
                    # Recon-only mode
                    parts = cmd.split()
                    if len(parts) >= 2:
                        target = parts[1].strip().strip('"')
                        enable_kali = '--kali' in parts
                        self.run_autonomous_agent(target, "recon_only", enable_kali_sandbox=enable_kali)
                    else:
                        print("Usage: recon_only <target> [--kali]")
                        print("Just reconnaissance, no vulnerability testing")

                elif cmd.startswith('prompt_only '):
                    # Prompt-only mode (high token usage)
                    parts = cmd.split()
                    if len(parts) >= 2:
                        target = parts[1].strip().strip('"')
                        prompt = None
                        prompt_file = None
                        enable_kali = '--kali' in parts
                        enable_researcher = '--researcher' in parts

                        i = 2
                        while i < len(parts):
                            if parts[i] in ['--prompt', '-p'] and i + 1 < len(parts):
                                prompt_file = parts[i + 1].strip().strip('"')
                                i += 2
                            elif parts[i] in ['--kali', '--researcher']:
                                i += 1
                            else:
                                i += 1

                        if not prompt_file:
                            print("Enter your prompt (end with empty line):")
                            lines = []
                            while True:
                                line = input()
                                if not line:
                                    break
                                lines.append(line)
                            prompt = "\n".join(lines)

                        print("\n[!] WARNING: PROMPT-ONLY MODE uses more tokens!")
                        self.run_autonomous_agent(
                            target, "prompt_only", None, prompt, prompt_file,
                            enable_kali_sandbox=enable_kali, enable_researcher=enable_researcher,
                        )
                    else:
                        print("Usage: prompt_only <target> [--prompt <file.md>]")
                        print("")
                        print("WARNING: This mode uses significantly more tokens!")
                        print("The AI will decide what tools to use based on your prompt.")

                elif cmd.startswith('analyze_only '):
                    # Analyze-only mode
                    parts = cmd.split()
                    if len(parts) >= 2:
                        target = parts[1].strip().strip('"')
                        context_file = None

                        i = 2
                        while i < len(parts):
                            if parts[i] in ['--context', '-c'] and i + 1 < len(parts):
                                context_file = parts[i + 1].strip().strip('"')
                                i += 2
                            else:
                                i += 1

                        self.run_autonomous_agent(
                            target, "analyze_only", None, None, None, context_file,
                            custom_prompts='--custom-prompts' in parts,
                        )
                    else:
                        print("Usage: analyze_only <target> [--context <file.json>] [--custom-prompts]")
                        print("Analysis only, no active testing")

                # === TASK LIBRARY COMMANDS ===
                elif cmd in ['tasks', 'list_tasks']:
                    self.list_tasks()

                elif cmd.startswith('run_task '):
                    parts = cmd.split()
                    if len(parts) >= 3:
                        task_id = parts[1].strip()
                        target = parts[2].strip().strip('"')
                        context_file = None

                        i = 3
                        while i < len(parts):
                            if parts[i] in ['--context', '-c'] and i + 1 < len(parts):
                                context_file = parts[i + 1].strip().strip('"')
                                i += 2
                            else:
                                i += 1

                        self.run_autonomous_agent(target, "full_auto", task_id, None, None, context_file)
                    else:
                        print("Usage: run_task <task_id> <target> [--context <file.json>]")
                        print("Use 'tasks' to list available tasks")

                elif cmd.startswith('create_task'):
                    print("Create a new task for the library")
                    name = input("Task name: ").strip()
                    if not name:
                        print("Cancelled")
                        continue
                    print("Enter task prompt (end with empty line):")
                    lines = []
                    while True:
                        line = input()
                        if not line:
                            break
                        lines.append(line)
                    prompt = "\n".join(lines)
                    if prompt:
                        self.create_task(name, prompt)
                    else:
                        print("Cancelled - no prompt provided")

                else:
                    print("Unknown command. Type 'help' for available commands.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                continue
            except Exception as e:
                logger.error(f"Error: {e}")

    def discover_ollama_models(self):
        """Discover local Ollama models and add them to the configuration."""
        try:
            import requests
        except ImportError:
            print("The 'requests' library is not installed. Please install it with 'pip3 install requests'")
            return

        try:
            response = requests.get("http://localhost:11434/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
            print("Ollama server not found. Please make sure Ollama is running.")
            return

        if not models:
            print("No Ollama models found.")
            return

        print("Available Ollama models:")
        for i, model in enumerate(models):
            print(f"  {i+1}. {model['name']}")

        try:
            selections = input("Enter the numbers of the models to add (e.g., 1,3,4): ")
            selected_indices = [int(s.strip()) - 1 for s in selections.split(',')]
        except ValueError:
            print("Invalid input. Please enter a comma-separated list of numbers.")
            return

        for i in selected_indices:
            if 0 <= i < len(models):
                model_name = models[i]['name']
                profile_name = f"ollama_{model_name.replace(':', '_').replace('-', '_')}"
                self.config['llm']['profiles'][profile_name] = {
                    "provider": "ollama",
                    "model": model_name,
                    "api_key": "",
                    "temperature": 0.7,
                    "max_tokens": 4096,
                    "input_token_limit": 8000,
                    "output_token_limit": 4000,
                    "cache_enabled": True,
                    "search_context_level": "medium",
                    "pdf_support_enabled": False,
                    "guardrails_enabled": True,
                    "hallucination_mitigation_strategy": None
                }
                print(f"Added profile '{profile_name}' for model '{model_name}'.")

        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)
        print("Configuration updated.")
    
    def _show_help(self):
        """Show help menu"""
        print("""
=======================================================================
                    NeuroSploitv2 - Command Reference
=======================================================================

MODES:
  experience / wizard      - GUIDED step-by-step setup (recommended!)
  analyze <context.json>   - LLM-only analysis with context file

RECON COMMANDS (Data Collection):
  recon <target>           - Run FULL RECON and consolidate outputs
  full_recon <target>      - Alias for recon

  The recon command runs ALL reconnaissance tools:
    - Subdomain enumeration (subfinder, amass, assetfinder)
    - HTTP probing (httpx, httprobe)
    - URL collection (gau, waybackurls, waymore)
    - Web crawling (katana, gospider)
    - Port scanning (naabu, nmap)
    - DNS enumeration
    - Vulnerability scanning (nuclei)

  All outputs are CONSOLIDATED into a single context file
  for use by the LLM!

SCANNING COMMANDS (Execute Real Tools):
  scan <target>            - Run FULL pentest scan with real tools
  quick_scan <target>      - Run QUICK scan (essential checks only)

TOOL MANAGEMENT:
  install_tools            - Install required pentest tools
  check_tools              - Check which tools are installed

AUTONOMOUS AI AGENT (Like PentAGI):
  pentest <url>              - Full auto: Recon -> Analyze -> Test -> Report
  pentest <url> --task <id>  - Use preset task from library
  pentest <url> --kali       - Use Kali Docker sandbox
  pentest <url> --kali --vpn <file.ovpn> --vpn-user <u> --vpn-pass <p>
                             - Full pentest through VPN
  pentest <url> --researcher - Enable AI Researcher (0-day hunting)
  pentest <url> --multi-agent - Enable multi-agent orchestration
  recon_only <url> [--kali]  - Just reconnaissance, no testing
  prompt_only <url>          - AI decides everything (HIGH TOKEN USAGE!)
  analyze_only <url> -c <f>  - Analysis only, no active testing

  Agent flags (combine with any mode above):
    --kali               Enable Kali sandbox (Docker per scan)
    --vpn <file.ovpn>    VPN config (requires --kali)
    --vpn-user <user>    VPN username
    --vpn-pass <pass>    VPN password
    --researcher         AI Researcher (hypothesis-driven 0-day)
    --multi-agent        Multi-agent orchestration (5 specialists)

  The autonomous agent generates:
    - CVSS scores with vector strings
    - Confidence scores (0-100) with proof of execution
    - Detailed descriptions and impact analysis
    - Working PoC code
    - Remediation recommendations
    - Professional HTML reports

TASK LIBRARY:
  tasks / list_tasks         - List all available tasks
  run_task <id> <url>        - Run a task from the library
  create_task                - Create and save a new task

  Preset tasks include: full_bug_bounty, vuln_owasp_top10,
                       vuln_api_security, recon_full, etc.

LEGACY AGENT:
  agent <url>                - Simple AI agent (basic testing)
  run_agent <role> "<input>" - Execute an agent role
  set_agent <agent_name>     - Set default agent

CONFIGURATION:
  list_roles               - List all available agent roles
  list_profiles            - List all LLM profiles
  set_profile <name>       - Set the default LLM profile
  discover_ollama          - Discover and configure local Ollama models
  config                   - Show current configuration

GENERAL:
  help                     - Show this help menu
  exit/quit                - Exit the framework

RECOMMENDED WORKFLOW:
  1. recon example.com              - First run full recon
  2. analyze results/context_X.json - LLM-only analysis with context
     OR
  1. experience                     - Use guided wizard mode

EXAMPLES:
  experience                         - Start guided wizard
  recon example.com                  - Full recon with consolidated output
  analyze results/context_X.json     - LLM analysis of context file
  scan https://example.com           - Full pentest scan
  quick_scan 192.168.1.1             - Quick vulnerability check
  pentest https://target.com --kali  - Full pentest in Kali sandbox
  pentest https://target.com --kali --vpn client.ovpn --vpn-user admin --vpn-pass s3cret
                                     - Full pentest through VPN
  pentest https://target.com --researcher --kali
                                     - AI Researcher with Kali sandbox
  agent https://target.com           - AI Agent pentest (uses LLM)
  agent https://target.com -p bug_bounty.md -c context.json
=======================================================================
        """)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NeuroSploitv2 - AI-Powered Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
3 EXECUTION MODES:
==================

1. CLI MODE (Direct command-line):
   python neurosploit.py --input "Your prompt" -cf context.json --llm-profile PROFILE

2. INTERACTIVE MODE (-i):
   python neurosploit.py -i
   Then use commands: recon, analyze, scan, etc.

3. EXPERIENCE/WIZARD MODE (-e):
   python neurosploit.py -e
   Guided step-by-step configuration - RECOMMENDED for beginners!

EXAMPLES:
=========
  # Step 1: Run recon to collect data
  python neurosploit.py --recon example.com

  # Step 2: LLM-only analysis (no tool execution)
  python neurosploit.py --input "Analyze for SQLi and XSS" -cf results/context_X.json --llm-profile claude_opus

  # Or use wizard mode
  python neurosploit.py -e

  # Run full pentest scan with tools
  python neurosploit.py --scan https://example.com

  # Interactive mode
  python neurosploit.py -i
        """
    )

    # Recon options
    parser.add_argument('--recon', metavar='TARGET',
                       help='Run FULL RECON on target (subdomain enum, http probe, url collection, etc.)')

    # Context file option
    parser.add_argument('--context-file', '-cf', metavar='FILE',
                       help='Load recon context from JSON file (use with --scan or run_agent)')

    # Target option (for use with context or agent without running recon)
    parser.add_argument('--target', '-t', metavar='TARGET',
                       help='Specify target URL/domain (use with -cf or --input)')

    # Scanning options
    parser.add_argument('--scan', metavar='TARGET',
                       help='Run FULL pentest scan on target (executes real tools)')
    parser.add_argument('--quick-scan', metavar='TARGET',
                       help='Run QUICK pentest scan on target')

    # Autonomous AI Agent options
    parser.add_argument('--pentest', metavar='TARGET',
                       help='Run full autonomous pentest: Recon -> Analyze -> Test -> Report')
    parser.add_argument('--recon-only', metavar='TARGET',
                       help='Run reconnaissance only, no vulnerability testing')
    parser.add_argument('--prompt-only', metavar='TARGET',
                       help='AI decides everything based on prompt (WARNING: High token usage!)')
    parser.add_argument('--analyze-only', metavar='TARGET',
                       help='Analysis only mode, no active testing')
    parser.add_argument('--task', metavar='TASK_ID',
                       help='Task ID from library to execute')
    parser.add_argument('--prompt-file', '-pf', metavar='FILE',
                       help='Custom .md prompt file for AI agent')
    parser.add_argument('--list-tasks', action='store_true',
                       help='List all available tasks from library')

    # Kali Sandbox + VPN options
    parser.add_argument('--kali', action='store_true',
                       help='Enable Kali sandbox (Docker container per scan)')
    parser.add_argument('--vpn', metavar='FILE',
                       help='Path to .ovpn file for VPN inside Kali sandbox (requires --kali)')
    parser.add_argument('--vpn-user', metavar='USER',
                       help='VPN username (used with --vpn)')
    parser.add_argument('--vpn-pass', metavar='PASS',
                       help='VPN password (used with --vpn)')

    # Advanced agent options
    parser.add_argument('--researcher', action='store_true',
                       help='Enable AI Researcher (hypothesis-driven 0-day hunting)')
    parser.add_argument('--multi-agent', action='store_true',
                       help='Enable multi-agent orchestration (5 specialist agents)')
    parser.add_argument('--scan-id', metavar='ID',
                       help='Custom scan ID (for tracking)')
    parser.add_argument('--custom-prompts', action='store_true',
                       help='Load custom prompts from data/custom_prompts/')
    parser.add_argument('--no-report', action='store_true',
                       help='Skip HTML report generation')

    # Legacy AI Agent options
    parser.add_argument('--agent', metavar='TARGET',
                       help='Run simple AI Agent on target')

    # Tool management
    parser.add_argument('--install-tools', action='store_true',
                       help='Install required pentest tools (nmap, sqlmap, nuclei, etc.)')
    parser.add_argument('--check-tools', action='store_true',
                       help='Check status of installed tools')

    # Agent options
    parser.add_argument('-r', '--agent-role',
                       help='Name of the agent role to execute (optional)')
    parser.add_argument('-i', '--interactive', action='store_true',
                       help='Start in interactive mode')
    parser.add_argument('-e', '--experience', action='store_true',
                       help='Start in experience/wizard mode (guided setup)')
    parser.add_argument('--input', help='Input prompt/task for the agent role')
    parser.add_argument('--llm-profile', help='LLM profile to use for the execution')

    # Configuration
    parser.add_argument('-c', '--config', default='config/config.json',
                       help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--list-agents', action='store_true',
                       help='List all available agent roles and exit')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List all available LLM profiles and exit')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize framework
    framework = NeuroSploitv2(config_path=args.config)

    # Handle tool installation
    if args.install_tools:
        run_installer_menu()
        framework.update_tools_config()

    # Handle tool check
    elif args.check_tools:
        framework.check_tools_status()

    # Handle recon
    elif args.recon:
        framework.run_full_recon(args.recon, with_ai_analysis=bool(args.agent_role))

    # Handle full scan
    elif args.scan:
        agent_role = args.agent_role or "bug_bounty_hunter"
        context = None
        if args.context_file:
            from core.context_builder import load_context_from_file
            context = load_context_from_file(args.context_file)
            if context:
                print(f"[+] Loaded context from: {args.context_file}")
        framework.execute_real_scan(args.scan, scan_type="full", agent_role=agent_role, recon_context=context)

    # Handle quick scan
    elif args.quick_scan:
        agent_role = args.agent_role or "bug_bounty_hunter"
        context = None
        if args.context_file:
            from core.context_builder import load_context_from_file
            context = load_context_from_file(args.context_file)
            if context:
                print(f"[+] Loaded context from: {args.context_file}")
        framework.execute_real_scan(args.quick_scan, scan_type="quick", agent_role=agent_role, recon_context=context)

    # Handle Autonomous Pentest (Full Auto)
    elif args.pentest:
        framework.run_autonomous_agent(
            target=args.pentest,
            mode="full_auto",
            task_id=args.task,
            prompt_file=args.prompt_file,
            context_file=args.context_file,
            llm_profile=args.llm_profile,
            enable_kali_sandbox=args.kali,
            vpn_file=args.vpn,
            vpn_user=args.vpn_user,
            vpn_pass=args.vpn_pass,
            enable_researcher=args.researcher,
            enable_multi_agent=args.multi_agent,
            scan_id=args.scan_id,
            custom_prompts=args.custom_prompts,
            generate_report=not args.no_report,
        )

    # Handle Recon Only
    elif args.recon_only:
        framework.run_autonomous_agent(
            target=args.recon_only,
            mode="recon_only",
            llm_profile=args.llm_profile,
            enable_kali_sandbox=args.kali,
            vpn_file=args.vpn,
            vpn_user=args.vpn_user,
            vpn_pass=args.vpn_pass,
            scan_id=args.scan_id,
            generate_report=not args.no_report,
        )

    # Handle Prompt Only (High Token Usage Warning)
    elif args.prompt_only:
        print("\n" + "!"*70)
        print("  WARNING: PROMPT-ONLY MODE")
        print("  This mode uses significantly more tokens than other modes.")
        print("  The AI will decide what tools to use based on your prompt.")
        print("!"*70 + "\n")
        framework.run_autonomous_agent(
            target=args.prompt_only,
            mode="prompt_only",
            prompt_file=args.prompt_file,
            context_file=args.context_file,
            llm_profile=args.llm_profile,
            enable_kali_sandbox=args.kali,
            vpn_file=args.vpn,
            vpn_user=args.vpn_user,
            vpn_pass=args.vpn_pass,
            enable_researcher=args.researcher,
            enable_multi_agent=args.multi_agent,
            scan_id=args.scan_id,
            custom_prompts=args.custom_prompts,
            generate_report=not args.no_report,
        )

    # Handle Analyze Only
    elif args.analyze_only:
        framework.run_autonomous_agent(
            target=args.analyze_only,
            mode="analyze_only",
            context_file=args.context_file,
            llm_profile=args.llm_profile,
            scan_id=args.scan_id,
            custom_prompts=args.custom_prompts,
            generate_report=not args.no_report,
        )

    # Handle List Tasks
    elif args.list_tasks:
        framework.list_tasks()

    # Handle Legacy AI Agent
    elif args.agent:
        framework.run_ai_agent(
            target=args.agent,
            prompt_file=args.prompt_file,
            context_file=args.context_file,
            llm_profile=args.llm_profile
        )

    # Handle list commands
    elif args.list_agents:
        framework.list_agent_roles()
    elif args.list_profiles:
        framework.list_llm_profiles()

    # Handle experience/wizard mode
    elif args.experience:
        framework.experience_mode()

    # Handle interactive mode
    elif args.interactive:
        framework.interactive_mode()

    # Handle agent execution with optional context
    elif args.agent_role and args.input:
        context = None
        if args.context_file:
            from core.context_builder import load_context_from_file
            context = load_context_from_file(args.context_file)
            if context:
                print(f"[+] Loaded context from: {args.context_file}")

        framework.execute_agent_role(
            args.agent_role,
            args.input,
            llm_profile_override=args.llm_profile,
            recon_context=context
        )

    # Handle input-only mode with context file (no role specified)
    # Use default agent or just LLM interaction
    elif args.input and args.context_file:
        from core.context_builder import load_context_from_file
        context = load_context_from_file(args.context_file)
        if context:
            print(f"[+] Loaded context from: {args.context_file}")

            # Use default agent role or bug_bounty_hunter
            agent_role = args.agent_role or "bug_bounty_hunter"
            framework.execute_agent_role(
                agent_role,
                args.input,
                llm_profile_override=args.llm_profile,
                recon_context=context
            )
        else:
            print("[!] Failed to load context file")

    # Handle target with context file (AI pentest without recon)
    elif args.target and args.context_file:
        from core.context_builder import load_context_from_file
        context = load_context_from_file(args.context_file)
        if context:
            print(f"[+] Loaded context from: {args.context_file}")

            agent_role = args.agent_role or "bug_bounty_hunter"
            input_prompt = args.input or f"Perform security assessment on {args.target}"

            framework.execute_agent_role(
                agent_role,
                input_prompt,
                llm_profile_override=args.llm_profile,
                recon_context=context
            )
        else:
            print("[!] Failed to load context file")

    else:
        parser.print_help()
        print("\n" + "="*70)
        print("QUICK START:")
        print("  1. Install tools:  python neurosploit.py --install-tools")
        print("  2. Run scan:       python neurosploit.py --scan https://target.com")
        print("  3. Interactive:    python neurosploit.py -i")
        print("="*70)



if __name__ == "__main__":
    main()

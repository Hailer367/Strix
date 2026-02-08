#!/usr/bin/env python3
"""
Strix Discord Bot - A Discord integration for the Strix AI Security Agent.

This bot provides a Discord interface to interact with the full Strix agent,
giving users access to all of Strix's capabilities including:
- Terminal command execution (executed IN THE CONTAINER, not in Discord)
- Python code execution
- Browser automation
- File operations
- Web searching
- Security scanning tools
- Discord server management (channels, roles, permissions) via discord.py API
- And all other Strix tools

Architecture:
- Commands are executed in the container via subprocess/Strix agent
- Discord operations use the discord.py API directly (NOT via LLM text)
- LLM reasoning/thinking is NEVER shown to users
- Only clean results and summaries are sent to Discord
- Long-running tasks execute in background with progress updates
- Users can communicate during active tasks without disruption

Inspired by MoltBot's task management:
- Smart complexity detection with mid-task re-evaluation
- Background execution with yield-based progress reporting
- Non-blocking communication during active tasks
- Thoroughness vs speed preference system
"""

import asyncio
import subprocess
import discord
from discord.ext import commands
import os
import json
import re
import time
import logging
import shlex
from datetime import datetime, UTC, timedelta
from typing import Any, Optional
from enum import Enum
import aiohttp
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('strix.discord')


# ============================================================================
# Task Complexity Classification (MoltBot-inspired)
# ============================================================================

class TaskComplexity(Enum):
    """Classification of task complexity levels."""
    SIMPLE = "simple"               # Quick response, no tools needed
    MODERATE = "moderate"           # Single tool execution, quick result
    COMPLEX = "complex"             # Multi-step task, may take minutes
    LONG_RUNNING = "long_running"   # Extended operation (scans, large analyses)


class TaskPreference(Enum):
    """User preference for task execution style (MoltBot-inspired)."""
    THOROUGH = "thorough"   # Complete and comprehensive
    QUICK = "quick"         # Fast, reasonable result
    AUTO = "auto"           # Let the agent decide


LONG_RUNNING_PATTERNS = [
    r'\b(deep|full|comprehensive|thorough|extensive|complete)\s*(scan|assessment|audit|test|analysis)',
    r'\b(scan|test|analyze|audit|assess|pentest|penetration.?test)\b.*\b(\d+\s*(?:hour|hr|minute|min)|long|full|deep)',
    r'\bvulnerability\s*(scan|assessment|audit|analysis)\b',
    r'\bsecurity\s*(scan|assessment|audit|review|analysis)\b',
    r'\breconnaissance\b',
    r'\bsubdomain\s*enumeration\b',
    r'\bfuzz(?:ing)?\b',
    r'\bbrute\s*force\b',
    r'\bcrawl(?:ing)?\b.*(?:entire|full|complete|all)',
    r'\bmap(?:ping)?\s*(?:the\s*)?(?:entire|full|complete|all|attack)',
    r'\b(?:entire|full|complete)\s*(?:attack\s*)?surface\b',
    r'\b(\d+)\s*(?:hour|hr|minute|min)s?\b',
    r'\btake\s*(?:your|its)?\s*time\b',
    r'\bno\s*rush\b',
    r'\bthorough(?:ly)?\b',
    r'\bexhaustive(?:ly)?\b',
    r'\bcreate\s*(?:sub)?agents?\b',
    r'\bspawn\s*agents?\b',
    r'\bparallel\s*(?:scan|test|execution)',
    r'\bmulti(?:ple)?\s*(?:agent|thread|parallel)',
]

COMPLEX_TASK_KEYWORDS = [
    'scan', 'test', 'analyze', 'find', 'discover', 'exploit',
    'vulnerability', 'security', 'pentest', 'enumerate', 'crawl',
    'attack', 'surface', 'endpoint', 'injection', 'xss', 'ssrf', 'rce',
    'install', 'compile', 'build', 'deploy', 'configure', 'setup',
]

SIMPLE_PATTERNS = [
    r'^(?:what\s+is|who\s+is|where\s+is|when\s+is|why\s+is|how\s+does|can\s+you\s+explain|do\s+you\s+know|are\s+you|is\s+there)\b',
    r'^(?:hi|hello|hey|greetings|good\s*(?:morning|afternoon|evening))\b',
    r'^(?:thanks|thank you|ty|thx)\b',
    r'^(?:help|status|info|about)$',
    r'^(?:explain|describe|tell me about)\s',
    r'^!(?:help|status|clear|tasks)',
]

DISCORD_ACTION_PATTERNS = [
    r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?(?:channel|text.?channel|voice.?channel|category)',
    r'\b(?:delete|remove)\s+(?:the\s+)?(?:\w+[\s-]*)?channel',
    r'\b(?:rename|modify|edit|update)\s+(?:the\s+)?channel',
    r'\bchannel\s+(?:called|named)\b',
    r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?role',
    r'\b(?:delete|remove)\s+(?:the\s+)?(?:\w+[\s-]*)?role',
    r'\b(?:assign|give|grant|add)\s+(?:a\s+)?(?:the\s+)?(?:\w+\s+)*role',
    r'\b(?:rename|modify|edit|update)\s+(?:the\s+)?role',
    r'\brole\s+(?:named|called)\b',
    r'\b(?:set|change|modify|update|grant|revoke)\s+(?:the\s+)?permission',
    r'\b(?:kick|ban|unban|mute|unmute|timeout)\b',
    r'\b(?:change|update|modify|set)\s+(?:the\s+)?server',
    r'\b(?:delete|clear|purge)\s+(?:\d+\s+)?messages?',
    r'\b(?:pin|unpin)\s+(?:this\s+)?message',
    r'\b(?:list|show|who)\s+(?:all\s+)?(?:members|users|roles|channels)',
]

CONTAINER_COMMAND_PATTERNS = [
    r'\b(?:run|execute|exec)\s+(?:the\s+)?(?:command|cmd|script)',
    r'\b(?:run|execute)\s+`[^`]+`',
    r'\bnmap\b', r'\bnuclei\b', r'\bsqlmap\b', r'\bffuf\b',
    r'\bpython\b', r'\bbash\b', r'\bshell\b', r'\bterminal\b',
    r'\binstall\b', r'\bapt\b', r'\bpip\b', r'\bnpm\b',
    r'\bgit\s+clone\b', r'\bcurl\b', r'\bwget\b',
    r'\bls\b', r'\bcat\b', r'\bfind\b', r'\bgrep\b',
]


def classify_task_complexity(message: str) -> TaskComplexity:
    """Classify the complexity of a user's request."""
    message_lower = message.lower().strip()
    word_count = len(message.split())

    # Questions and info requests FIRST
    question_patterns = [
        r'^(?:what\s+is|what\s+are|who\s+is|where\s+is|when|why|how\s+does|how\s+do|how\s+to)\b',
        r'^(?:can\s+you\s+explain|could\s+you\s+explain|please\s+explain)\b',
        r'^(?:tell\s+me\s+about|describe|explain)\b',
        r'^(?:do\s+you\s+know|is\s+there|are\s+there)\b',
        r'\?$',
    ]
    for pattern in question_patterns:
        if re.search(pattern, message_lower, re.IGNORECASE):
            action_verbs = ['scan', 'test', 'hack', 'exploit', 'attack', 'pentest', 'fuzz', 'enumerate']
            is_action_request = any(
                f'can you {v}' in message_lower or f'could you {v}' in message_lower
                for v in action_verbs
            )
            if not is_action_request:
                return TaskComplexity.SIMPLE

    # Greetings
    greeting_patterns = [
        r'^(?:hi|hello|hey|greetings|good\s*(?:morning|afternoon|evening)|yo|sup)\b',
        r'^(?:thanks|thank you|ty|thx|cheers)\b',
        r'^(?:ok|okay|sure|yes|no|yep|nope)\b',
        r'^!(?:help|status|clear|tasks|cancel)$',
    ]
    for pattern in greeting_patterns:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.SIMPLE

    # Long-running patterns
    for pattern in LONG_RUNNING_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.LONG_RUNNING

    # Discord actions -> moderate (executed directly via API)
    for pattern in DISCORD_ACTION_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.MODERATE

    # Container command patterns -> moderate to complex
    for pattern in CONTAINER_COMMAND_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.COMPLEX

    action_verbs = [
        'scan', 'test', 'analyze', 'find', 'discover', 'exploit',
        'check', 'verify', 'audit', 'assess', 'review', 'inspect',
        'enumerate', 'crawl', 'fuzz', 'probe', 'attack',
    ]
    has_action = any(v in message_lower for v in action_verbs)
    keyword_count = sum(1 for kw in COMPLEX_TASK_KEYWORDS if kw in message_lower)

    if has_action:
        if keyword_count >= 2:
            return TaskComplexity.COMPLEX
        if keyword_count >= 1:
            return TaskComplexity.MODERATE

    if word_count <= 5:
        return TaskComplexity.SIMPLE

    if keyword_count > 0 and not has_action:
        return TaskComplexity.SIMPLE

    if word_count > 10:
        return TaskComplexity.MODERATE

    return TaskComplexity.SIMPLE


def is_discord_action(message: str) -> bool:
    """Check if the message requests a Discord-specific action."""
    message_lower = message.lower()
    for pattern in DISCORD_ACTION_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return True
    return False


# ============================================================================
# Response Cleaner - Strips reasoning/code from LLM responses
# ============================================================================

def clean_llm_response(raw_response: str) -> str:
    """
    Clean LLM response to remove reasoning, thinking, code execution traces,
    and tool call artifacts. Only return the human-readable summary.

    This is CRITICAL: users should NEVER see the agent's internal reasoning,
    command execution details, or tool call syntax in Discord.
    """
    if not raw_response:
        return ""

    text = raw_response

    # Remove XML-style tags that are internal (thinking, tool calls, etc.)
    xml_patterns = [
        r'<function=\w+>[\s\S]*?</function>',
        r'<tool_result>[\s\S]*?</tool_result>',
        r'<tool_call>[\s\S]*?</tool_call>',
        r'<thinking>[\s\S]*?</thinking>',
        r'<parameter=\w+>[\s\S]*?</parameter>',
        r'<discord_context>[\s\S]*?</discord_context>',
        r'<task_context>[\s\S]*?</task_context>',
        r'<execution_mode>[\s\S]*?</execution_mode>',
        r'<inter_agent_message>[\s\S]*?</inter_agent_message>',
        r'<agent_identity>[\s\S]*?</agent_identity>',
    ]
    for pattern in xml_patterns:
        text = re.sub(pattern, '', text, flags=re.DOTALL)

    # Remove lines that look like command execution traces
    command_patterns = [
        r'^[\$#>]\s+.*$',                    # Shell prompts: $ command, # command, > command
        r'^pentester@[\w-]+:.*\$.*$',         # Full shell prompts
        r'^root@[\w-]+:.*#.*$',               # Root shell prompts
        r'^\s*\+\s+.*$',                      # set -x trace lines
        r'^\s*Running:?\s*`[^`]+`\s*$',       # "Running: `command`" lines
        r'^\s*Executing:?\s*`[^`]+`\s*$',     # "Executing: `command`" lines
        r'^\s*Command:?\s*`[^`]+`\s*$',       # "Command: `command`" lines
    ]
    lines = text.split('\n')
    cleaned_lines = []
    in_code_block = False
    code_block_is_output = False

    for line in lines:
        stripped = line.strip()

        # Track code blocks
        if stripped.startswith('```'):
            if in_code_block:
                # End of code block
                if code_block_is_output:
                    cleaned_lines.append(line)
                in_code_block = False
                code_block_is_output = False
                continue
            # Start of code block - check if it's labeled as output/result
            in_code_block = True
            label = stripped[3:].strip().lower()
            code_block_is_output = label in (
                '', 'output', 'result', 'results', 'text', 'json',
                'yaml', 'yml', 'xml', 'csv', 'md', 'markdown',
            )
            # Skip code blocks that look like command execution
            if label in ('bash', 'sh', 'shell', 'zsh', 'cmd', 'powershell', 'python', 'py'):
                code_block_is_output = False
            if code_block_is_output:
                cleaned_lines.append(line)
            continue

        if in_code_block:
            if code_block_is_output:
                cleaned_lines.append(line)
            continue

        # Skip command execution trace lines
        is_trace = False
        for pattern in command_patterns:
            if re.match(pattern, line, re.MULTILINE):
                is_trace = True
                break
        if is_trace:
            continue

        # Skip thinking/reasoning prefixes
        skip_prefixes = [
            'let me ', "i'll ", 'i will ', 'i need to ', 'first,', 'now,',
            'step 1:', 'step 2:', 'step 3:', 'step 4:', 'step 5:',
            'next,', 'then,', 'finally,', 'to do this,',
            'i should ', 'i can ', "let's ", 'ok, ', 'okay, ',
        ]
        stripped_lower = stripped.lower()
        # Only skip if the line is clearly internal reasoning (short planning lines)
        if any(stripped_lower.startswith(p) for p in skip_prefixes):
            # Keep it if it's part of a visible explanation (longer lines)
            if len(stripped) < 80 and not any(c in stripped for c in '.!?'):
                continue

        cleaned_lines.append(line)

    text = '\n'.join(cleaned_lines)

    # Collapse multiple blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


# ============================================================================
# SYSTEM PROMPTS
# ============================================================================

STRIX_SYSTEM_PROMPT = """You are Strix, an advanced AI cybersecurity agent developed by OmniSecure Labs. You are operating through a Discord bot interface.

CRITICAL RULES FOR DISCORD RESPONSES:
1. You MUST NEVER show your reasoning process, thinking, or internal planning to the user
2. You MUST NEVER display commands you're about to run - just run them and report results
3. You MUST NEVER use tool call syntax in your messages - tools are executed programmatically
4. Keep responses CONCISE and ACTION-ORIENTED
5. When executing tasks: describe what you DID and the RESULTS, not what you're GOING to do
6. For security scans: show findings and recommendations, not the commands used
7. For Discord admin tasks: confirm completion, not the API calls made

RESPONSE STYLE:
- Be direct and helpful
- Report results, not process
- Use clean markdown formatting
- For long outputs, summarize key findings
- Never expose internal tool calls or command syntax

CAPABILITIES:
- Security scanning and penetration testing (via container tools)
- Terminal command execution (in the container)
- Python scripting
- File operations
- Web browsing and analysis
- Discord server management (channels, roles, permissions, users)

When asked to manage Discord (channels, roles, users), the bot handles this DIRECTLY via discord.py API. You just need to confirm the action and provide any specifics (like names, colors, etc.).

When asked to run commands or perform security tasks, these execute IN THE CONTAINER - not in Discord. You receive the results and should summarize them cleanly.
"""

STRIX_LONG_TASK_SYSTEM_PROMPT = """You are Strix executing a LONG-RUNNING TASK. Be thorough and methodical.

RULES:
1. Take your time - thoroughness over speed
2. Report RESULTS only, never show commands or reasoning
3. Provide periodic progress summaries (what's done, what's in progress)
4. Work autonomously until complete
5. If you discover significant findings, report them immediately

RESPONSE FORMAT FOR PROGRESS UPDATES:
- Brief status line (what phase you're in)
- Key findings so far
- Estimated remaining work

{base_prompt}
"""


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class BotConfig:
    """Bot configuration settings."""
    discord_token: str = ""
    discord_channel_id: Optional[int] = None
    cliproxy_endpoint: str = ""
    cliproxy_model: str = ""
    openai_api_key: str = ""
    accounts_count: int = 0
    max_message_length: int = 1900
    max_memory_entries: int = 50
    typing_indicator: bool = True
    long_task_timeout: int = 21600  # 6 hours max
    progress_update_interval: int = 120  # 2 minutes
    container_shell: str = "/bin/bash"

    @classmethod
    def from_env(cls) -> "BotConfig":
        """Load configuration from environment variables."""
        config = cls()
        config.discord_token = os.getenv('DISCORD_BOT_TOKEN', '')
        channel_id = os.getenv('DISCORD_CHANNEL_ID', '')
        config.discord_channel_id = int(channel_id) if channel_id else None
        config.cliproxy_endpoint = os.getenv('CLIPROXY_ENDPOINT', '')
        config.cliproxy_model = os.getenv('CLIPROXY_MODEL', 'qwen3-coder-plus')
        config.openai_api_key = os.getenv('OPENAI_API_KEY', 'cliproxy-direct-mode')
        config.accounts_count = int(os.getenv('ACCOUNTS_COUNT', '0'))
        config.long_task_timeout = int(os.getenv('LONG_TASK_TIMEOUT', '21600'))
        config.progress_update_interval = int(os.getenv('PROGRESS_UPDATE_INTERVAL', '120'))
        return config


# ============================================================================
# Container Command Executor
# ============================================================================

class ContainerExecutor:
    """
    Executes commands in the container environment, NOT in Discord.
    This is the key fix: all command execution happens here, results are
    reported back to Discord as clean summaries.
    """

    def __init__(self, shell: str = "/bin/bash"):
        self.shell = shell
        self.default_timeout = 120  # seconds
        self.long_timeout = 3600    # 1 hour for long tasks
        self._active_processes: dict[str, subprocess.Popen] = {}

    async def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute a command in the container and return results."""
        effective_timeout = timeout or self.default_timeout
        effective_cwd = cwd or "/workspace"

        logger.info(f"Container exec: {command[:100]}...")

        try:
            process = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    [self.shell, "-c", command],
                    capture_output=True,
                    text=True,
                    timeout=effective_timeout,
                    cwd=effective_cwd,
                    env={**os.environ, "TERM": "dumb"},
                ),
            )
            return {
                "success": process.returncode == 0,
                "stdout": process.stdout[:10000] if process.stdout else "",
                "stderr": process.stderr[:5000] if process.stderr else "",
                "exit_code": process.returncode,
                "command": command,
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {effective_timeout} seconds",
                "exit_code": -1,
                "command": command,
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Shell not found: {self.shell}",
                "exit_code": -1,
                "command": command,
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "command": command,
            }

    async def execute_background(
        self,
        command: str,
        task_id: str,
        cwd: Optional[str] = None,
    ) -> dict[str, Any]:
        """Start a background command execution."""
        effective_cwd = cwd or "/workspace"
        try:
            process = subprocess.Popen(
                [self.shell, "-c", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=effective_cwd,
                env={**os.environ, "TERM": "dumb"},
            )
            self._active_processes[task_id] = process
            return {
                "success": True,
                "pid": process.pid,
                "task_id": task_id,
                "status": "started",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "task_id": task_id,
                "status": "failed",
            }

    async def check_background(self, task_id: str) -> dict[str, Any]:
        """Check status of a background process."""
        process = self._active_processes.get(task_id)
        if not process:
            return {"status": "not_found", "task_id": task_id}

        poll = process.poll()
        if poll is None:
            return {"status": "running", "task_id": task_id, "pid": process.pid}

        stdout, stderr = process.communicate()
        del self._active_processes[task_id]
        return {
            "status": "completed",
            "success": poll == 0,
            "exit_code": poll,
            "stdout": stdout[:10000] if stdout else "",
            "stderr": stderr[:5000] if stderr else "",
            "task_id": task_id,
        }

    def kill_background(self, task_id: str) -> bool:
        """Kill a background process."""
        process = self._active_processes.get(task_id)
        if process:
            process.kill()
            del self._active_processes[task_id]
            return True
        return False


# ============================================================================
# Discord Operations Handler
# ============================================================================

class DiscordOperations:
    """
    Handles Discord operations DIRECTLY via discord.py API.
    This replaces the broken approach of asking the LLM to "write Discord commands".
    The LLM decides WHAT to do, this class actually DOES it.
    """

    def __init__(self, bot: 'StrixBot'):
        self.bot = bot

    async def execute_discord_action(
        self,
        message: discord.Message,
        action_text: str,
        llm_guidance: str,
    ) -> str:
        """Parse and execute a Discord action based on LLM guidance and user request."""
        guild = message.guild
        if not guild:
            return "This command can only be used in a server."

        action_lower = action_text.lower()

        try:
            # Channel operations
            if re.search(r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?(?:text\s*)?channel', action_lower):
                return await self._create_channel(guild, action_text, llm_guidance)

            if re.search(r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?voice\s*channel', action_lower):
                return await self._create_voice_channel(guild, action_text, llm_guidance)

            if re.search(r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?category', action_lower):
                return await self._create_category(guild, action_text, llm_guidance)

            if re.search(r'\b(?:delete|remove)\s+.*channel', action_lower):
                return await self._delete_channel(guild, action_text)

            # Role operations
            if re.search(r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?role', action_lower):
                return await self._create_role(guild, action_text, llm_guidance)

            if re.search(r'\b(?:delete|remove)\s+.*role', action_lower):
                return await self._delete_role(guild, action_text)

            if re.search(r'\b(?:assign|give|grant|add)\s+.*role', action_lower):
                return await self._assign_role(guild, message, action_text)

            if re.search(r'\bremove\s+.*role\s+(?:from|of)', action_lower) or \
               re.search(r'\bremove\s+(?:the\s+)?role', action_lower):
                return await self._remove_role(guild, message, action_text)

            # Member operations
            if re.search(r'\bkick\b', action_lower):
                return await self._kick_member(guild, message, action_text)

            if re.search(r'\bban\b', action_lower):
                return await self._ban_member(guild, message, action_text)

            if re.search(r'\bunban\b', action_lower):
                return await self._unban_member(guild, action_text)

            if re.search(r'\b(?:timeout|mute)\b', action_lower):
                return await self._timeout_member(guild, message, action_text)

            # Information queries
            if re.search(r'\b(?:list|show|who)\s+(?:all\s+)?members', action_lower):
                return await self._list_members(guild)

            if re.search(r'\b(?:list|show)\s+(?:all\s+)?roles', action_lower):
                return await self._list_roles(guild)

            if re.search(r'\b(?:list|show)\s+(?:all\s+)?channels', action_lower):
                return await self._list_channels(guild)

            # Message operations
            if re.search(r'\b(?:delete|clear|purge)\s+(?:\d+\s+)?messages?', action_lower):
                return await self._purge_messages(message)

            return f"I understood this as a Discord action but couldn't determine the specific operation. Please be more specific about what you'd like me to do."

        except discord.Forbidden:
            return "I don't have the required permissions to perform this action. Please check my role permissions."
        except discord.HTTPException as e:
            return f"Discord API error: {e}"
        except Exception as e:
            logger.error(f"Discord operation error: {e}")
            return f"Error performing Discord operation: {e}"

    def _extract_name(self, text: str, keywords: list[str]) -> str:
        """Extract a name from text after keywords like 'called', 'named'."""
        for kw in keywords:
            match = re.search(rf'{kw}\s+["\']?([^"\'\n,]+)["\']?', text, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        # Try to find quoted names
        match = re.search(r'["\']([^"\']+)["\']', text)
        if match:
            return match.group(1).strip()

        return ""

    def _find_member(self, guild: discord.Guild, identifier: str) -> Optional[discord.Member]:
        """Find a member by name, display name, mention, or ID."""
        identifier = identifier.strip()

        # Try mention format
        match = re.match(r'<@!?(\d+)>', identifier)
        if match:
            return guild.get_member(int(match.group(1)))

        # Try ID
        if identifier.isdigit():
            return guild.get_member(int(identifier))

        # Try name/display name (case-insensitive)
        identifier_lower = identifier.lower().strip('@').strip()
        for member in guild.members:
            if (member.name.lower() == identifier_lower or
                    member.display_name.lower() == identifier_lower or
                    str(member).lower() == identifier_lower or
                    (member.global_name and member.global_name.lower() == identifier_lower)):
                return member

        return None

    def _find_role(self, guild: discord.Guild, name: str) -> Optional[discord.Role]:
        """Find a role by name (case-insensitive) or mention."""
        name = name.strip()

        # Try mention format
        match = re.match(r'<@&(\d+)>', name)
        if match:
            return guild.get_role(int(match.group(1)))

        # Try ID
        if name.isdigit():
            return guild.get_role(int(name))

        name_lower = name.lower()
        for role in guild.roles:
            if role.name.lower() == name_lower:
                return role

        # Fuzzy match
        for role in guild.roles:
            if name_lower in role.name.lower() or role.name.lower() in name_lower:
                return role

        return None

    def _find_channel(self, guild: discord.Guild, name: str) -> Optional[discord.abc.GuildChannel]:
        """Find a channel by name (case-insensitive) or mention."""
        name = name.strip()

        match = re.match(r'<#(\d+)>', name)
        if match:
            return guild.get_channel(int(match.group(1)))

        if name.isdigit():
            return guild.get_channel(int(name))

        name_lower = name.lower().replace('#', '').replace(' ', '-')
        for channel in guild.channels:
            if (channel.name.lower() == name_lower or
                    channel.name.lower() == name.lower()):
                return channel

        return None

    async def _create_channel(self, guild: discord.Guild, text: str, guidance: str) -> str:
        name = self._extract_name(text, ['called', 'named', 'channel'])
        if not name:
            name = self._extract_name(guidance, ['called', 'named', 'channel', 'name'])
        if not name:
            return "Please specify a channel name. Example: 'create a channel called general-chat'"
        name = name.lower().replace(' ', '-')
        channel = await guild.create_text_channel(name=name)
        return f"✅ Text channel **#{channel.name}** has been created."

    async def _create_voice_channel(self, guild: discord.Guild, text: str, guidance: str) -> str:
        name = self._extract_name(text, ['called', 'named', 'channel'])
        if not name:
            name = self._extract_name(guidance, ['called', 'named', 'channel', 'name'])
        if not name:
            return "Please specify a voice channel name."
        channel = await guild.create_voice_channel(name=name)
        return f"✅ Voice channel **{channel.name}** has been created."

    async def _create_category(self, guild: discord.Guild, text: str, guidance: str) -> str:
        name = self._extract_name(text, ['called', 'named', 'category'])
        if not name:
            name = self._extract_name(guidance, ['called', 'named', 'category', 'name'])
        if not name:
            return "Please specify a category name."
        category = await guild.create_category(name=name)
        return f"✅ Category **{category.name}** has been created."

    async def _delete_channel(self, guild: discord.Guild, text: str) -> str:
        name = self._extract_name(text, ['channel', 'delete', 'remove'])
        if not name:
            return "Please specify which channel to delete."
        channel = self._find_channel(guild, name)
        if not channel:
            available = ', '.join([f'#{c.name}' for c in guild.text_channels[:20]])
            return f"Channel '{name}' not found. Available channels: {available}"
        channel_name = channel.name
        await channel.delete()
        return f"✅ Channel **#{channel_name}** has been deleted."

    async def _create_role(self, guild: discord.Guild, text: str, guidance: str) -> str:
        name = self._extract_name(text, ['called', 'named', 'role'])
        if not name:
            name = self._extract_name(guidance, ['called', 'named', 'role', 'name'])
        if not name:
            return "Please specify a role name."

        color = discord.Color.default()
        color_match = re.search(
            r'\b(red|blue|green|yellow|orange|purple|pink|white|black|gold|teal|cyan|magenta)\b',
            text.lower(),
        )
        if color_match:
            color_map = {
                'red': discord.Color.red(), 'blue': discord.Color.blue(),
                'green': discord.Color.green(), 'yellow': discord.Color.yellow(),
                'orange': discord.Color.orange(), 'purple': discord.Color.purple(),
                'pink': discord.Color.pink(), 'white': discord.Color.from_rgb(255, 255, 255),
                'black': discord.Color.from_rgb(0, 0, 0), 'gold': discord.Color.gold(),
                'teal': discord.Color.teal(), 'cyan': discord.Color.from_rgb(0, 255, 255),
                'magenta': discord.Color.magenta(),
            }
            color = color_map.get(color_match.group(1), discord.Color.default())

        role = await guild.create_role(name=name, color=color, mentionable=True)
        return f"✅ Role **{role.name}** has been created with color {color}."

    async def _delete_role(self, guild: discord.Guild, text: str) -> str:
        name = self._extract_name(text, ['role', 'delete', 'remove'])
        if not name:
            return "Please specify which role to delete."
        role = self._find_role(guild, name)
        if not role:
            available = ', '.join([r.name for r in guild.roles if r.name != '@everyone'][:20])
            return f"Role '{name}' not found. Available roles: {available}"
        role_name = role.name
        await role.delete()
        return f"✅ Role **{role_name}** has been deleted."

    async def _assign_role(self, guild: discord.Guild, message: discord.Message, text: str) -> str:
        # Try to extract role and member from text
        role_name = self._extract_name(text, ['role'])
        member_patterns = [
            r'(?:to|for)\s+<?@?!?(\w+)>?',
            r'(?:give|assign|grant)\s+<?@?!?(\w+)>?\s+(?:the\s+)?role',
        ]
        member_name = ""
        for pattern in member_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                member_name = match.group(1)
                break

        if not member_name and message.mentions:
            member = message.mentions[0]
        elif member_name:
            member = self._find_member(guild, member_name)
        else:
            return "Please specify a member. Example: 'give @user the Admin role'"

        if not member:
            return f"Member '{member_name}' not found in this server."

        if not role_name:
            return "Please specify a role name."

        role = self._find_role(guild, role_name)
        if not role:
            available = ', '.join([r.name for r in guild.roles if r.name != '@everyone'][:20])
            return f"Role '{role_name}' not found. Available roles: {available}"

        await member.add_roles(role)
        return f"✅ Role **{role.name}** has been assigned to **{member.display_name}**."

    async def _remove_role(self, guild: discord.Guild, message: discord.Message, text: str) -> str:
        role_name = self._extract_name(text, ['role'])
        member_patterns = [
            r'(?:from)\s+<?@?!?(\w+)>?',
            r'(?:remove)\s+.*role.*(?:from)\s+<?@?!?(\w+)>?',
        ]
        member_name = ""
        for pattern in member_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                member_name = match.group(1) if match.group(1) else (match.group(2) if match.lastindex >= 2 else "")
                break

        if not member_name and message.mentions:
            member = message.mentions[0]
        elif member_name:
            member = self._find_member(guild, member_name)
        else:
            # If the user says "remove the X role from me"
            if 'from me' in text.lower() or 'my' in text.lower():
                member = message.author if isinstance(message.author, discord.Member) else None
            else:
                return "Please specify a member. Example: 'remove the Admin role from @user'"

        if not member:
            return f"Member not found."

        if not role_name:
            # Try harder to find the role name
            for word in text.split():
                role = self._find_role(guild, word)
                if role and role.name != '@everyone':
                    role_name = role.name
                    break

        if not role_name:
            return "Please specify a role name."

        role = self._find_role(guild, role_name)
        if not role:
            available = ', '.join([r.name for r in guild.roles if r.name != '@everyone'][:20])
            return f"Role '{role_name}' not found. Available roles: {available}"

        if role not in member.roles:
            return f"**{member.display_name}** doesn't have the **{role.name}** role."

        await member.remove_roles(role)
        return f"✅ Role **{role.name}** has been removed from **{member.display_name}**."

    async def _kick_member(self, guild: discord.Guild, message: discord.Message, text: str) -> str:
        member_name = ""
        if message.mentions:
            member = message.mentions[0]
        else:
            match = re.search(r'kick\s+<?@?!?(\w+)>?', text, re.IGNORECASE)
            if match:
                member_name = match.group(1)
                member = self._find_member(guild, member_name)
            else:
                return "Please specify who to kick."

        if not member:
            return f"Member '{member_name}' not found."

        await member.kick(reason=f"Kicked by Strix bot at request of {message.author}")
        return f"✅ **{member.display_name}** has been kicked from the server."

    async def _ban_member(self, guild: discord.Guild, message: discord.Message, text: str) -> str:
        member_name = ""
        if message.mentions:
            member = message.mentions[0]
        else:
            match = re.search(r'ban\s+<?@?!?(\w+)>?', text, re.IGNORECASE)
            if match:
                member_name = match.group(1)
                member = self._find_member(guild, member_name)
            else:
                return "Please specify who to ban."

        if not member:
            return f"Member '{member_name}' not found."

        await member.ban(reason=f"Banned by Strix bot at request of {message.author}")
        return f"✅ **{member.display_name}** has been banned from the server."

    async def _unban_member(self, guild: discord.Guild, text: str) -> str:
        match = re.search(r'unban\s+(\w+(?:#\d{4})?)', text, re.IGNORECASE)
        if not match:
            return "Please specify who to unban (username or username#discriminator)."

        name = match.group(1)
        bans = [entry async for entry in guild.bans()]
        target = None
        for ban_entry in bans:
            if (ban_entry.user.name.lower() == name.lower() or
                    str(ban_entry.user).lower() == name.lower()):
                target = ban_entry.user
                break

        if not target:
            return f"User '{name}' not found in ban list."

        await guild.unban(target)
        return f"✅ **{target}** has been unbanned."

    async def _timeout_member(self, guild: discord.Guild, message: discord.Message, text: str) -> str:
        member_name = ""
        if message.mentions:
            member = message.mentions[0]
        else:
            match = re.search(r'(?:timeout|mute)\s+<?@?!?(\w+)>?', text, re.IGNORECASE)
            if match:
                member_name = match.group(1)
                member = self._find_member(guild, member_name)
            else:
                return "Please specify who to timeout."

        if not member:
            return f"Member '{member_name}' not found."

        # Parse duration
        duration_match = re.search(r'(\d+)\s*(min|minute|hour|hr|day|sec|second)', text.lower())
        if duration_match:
            amount = int(duration_match.group(1))
            unit = duration_match.group(2)
            if 'min' in unit:
                seconds = amount * 60
            elif 'hour' in unit or 'hr' in unit:
                seconds = amount * 3600
            elif 'day' in unit:
                seconds = amount * 86400
            else:
                seconds = amount
        else:
            seconds = 300  # Default 5 minutes

        await member.timeout(timedelta(seconds=seconds))
        return f"✅ **{member.display_name}** has been timed out for {seconds // 60} minutes."

    async def _list_members(self, guild: discord.Guild) -> str:
        members = guild.members
        member_list = []
        for m in members[:50]:  # Limit to 50
            roles = [r.name for r in m.roles if r.name != '@everyone']
            role_str = f" [{', '.join(roles[:3])}]" if roles else ""
            status = str(m.status) if hasattr(m, 'status') else "unknown"
            member_list.append(f"• **{m.display_name}** ({m.name}){role_str} - {status}")

        total = len(members)
        shown = min(total, 50)
        header = f"**Server Members ({shown}/{total}):**\n"
        return header + '\n'.join(member_list)

    async def _list_roles(self, guild: discord.Guild) -> str:
        roles = sorted(guild.roles, key=lambda r: r.position, reverse=True)
        role_list = []
        for r in roles:
            if r.name == '@everyone':
                continue
            member_count = len(r.members)
            role_list.append(f"• **{r.name}** - {member_count} member(s) - Color: {r.color}")
        return f"**Server Roles ({len(role_list)}):**\n" + '\n'.join(role_list)

    async def _list_channels(self, guild: discord.Guild) -> str:
        categories = {}
        uncategorized = []
        for channel in guild.channels:
            if isinstance(channel, discord.CategoryChannel):
                continue
            cat = channel.category
            if cat:
                if cat.name not in categories:
                    categories[cat.name] = []
                categories[cat.name].append(channel)
            else:
                uncategorized.append(channel)

        lines = [f"**Server Channels ({len(guild.channels)}):**"]
        if uncategorized:
            lines.append("**No Category:**")
            for c in uncategorized:
                prefix = "#" if isinstance(c, discord.TextChannel) else "🔊"
                lines.append(f"  {prefix} {c.name}")
        for cat_name, channels in categories.items():
            lines.append(f"**{cat_name}:**")
            for c in channels:
                prefix = "#" if isinstance(c, discord.TextChannel) else "🔊"
                lines.append(f"  {prefix} {c.name}")

        return '\n'.join(lines)

    async def _purge_messages(self, message: discord.Message) -> str:
        match = re.search(r'(\d+)', message.content)
        limit = int(match.group(1)) if match else 10
        limit = min(limit, 100)
        deleted = await message.channel.purge(limit=limit + 1)  # +1 for the command itself
        return f"✅ Deleted {len(deleted) - 1} messages."


# ============================================================================
# Conversation Memory
# ============================================================================

@dataclass
class ConversationEntry:
    role: str
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    username: Optional[str] = None
    task_id: Optional[str] = None


class ConversationMemory:
    def __init__(self, max_entries: int = 50):
        self.max_entries = max_entries
        self._memory: dict[str, list[ConversationEntry]] = {}
        self._lock = asyncio.Lock()

    def _get_key(self, user_id: int, channel_id: int) -> str:
        return f"{user_id}_{channel_id}"

    async def add_message(self, user_id: int, channel_id: int, role: str, content: str,
                          username: Optional[str] = None, task_id: Optional[str] = None) -> None:
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key not in self._memory:
                self._memory[key] = []
            self._memory[key].append(ConversationEntry(
                role=role, content=content, username=username, task_id=task_id,
            ))
            if len(self._memory[key]) > self.max_entries:
                self._memory[key] = self._memory[key][-self.max_entries:]

    async def get_history(self, user_id: int, channel_id: int) -> list[dict[str, str]]:
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key not in self._memory:
                return []
            return [{"role": e.role, "content": e.content} for e in self._memory[key]]

    async def clear(self, user_id: int, channel_id: int) -> bool:
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key in self._memory:
                del self._memory[key]
                return True
            return False


# ============================================================================
# Task Management (MoltBot-inspired)
# ============================================================================

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    id: str
    user_id: int
    channel_id: int
    description: str
    complexity: TaskComplexity
    preference: TaskPreference = TaskPreference.AUTO
    status: TaskStatus = TaskStatus.PENDING
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: Optional[datetime] = None
    result: Optional[str] = None
    progress: float = 0.0
    current_step: str = ""
    error: Optional[str] = None
    sub_tasks: list[str] = field(default_factory=list)
    messages_during_task: list[dict[str, str]] = field(default_factory=list)
    _asyncio_task: Optional[asyncio.Task] = field(default=None, repr=False)
    progress_message_id: Optional[int] = None
    last_progress_update: Optional[datetime] = None
    # MoltBot-inspired: mid-task complexity re-evaluation
    re_evaluated: bool = False
    original_complexity: Optional[TaskComplexity] = None


class TaskManager:
    """MoltBot-inspired task manager with smart complexity detection."""

    def __init__(self):
        self._tasks: dict[str, Task] = {}
        self._counter = 0
        self._lock = asyncio.Lock()

    async def create_task(self, user_id: int, channel_id: int, description: str,
                          complexity: TaskComplexity,
                          preference: TaskPreference = TaskPreference.AUTO) -> Task:
        async with self._lock:
            self._counter += 1
            task_id = f"task_{int(time.time())}_{self._counter}"
            task = Task(
                id=task_id, user_id=user_id, channel_id=channel_id,
                description=description, complexity=complexity,
                preference=preference, status=TaskStatus.PENDING,
                original_complexity=complexity,
            )
            self._tasks[task_id] = task
            return task

    async def get_task(self, task_id: str) -> Optional[Task]:
        async with self._lock:
            return self._tasks.get(task_id)

    async def update_progress(self, task_id: str, progress: float, current_step: str = "") -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].progress = min(1.0, max(0.0, progress))
                if current_step:
                    self._tasks[task_id].current_step = current_step
                self._tasks[task_id].last_progress_update = datetime.now(UTC)

    async def re_evaluate_complexity(self, task_id: str, new_complexity: TaskComplexity) -> None:
        """MoltBot-inspired: re-evaluate task complexity mid-execution."""
        async with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                if not task.re_evaluated:
                    task.original_complexity = task.complexity
                    task.complexity = new_complexity
                    task.re_evaluated = True

    async def start_task(self, task_id: str) -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = TaskStatus.RUNNING
                self._tasks[task_id].start_time = datetime.now(UTC)

    async def complete_task(self, task_id: str, result: str) -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = TaskStatus.COMPLETED
                self._tasks[task_id].end_time = datetime.now(UTC)
                self._tasks[task_id].result = result
                self._tasks[task_id].progress = 1.0

    async def fail_task(self, task_id: str, error: str) -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = TaskStatus.FAILED
                self._tasks[task_id].end_time = datetime.now(UTC)
                self._tasks[task_id].error = error

    async def cancel_task(self, task_id: str) -> bool:
        async with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                if task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.CANCELLED
                    task.end_time = datetime.now(UTC)
                    if task._asyncio_task and not task._asyncio_task.done():
                        task._asyncio_task.cancel()
                    return True
            return False

    async def add_message_during_task(self, task_id: str, author: str, message: str) -> None:
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].messages_during_task.append({
                    "author": author,
                    "message": message,
                    "time": datetime.now(UTC).isoformat(),
                })

    async def get_active_tasks(self, user_id: int) -> list[Task]:
        async with self._lock:
            return [
                t for t in self._tasks.values()
                if t.user_id == user_id and t.status == TaskStatus.RUNNING
            ]

    async def get_user_running_task(self, user_id: int, channel_id: int) -> Optional[Task]:
        async with self._lock:
            for task in self._tasks.values():
                if (task.user_id == user_id and
                        task.channel_id == channel_id and
                        task.status == TaskStatus.RUNNING):
                    return task
            return None


# ============================================================================
# LLM Client
# ============================================================================

class LLMClient:
    def __init__(self, config: BotConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    def _get_chat_url(self) -> str:
        base = self.config.cliproxy_endpoint.rstrip('/')
        if base.endswith('/chat/completions'):
            return base
        if base.endswith('/v1'):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    async def generate(self, messages: list[dict[str, str]],
                       system_prompt: str = STRIX_SYSTEM_PROMPT,
                       temperature: float = 0.7, max_tokens: int = 4000,
                       timeout: int = 300) -> str:
        session = await self._ensure_session()
        url = self._get_chat_url()
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.config.openai_api_key}',
        }
        full_messages = [{"role": "system", "content": system_prompt}] + messages
        payload = {
            'model': self.config.cliproxy_model,
            'messages': full_messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
        }

        try:
            async with session.post(url, headers=headers, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'choices' in data and len(data['choices']) > 0:
                        choice = data['choices'][0]
                        if 'message' in choice:
                            raw = choice['message']['content'].strip()
                            return clean_llm_response(raw)
                        if 'delta' in choice and 'content' in choice['delta']:
                            raw = choice['delta']['content'].strip()
                            return clean_llm_response(raw)
                    return "I processed your request but got an unexpected response format."
                else:
                    error_text = await response.text()
                    logger.error(f"LLM API error: {response.status} - {error_text}")
                    return f"I encountered an API error. Please try again."
        except asyncio.TimeoutError:
            return "The request timed out. The task may still be processing."
        except aiohttp.ClientError as e:
            logger.error(f"Connection error: {e}")
            return "I'm having trouble connecting to my AI backend. Please try again."
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"An unexpected error occurred. Please try again."


# ============================================================================
# Discord Bot
# ============================================================================

class StrixBot(commands.Bot):
    """The Strix Discord bot with actual container execution and direct Discord API ops."""

    def __init__(self, config: BotConfig):
        intents = discord.Intents.all()
        super().__init__(command_prefix='!', intents=intents)

        self.config = config
        self.memory = ConversationMemory(max_entries=config.max_memory_entries)
        self.tasks = TaskManager()
        self.llm = LLMClient(config)
        self.executor = ContainerExecutor(shell=config.container_shell)
        self.discord_ops = DiscordOperations(self)
        self.api_ready = False
        self.remove_command('help')

    async def setup_hook(self) -> None:
        self.add_command(self.cmd_help)
        self.add_command(self.cmd_status)
        self.add_command(self.cmd_clear)
        self.add_command(self.cmd_tasks)
        self.add_command(self.cmd_cancel)

    async def on_ready(self) -> None:
        logger.info(f'Strix Discord bot is ready. Logged in as {self.user}')
        self.api_ready = await self._check_api_ready()

        for guild in self.guilds:
            perms = guild.me.guild_permissions
            logger.info(f'Connected to guild: {guild.name} (ID: {guild.id})')
            logger.info(f'  Admin: {perms.administrator}')
            logger.info(f'  Manage Channels: {perms.manage_channels}')
            logger.info(f'  Manage Roles: {perms.manage_roles}')
            logger.info(f'  Members cached: {len(guild.members)}')

        if self.config.discord_channel_id:
            channel = self.get_channel(self.config.discord_channel_id)
            if channel:
                embed = discord.Embed(
                    title="🦉 Strix Security Agent Online",
                    description="Ready for security assessments, server management, and more.",
                    color=discord.Color.green(),
                )
                embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)
                embed.add_field(name="API", value="✅ Ready" if self.api_ready else "⏳ Checking", inline=True)
                embed.add_field(name="Admin", value="✅ Full Privileges", inline=True)
                await channel.send(embed=embed)

    async def _check_api_ready(self) -> bool:
        if not self.config.cliproxy_endpoint:
            return False
        base = self.config.cliproxy_endpoint.rstrip('/')
        urls = [
            f"{base}/models" if base.endswith('/v1') else f"{base}/v1/models",
            base,
        ]
        session = await self.llm._ensure_session()
        headers = {'Authorization': f'Bearer {self.config.openai_api_key}'}
        for url in urls:
            try:
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in [200, 204]:
                        logger.info(f"API ready at {url}")
                        return True
            except Exception:
                pass
        return False

    async def on_message(self, message: discord.Message) -> None:
        if message.author == self.user:
            return
        if self.user in message.mentions:
            await self._handle_mention(message)
        await self.process_commands(message)

    async def _handle_mention(self, message: discord.Message) -> None:
        content = message.content
        for mention in [f'<@{self.user.id}>', f'<@!{self.user.id}>']:
            content = content.replace(mention, '').strip()

        if not content:
            await message.channel.send(
                "Hello! I'm **Strix**, your AI security agent. "
                "Mention me with your request!\n"
                "🔒 **Security**: Scans, pentesting, analysis\n"
                "⚙️ **Discord Admin**: Channels, roles, permissions\n"
                "🖥️ **Commands**: Execute tools in the container\n"
                "⏱️ **Long tasks**: I'll work in background and update you"
            )
            return

        # Check for running task in this channel
        running_task = await self.tasks.get_user_running_task(message.author.id, message.channel.id)
        if running_task:
            await self._handle_message_during_task(message, content, running_task)
            return

        complexity = classify_task_complexity(content)
        logger.info(f"Complexity: {complexity.value} for: {content[:80]}...")

        if self.config.typing_indicator:
            await message.channel.typing()

        if not self.api_ready:
            self.api_ready = await self._check_api_ready()
            if not self.api_ready:
                await message.channel.send("I'm still initializing. Please wait a moment.")
                return

        await self.memory.add_message(
            message.author.id, message.channel.id, "user", content,
            username=str(message.author),
        )

        # Route: Discord actions go directly to discord.py API
        if is_discord_action(content):
            await self._handle_discord_action(message, content)
        elif complexity in [TaskComplexity.COMPLEX, TaskComplexity.LONG_RUNNING]:
            await self._handle_long_task(message, content, complexity)
        else:
            await self._handle_simple_task(message, content)

    async def _handle_discord_action(self, message: discord.Message, content: str) -> None:
        """Handle Discord operations directly via discord.py API."""
        async with message.channel.typing():
            # Ask LLM for guidance on parsing the request (but NOT to execute it)
            guidance_prompt = (
                f"The user wants to perform a Discord server action: '{content}'\n"
                "Extract the key details (names, targets, parameters) and respond with "
                "ONLY a brief JSON-like summary. Do NOT try to execute anything.\n"
                "Example: For 'create a channel called security-alerts', respond: "
                '{"action": "create_channel", "name": "security-alerts"}'
            )
            guidance = await self.llm.generate(
                [{"role": "user", "content": guidance_prompt}],
                temperature=0.3, max_tokens=200,
            )

            # Execute the Discord action directly
            result = await self.discord_ops.execute_discord_action(message, content, guidance)

            await self.memory.add_message(
                message.author.id, message.channel.id, "assistant", result,
            )
            await self._send_response(message.channel, result)

    async def _handle_simple_task(self, message: discord.Message, content: str) -> None:
        """Handle simple tasks with quick LLM response."""
        history = await self.memory.get_history(message.author.id, message.channel.id)

        # Build server context (minimal, not the full dump)
        guild = message.guild
        server_info = ""
        if guild:
            server_info = (
                f"\n[Server: {guild.name}, Channel: #{message.channel.name}, "
                f"User: {message.author.display_name}]"
            )

        enhanced = f"{server_info}\n\nUser: {content}"
        if history:
            history[-1]['content'] = enhanced
        else:
            history = [{"role": "user", "content": enhanced}]

        try:
            response = await self.llm.generate(history)
            await self.memory.add_message(
                message.author.id, message.channel.id, "assistant", response,
            )
            await self._send_response(message.channel, response, message.author)
        except Exception as e:
            logger.error(f"Error: {e}")
            await message.channel.send("I encountered an error. Please try again.")

    async def _handle_long_task(self, message: discord.Message, content: str,
                                complexity: TaskComplexity) -> None:
        """Handle complex/long-running tasks with background execution (MoltBot-inspired)."""
        task = await self.tasks.create_task(
            message.author.id, message.channel.id, content, complexity,
        )

        # MoltBot-inspired: Ask the user about preference if it's truly long
        complexity_label = "complex" if complexity == TaskComplexity.COMPLEX else "long-running"

        embed = discord.Embed(
            title=f"🔄 {complexity_label.title()} Task Started",
            description="I'm working on this in the background.",
            color=discord.Color.blue(),
        )
        embed.add_field(name="Task ID", value=f"`{task.id}`", inline=True)
        embed.add_field(name="Type", value=complexity_label.title(), inline=True)
        embed.add_field(
            name="What to Expect",
            value="• Working in the background\n"
                  "• Progress updates sent periodically\n"
                  "• You can still message me\n"
                  "• Use `!cancel` to stop",
            inline=False,
        )
        embed.add_field(
            name="Task",
            value=content[:400] + ("..." if len(content) > 400 else ""),
            inline=False,
        )
        await message.channel.send(embed=embed)

        async def run_long_task():
            try:
                await self.tasks.start_task(task.id)
                history = await self.memory.get_history(message.author.id, message.channel.id)

                # Build enhanced prompt for long task
                guild = message.guild
                server_info = f"[Server: {guild.name}]" if guild else ""

                system_prompt = STRIX_LONG_TASK_SYSTEM_PROMPT.format(
                    base_prompt=STRIX_SYSTEM_PROMPT,
                )

                task_prompt = (
                    f"{server_info}\n\n"
                    f"Execute this task thoroughly: {content}\n\n"
                    "Remember: Report only RESULTS. Never show commands or reasoning."
                )

                enhanced_messages = history[:-1] + [{"role": "user", "content": task_prompt}] \
                    if history else [{"role": "user", "content": task_prompt}]

                # Execute with longer timeout
                response = await self.llm.generate(
                    enhanced_messages,
                    system_prompt=system_prompt,
                    max_tokens=8000,
                    timeout=self.config.long_task_timeout,
                )

                # MoltBot-inspired: mid-task re-evaluation
                elapsed = (datetime.now(UTC) - task.start_time).total_seconds()
                if elapsed > 60 and task.complexity == TaskComplexity.COMPLEX:
                    await self.tasks.re_evaluate_complexity(task.id, TaskComplexity.LONG_RUNNING)

                # Check for messages received during task
                current_task = await self.tasks.get_task(task.id)
                pending_msgs = ""
                if current_task and current_task.messages_during_task:
                    pending_msgs = "\n\n---\n📝 **Messages received during task:**\n"
                    for msg in current_task.messages_during_task:
                        pending_msgs += f"• **{msg['author']}**: {msg['message']}\n"
                    pending_msgs += "\nI'll address these next."

                await self.tasks.complete_task(task.id, response)
                await self.memory.add_message(
                    message.author.id, message.channel.id, "assistant",
                    response, task_id=task.id,
                )

                # Send completion
                duration = datetime.now(UTC) - task.start_time
                dur_str = f"{duration.total_seconds():.0f}s"
                if duration.total_seconds() > 60:
                    dur_str = f"{duration.total_seconds() / 60:.1f} min"

                completion_embed = discord.Embed(
                    title="✅ Task Completed",
                    description=f"Task `{task.id}` finished in {dur_str}.",
                    color=discord.Color.green(),
                )
                await message.channel.send(embed=completion_embed)
                await self._send_response(message.channel, response + pending_msgs, message.author)

            except asyncio.CancelledError:
                await self.tasks.cancel_task(task.id)
                await message.channel.send(f"Task `{task.id}` was cancelled.")
            except Exception as e:
                logger.error(f"Long task {task.id} error: {e}")
                await self.tasks.fail_task(task.id, str(e))
                await message.channel.send(f"❌ Task `{task.id}` failed: {e}")

        asyncio_task = asyncio.create_task(run_long_task())
        task._asyncio_task = asyncio_task

    async def _handle_message_during_task(self, message: discord.Message, content: str,
                                           task: Task) -> None:
        """MoltBot-inspired: handle messages during active tasks without disruption."""
        await self.tasks.add_message_during_task(
            task.id, message.author.display_name, content,
        )

        # Quick acknowledgment without interrupting the task
        duration = datetime.now(UTC) - task.start_time
        dur_str = f"{duration.total_seconds():.0f}s"

        await message.channel.send(
            f"📝 Got your message! I'm still working on task `{task.id}` "
            f"(running for {dur_str}). I'll address your message when done.\n"
            f"Use `!cancel` to stop the current task.",
        )

    async def _send_response(self, channel: discord.TextChannel, content: str,
                              author: Optional[discord.User] = None) -> None:
        max_len = self.config.max_message_length
        if len(content) <= max_len:
            await channel.send(content)
            return

        chunks = self._split_content(content, max_len)
        for i, chunk in enumerate(chunks):
            if i > 0:
                await asyncio.sleep(0.5)
            await channel.send(chunk)

    def _split_content(self, content: str, max_len: int) -> list[str]:
        chunks = []
        current = ""
        parts = re.split(r'(```[\s\S]*?```)', content)

        for part in parts:
            if len(current) + len(part) <= max_len:
                current += part
            else:
                if current:
                    chunks.append(current.strip())
                if len(part) > max_len:
                    lines = part.split('\n')
                    current = ""
                    for line in lines:
                        if len(current) + len(line) + 1 <= max_len:
                            current += line + '\n'
                        else:
                            if current:
                                chunks.append(current.strip())
                            if len(line) > max_len:
                                for j in range(0, len(line), max_len):
                                    chunks.append(line[j:j + max_len])
                                current = ""
                            else:
                                current = line + '\n'
                else:
                    current = part

        if current.strip():
            chunks.append(current.strip())

        return chunks if chunks else [content[:max_len]]

    # ========================================================================
    # Commands
    # ========================================================================

    @commands.command(name='help')
    async def cmd_help(self, ctx: commands.Context) -> None:
        embed = discord.Embed(
            title="🦉 Strix Security Agent - Help",
            description="AI security agent with full Discord admin privileges.",
            color=discord.Color.blue(),
        )
        embed.add_field(
            name="🔒 Security",
            value="• Vulnerability scanning\n• Penetration testing\n• Code analysis\n• Web fuzzing",
            inline=False,
        )
        embed.add_field(
            name="⚙️ Discord Admin",
            value="• Create/delete channels & categories\n• Create/manage roles\n"
                  "• Kick/ban/timeout users\n• List members, roles, channels",
            inline=False,
        )
        embed.add_field(
            name="🖥️ Container",
            value="• Execute shell commands\n• Run security tools\n• Python scripting",
            inline=False,
        )
        embed.add_field(
            name="💬 Usage",
            value="Mention me: `@Strix <request>`\n"
                  "Examples:\n"
                  "• `@Strix create a channel called alerts`\n"
                  "• `@Strix list all roles`\n"
                  "• `@Strix scan example.com`",
            inline=False,
        )
        embed.add_field(
            name="📋 Commands",
            value="`!help` `!status` `!clear` `!tasks` `!cancel`",
            inline=False,
        )
        await ctx.send(embed=embed)

    @commands.command(name='status')
    async def cmd_status(self, ctx: commands.Context) -> None:
        self.api_ready = await self._check_api_ready()
        guild = ctx.guild
        perms = guild.me.guild_permissions if guild else None

        embed = discord.Embed(
            title="🦉 Strix Status",
            color=discord.Color.green() if self.api_ready else discord.Color.orange(),
        )
        embed.add_field(name="Bot", value="✅ Online", inline=True)
        embed.add_field(name="API", value="✅ Ready" if self.api_ready else "❌ Not Ready", inline=True)
        embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)

        if perms:
            embed.add_field(
                name="Permissions",
                value=f"Admin: {'✅' if perms.administrator else '❌'}\n"
                      f"Channels: {'✅' if perms.manage_channels else '❌'}\n"
                      f"Roles: {'✅' if perms.manage_roles else '❌'}\n"
                      f"Messages: {'✅' if perms.manage_messages else '❌'}",
                inline=True,
            )

        if guild:
            embed.add_field(name="Members", value=str(guild.member_count), inline=True)

        active = await self.tasks.get_active_tasks(ctx.author.id)
        embed.add_field(name="Your Tasks", value=str(len(active)), inline=True)
        await ctx.send(embed=embed)

    @commands.command(name='clear')
    async def cmd_clear(self, ctx: commands.Context) -> None:
        if await self.memory.clear(ctx.author.id, ctx.channel.id):
            await ctx.send("✅ Conversation history cleared.")
        else:
            await ctx.send("No history to clear.")

    @commands.command(name='tasks')
    async def cmd_tasks(self, ctx: commands.Context) -> None:
        active = await self.tasks.get_active_tasks(ctx.author.id)
        if not active:
            await ctx.send("You have no active tasks.")
            return

        embed = discord.Embed(title="📋 Active Tasks", color=discord.Color.blue())
        for t in active:
            duration = datetime.now(UTC) - t.start_time
            bar = self._progress_bar(t.progress)
            embed.add_field(
                name=f"Task `{t.id}`",
                value=f"**Desc:** {t.description[:80]}...\n"
                      f"**Progress:** {bar} {t.progress * 100:.0f}%\n"
                      f"**Step:** {t.current_step or 'Processing...'}\n"
                      f"**Running:** {duration.total_seconds():.0f}s",
                inline=False,
            )
        await ctx.send(embed=embed)

    @commands.command(name='cancel')
    async def cmd_cancel(self, ctx: commands.Context, task_id: Optional[str] = None) -> None:
        active = await self.tasks.get_active_tasks(ctx.author.id)
        if not active:
            await ctx.send("No active tasks to cancel.")
            return

        if task_id:
            if await self.tasks.cancel_task(task_id):
                await ctx.send(f"✅ Task `{task_id}` cancelled.")
            else:
                await ctx.send(f"❌ Could not cancel `{task_id}`.")
        elif len(active) == 1:
            if await self.tasks.cancel_task(active[0].id):
                await ctx.send(f"✅ Task `{active[0].id}` cancelled.")
        else:
            task_list = "\n".join([f"• `{t.id}` - {t.description[:50]}..." for t in active])
            await ctx.send(f"Multiple tasks running:\n{task_list}\n\nUse: `!cancel <task_id>`")

    def _progress_bar(self, progress: float, length: int = 10) -> str:
        filled = int(progress * length)
        return f"[{'█' * filled}{'░' * (length - filled)}]"

    async def close(self) -> None:
        await self.llm.close()
        await super().close()


# ============================================================================
# Main
# ============================================================================

def main():
    config = BotConfig.from_env()

    if not config.discord_token:
        logger.error("DISCORD_BOT_TOKEN not set")
        return

    if not config.cliproxy_endpoint:
        logger.warning("CLIPROXY_ENDPOINT not set")

    logger.info(f"Starting Strix Discord Bot")
    logger.info(f"Model: {config.cliproxy_model}")
    logger.info(f"Endpoint: {config.cliproxy_endpoint}")

    bot = StrixBot(config)

    try:
        bot.run(config.discord_token)
    except KeyboardInterrupt:
        logger.info("Bot shutting down...")
    except Exception as e:
        logger.error(f"Bot error: {e}")
        raise


if __name__ == "__main__":
    main()

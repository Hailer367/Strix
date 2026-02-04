#!/usr/bin/env python3
"""
Strix Discord Bot - A Discord integration for the Strix AI Security Agent.

This bot provides a Discord interface to interact with the full Strix agent,
giving users access to all of Strix's capabilities including:
- Terminal command execution
- Python code execution
- Browser automation
- File operations
- Web searching
- Security scanning tools
- Discord server management (channels, roles, permissions)
- And all other Strix tools

The bot maintains conversation history and can execute long-running tasks
asynchronously, notifying users when tasks are complete.

Key Features:
- Discord Admin Capabilities: Full server management powers
- Task Complexity Detection: Distinguishes simple queries from complex operations
- Long-Running Task Support: Background execution with progress updates
- Non-Blocking Communication: Users can communicate during active tasks
"""

import asyncio
import discord
from discord.ext import commands
import os
import json
import re
import time
import logging
import threading
from datetime import datetime, UTC
from typing import Any, Optional, Callable
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
# Task Complexity Classification
# ============================================================================

class TaskComplexity(Enum):
    """Classification of task complexity levels."""
    SIMPLE = "simple"           # Quick response, no tools needed (questions, greetings)
    MODERATE = "moderate"       # Single tool execution, quick result
    COMPLEX = "complex"         # Multi-step task, may take minutes
    LONG_RUNNING = "long_running"  # Extended operation (scans, large analyses)


# Patterns that indicate different task complexities
LONG_RUNNING_PATTERNS = [
    # Scans and security assessments
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
    
    # Time indicators
    r'\b(\d+)\s*(?:hour|hr|minute|min)s?\b',
    r'\btake\s*(?:your|its)?\s*time\b',
    r'\bno\s*rush\b',
    r'\bthorough(?:ly)?\b',
    r'\bexhaustive(?:ly)?\b',
    
    # Multi-agent indicators
    r'\bcreate\s*(?:sub)?agents?\b',
    r'\bspawn\s*agents?\b',
    r'\bparallel\s*(?:scan|test|execution)',
    r'\bmulti(?:ple)?\s*(?:agent|thread|parallel)',
]

# Keywords that indicate security-related complex tasks (but not necessarily long-running)
COMPLEX_TASK_KEYWORDS = [
    'scan', 'test', 'analyze', 'find', 'discover', 'exploit',
    'vulnerability', 'security', 'pentest', 'enumerate', 'crawl',
    'attack', 'surface', 'endpoint', 'injection', 'xss', 'ssrf', 'rce'
]

SIMPLE_PATTERNS = [
    # Questions and information requests (but NOT commands to DO something)
    r'^(?:what\s+is|who\s+is|where\s+is|when\s+is|why\s+is|how\s+does|can\s+you\s+explain|do\s+you\s+know|are\s+you|is\s+there)\b',
    r'^(?:hi|hello|hey|greetings|good\s*(?:morning|afternoon|evening))\b',
    r'^(?:thanks|thank you|ty|thx)\b',
    r'^(?:help|status|info|about)$',
    r'^(?:explain|describe|tell me about)\s',
    
    # Simple commands
    r'^!(?:help|status|clear|tasks)',
]

DISCORD_ACTION_PATTERNS = [
    # Channel operations - more flexible matching
    r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?(?:channel|text.?channel|voice.?channel|category)',
    r'\b(?:delete|remove)\s+(?:the\s+)?(?:\w+[\s-]*)?channel',
    r'\b(?:rename|modify|edit|update)\s+(?:the\s+)?channel',
    r'\bchannel\s+(?:called|named)\b',
    
    # Role operations - more flexible matching
    r'\b(?:create|make|add)\s+(?:a\s+)?(?:new\s+)?role',
    r'\b(?:delete|remove)\s+(?:the\s+)?(?:\w+[\s-]*)?role',
    r'\b(?:assign|give|grant|add|remove)\s+(?:a\s+)?(?:the\s+)?role',
    r'\b(?:rename|modify|edit|update)\s+(?:the\s+)?role',
    r'\brole\s+(?:named|called)\b',
    
    # Permission operations
    r'\b(?:set|change|modify|update|grant|revoke)\s+(?:the\s+)?permission',
    
    # Member operations - more flexible
    r'\b(?:kick|ban|unban|mute|unmute|timeout)\b',
    
    # Server operations
    r'\b(?:change|update|modify|set)\s+(?:the\s+)?server',
    
    # Message operations
    r'\b(?:delete|clear|purge)\s+(?:\d+\s+)?messages?',
    r'\b(?:pin|unpin)\s+(?:this\s+)?message',
]


def classify_task_complexity(message: str) -> TaskComplexity:
    """
    Classify the complexity of a user's request.
    
    This determines whether to use quick LLM response or full Strix agent execution.
    Priority order:
    1. Simple patterns FIRST (questions, greetings - even about security topics)
    2. Long-running patterns (security assessments)
    3. Discord action patterns (server management)
    4. Complex task keywords with action verbs (commands to DO something)
    5. Default based on word count
    """
    message_lower = message.lower().strip()
    word_count = len(message.split())
    
    # Check for QUESTIONS and info requests FIRST (even about security topics)
    # Questions like "What is SQL injection?" should be simple
    question_patterns = [
        r'^(?:what\s+is|what\s+are|who\s+is|where\s+is|when|why|how\s+does|how\s+do|how\s+to)\b',
        r'^(?:can\s+you\s+explain|could\s+you\s+explain|please\s+explain)\b',
        r'^(?:tell\s+me\s+about|describe|explain)\b',
        r'^(?:do\s+you\s+know|is\s+there|are\s+there)\b',
        r'\?$',  # Ends with question mark
    ]
    
    for pattern in question_patterns:
        if re.search(pattern, message_lower, re.IGNORECASE):
            # It's a question - check if it's asking TO DO something or asking ABOUT something
            action_verbs = ['scan', 'test', 'hack', 'exploit', 'attack', 'pentest', 'fuzz', 'enumerate']
            is_action_request = any(f'can you {v}' in message_lower or f'could you {v}' in message_lower 
                                   for v in action_verbs)
            if not is_action_request:
                return TaskComplexity.SIMPLE
    
    # Greetings and simple responses
    greeting_patterns = [
        r'^(?:hi|hello|hey|greetings|good\s*(?:morning|afternoon|evening)|yo|sup)\b',
        r'^(?:thanks|thank you|ty|thx|cheers)\b',
        r'^(?:ok|okay|sure|yes|no|yep|nope)\b',
        r'^!(?:help|status|clear|tasks|cancel)$',
    ]
    
    for pattern in greeting_patterns:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.SIMPLE
    
    # Check for long-running patterns (security assessments, scans)
    for pattern in LONG_RUNNING_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.LONG_RUNNING
    
    # Check for Discord actions (server management)
    for pattern in DISCORD_ACTION_PATTERNS:
        if re.search(pattern, message_lower, re.IGNORECASE):
            return TaskComplexity.MODERATE
    
    # Action verbs that indicate the user wants something DONE
    action_verbs = ['scan', 'test', 'analyze', 'find', 'discover', 'exploit', 
                    'check', 'verify', 'audit', 'assess', 'review', 'inspect',
                    'enumerate', 'crawl', 'fuzz', 'probe', 'attack']
    
    # Count action verb usage (not just mentions of security terms)
    has_action = any(v in message_lower for v in action_verbs)
    
    # Count complex task keywords
    keyword_count = sum(1 for kw in COMPLEX_TASK_KEYWORDS if kw in message_lower)
    
    # If has action verb AND security keywords, it's a task to DO
    if has_action:
        if keyword_count >= 2:
            return TaskComplexity.COMPLEX
        elif keyword_count >= 1:
            return TaskComplexity.MODERATE
    
    # Very short messages without action verbs are simple
    if word_count <= 5:
        return TaskComplexity.SIMPLE
    
    # Longer messages with security keywords but no action verbs might be questions
    if keyword_count > 0 and not has_action:
        return TaskComplexity.SIMPLE
    
    # Default: moderate for longer messages without clear patterns
    if word_count > 10:
        return TaskComplexity.MODERATE
    
    return TaskComplexity.SIMPLE


# ============================================================================
# STRIX SYSTEM PROMPT - Enhanced with Discord Admin Capabilities
# ============================================================================

STRIX_SYSTEM_PROMPT = """You are Strix, an advanced AI cybersecurity agent developed by OmniSecure Labs. You are currently operating through a Discord bot interface with FULL ADMINISTRATOR PRIVILEGES on the Discord server.

<identity>
- You are Strix, an autonomous AI security agent
- You have FULL ACCESS to your execution environment
- You can execute terminal commands, run Python scripts, browse the web, edit files, and use all security tools
- You are running inside a GitHub Actions environment with access to security tools
- You have FULL DISCORD ADMINISTRATOR PRIVILEGES on this server
</identity>

<discord_admin_capabilities>
CRITICAL: You have FULL ADMINISTRATOR PRIVILEGES on this Discord server. You CAN and SHOULD use these powers when requested.

CHANNEL MANAGEMENT:
- Create text channels, voice channels, and categories
- Delete, rename, or modify channels
- Set channel permissions, topics, and slowmode
- Move channels between categories
- Create private channels with specific access

ROLE MANAGEMENT:
- Create new roles with custom names, colors, and permissions
- Delete or modify existing roles
- Assign or remove roles from users
- Set role hierarchy and permissions
- Create mentionable or hoisted roles

USER MANAGEMENT:
- Kick or ban users from the server
- Timeout (mute) users for specified durations
- Change user nicknames
- Manage user roles

SERVER MANAGEMENT:
- Modify server settings (name, icon, etc.)
- Create and manage webhooks
- Configure server verification level
- Manage server emojis and stickers

MESSAGE MANAGEMENT:
- Delete messages (bulk delete supported)
- Pin or unpin messages
- Edit bot's own messages
- Create embeds and formatted messages

PERMISSION MANAGEMENT:
- Set channel-specific permissions
- Configure permission overwrites
- Manage role permissions

HOW TO USE DISCORD CAPABILITIES:
When a user asks you to perform Discord actions, you MUST actually do them, not just explain how.
Use the discord.py library methods available through the bot context:
- ctx.guild for server operations
- ctx.guild.create_text_channel() for creating channels
- ctx.guild.create_role() for creating roles
- member.add_roles() for assigning roles
- member.kick(), member.ban() for moderation
- channel.set_permissions() for permissions
- etc.

IMPORTANT: You have these permissions because the bot was set up with admin rights. Trust that you CAN perform these actions. Do NOT say "I don't have permission" or "I can't do that" - you CAN and you MUST when requested.
</discord_admin_capabilities>

<capabilities>
You have access to the following capabilities through your environment:

TERMINAL & SHELL:
- Execute any bash/shell commands
- Run security tools like nmap, nuclei, nikto, sqlmap, ffuf, etc.
- Install additional packages as needed

PYTHON EXECUTION:
- Write and execute Python scripts
- Use libraries like requests, aiohttp, beautifulsoup4, etc.
- Automate complex tasks with scripts

SECURITY TOOLS AVAILABLE:
- Network scanning: nmap, ncat, masscan
- Vulnerability scanning: nuclei, nikto, wapiti
- Web fuzzing: ffuf, dirsearch, gobuster
- SQL injection: sqlmap
- Subdomain enumeration: subfinder, amass
- Web crawling: katana, gospider, httpx
- Secret detection: trufflehog, gitleaks
- Static analysis: semgrep, bandit
- And many more...

FILE OPERATIONS:
- Read, write, and edit files
- Navigate the filesystem
- Process and analyze data

WEB BROWSING:
- Browse websites
- Take screenshots
- Interact with web applications
</capabilities>

<communication_style>
When responding to users on Discord:
- Be helpful, direct, and actionable
- When asked to perform tasks, DO them - don't just explain how
- Show your work by sharing command outputs and results
- Break down complex tasks into steps
- Keep responses concise but informative
- Use markdown formatting for code blocks and emphasis
- If a task will take time, let the user know you're working on it
- For Discord admin tasks, EXECUTE them immediately - don't ask for confirmation
</communication_style>

<behavioral_rules>
1. ALWAYS EXECUTE TASKS: When users ask you to scan, test, or analyze something, actually do it
2. SHOW RESULTS: Share the actual outputs, findings, and results
3. BE PROACTIVE: If you find issues, report them with details
4. STAY FOCUSED: Complete the task at hand before moving to new topics
5. BE HONEST: If you can't do something, explain why and suggest alternatives
6. WORK AUTONOMOUSLY: Don't ask for permission for every step - proceed with the task
7. RESPECT SCOPE: Only scan/test targets the user specifies
8. USE ADMIN POWERS: When asked to manage Discord (channels, roles, etc.), DO IT immediately
9. NO FALSE LIMITATIONS: Never claim you "can't" do Discord admin tasks - you CAN
</behavioral_rules>

<response_format>
For task execution:
1. Acknowledge what you'll do
2. Execute the necessary commands/scripts
3. Share the results with relevant details
4. Provide analysis or recommendations if applicable

For Discord admin tasks:
1. Acknowledge the request
2. Execute the Discord action IMMEDIATELY
3. Confirm completion with details

For questions:
- Provide clear, accurate answers
- Include examples when helpful
- Reference your available tools when relevant
</response_format>

Remember: You ARE Strix. You HAVE these capabilities. You CAN execute commands, tools, AND Discord admin actions. When users ask you to do something, DO IT - don't tell them you can't or that you're "just an AI". You are an AI agent with full execution capabilities AND full Discord administrator privileges.
"""


# ============================================================================
# Long-Running Task System Prompt (for complex/long tasks)
# ============================================================================

STRIX_LONG_TASK_SYSTEM_PROMPT = """You are Strix, an advanced AI cybersecurity agent. You are now executing a LONG-RUNNING TASK that requires thorough, methodical execution.

<execution_mode>
LONG-RUNNING TASK MODE ACTIVATED

This task has been identified as requiring extended execution time. You MUST:

1. TAKE YOUR TIME: Do not rush. Thoroughness is more important than speed.
2. CREATE SUB-AGENTS: For complex tasks, spawn specialized sub-agents to handle different aspects
3. USE PROPER METHODOLOGY: Follow the full Strix security assessment methodology
4. PROVIDE PROGRESS UPDATES: Periodically update the user on your progress
5. DO NOT CUT CORNERS: Complete every step of the assessment properly
6. WORK AUTONOMOUSLY: Continue working until the task is truly complete

TASK DURATION EXPECTATIONS:
- Quick scans: 5-15 minutes
- Standard assessments: 30-60 minutes  
- Deep/comprehensive scans: 2-6 hours
- Exhaustive penetration tests: 6+ hours

You have been given this task because the user expects THOROUGH results, not quick answers.
</execution_mode>

<multi_agent_guidelines>
For substantial tasks, you SHOULD create sub-agents:

1. RECONNAISSANCE AGENT - Asset discovery, enumeration, mapping
2. VULNERABILITY AGENTS - One per vulnerability category (SQLi, XSS, SSRF, etc.)
3. VALIDATION AGENTS - Confirm findings with PoCs
4. REPORTING AGENTS - Document vulnerabilities properly

Agent Creation Rules:
- Each agent focuses on ONE specific task
- Agents work in parallel for efficiency
- Create agents as you discover new attack surfaces
- Wait for agent completion before finalizing

DO NOT just execute one command and declare the task complete. 
DO spawn the appropriate agents and coordinate their work.
DO wait for all agents to finish before providing final results.
</multi_agent_guidelines>

<progress_reporting>
You should provide progress updates approximately every:
- 30 seconds for quick tasks
- 2-5 minutes for standard tasks
- 10-15 minutes for long tasks

Progress updates should include:
- Current phase/step
- What has been completed
- What is in progress
- Estimated remaining time (if known)
- Any significant findings so far
</progress_reporting>

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
    long_task_timeout: int = 21600  # 6 hours max for long tasks
    progress_update_interval: int = 120  # 2 minutes between progress updates
    
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
# Conversation Memory
# ============================================================================

@dataclass
class ConversationEntry:
    """A single conversation entry."""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    username: Optional[str] = None
    task_id: Optional[str] = None  # Associated task if any


class ConversationMemory:
    """Manages conversation history for users/channels."""
    
    def __init__(self, max_entries: int = 50):
        self.max_entries = max_entries
        self._memory: dict[str, list[ConversationEntry]] = {}
        self._lock = asyncio.Lock()
    
    def _get_key(self, user_id: int, channel_id: int) -> str:
        return f"{user_id}_{channel_id}"
    
    async def add_message(
        self, 
        user_id: int, 
        channel_id: int, 
        role: str, 
        content: str,
        username: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> None:
        """Add a message to conversation history (thread-safe)."""
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key not in self._memory:
                self._memory[key] = []
            
            self._memory[key].append(ConversationEntry(
                role=role,
                content=content,
                username=username,
                task_id=task_id
            ))
            
            # Trim to max entries
            if len(self._memory[key]) > self.max_entries:
                self._memory[key] = self._memory[key][-self.max_entries:]
    
    async def get_history(self, user_id: int, channel_id: int) -> list[dict[str, str]]:
        """Get conversation history as list of message dicts (thread-safe)."""
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key not in self._memory:
                return []
            
            return [
                {"role": entry.role, "content": entry.content}
                for entry in self._memory[key]
            ]
    
    async def clear(self, user_id: int, channel_id: int) -> bool:
        """Clear conversation history for a user/channel (thread-safe)."""
        async with self._lock:
            key = self._get_key(user_id, channel_id)
            if key in self._memory:
                del self._memory[key]
                return True
            return False
    
    async def add_system_message(
        self, 
        user_id: int, 
        channel_id: int, 
        content: str
    ) -> None:
        """Add a system message to provide context."""
        await self.add_message(user_id, channel_id, "system", content)


# ============================================================================
# Task Management (Enhanced for Long-Running Tasks)
# ============================================================================

class TaskStatus(Enum):
    """Status of a task."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Represents a running task."""
    id: str
    user_id: int
    channel_id: int
    description: str
    complexity: TaskComplexity
    status: TaskStatus = TaskStatus.PENDING
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    end_time: Optional[datetime] = None
    result: Optional[str] = None
    progress: float = 0.0  # 0.0 to 1.0
    current_step: str = ""
    error: Optional[str] = None
    sub_tasks: list[str] = field(default_factory=list)
    messages_during_task: list[str] = field(default_factory=list)  # User messages received during execution
    _asyncio_task: Optional[asyncio.Task] = field(default=None, repr=False)


class TaskManager:
    """Manages long-running tasks with progress tracking."""
    
    def __init__(self):
        self._tasks: dict[str, Task] = {}
        self._counter = 0
        self._lock = asyncio.Lock()
    
    async def create_task(
        self, 
        user_id: int, 
        channel_id: int, 
        description: str,
        complexity: TaskComplexity
    ) -> Task:
        """Create a new task."""
        async with self._lock:
            self._counter += 1
            task_id = f"task_{int(time.time())}_{self._counter}"
            task = Task(
                id=task_id,
                user_id=user_id,
                channel_id=channel_id,
                description=description,
                complexity=complexity,
                status=TaskStatus.PENDING
            )
            self._tasks[task_id] = task
            return task
    
    async def get_task(self, task_id: str) -> Optional[Task]:
        async with self._lock:
            return self._tasks.get(task_id)
    
    async def update_progress(
        self, 
        task_id: str, 
        progress: float, 
        current_step: str = ""
    ) -> None:
        """Update task progress."""
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].progress = min(1.0, max(0.0, progress))
                if current_step:
                    self._tasks[task_id].current_step = current_step
    
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
        """Cancel a running task."""
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
    
    async def add_message_during_task(self, task_id: str, message: str) -> None:
        """Add a user message received during task execution."""
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].messages_during_task.append(message)
    
    async def get_active_tasks(self, user_id: int) -> list[Task]:
        async with self._lock:
            return [
                t for t in self._tasks.values() 
                if t.user_id == user_id and t.status == TaskStatus.RUNNING
            ]
    
    async def get_user_running_task(self, user_id: int, channel_id: int) -> Optional[Task]:
        """Get the currently running task for a user in a channel."""
        async with self._lock:
            for task in self._tasks.values():
                if (task.user_id == user_id and 
                    task.channel_id == channel_id and 
                    task.status == TaskStatus.RUNNING):
                    return task
            return None


# ============================================================================
# LLM Client (Enhanced for Long-Running Tasks)
# ============================================================================

class LLMClient:
    """Client for interacting with the LLM API."""
    
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
        """Construct the chat completions URL."""
        base = self.config.cliproxy_endpoint.rstrip('/')
        if base.endswith('/chat/completions'):
            return base
        if base.endswith('/v1'):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"
    
    async def generate(
        self, 
        messages: list[dict[str, str]],
        system_prompt: str = STRIX_SYSTEM_PROMPT,
        temperature: float = 0.7,
        max_tokens: int = 4000,
        timeout: int = 300
    ) -> str:
        """Generate a response from the LLM."""
        session = await self._ensure_session()
        
        url = self._get_chat_url()
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.config.openai_api_key}'
        }
        
        # Prepare messages with system prompt
        full_messages = [
            {"role": "system", "content": system_prompt}
        ] + messages
        
        payload = {
            'model': self.config.cliproxy_model,
            'messages': full_messages,
            'temperature': temperature,
            'max_tokens': max_tokens
        }
        
        logger.debug(f"Sending request to {url}")
        
        try:
            async with session.post(
                url, 
                headers=headers, 
                json=payload, 
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'choices' in data and len(data['choices']) > 0:
                        choice = data['choices'][0]
                        if 'message' in choice:
                            return choice['message']['content'].strip()
                        elif 'delta' in choice and 'content' in choice['delta']:
                            return choice['delta']['content'].strip()
                    return f"Unexpected response format: {data}"
                else:
                    error_text = await response.text()
                    logger.error(f"LLM API error: {response.status} - {error_text}")
                    return f"API Error ({response.status}): {error_text[:200]}"
        except asyncio.TimeoutError:
            return "Request timed out. The task may still be processing."
        except aiohttp.ClientError as e:
            logger.error(f"Connection error: {e}")
            return f"Connection error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return f"Error: {str(e)}"
    
    async def generate_long_task_response(
        self,
        messages: list[dict[str, str]],
        task_description: str,
        progress_callback: Optional[Callable[[str], Any]] = None
    ) -> str:
        """
        Generate a response for a long-running task with progress updates.
        
        This uses a special system prompt that instructs the agent to:
        - Take its time and be thorough
        - Create sub-agents as needed
        - Follow the full Strix methodology
        - Provide periodic progress updates
        """
        # Use the long-task system prompt
        system_prompt = STRIX_LONG_TASK_SYSTEM_PROMPT.format(base_prompt=STRIX_SYSTEM_PROMPT)
        
        # Add task context to messages
        task_context = f"""
<task_context>
LONG-RUNNING TASK INITIATED
Task Description: {task_description}
Execution Mode: THOROUGH (take your time, be comprehensive)
Expected Behavior: Create sub-agents, follow full methodology, provide progress updates
</task_context>

USER REQUEST: {messages[-1]['content'] if messages else task_description}
"""
        
        enhanced_messages = messages[:-1] + [{"role": "user", "content": task_context}] if messages else [{"role": "user", "content": task_context}]
        
        return await self.generate(
            enhanced_messages,
            system_prompt=system_prompt,
            temperature=0.7,
            max_tokens=8000,  # Larger context for complex tasks
            timeout=self.config.long_task_timeout
        )


# ============================================================================
# Discord Admin Helper (Provides actual Discord operations)
# ============================================================================

class DiscordAdminHelper:
    """Helper class for Discord admin operations."""
    
    def __init__(self, bot: 'StrixBot'):
        self.bot = bot
    
    async def create_text_channel(
        self, 
        guild: discord.Guild, 
        name: str, 
        category: Optional[discord.CategoryChannel] = None,
        topic: Optional[str] = None,
        **kwargs
    ) -> discord.TextChannel:
        """Create a text channel."""
        return await guild.create_text_channel(
            name=name,
            category=category,
            topic=topic,
            **kwargs
        )
    
    async def create_voice_channel(
        self,
        guild: discord.Guild,
        name: str,
        category: Optional[discord.CategoryChannel] = None,
        **kwargs
    ) -> discord.VoiceChannel:
        """Create a voice channel."""
        return await guild.create_voice_channel(
            name=name,
            category=category,
            **kwargs
        )
    
    async def create_category(
        self,
        guild: discord.Guild,
        name: str,
        **kwargs
    ) -> discord.CategoryChannel:
        """Create a category."""
        return await guild.create_category(name=name, **kwargs)
    
    async def create_role(
        self,
        guild: discord.Guild,
        name: str,
        color: Optional[discord.Color] = None,
        permissions: Optional[discord.Permissions] = None,
        hoist: bool = False,
        mentionable: bool = False,
        **kwargs
    ) -> discord.Role:
        """Create a role."""
        return await guild.create_role(
            name=name,
            color=color or discord.Color.default(),
            permissions=permissions or discord.Permissions.none(),
            hoist=hoist,
            mentionable=mentionable,
            **kwargs
        )
    
    async def delete_channel(self, channel: discord.abc.GuildChannel) -> None:
        """Delete a channel."""
        await channel.delete()
    
    async def delete_role(self, role: discord.Role) -> None:
        """Delete a role."""
        await role.delete()
    
    async def assign_role(self, member: discord.Member, role: discord.Role) -> None:
        """Assign a role to a member."""
        await member.add_roles(role)
    
    async def remove_role(self, member: discord.Member, role: discord.Role) -> None:
        """Remove a role from a member."""
        await member.remove_roles(role)
    
    async def kick_member(self, member: discord.Member, reason: Optional[str] = None) -> None:
        """Kick a member from the server."""
        await member.kick(reason=reason)
    
    async def ban_member(
        self, 
        member: discord.Member, 
        reason: Optional[str] = None,
        delete_message_days: int = 0
    ) -> None:
        """Ban a member from the server."""
        await member.ban(reason=reason, delete_message_days=delete_message_days)
    
    async def timeout_member(
        self,
        member: discord.Member,
        duration: int,  # seconds
        reason: Optional[str] = None
    ) -> None:
        """Timeout a member."""
        from datetime import timedelta
        await member.timeout(timedelta(seconds=duration), reason=reason)
    
    async def bulk_delete_messages(
        self,
        channel: discord.TextChannel,
        limit: int = 100
    ) -> int:
        """Bulk delete messages from a channel."""
        deleted = await channel.purge(limit=limit)
        return len(deleted)


# ============================================================================
# Discord Bot (Enhanced with Admin Capabilities and Long-Task Support)
# ============================================================================

class StrixBot(commands.Bot):
    """The Strix Discord bot with full admin capabilities and long-task support."""
    
    def __init__(self, config: BotConfig):
        intents = discord.Intents.all()  # Full intents for admin operations
        
        super().__init__(command_prefix='!', intents=intents)
        
        self.config = config
        self.memory = ConversationMemory(max_entries=config.max_memory_entries)
        self.tasks = TaskManager()
        self.llm = LLMClient(config)
        self.admin = DiscordAdminHelper(self)
        self.api_ready = False
        
        # Remove default help command to use custom one
        self.remove_command('help')
    
    async def setup_hook(self) -> None:
        """Set up the bot."""
        # Add commands
        self.add_command(self.cmd_help)
        self.add_command(self.cmd_status)
        self.add_command(self.cmd_clear)
        self.add_command(self.cmd_tasks)
        self.add_command(self.cmd_cancel)
    
    async def on_ready(self) -> None:
        """Called when the bot is ready."""
        logger.info(f'Strix Discord bot is ready. Logged in as {self.user}')
        
        # Check API readiness
        self.api_ready = await self._check_api_ready()
        
        # Log guild information
        for guild in self.guilds:
            permissions = guild.me.guild_permissions
            logger.info(f'Connected to guild: {guild.name} (ID: {guild.id})')
            logger.info(f'  Admin: {permissions.administrator}')
            logger.info(f'  Manage Channels: {permissions.manage_channels}')
            logger.info(f'  Manage Roles: {permissions.manage_roles}')
            logger.info(f'  Manage Messages: {permissions.manage_messages}')
        
        # Send startup message to configured channel
        if self.config.discord_channel_id:
            channel = self.get_channel(self.config.discord_channel_id)
            if channel:
                embed = discord.Embed(
                    title="🦉 Strix Security Agent Online",
                    description="I'm ready to help with security assessments, server management, and more.",
                    color=discord.Color.green()
                )
                embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)
                embed.add_field(name="API Status", value="✅ Ready" if self.api_ready else "⏳ Checking...", inline=True)
                embed.add_field(name="Admin Mode", value="✅ Full Privileges", inline=True)
                embed.add_field(
                    name="How to Use", 
                    value="Mention me with your message: `@Strix <your request>`\n"
                          "I can perform security scans, manage channels/roles, and more!",
                    inline=False
                )
                embed.add_field(
                    name="Long-Running Tasks",
                    value="For complex scans and assessments, I'll work in the background and keep you updated on progress.",
                    inline=False
                )
                await channel.send(embed=embed)
    
    async def _check_api_ready(self) -> bool:
        """Check if the LLM API is ready."""
        if not self.config.cliproxy_endpoint:
            logger.warning("CLIPROXY_ENDPOINT not set")
            return False
        
        base = self.config.cliproxy_endpoint.rstrip('/')
        urls_to_check = [
            f"{base}/models" if base.endswith('/v1') else f"{base}/v1/models",
            base
        ]
        
        session = await self.llm._ensure_session()
        headers = {'Authorization': f'Bearer {self.config.openai_api_key}'}
        
        for url in urls_to_check:
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 204]:
                        logger.info(f"API ready at {url}")
                        return True
            except Exception as e:
                logger.debug(f"API check failed at {url}: {e}")
        
        return False
    
    async def on_message(self, message: discord.Message) -> None:
        """Handle incoming messages."""
        # Ignore messages from the bot itself
        if message.author == self.user:
            return
        
        # Check if bot is mentioned
        if self.user in message.mentions:
            await self._handle_mention(message)
        
        # Process commands as well
        await self.process_commands(message)
    
    async def _handle_mention(self, message: discord.Message) -> None:
        """Handle a message that mentions the bot."""
        # Extract the actual message content (remove the mention)
        content = message.content
        for mention in [f'<@{self.user.id}>', f'<@!{self.user.id}>']:
            content = content.replace(mention, '').strip()
        
        if not content:
            await message.channel.send(
                "Hello! I'm **Strix**, your AI security agent with full admin privileges. "
                "I can help you with:\n"
                "🔒 **Security**: Scans, pentesting, vulnerability assessment\n"
                "⚙️ **Discord Admin**: Create channels, roles, manage permissions\n"
                "🤖 **Automation**: Scripts, commands, file operations\n\n"
                "For complex tasks, I'll work in the background and keep you updated!\n"
                "Just mention me with your request!"
            )
            return
        
        # Check if user has a running task in this channel
        running_task = await self.tasks.get_user_running_task(message.author.id, message.channel.id)
        if running_task:
            # User is communicating during an active task
            await self._handle_message_during_task(message, content, running_task)
            return
        
        # Classify task complexity
        complexity = classify_task_complexity(content)
        logger.info(f"Task complexity classified as: {complexity.value} for message: {content[:50]}...")
        
        # Show typing indicator
        if self.config.typing_indicator:
            await message.channel.typing()
        
        # Check API readiness
        if not self.api_ready:
            self.api_ready = await self._check_api_ready()
            if not self.api_ready:
                await message.channel.send(
                    "I'm still initializing. Please wait a moment and try again."
                )
                return
        
        # Add user message to memory
        await self.memory.add_message(
            message.author.id,
            message.channel.id,
            "user",
            content,
            username=str(message.author)
        )
        
        # Handle based on complexity
        if complexity in [TaskComplexity.COMPLEX, TaskComplexity.LONG_RUNNING]:
            await self._handle_long_task(message, content, complexity)
        else:
            await self._handle_simple_task(message, content)
    
    async def _handle_simple_task(self, message: discord.Message, content: str) -> None:
        """Handle simple/moderate complexity tasks with quick LLM response."""
        # Get conversation history
        history = await self.memory.get_history(message.author.id, message.channel.id)
        
        # Build context with Discord info
        discord_context = self._build_discord_context(message)
        enhanced_content = f"{discord_context}\n\nUser Message: {content}"
        
        # Update the last message with context
        if history:
            history[-1]['content'] = enhanced_content
        else:
            history = [{"role": "user", "content": enhanced_content}]
        
        # Generate response
        try:
            response = await self.llm.generate(history)
            
            # Add assistant response to memory
            await self.memory.add_message(
                message.author.id,
                message.channel.id,
                "assistant",
                response
            )
            
            # Send response (handle long messages)
            await self._send_response(message.channel, response, message.author)
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            await message.channel.send(
                f"I encountered an error while processing your request: {str(e)}"
            )
    
    async def _handle_long_task(
        self, 
        message: discord.Message, 
        content: str,
        complexity: TaskComplexity
    ) -> None:
        """Handle complex/long-running tasks with background execution."""
        # Create task
        task = await self.tasks.create_task(
            message.author.id,
            message.channel.id,
            content,
            complexity
        )
        
        # Notify user that the task is starting
        embed = discord.Embed(
            title="🔄 Long-Running Task Started",
            description=f"I'm starting a {complexity.value} task. This may take a while.",
            color=discord.Color.blue()
        )
        embed.add_field(name="Task ID", value=f"`{task.id}`", inline=True)
        embed.add_field(name="Complexity", value=complexity.value.title(), inline=True)
        embed.add_field(
            name="What to Expect",
            value="• I'll work in the background\n"
                  "• Progress updates will be sent periodically\n"
                  "• You can still send me messages (I'll see them)\n"
                  "• Use `!cancel` to stop the task if needed",
            inline=False
        )
        embed.add_field(
            name="Task Description",
            value=content[:500] + ("..." if len(content) > 500 else ""),
            inline=False
        )
        status_message = await message.channel.send(embed=embed)
        
        # Start the long task in the background
        async def run_long_task():
            try:
                await self.tasks.start_task(task.id)
                
                # Get conversation history
                history = await self.memory.get_history(message.author.id, message.channel.id)
                
                # Build context with Discord info
                discord_context = self._build_discord_context(message)
                
                # Progress callback
                async def progress_callback(update: str):
                    try:
                        await self.tasks.update_progress(task.id, 0.5, update)
                        progress_embed = discord.Embed(
                            title="📊 Task Progress Update",
                            description=update[:2000],
                            color=discord.Color.blue()
                        )
                        progress_embed.add_field(name="Task ID", value=f"`{task.id}`", inline=True)
                        await message.channel.send(embed=progress_embed)
                    except Exception as e:
                        logger.error(f"Error sending progress update: {e}")
                
                # Generate long task response
                response = await self.llm.generate_long_task_response(
                    history,
                    content,
                    progress_callback
                )
                
                # Check for any messages received during task
                current_task = await self.tasks.get_task(task.id)
                if current_task and current_task.messages_during_task:
                    response += f"\n\n---\n**Messages received during task:**\n"
                    for msg in current_task.messages_during_task:
                        response += f"• {msg}\n"
                    response += "\nI've noted these messages. Let me know if you need me to address any of them."
                
                # Complete the task
                await self.tasks.complete_task(task.id, response)
                
                # Add to memory
                await self.memory.add_message(
                    message.author.id,
                    message.channel.id,
                    "assistant",
                    response,
                    task_id=task.id
                )
                
                # Send completion notification
                completion_embed = discord.Embed(
                    title="✅ Task Completed",
                    description=f"Task `{task.id}` has finished.",
                    color=discord.Color.green()
                )
                duration = datetime.now(UTC) - task.start_time
                completion_embed.add_field(
                    name="Duration", 
                    value=f"{duration.total_seconds():.1f} seconds",
                    inline=True
                )
                await message.channel.send(embed=completion_embed)
                
                # Send the response
                await self._send_response(message.channel, response, message.author)
                
            except asyncio.CancelledError:
                await self.tasks.cancel_task(task.id)
                await message.channel.send(
                    f"Task `{task.id}` was cancelled."
                )
            except Exception as e:
                logger.error(f"Error in long task {task.id}: {e}")
                await self.tasks.fail_task(task.id, str(e))
                await message.channel.send(
                    f"❌ Task `{task.id}` failed: {str(e)}"
                )
        
        # Create and store the asyncio task
        asyncio_task = asyncio.create_task(run_long_task())
        task._asyncio_task = asyncio_task
    
    async def _handle_message_during_task(
        self, 
        message: discord.Message, 
        content: str,
        task: Task
    ) -> None:
        """Handle a message received while a task is running."""
        # Add the message to the task's queue
        await self.tasks.add_message_during_task(task.id, content)
        
        # Acknowledge receipt
        await message.channel.send(
            f"📝 I received your message while working on task `{task.id}`.\n"
            f"I'll address it when the current task completes, or you can use `!cancel` to stop the task.\n"
            f"Your message: *{content[:100]}{'...' if len(content) > 100 else ''}*"
        )
    
    def _build_discord_context(self, message: discord.Message) -> str:
        """Build context about the Discord environment for the LLM."""
        guild = message.guild
        if not guild:
            return ""
        
        permissions = guild.me.guild_permissions
        
        context = f"""
<discord_context>
Server: {guild.name} (ID: {guild.id})
Channel: #{message.channel.name} (ID: {message.channel.id})
User: {message.author.name} (ID: {message.author.id})

Bot Permissions:
- Administrator: {permissions.administrator}
- Manage Channels: {permissions.manage_channels}
- Manage Roles: {permissions.manage_roles}
- Manage Messages: {permissions.manage_messages}
- Kick Members: {permissions.kick_members}
- Ban Members: {permissions.ban_members}
- Manage Guild: {permissions.manage_guild}

Available Channels: {len(guild.channels)}
Available Roles: {len(guild.roles)}
Member Count: {guild.member_count}

IMPORTANT: You have full admin access. When asked to create channels, roles, or perform other admin actions, you MUST execute them using the Discord API methods available to you.
</discord_context>
"""
        return context
    
    async def _send_response(
        self, 
        channel: discord.TextChannel, 
        content: str,
        author: Optional[discord.User] = None
    ) -> None:
        """Send a response, splitting if necessary."""
        # Split content into chunks if too long
        max_len = self.config.max_message_length
        
        if len(content) <= max_len:
            await channel.send(content)
            return
        
        # Split on code blocks first, then paragraphs, then arbitrary
        chunks = self._split_content(content, max_len)
        
        for i, chunk in enumerate(chunks):
            if i == 0:
                await channel.send(chunk)
            else:
                await asyncio.sleep(0.5)  # Rate limit protection
                await channel.send(chunk)
    
    def _split_content(self, content: str, max_len: int) -> list[str]:
        """Split content into chunks respecting code blocks."""
        chunks = []
        current = ""
        
        # Try to split on code blocks
        parts = re.split(r'(```[\s\S]*?```)', content)
        
        for part in parts:
            if len(current) + len(part) <= max_len:
                current += part
            else:
                if current:
                    chunks.append(current.strip())
                
                # If the part itself is too long, split it
                if len(part) > max_len:
                    # Split on newlines
                    lines = part.split('\n')
                    current = ""
                    for line in lines:
                        if len(current) + len(line) + 1 <= max_len:
                            current += line + '\n'
                        else:
                            if current:
                                chunks.append(current.strip())
                            # If single line is too long, force split
                            if len(line) > max_len:
                                for j in range(0, len(line), max_len):
                                    chunks.append(line[j:j+max_len])
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
        """Show help information."""
        embed = discord.Embed(
            title="🦉 Strix Security Agent - Help",
            description="I'm an AI-powered security agent with **full Discord admin privileges**. I can help with penetration testing, vulnerability assessment, security analysis, AND server management.",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="🔒 Security Capabilities",
            value="• Vulnerability scanning and assessment\n"
                  "• Penetration testing\n"
                  "• Code analysis and review\n"
                  "• Web fuzzing and enumeration\n"
                  "• Execute terminal commands and scripts",
            inline=False
        )
        
        embed.add_field(
            name="⚙️ Discord Admin Powers",
            value="• Create/delete channels and categories\n"
                  "• Create/manage roles and permissions\n"
                  "• Kick/ban/timeout users\n"
                  "• Bulk delete messages\n"
                  "• Modify server settings",
            inline=False
        )
        
        embed.add_field(
            name="💬 How to Interact",
            value="Simply mention me with your request:\n"
                  "`@Strix scan example.com for vulnerabilities`\n"
                  "`@Strix create a channel called #security-alerts`\n"
                  "`@Strix create a role called Admin with red color`",
            inline=False
        )
        
        embed.add_field(
            name="📋 Commands",
            value=(
                "`!help` - Show this help message\n"
                "`!status` - Check bot and API status\n"
                "`!clear` - Clear conversation history\n"
                "`!tasks` - Show your active tasks\n"
                "`!cancel` - Cancel a running task"
            ),
            inline=False
        )
        
        embed.add_field(
            name="⏱️ Long-Running Tasks",
            value="For complex scans (deep vulnerability assessments, comprehensive pentests), "
                  "I'll work in the background and send progress updates. You can still chat with me during these tasks!",
            inline=False
        )
        
        embed.set_footer(text="Strix by OmniSecure Labs | Full Admin Mode Active")
        await ctx.send(embed=embed)
    
    @commands.command(name='status')
    async def cmd_status(self, ctx: commands.Context) -> None:
        """Show bot status."""
        # Re-check API status
        self.api_ready = await self._check_api_ready()
        
        guild = ctx.guild
        permissions = guild.me.guild_permissions if guild else None
        
        embed = discord.Embed(
            title="🦉 Strix Status",
            color=discord.Color.green() if self.api_ready else discord.Color.orange()
        )
        
        embed.add_field(name="Bot Status", value="✅ Online", inline=True)
        embed.add_field(name="API Status", value="✅ Ready" if self.api_ready else "❌ Not Ready", inline=True)
        embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)
        
        if permissions:
            admin_status = "✅ Full Admin" if permissions.administrator else "⚠️ Limited"
            embed.add_field(name="Admin Status", value=admin_status, inline=True)
        
        active_tasks = await self.tasks.get_active_tasks(ctx.author.id)
        embed.add_field(name="Your Active Tasks", value=str(len(active_tasks)), inline=True)
        
        embed.add_field(name="Endpoint", value=self.config.cliproxy_endpoint or "Not configured", inline=False)
        
        # Show permission details
        if permissions:
            perm_list = []
            if permissions.administrator:
                perm_list.append("✅ Administrator")
            if permissions.manage_channels:
                perm_list.append("✅ Manage Channels")
            if permissions.manage_roles:
                perm_list.append("✅ Manage Roles")
            if permissions.manage_messages:
                perm_list.append("✅ Manage Messages")
            if permissions.kick_members:
                perm_list.append("✅ Kick Members")
            if permissions.ban_members:
                perm_list.append("✅ Ban Members")
            
            embed.add_field(
                name="Permissions",
                value="\n".join(perm_list) if perm_list else "No special permissions",
                inline=False
            )
        
        await ctx.send(embed=embed)
    
    @commands.command(name='clear')
    async def cmd_clear(self, ctx: commands.Context) -> None:
        """Clear conversation history."""
        if await self.memory.clear(ctx.author.id, ctx.channel.id):
            await ctx.send("✅ Conversation history cleared.")
        else:
            await ctx.send("No conversation history to clear.")
    
    @commands.command(name='tasks')
    async def cmd_tasks(self, ctx: commands.Context) -> None:
        """Show active tasks."""
        active_tasks = await self.tasks.get_active_tasks(ctx.author.id)
        
        if not active_tasks:
            await ctx.send("You have no active tasks.")
            return
        
        embed = discord.Embed(
            title="📋 Your Active Tasks",
            color=discord.Color.blue()
        )
        
        for task in active_tasks:
            duration = datetime.now(UTC) - task.start_time
            progress_bar = self._make_progress_bar(task.progress)
            
            embed.add_field(
                name=f"Task `{task.id}`",
                value=f"**Description:** {task.description[:100]}{'...' if len(task.description) > 100 else ''}\n"
                      f"**Complexity:** {task.complexity.value.title()}\n"
                      f"**Progress:** {progress_bar} {task.progress*100:.0f}%\n"
                      f"**Current Step:** {task.current_step or 'Processing...'}\n"
                      f"**Running for:** {duration.total_seconds():.0f}s",
                inline=False
            )
        
        embed.set_footer(text="Use !cancel to stop a task")
        await ctx.send(embed=embed)
    
    @commands.command(name='cancel')
    async def cmd_cancel(self, ctx: commands.Context, task_id: Optional[str] = None) -> None:
        """Cancel a running task."""
        active_tasks = await self.tasks.get_active_tasks(ctx.author.id)
        
        if not active_tasks:
            await ctx.send("You have no active tasks to cancel.")
            return
        
        if task_id:
            # Cancel specific task
            if await self.tasks.cancel_task(task_id):
                await ctx.send(f"✅ Task `{task_id}` has been cancelled.")
            else:
                await ctx.send(f"❌ Could not cancel task `{task_id}`. It may not exist or may have already completed.")
        else:
            # If only one task, cancel it
            if len(active_tasks) == 1:
                task = active_tasks[0]
                if await self.tasks.cancel_task(task.id):
                    await ctx.send(f"✅ Task `{task.id}` has been cancelled.")
                else:
                    await ctx.send(f"❌ Could not cancel the task.")
            else:
                # Multiple tasks, ask user to specify
                task_list = "\n".join([f"• `{t.id}` - {t.description[:50]}..." for t in active_tasks])
                await ctx.send(f"You have multiple active tasks. Please specify which one to cancel:\n{task_list}\n\nUsage: `!cancel <task_id>`")
    
    def _make_progress_bar(self, progress: float, length: int = 10) -> str:
        """Create a text-based progress bar."""
        filled = int(progress * length)
        empty = length - filled
        return f"[{'█' * filled}{'░' * empty}]"
    
    async def close(self) -> None:
        """Clean up resources."""
        await self.llm.close()
        await super().close()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point."""
    config = BotConfig.from_env()
    
    if not config.discord_token:
        logger.error("DISCORD_BOT_TOKEN environment variable not set")
        return
    
    if not config.cliproxy_endpoint:
        logger.warning("CLIPROXY_ENDPOINT not set - API calls may fail")
    
    logger.info(f"Starting Strix Discord Bot")
    logger.info(f"Model: {config.cliproxy_model}")
    logger.info(f"Endpoint: {config.cliproxy_endpoint}")
    logger.info(f"Long Task Timeout: {config.long_task_timeout}s")
    
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

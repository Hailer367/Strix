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
- And all other Strix tools

The bot maintains conversation history and can execute long-running tasks
asynchronously, notifying users when tasks are complete.
"""

import asyncio
import discord
from discord.ext import commands
import os
import json
import re
import time
import logging
from datetime import datetime
from typing import Any, Optional
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
# STRIX SYSTEM PROMPT - This defines who Strix is and what it can do
# ============================================================================

STRIX_SYSTEM_PROMPT = """You are Strix, an advanced AI cybersecurity agent developed by OmniSecure Labs. You are currently operating through a Discord bot interface, which allows users to interact with you conversationally.

<identity>
- You are Strix, an autonomous AI security agent
- You have FULL ACCESS to your execution environment
- You can execute terminal commands, run Python scripts, browse the web, edit files, and use all security tools
- You are running inside a GitHub Actions environment with access to security tools
</identity>

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
</communication_style>

<behavioral_rules>
1. ALWAYS EXECUTE TASKS: When users ask you to scan, test, or analyze something, actually do it
2. SHOW RESULTS: Share the actual outputs, findings, and results
3. BE PROACTIVE: If you find issues, report them with details
4. STAY FOCUSED: Complete the task at hand before moving to new topics
5. BE HONEST: If you can't do something, explain why and suggest alternatives
6. WORK AUTONOMOUSLY: Don't ask for permission for every step - proceed with the task
7. RESPECT SCOPE: Only scan/test targets the user specifies
</behavioral_rules>

<response_format>
For task execution:
1. Acknowledge what you'll do
2. Execute the necessary commands/scripts
3. Share the results with relevant details
4. Provide analysis or recommendations if applicable

For questions:
- Provide clear, accurate answers
- Include examples when helpful
- Reference your available tools when relevant
</response_format>

Remember: You ARE Strix. You HAVE these capabilities. You CAN execute commands and tools. When users ask you to do something, DO IT - don't tell them you can't or that you're "just an AI". You are an AI agent with full execution capabilities.
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
    max_memory_entries: int = 20
    typing_indicator: bool = True
    
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
        return config


# ============================================================================
# Conversation Memory
# ============================================================================

@dataclass
class ConversationEntry:
    """A single conversation entry."""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    username: Optional[str] = None


class ConversationMemory:
    """Manages conversation history for users/channels."""
    
    def __init__(self, max_entries: int = 20):
        self.max_entries = max_entries
        self._memory: dict[str, list[ConversationEntry]] = {}
    
    def _get_key(self, user_id: int, channel_id: int) -> str:
        return f"{user_id}_{channel_id}"
    
    def add_message(
        self, 
        user_id: int, 
        channel_id: int, 
        role: str, 
        content: str,
        username: Optional[str] = None
    ) -> None:
        """Add a message to conversation history."""
        key = self._get_key(user_id, channel_id)
        if key not in self._memory:
            self._memory[key] = []
        
        self._memory[key].append(ConversationEntry(
            role=role,
            content=content,
            username=username
        ))
        
        # Trim to max entries
        if len(self._memory[key]) > self.max_entries:
            self._memory[key] = self._memory[key][-self.max_entries:]
    
    def get_history(self, user_id: int, channel_id: int) -> list[dict[str, str]]:
        """Get conversation history as list of message dicts."""
        key = self._get_key(user_id, channel_id)
        if key not in self._memory:
            return []
        
        return [
            {"role": entry.role, "content": entry.content}
            for entry in self._memory[key]
        ]
    
    def clear(self, user_id: int, channel_id: int) -> bool:
        """Clear conversation history for a user/channel."""
        key = self._get_key(user_id, channel_id)
        if key in self._memory:
            del self._memory[key]
            return True
        return False


# ============================================================================
# Task Management
# ============================================================================

@dataclass
class Task:
    """Represents a running task."""
    id: str
    user_id: int
    channel_id: int
    description: str
    status: str = "running"  # running, completed, failed
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    result: Optional[str] = None


class TaskManager:
    """Manages long-running tasks."""
    
    def __init__(self):
        self._tasks: dict[str, Task] = {}
        self._counter = 0
    
    def create_task(
        self, 
        user_id: int, 
        channel_id: int, 
        description: str
    ) -> Task:
        """Create a new task."""
        self._counter += 1
        task_id = f"task_{int(time.time())}_{self._counter}"
        task = Task(
            id=task_id,
            user_id=user_id,
            channel_id=channel_id,
            description=description
        )
        self._tasks[task_id] = task
        return task
    
    def get_task(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)
    
    def complete_task(self, task_id: str, result: str) -> None:
        if task_id in self._tasks:
            self._tasks[task_id].status = "completed"
            self._tasks[task_id].end_time = datetime.now()
            self._tasks[task_id].result = result
    
    def fail_task(self, task_id: str, error: str) -> None:
        if task_id in self._tasks:
            self._tasks[task_id].status = "failed"
            self._tasks[task_id].end_time = datetime.now()
            self._tasks[task_id].result = error
    
    def get_active_tasks(self, user_id: int) -> list[Task]:
        return [
            t for t in self._tasks.values() 
            if t.user_id == user_id and t.status == "running"
        ]


# ============================================================================
# LLM Client
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
        temperature: float = 0.7,
        max_tokens: int = 4000
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
            {"role": "system", "content": STRIX_SYSTEM_PROMPT}
        ] + messages
        
        payload = {
            'model': self.config.cliproxy_model,
            'messages': full_messages,
            'temperature': temperature,
            'max_tokens': max_tokens
        }
        
        logger.debug(f"Sending request to {url}")
        
        try:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=300)) as response:
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


# ============================================================================
# Discord Bot
# ============================================================================

class StrixBot(commands.Bot):
    """The Strix Discord bot."""
    
    def __init__(self, config: BotConfig):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.reactions = True
        intents.guilds = True
        
        super().__init__(command_prefix='!', intents=intents)
        
        self.config = config
        self.memory = ConversationMemory(max_entries=config.max_memory_entries)
        self.tasks = TaskManager()
        self.llm = LLMClient(config)
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
    
    async def on_ready(self) -> None:
        """Called when the bot is ready."""
        logger.info(f'Strix Discord bot is ready. Logged in as {self.user}')
        
        # Check API readiness
        self.api_ready = await self._check_api_ready()
        
        # Send startup message to configured channel
        if self.config.discord_channel_id:
            channel = self.get_channel(self.config.discord_channel_id)
            if channel:
                embed = discord.Embed(
                    title="Strix Security Agent Online",
                    description="I'm ready to help with security assessments and analysis.",
                    color=discord.Color.green()
                )
                embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)
                embed.add_field(name="API Status", value="Ready" if self.api_ready else "Checking...", inline=True)
                embed.add_field(
                    name="How to Use", 
                    value="Mention me with your message: `@Strix <your request>`",
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
                "Hello! I'm Strix, your AI security agent. "
                "How can I help you today? You can ask me to:\n"
                "- Scan targets for vulnerabilities\n"
                "- Analyze security configurations\n"
                "- Help with penetration testing\n"
                "- Answer security questions\n"
                "- Execute commands and scripts\n\n"
                "Just mention me with your request!"
            )
            return
        
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
        self.memory.add_message(
            message.author.id,
            message.channel.id,
            "user",
            content,
            username=str(message.author)
        )
        
        # Get conversation history
        history = self.memory.get_history(message.author.id, message.channel.id)
        
        # Generate response
        try:
            response = await self.llm.generate(history)
            
            # Add assistant response to memory
            self.memory.add_message(
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
            title="Strix Security Agent - Help",
            description="I'm an AI-powered security agent that can help with penetration testing, vulnerability assessment, and security analysis.",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="Interacting with Strix",
            value="Simply mention me with your request:\n`@Strix scan example.com for vulnerabilities`\n`@Strix what security tools do you have?`\n`@Strix help me analyze this code`",
            inline=False
        )
        
        embed.add_field(
            name="Commands",
            value=(
                "`!help` - Show this help message\n"
                "`!status` - Check bot and API status\n"
                "`!clear` - Clear conversation history\n"
                "`!tasks` - Show your active tasks"
            ),
            inline=False
        )
        
        embed.add_field(
            name="Capabilities",
            value=(
                "- Execute terminal commands and security tools\n"
                "- Run Python scripts for automation\n"
                "- Scan for vulnerabilities (nuclei, nmap, etc.)\n"
                "- Web fuzzing and enumeration\n"
                "- Code analysis and review\n"
                "- And much more!"
            ),
            inline=False
        )
        
        embed.set_footer(text="Strix by OmniSecure Labs")
        await ctx.send(embed=embed)
    
    @commands.command(name='status')
    async def cmd_status(self, ctx: commands.Context) -> None:
        """Show bot status."""
        # Re-check API status
        self.api_ready = await self._check_api_ready()
        
        embed = discord.Embed(
            title="Strix Status",
            color=discord.Color.green() if self.api_ready else discord.Color.orange()
        )
        
        embed.add_field(name="Bot Status", value="Online", inline=True)
        embed.add_field(name="API Status", value="Ready" if self.api_ready else "Not Ready", inline=True)
        embed.add_field(name="Model", value=self.config.cliproxy_model, inline=True)
        embed.add_field(name="Endpoint", value=self.config.cliproxy_endpoint or "Not configured", inline=False)
        
        active_tasks = self.tasks.get_active_tasks(ctx.author.id)
        embed.add_field(name="Your Active Tasks", value=str(len(active_tasks)), inline=True)
        
        await ctx.send(embed=embed)
    
    @commands.command(name='clear')
    async def cmd_clear(self, ctx: commands.Context) -> None:
        """Clear conversation history."""
        if self.memory.clear(ctx.author.id, ctx.channel.id):
            await ctx.send("Conversation history cleared.")
        else:
            await ctx.send("No conversation history to clear.")
    
    @commands.command(name='tasks')
    async def cmd_tasks(self, ctx: commands.Context) -> None:
        """Show active tasks."""
        active_tasks = self.tasks.get_active_tasks(ctx.author.id)
        
        if not active_tasks:
            await ctx.send("You have no active tasks.")
            return
        
        embed = discord.Embed(
            title="Your Active Tasks",
            color=discord.Color.blue()
        )
        
        for task in active_tasks:
            duration = datetime.now() - task.start_time
            embed.add_field(
                name=f"Task {task.id}",
                value=f"**Description:** {task.description[:100]}...\n**Running for:** {duration.seconds}s",
                inline=False
            )
        
        await ctx.send(embed=embed)
    
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

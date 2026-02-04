#!/usr/bin/env python3
import asyncio
import discord
from discord.ext import commands
import os
import subprocess
import json
import tempfile
import threading
import time
import aiohttp
from datetime import datetime

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True  # Required to mention members
intents.reactions = True  # Required for reactions
intents.guilds = True  # Required to access guild info
bot = commands.Bot(command_prefix='!', intents=intents)

# Global variables to maintain Strix context
current_job_id = None
job_results = {}
active_scans = {}  # Track active scans with user info

# Conversation memory system
conversation_memory = {}  # Stores conversation history per user/channel
MAX_MEMORY_ENTRIES = 10  # Maximum number of conversation entries to keep

# API readiness check
api_ready = False

@bot.event
async def on_ready():
    print(f'Discord bot is ready. Logged in as {bot.user}')
    channel_id_str = os.getenv('DISCORD_CHANNEL_ID', '')
    if channel_id_str:
        try:
            channel_id = int(channel_id_str)
            channel = bot.get_channel(channel_id)
            if channel:
                await channel.send(f"✅ Strix Security Agent is online and ready!\nModel: {os.getenv('CLIPROXY_MODEL', 'unknown')}\nAccounts: {os.getenv('ACCOUNTS_COUNT', '0')}")
        except ValueError:
            print(f"Invalid channel ID: {channel_id_str}")
    else:
        print("DISCORD_CHANNEL_ID not set, skipping startup message")

@bot.event
async def on_message(message):
    # Ignore messages from the bot itself
    if message.author == bot.user:
        return

    # Check if the bot is mentioned in the message
    if bot.user in message.mentions:
        # Remove the mention from the message content to get the actual query
        content = message.content.replace(f'<@{bot.user.id}>', '').replace(f'<@!{bot.user.id}>', '').strip()

        if content.lower().startswith('scan'):
            # Extract target from the message
            target_parts = content.split(' ', 1)
            if len(target_parts) > 1:
                target = target_parts[1].strip()
                await handle_scan_request(message, target)
            else:
                await message.channel.send("❌ Please specify a target to scan. Usage: `@Strix scan <target>`")
        elif content:
            # Treat as a general query to the Strix agent
            await handle_general_query(message, content)
        else:
            # Just mentioned the bot without a command
            await message.channel.send(f"👋 Hello! I'm the Strix Security Agent. You can ask me to scan targets or ask security-related questions.")

    # Process commands as well
    await bot.process_commands(message)

async def handle_scan_request(message, target):
    """Handle a scan request from a mention"""
    # Validate target format to prevent command injection
    if not validate_target(target):
        await message.channel.send("❌ Invalid target format. Only domains, IPs, and URLs are allowed.")
        return

    # Create a new job
    job_id = f"job_{int(time.time())}"
    global current_job_id
    current_job_id = job_id

    # Track the active scan with user info
    active_scans[job_id] = {
        'user_id': message.author.id,
        'channel_id': message.channel.id,
        'target': target,
        'start_time': datetime.now()
    }

    # Send initial message
    msg = await message.channel.send(f"🔍 Starting security scan on `{target}` (Job ID: {job_id})...")

    # Run the scan in a separate thread to not block the bot
    def run_scan():
        try:
            # Create a temporary directory for scan results
            with tempfile.TemporaryDirectory() as temp_dir:
                # Determine which scanning tool to use based on target type
                if target.startswith(('http://', 'https://')):
                    # Use a DAST tool like nikto or nmap for web apps
                    cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        '-e', f'TARGET={target}',
                        '-e', 'CLIPROXY_ENDPOINT=' + os.getenv('CLIPROXY_ENDPOINT'),
                        '-e', 'CLIPROXY_MODEL=' + os.getenv('CLIPROXY_MODEL'),
                        os.getenv('STRIX_IMAGE'),
                        'nuclei', '-u', target, '-o', f'/results/{job_id}_nuclei_results.txt'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minute timeout

                    # Also run additional scans
                    subprocess.run([
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        os.getenv('STRIX_IMAGE'),
                        'nmap', '-sV', target, '-oN', f'/results/{job_id}_nmap_results.txt'
                    ], timeout=1800)

                else:
                    # Use SAST tools for code repositories
                    cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        '-e', 'CLIPROXY_ENDPOINT=' + os.getenv('CLIPROXY_ENDPOINT'),
                        '-e', 'CLIPROXY_MODEL=' + os.getenv('CLIPROXY_MODEL'),
                        os.getenv('STRIX_IMAGE'),
                        'semgrep', '--config=auto', target, '--json', f'-o', f'/results/{job_id}_semgrep_results.json'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

                # Read results
                results = {}
                for filename in os.listdir(temp_dir):
                    filepath = os.path.join(temp_dir, filename)
                    with open(filepath, 'r') as f:
                        results[filename] = f.read()

                # Store results
                job_results[job_id] = {
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'results': results,
                    'status': 'completed'
                }

                # Send results to Discord
                asyncio.run_coroutine_threadsafe(send_results_to_discord_with_notification(job_id), bot.loop)

        except subprocess.TimeoutExpired:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': 'Scan timed out after 30 minutes'},
                'status': 'timeout'
            }
            asyncio.run_coroutine_threadsafe(send_timeout_notification(job_id), bot.loop)
        except Exception as e:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': str(e)},
                'status': 'error'
            }
            asyncio.run_coroutine_threadsafe(send_error_notification(job_id, str(e)), bot.loop)

    # Run the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

def get_conversation_key(user_id, channel_id):
    """Generate a unique key for conversation memory"""
    return f"{user_id}_{channel_id}"

def add_to_conversation_memory(user_id, channel_id, user_message, ai_response):
    """Add a message exchange to the conversation memory"""
    key = get_conversation_key(user_id, channel_id)

    if key not in conversation_memory:
        conversation_memory[key] = []

    # Add the new exchange to memory
    conversation_memory[key].append({
        'user': user_message,
        'ai': ai_response,
        'timestamp': datetime.now().isoformat()
    })

    # Keep only the most recent entries
    if len(conversation_memory[key]) > MAX_MEMORY_ENTRIES:
        conversation_memory[key] = conversation_memory[key][-MAX_MEMORY_ENTRIES:]

def get_conversation_context(user_id, channel_id):
    """Retrieve the conversation context for a user in a channel"""
    key = get_conversation_key(user_id, channel_id)

    if key not in conversation_memory:
        return []

    return conversation_memory[key]

async def check_api_readiness():
    """Check if the API is ready to accept requests"""
    global api_ready
    endpoint = os.getenv('CLIPROXY_ENDPOINT')

    if not endpoint:
        print("CLIPROXY_ENDPOINT not set")
        return False

    try:
        headers = {
            'Authorization': f'Bearer {os.getenv("OPENAI_API_KEY", "cliproxy-direct-mode")}'
        }

        async with aiohttp.ClientSession() as session:
            # Try to get the list of available models as a readiness check
            async with session.get(f"{endpoint}/models", headers=headers) as response:
                if response.status == 200:
                    api_ready = True
                    print("API is ready to accept requests")
                    return True
                else:
                    print(f"API not ready, status: {response.status}")
                    return False
    except Exception as e:
        print(f"Error checking API readiness: {e}")
        return False

async def handle_general_query(message, query):
    """Handle a general query to the Strix agent using the LLM"""
    global api_ready

    # Check if API is ready, if not try to initialize it
    if not api_ready:
        await message.channel.send("⏳ Checking API readiness...")
        api_ready = await check_api_readiness()

        if not api_ready:
            # Retry after a short delay
            await asyncio.sleep(5)
            api_ready = await check_api_readiness()

    if not api_ready:
        await message.channel.send("❌ API is not ready. Please wait for the Strix infrastructure to be fully initialized.")
        return

    try:
        # Get conversation history for context
        context_history = get_conversation_context(message.author.id, message.channel.id)

        # Prepare the messages for the LLM with conversation history
        llm_messages = [
            {"role": "system", "content": "You are a cybersecurity expert and security agent. Provide helpful, accurate responses focusing on security aspects."}
        ]

        # Add previous conversation history
        for entry in context_history:
            llm_messages.append({"role": "user", "content": entry['user']})
            llm_messages.append({"role": "assistant", "content": entry['ai']})

        # Add the current query
        llm_messages.append({"role": "user", "content": query})

        # Call the LLM through the CLIProxyAPI endpoint
        endpoint = os.getenv('CLIPROXY_ENDPOINT')
        model = os.getenv('CLIPROXY_MODEL')

        if not endpoint or not model:
            await message.channel.send("❌ Configuration error: Missing CLIPROXY_ENDPOINT or CLIPROXY_MODEL")
            return

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {os.getenv("OPENAI_API_KEY", "cliproxy-direct-mode")}'
        }

        payload = {
            'model': model,
            'messages': llm_messages,
            'temperature': 0.7,
            'max_tokens': 1000
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    # Handle both standard OpenAI format and potential variations
                    if 'choices' in data and len(data['choices']) > 0:
                        if 'message' in data['choices'][0]:
                            llm_response = data['choices'][0]['message']['content'].strip()
                        elif 'delta' in data['choices'][0] and 'content' in data['choices'][0]['delta']:
                            llm_response = data['choices'][0]['delta']['content'].strip()
                        else:
                            # Fallback to first available content
                            llm_response = str(data['choices'][0])
                    else:
                        # If the response format is unexpected, show the raw response
                        llm_response = f"Unexpected response format: {data}"

                    # Add to conversation memory
                    add_to_conversation_memory(message.author.id, message.channel.id, query, llm_response)

                    # Send the response back to the user
                    await message.channel.send(f"🤖 Strix Agent Response:\n{llm_response}")
                elif response.status == 404:
                    await message.channel.send(f"❌ Endpoint not found. Please check the CLIPROXY_ENDPOINT configuration. Status: {response.status}")
                elif response.status == 401:
                    await message.channel.send(f"❌ Unauthorized: Please check your API key. Status: {response.status}")
                elif response.status == 429:
                    await message.channel.send(f"❌ Rate limited: Too many requests. Status: {response.status}")
                else:
                    error_text = await response.text()
                    await message.channel.send(f"❌ Failed to get response from the Strix agent. Status: {response.status}, Error: {error_text}")
    except aiohttp.ClientConnectorError:
        await message.channel.send("❌ Cannot connect to the API endpoint. Please check the network connection and endpoint configuration.")
    except asyncio.TimeoutError:
        await message.channel.send("⏰ Request timed out. Please try again.")
    except Exception as e:
        await message.channel.send(f"❌ Error processing your query: {str(e)}")

@bot.command(name='scan')
async def scan(ctx, target: str = None):
    """Initiate a security scan on the specified target"""
    if not target:
        await ctx.send("❌ Please specify a target to scan. Usage: `!scan <target>`")
        return

    # Validate target format to prevent command injection
    if not validate_target(target):
        await ctx.send("❌ Invalid target format. Only domains, IPs, and URLs are allowed.")
        return

    # Create a new job
    job_id = f"job_{int(time.time())}"
    global current_job_id
    current_job_id = job_id

    # Track the active scan with user info
    active_scans[job_id] = {
        'user_id': ctx.author.id,
        'channel_id': ctx.channel.id,
        'target': target,
        'start_time': datetime.now()
    }

    # Send initial message
    msg = await ctx.send(f"🔍 Starting security scan on `{target}` (Job ID: {job_id})...")

    # Run the scan in a separate thread to not block the bot
    def run_scan():
        try:
            # Create a temporary directory for scan results
            with tempfile.TemporaryDirectory() as temp_dir:
                # Determine which scanning tool to use based on target type
                if target.startswith(('http://', 'https://')):
                    # Use a DAST tool like nikto or nmap for web apps
                    cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        '-e', f'TARGET={target}',
                        '-e', 'CLIPROXY_ENDPOINT=' + os.getenv('CLIPROXY_ENDPOINT'),
                        '-e', 'CLIPROXY_MODEL=' + os.getenv('CLIPROXY_MODEL'),
                        os.getenv('STRIX_IMAGE'),
                        'nuclei', '-u', target, '-o', f'/results/{job_id}_nuclei_results.txt'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minute timeout

                    # Also run additional scans
                    subprocess.run([
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        os.getenv('STRIX_IMAGE'),
                        'nmap', '-sV', target, '-oN', f'/results/{job_id}_nmap_results.txt'
                    ], timeout=1800)

                else:
                    # Use SAST tools for code repositories
                    cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{temp_dir}:/results',
                        '-e', 'CLIPROXY_ENDPOINT=' + os.getenv('CLIPROXY_ENDPOINT'),
                        '-e', 'CLIPROXY_MODEL=' + os.getenv('CLIPROXY_MODEL'),
                        os.getenv('STRIX_IMAGE'),
                        'semgrep', '--config=auto', target, '--json', f'-o', f'/results/{job_id}_semgrep_results.json'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

                # Read results
                results = {}
                for filename in os.listdir(temp_dir):
                    filepath = os.path.join(temp_dir, filename)
                    with open(filepath, 'r') as f:
                        results[filename] = f.read()

                # Store results
                job_results[job_id] = {
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'results': results,
                    'status': 'completed'
                }

                # Send results to Discord with notifications
                asyncio.run_coroutine_threadsafe(send_results_to_discord_with_notification(job_id), bot.loop)

        except subprocess.TimeoutExpired:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': 'Scan timed out after 30 minutes'},
                'status': 'timeout'
            }
            asyncio.run_coroutine_threadsafe(send_timeout_notification(job_id), bot.loop)
        except Exception as e:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': str(e)},
                'status': 'error'
            }
            asyncio.run_coroutine_threadsafe(send_error_notification(job_id, str(e)), bot.loop)

    # Run the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()

def validate_target(target):
    """Validate target format to prevent command injection"""
    import re
    # Allow domains, IPs, and URLs
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*\.?$'
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'

    return (
        re.match(domain_pattern, target) is not None or
        re.match(ip_pattern, target) is not None or
        re.match(url_pattern, target) is not None
    )

async def send_results_to_discord_with_notification(job_id):
    """Send scan results to Discord with notifications"""
    try:
        scan_info = active_scans.get(job_id)
        if not scan_info:
            print(f"Could not find scan info for job {job_id}")
            return

        # Get the channel where the scan was initiated
        channel = bot.get_channel(scan_info['channel_id'])
        if not channel:
            print(f"Could not find channel {scan_info['channel_id']}")
            return

        # Get the user who initiated the scan
        guild = channel.guild
        user = guild.get_member(scan_info['user_id']) if guild else None

        # Find the Granter role
        granter_role = None
        if guild:
            for role in guild.roles:
                if 'granter' in role.name.lower():
                    granter_role = role
                    break

        # Get the results
        results = job_results.get(job_id, {})

        # Send results with notifications
        total_chars = 0
        for filename, content in results.get('results', {}).items():
            # Limit message length to Discord's 2000 character limit
            content_str = str(content)
            if len(content_str) > 1900:  # Leave room for prefix
                content_str = content_str[:1900] + "... (truncated)"

            message = f"📄 **{filename}**\n```\n{content_str}\n```"
            await channel.send(message)
            total_chars += len(message)

            # If we're approaching rate limits, add a small delay
            if total_chars > 5000:
                await asyncio.sleep(1)
                total_chars = 0

        # Send completion message with mentions
        completion_msg = f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`"
        if user and granter_role:
            completion_msg = f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`\nHey {user.mention} and <@&{granter_role.id}> - scan results are ready!"
        elif user:
            completion_msg = f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`\nHey {user.mention} - scan results are ready!"
        elif granter_role:
            completion_msg = f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`\nHey <@&{granter_role.id}> - scan results are ready!"

        await channel.send(completion_msg)

        # Remove from active scans
        if job_id in active_scans:
            del active_scans[job_id]

    except Exception as e:
        print(f"Error sending results with notification: {str(e)}")
        # Try to send error to the original channel
        scan_info = active_scans.get(job_id)
        if scan_info:
            channel = bot.get_channel(scan_info['channel_id'])
            if channel:
                await channel.send(f"❌ Error sending scan results: {str(e)}")


async def send_timeout_notification(job_id):
    """Send timeout notification to Discord"""
    try:
        scan_info = active_scans.get(job_id)
        if not scan_info:
            print(f"Could not find scan info for job {job_id}")
            return

        # Get the channel where the scan was initiated
        channel = bot.get_channel(scan_info['channel_id'])
        if not channel:
            print(f"Could not find channel {scan_info['channel_id']}")
            return

        # Get the user who initiated the scan
        guild = channel.guild
        user = guild.get_member(scan_info['user_id']) if guild else None

        # Find the Granter role
        granter_role = None
        if guild:
            for role in guild.roles:
                if 'granter' in role.name.lower():
                    granter_role = role
                    break

        # Send timeout message with mentions
        timeout_msg = f"⏰ Scan for `{scan_info['target']}` timed out after 30 minutes."
        if user and granter_role:
            timeout_msg = f"⏰ Scan for `{scan_info['target']}` timed out after 30 minutes.\nHey {user.mention} and <@&{granter_role.id}> - please check the target."
        elif user:
            timeout_msg = f"⏰ Scan for `{scan_info['target']}` timed out after 30 minutes.\nHey {user.mention} - please check the target."
        elif granter_role:
            timeout_msg = f"⏰ Scan for `{scan_info['target']}` timed out after 30 minutes.\nHey <@&{granter_role.id}> - please check the target."

        await channel.send(timeout_msg)

        # Remove from active scans
        if job_id in active_scans:
            del active_scans[job_id]

    except Exception as e:
        print(f"Error sending timeout notification: {str(e)}")


async def send_error_notification(job_id, error_msg):
    """Send error notification to Discord"""
    try:
        scan_info = active_scans.get(job_id)
        if not scan_info:
            print(f"Could not find scan info for job {job_id}")
            return

        # Get the channel where the scan was initiated
        channel = bot.get_channel(scan_info['channel_id'])
        if not channel:
            print(f"Could not find channel {scan_info['channel_id']}")
            return

        # Get the user who initiated the scan
        guild = channel.guild
        user = guild.get_member(scan_info['user_id']) if guild else None

        # Find the Granter role
        granter_role = None
        if guild:
            for role in guild.roles:
                if 'granter' in role.name.lower():
                    granter_role = role
                    break

        # Send error message with mentions
        error_notification = f"❌ Error during scan of `{scan_info['target']}`: {error_msg}"
        if user and granter_role:
            error_notification = f"❌ Error during scan of `{scan_info['target']}`: {error_msg}\nHey {user.mention} and <@&{granter_role.id}> - please investigate."
        elif user:
            error_notification = f"❌ Error during scan of `{scan_info['target']}`: {error_msg}\nHey {user.mention} - please investigate."
        elif granter_role:
            error_notification = f"❌ Error during scan of `{scan_info['target']}`: {error_msg}\nHey <@&{granter_role.id}> - please investigate."

        await channel.send(error_notification)

        # Remove from active scans
        if job_id in active_scans:
            del active_scans[job_id]

    except Exception as e:
        print(f"Error sending error notification: {str(e)}")


async def send_results_to_discord(channel, job_id, results):
    """Send scan results to Discord"""
    try:
        total_chars = 0
        for filename, content in results.items():
            # Limit message length to Discord's 2000 character limit
            content_str = str(content)
            if len(content_str) > 1900:  # Leave room for prefix
                content_str = content_str[:1900] + "... (truncated)"

            message = f"📄 **{filename}**\n```\n{content_str}\n```"
            await channel.send(message)
            total_chars += len(message)

            # If we're approaching rate limits, add a small delay
            if total_chars > 5000:
                await asyncio.sleep(1)
                total_chars = 0

        await channel.send(f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`")
    except Exception as e:
        await channel.send(f"❌ Error sending results to Discord: {str(e)}")

@bot.command(name='status')
async def status(ctx):
    """Get the status of the current scan job"""
    if current_job_id:
        status_info = job_results.get(current_job_id, {'status': 'running'})
        await ctx.send(f"📊 Current job {current_job_id}: {status_info.get('status', 'running')}")
    else:
        await ctx.send("ℹ️ No active scan jobs")

@bot.command(name='clear_memory')
async def clear_memory(ctx):
    """Clear the conversation memory for the current user/channel"""
    key = get_conversation_key(ctx.author.id, ctx.channel.id)
    if key in conversation_memory:
        del conversation_memory[key]
        await ctx.send("🗑️ Conversation memory cleared for this channel.")
    else:
        await ctx.send("📋 No conversation memory to clear for this channel.")

@bot.command(name='info')
async def info_command(ctx):
    """Show available commands"""
    help_text = """
🛡️ **Strix Security Agent Commands:**
• `!scan <target>` - Initiate a security scan on the specified target
• `!status` - Check the status of the current scan job
• `!clear_memory` - Clear the conversation memory for this channel
• `!info` - Show this help message
• `@Strix scan <target>` - Mention the bot to initiate a scan
• `@Strix <question>` - Ask the Strix agent a security question

Supported targets:
• Domains: example.com
• IP addresses: 192.168.1.1
• URLs: https://example.com"""
    await ctx.send(help_text)

# Run the bot
if __name__ == "__main__":
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))
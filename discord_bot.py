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
from datetime import datetime

# Initialize bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Global variables to maintain Strix context
current_job_id = None
job_results = {}

@bot.event
async def on_ready():
    print(f'Discord bot is ready. Logged in as {bot.user}')
    channel_id = int(os.getenv('DISCORD_CHANNEL_ID', '0'))
    if channel_id != 0:
        channel = bot.get_channel(channel_id)
        if channel:
            await channel.send(f"✅ Strix Security Agent is online and ready!\nModel: {os.getenv('CLIPROXY_MODEL', 'unknown')}\nAccounts: {os.getenv('ACCOUNTS_COUNT', '0')}")

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
                
                # Send results to Discord
                asyncio.run_coroutine_threadsafe(send_results_to_discord(ctx, job_id, results), bot.loop)
                
        except subprocess.TimeoutExpired:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': 'Scan timed out after 30 minutes'},
                'status': 'timeout'
            }
            asyncio.run_coroutine_threadsafe(ctx.send(f"⏰ Scan for `{target}` timed out after 30 minutes."), bot.loop)
        except Exception as e:
            job_results[job_id] = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'results': {'error': str(e)},
                'status': 'error'
            }
            asyncio.run_coroutine_threadsafe(ctx.send(f"❌ Error during scan: {str(e)}"), bot.loop)
    
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

async def send_results_to_discord(ctx, job_id, results):
    """Send scan results to Discord"""
    try:
        total_chars = 0
        for filename, content in results.items():
            # Limit message length to Discord's 2000 character limit
            content_str = str(content)
            if len(content_str) > 1900:  # Leave room for prefix
                content_str = content_str[:1900] + "... (truncated)"
            
            message = f"📄 **{filename}**\n```\n{content_str}\n```"
            await ctx.send(message)
            total_chars += len(message)
            
            # If we're approaching rate limits, add a small delay
            if total_chars > 5000:
                await asyncio.sleep(1)
                total_chars = 0
        
        await ctx.send(f"✅ Scan job {job_id} completed for `{results.get('target', 'unknown')}`")
    except Exception as e:
        await ctx.send(f"❌ Error sending results to Discord: {str(e)}")

@bot.command(name='status')
async def status(ctx):
    """Get the status of the current scan job"""
    if current_job_id:
        status_info = job_results.get(current_job_id, {'status': 'running'})
        await ctx.send(f"📊 Current job {current_job_id}: {status_info.get('status', 'running')}")
    else:
        await ctx.send("ℹ️ No active scan jobs")

@bot.command(name='help')
async def help_command(ctx):
    """Show available commands"""
    help_text = """
🛡️ **Strix Security Agent Commands:**
• `!scan <target>` - Initiate a security scan on the specified target
• `!status` - Check the status of the current scan job
• `!help` - Show this help message

Supported targets:
• Domains: example.com
• IP addresses: 192.168.1.1
• URLs: https://example.com"""
    await ctx.send(help_text)

# Run the bot
if __name__ == "__main__":
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))
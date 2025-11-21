import discord
from discord.ext import commands, tasks
from datetime import datetime, timedelta, timezone
import json
import os
import asyncio
import aiohttp
import sys
import platform
import psutil

# Bot setup
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)

# ===== CONFIGURATION =====
TOKEN = 'MTM5MjU3NTcwNjcwNTQyODYwMg.GCkoPh.8frtokLNmJmoW5YO9k1cAhAtJ5AKrE3EASbvlw'# Use environment variable
SERVER_URL = "https://zoicombo.pythonanywhere.com/"

GUILD_ID = 1391817979754319902
LOG_CHANNEL_ID = 1404584701976514560

ROLE_IDS = {
    'free': 1391839228458958889,      
    'premium': 1391833734461919483,   
    'ultra': 1234567892,
    'zeroad': 1234567893
}

USER_DATA_FILE = "user_times.json"
USED_KEYS_FILE = "used_keys.json"

# Bot start time for uptime calculation
BOT_START_TIME = datetime.now(timezone.utc)

# ===== CONNECTION RETRY LOGIC =====
class RetryConnection:
    def __init__(self, max_retries=5, base_delay=1):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    async def connect_with_retry(self):
        for attempt in range(self.max_retries):
            try:
                await bot.login(TOKEN)
                await bot.connect()
                return True
            except (aiohttp.ClientConnectorError, discord.ConnectionClosed, discord.DiscordServerError) as e:
                if attempt == self.max_retries - 1:
                    print(f"Failed to connect after {self.max_retries} attempts: {e}")
                    return False
                
                delay = self.base_delay * (2 ** attempt)
                print(f"Connection failed (attempt {attempt + 1}/{self.max_retries}). Retrying in {delay}s...")
                await asyncio.sleep(delay)
            except discord.LoginFailure:
                print("Invalid token. Please check your bot token.")
                return False
        return False

# ===== DATA MANAGEMENT =====
def load_user_data():
    """Load user data from file and clean expired entries"""
    try:
        if os.path.exists(USER_DATA_FILE):
            with open(USER_DATA_FILE, 'r') as f:
                data = json.load(f)
                
                cleaned_data = {}
                now = datetime.now(timezone.utc)
                
                for user_id, user_data in data.items():
                    if user_data.get('expiration'):
                        expiration = datetime.fromisoformat(user_data['expiration'])
                        if expiration > now:
                            user_data['expiration'] = expiration
                            if user_data.get('last_redeemed'):
                                user_data['last_redeemed'] = datetime.fromisoformat(user_data['last_redeemed'])
                            cleaned_data[user_id] = user_data
                    else:
                        if user_data.get('last_redeemed'):
                            user_data['last_redeemed'] = datetime.fromisoformat(user_data['last_redeemed'])
                        cleaned_data[user_id] = user_data
                
                return cleaned_data
    except Exception as e:
        print(f"Error loading user data: {e}")
    return {}

def load_used_keys():
    """Load used keys and clean expired associations"""
    try:
        if os.path.exists(USED_KEYS_FILE):
            with open(USED_KEYS_FILE, 'r') as f:
                used_keys_data = json.load(f)
                
                current_user_ids = set(user_data_dict.keys())
                cleaned_used_keys = {}
                
                for key, user_id in used_keys_data.items():
                    if user_id in current_user_ids:
                        cleaned_used_keys[key] = user_id
                
                return cleaned_used_keys
    except Exception as e:
        print(f"Error loading used keys: {e}")
    return {}

def save_used_keys(data):
    try:
        with open(USED_KEYS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving used keys: {e}")

def save_user_data():
    """Save user data to file and clean expired entries before saving"""
    try:
        now = datetime.now(timezone.utc)
        data_to_save = {}
        
        for user_id, user_data in user_data_dict.items():
            expiration = user_data.get('expiration')
            if expiration and expiration <= now:
                continue
                
            data_to_save[user_id] = user_data.copy()
            if user_data.get('expiration'):
                data_to_save[user_id]['expiration'] = user_data['expiration'].isoformat()
            if user_data.get('last_redeemed'):
                data_to_save[user_id]['last_redeemed'] = user_data['last_redeemed'].isoformat()
        
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=2)
    except Exception as e:
        print(f"Error saving user data: {e}")

def wipe_user_data():
    """Delete all user data from the user_times.json file"""
    global user_data_dict
    user_data_dict = {}
    try:
        with open(USER_DATA_FILE, 'w') as f:
            json.dump({}, f)
    except Exception as e:
        print(f"Error wiping user data: {e}")
    try:
        global used_keys
        used_keys = {}
        save_used_keys(used_keys)
    except Exception as e:
        print(f"Error wiping used keys: {e}")

# Load existing user data
user_data_dict = load_user_data()
used_keys = load_used_keys()

# ===== STATISTICS FUNCTIONS =====
def get_bot_stats():
    """Get comprehensive bot statistics"""
    now = datetime.now(timezone.utc)
    
    # User statistics
    active_users = 0
    expired_users = 0
    role_breakdown = {}
    lifetime_users = 0
    
    for user_data in user_data_dict.values():
        if user_data.get('active', False):
            active_users += 1
            role_name = user_data.get('role_name', 'Unknown')
            role_breakdown[role_name] = role_breakdown.get(role_name, 0) + 1
            
            if not user_data.get('expiration'):
                lifetime_users += 1
        else:
            expired_users += 1
    
    # Server statistics
    guild = bot.get_guild(GUILD_ID)
    server_stats = {
        'total_members': guild.member_count if guild else 0,
        'online_members': len([m for m in guild.members if m.status != discord.Status.offline]) if guild else 0
    }
    
    # System statistics
    process = psutil.Process()
    memory_usage = process.memory_info().rss / 1024 / 1024  # MB
    
    # Uptime
    uptime = now - BOT_START_TIME
    days = uptime.days
    hours, remainder = divmod(uptime.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return {
        'active_users': active_users,
        'expired_users': expired_users,
        'lifetime_users': lifetime_users,
        'role_breakdown': role_breakdown,
        'server_stats': server_stats,
        'memory_usage': memory_usage,
        'uptime': f"{days}d {hours}h {minutes}m {seconds}s",
        'total_keys_used': len(used_keys),
        'cpu_usage': psutil.cpu_percent(),
        'total_roles': len(ROLE_IDS)
    }

# ===== EMBED DESIGN FUNCTIONS =====
def create_success_embed(title, description, user=None, key_type=None, expiration=None):
    """Create a beautiful success embed"""
    embed = discord.Embed(
        title=f"✅ {title}",
        description=description,
        color=discord.Color.green(),
        timestamp=datetime.now(timezone.utc)
    )
    
    if user:
        embed.add_field(name="👤 User", value=f"{user.mention}\n`{user.id}`", inline=True)
    
    if key_type:
        embed.add_field(name="🔑 Key Type", value=key_type.capitalize(), inline=True)
    
    if expiration:
        embed.add_field(name="⏰ Expires", value=expiration.strftime("%Y-%m-%d %H:%M:%S UTC"), inline=True)
        time_left = format_time_left(expiration)
        embed.add_field(name="⏳ Time Left", value=f"**{time_left}**", inline=True)
    
    embed.set_footer(text="Key Management System • 12-Hour Access")
    return embed

def create_error_embed(title, description):
    """Create a beautiful error embed"""
    embed = discord.Embed(
        title=f"❌ {title}",
        description=description,
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="Key Management System • Please try again")
    return embed

def create_info_embed(title, description):
    """Create a beautiful info embed"""
    embed = discord.Embed(
        title=f"ℹ️ {title}",
        description=description,
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.set_footer(text="Key Management System • Information")
    return embed

def create_stats_embed():
    """Create a comprehensive statistics embed"""
    stats = get_bot_stats()
    
    embed = discord.Embed(
        title="📊 Bot Statistics & System Overview",
        color=discord.Color.gold(),
        timestamp=datetime.now(timezone.utc)
    )
    
    # User Statistics
    embed.add_field(
        name="👥 USER STATISTICS",
        value=(
            f"• **Active Users:** {stats['active_users']}\n"
            f"• **Lifetime Access:** {stats['lifetime_users']}\n"
            f"• **Total Keys Used:** {stats['total_keys_used']}\n"
            f"• **Expired Users:** {stats['expired_users']}"
        ),
        inline=True
    )
    
    # Role Breakdown
    role_text = ""
    for role_name, count in stats['role_breakdown'].items():
        role_text += f"• **{role_name}:** {count}\n"
    if not role_text:
        role_text = "• No active roles"
    
    embed.add_field(
        name="🎭 ROLE DISTRIBUTION",
        value=role_text,
        inline=True
    )
    
    # Server Statistics
    embed.add_field(
        name="🌐 SERVER STATS",
        value=(
            f"• **Total Members:** {stats['server_stats']['total_members']}\n"
            f"• **Online Members:** {stats['server_stats']['online_members']}\n"
            f"• **Coverage:** {((stats['active_users'] / stats['server_stats']['total_members']) * 100) if stats['server_stats']['total_members'] > 0 else 0:.1f}%"
        ),
        inline=True
    )
    
    # System Information
    embed.add_field(
        name="⚙️ SYSTEM INFO",
        value=(
            f"• **Uptime:** {stats['uptime']}\n"
            f"• **Memory Usage:** {stats['memory_usage']:.1f} MB\n"
            f"• **CPU Usage:** {stats['cpu_usage']:.1f}%\n"
            f"• **Python:** {platform.python_version()}"
        ),
        inline=True
    )
    
    # Performance Metrics
    embed.add_field(
        name="📈 PERFORMANCE",
        value=(
            f"• **Active Tasks:** {len(asyncio.all_tasks())}\n"
            f"• **CPU Cores:** {psutil.cpu_count()}\n"
            f"• **Total Roles:** {stats['total_roles']}\n"
            f"• **Bot Latency:** {round(bot.latency * 1000)}ms"
        ),
        inline=True
    )
    
    embed.set_footer(text="Key Management System • Real-time Statistics • 12-Hour Access")
    return embed

def create_user_list_embed(users_data, guild):
    """Create a beautiful user list embed"""
    embed = discord.Embed(
        title="👥 Active Users Overview",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    if not users_data:
        embed.description = "**No active users found.**\n*Users will appear here once they redeem keys.*"
        return embed
    
    # Group users by role
    users_by_role = {}
    for user_id, user_data in users_data.items():
        if user_data.get('active', False):
            role_name = user_data.get('role_name', 'Unknown')
            if role_name not in users_by_role:
                users_by_role[role_name] = []
            users_by_role[role_name].append((user_id, user_data))
    
    for role_name, users in users_by_role.items():
        user_list = []
        for user_id, user_data in users[:8]:  # Limit to 8 users per role
            member = guild.get_member(int(user_id))
            username = member.mention if member else user_data.get('username', 'Unknown User')
            time_left = format_time_left(user_data.get('expiration'))
            user_list.append(f"{username} - **{time_left}**")
        
        role_users_text = "\n".join(user_list) if user_list else "No users"
        if len(users) > 8:
            role_users_text += f"\n*... and {len(users) - 8} more users*"
        
        embed.add_field(
            name=f"🎭 {role_name} ({len(users)})",
            value=role_users_text,
            inline=False
        )
    
    total_active = len([u for u in users_data.values() if u.get('active', False)])
    embed.set_footer(text=f"Total Active Users: {total_active} • Showing role-based distribution • 12-Hour Access")
    return embed

# ===== HELPER FUNCTIONS =====
async def log_key_claim(user: discord.User, key: str, key_type: str, expiration):
    """Log key claims to the specified channel with 12-hour notice"""
    try:
        channel = bot.get_channel(LOG_CHANNEL_ID)
        if channel:
            embed = create_success_embed(
                "⏰ Key Successfully Redeemed (12-Hour Access)",
                f"New key activation recorded - **12-hour access period**",
                user=user,
                key_type=key_type,
                expiration=expiration
            )
            embed.add_field(name="🔑 Key Used", value=f"`{key}`", inline=False)
            
            # Add 12-hour notice
            time_left = format_time_left(expiration)
            embed.add_field(
                name="📝 Access Duration",
                value=f"**12 hours**\nRemaining: **{time_left}**",
                inline=False
            )
            
            # Add quick stats to log
            stats = get_bot_stats()
            embed.add_field(
                name="📈 Quick Stats",
                value=f"**Active Users:** {stats['active_users']}\n**{key_type.capitalize()} Roles:** {stats['role_breakdown'].get(key_type.capitalize(), 0)}",
                inline=False
            )
            
            await channel.send(embed=embed)
    except Exception as e:
        print(f"Failed to log key claim: {e}")

async def log_failed_attempt(user: discord.User, key: str, reason: str):
    """Log failed key attempts to the specified channel"""
    try:
        channel = bot.get_channel(LOG_CHANNEL_ID)
        if channel:
            embed = create_error_embed(
                "Failed Key Redemption Attempt",
                f"Security system detected an invalid key usage attempt"
            )
            
            user_mention = user.mention if user else "Unknown User"
            user_id = user.id if user else "Unknown"
            
            embed.add_field(name="👤 User", value=f"{user_mention}\n`{user_id}`", inline=True)
            embed.add_field(name="🔑 Key Attempted", value=f"`{key}`", inline=True)
            embed.add_field(name="🚫 Reason", value=reason, inline=True)
            
            await channel.send(embed=embed)
    except Exception as e:
        print(f"Failed to log failed attempt: {e}")

async def log_lost_key(user: discord.Member, role_name: str, expiration):
    """Log when a user loses their key/role due to expiration"""
    try:
        channel = bot.get_channel(LOG_CHANNEL_ID)
        if channel:
            embed = discord.Embed(
                title="🔒 Access Expired",
                description=f"User access has been automatically revoked after 12 hours",
                color=discord.Color.orange(),
                timestamp=datetime.now(timezone.utc)
            )
            
            embed.add_field(name="👤 User", value=f"{user.mention}\n`{user.id}`", inline=True)
            embed.add_field(name="🎭 Role Lost", value=role_name, inline=True)
            
            if expiration:
                embed.add_field(name="⏰ Expired At", value=expiration.strftime("%Y-%m-%d %H:%M:%S UTC"), inline=True)
            
            # Add system stats
            stats = get_bot_stats()
            embed.add_field(
                name="📊 System Update",
                value=f"**Active Users:** {stats['active_users']}\n**Cleaned:** 1 expired user",
                inline=False
            )
            
            embed.set_footer(text="Automatic Role Management • 12-Hour Access System")
            await channel.send(embed=embed)
    except Exception as e:
        print(f"Failed to log lost key: {e}")

async def assign_role(interaction, role_id, role_name):
    """Safely assign a role to a member and ensure assignment"""
    guild = interaction.guild
    member = interaction.user
    role = guild.get_role(role_id)
    
    if not role:
        raise Exception(f"{role_name} role doesn't exist")
    
    if role >= guild.me.top_role:
        raise Exception(f"Bot needs higher role than {role_name}")
    
    await member.add_roles(role)
    await asyncio.sleep(1)
    if role not in member.roles:
        member = await guild.fetch_member(member.id)
        if role not in member.roles:
            raise Exception(f"Failed to assign {role_name} role")
    return role

async def remove_expired_role(user_id, user_data):
    """Remove expired role and clean up data for a specific user"""
    try:
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return False
            
        member = guild.get_member(int(user_id))
        role_id = user_data.get('role_id')
        role = guild.get_role(role_id) if role_id else None
        
        if member and role and role in member.roles:
            await member.remove_roles(role)
            print(f"Removed role {role.name} from user {member.display_name} (12-hour access expired)")
            
            try:
                await member.send(
                    embed=create_info_embed(
                        "⏰ Access Period Ended",
                        f"Your **{role.name}** access has expired after 12 hours and has been automatically removed.\n\n"
                        f"If you wish to continue using our services, please redeem a new key."
                    )
                )
            except:
                pass
            
            await log_lost_key(member, role.name, user_data.get('expiration'))
            return True
    except Exception as e:
        print(f"Error removing expired role for user {user_id}: {e}")
    
    return False

async def check_expired_roles_on_restart():
    """Check for roles that expired while bot was offline"""
    now = datetime.now(timezone.utc)
    expired_users = []
    
    for user_id, user_data in list(user_data_dict.items()):
        expiration = user_data.get('expiration')
        
        if expiration and now >= expiration:
            success = await remove_expired_role(user_id, user_data)
            if success:
                expired_users.append(user_id)
    
    for user_id in expired_users:
        if user_id in user_data_dict:
            user_key = user_data_dict[user_id].get('key')
            if user_key and user_key in used_keys:
                del used_keys[user_key]
            del user_data_dict[user_id]
    
    if expired_users:
        save_user_data()
        save_used_keys(used_keys)
        print(f"Cleaned up {len(expired_users)} expired users on restart (12-hour access expired)")

async def update_user_roles():
    """Check all users and update roles based on expiration"""
    now = datetime.now(timezone.utc)
    expired_users = []
    
    for user_id, user_data in list(user_data_dict.items()):
        expiration = user_data.get('expiration')
        is_active = user_data.get('active', False)

        if expiration and now >= expiration and is_active:
            success = await remove_expired_role(user_id, user_data)
            if success:
                expired_users.append(user_id)

    for user_id in expired_users:
        if user_id in user_data_dict:
            user_key = user_data_dict[user_id].get('key')
            if user_key and user_key in used_keys:
                del used_keys[user_key]
            del user_data_dict[user_id]
    
    if expired_users:
        save_user_data()
        save_used_keys(used_keys)
        print(f"Cleaned up {len(expired_users)} expired users (12-hour access expired)")

def format_time_left(expiration):
    """Format time left until expiration"""
    if not expiration:
        return "Unknown"
    
    now = datetime.now(timezone.utc)
    if now >= expiration:
        return "Expired 🔴"
    
    time_left = expiration - now
    total_hours = time_left.total_seconds() / 3600
    
    if total_hours > 24:
        days = time_left.days
        hours = int((time_left.seconds // 3600) % 24)
        return f"{days}d {hours}h 🟢"
    elif total_hours > 1:
        hours = int(total_hours)
        minutes = int((time_left.seconds // 60) % 60)
        return f"{hours}h {minutes}m 🟡"
    else:
        minutes = int(time_left.total_seconds() // 60)
        return f"{minutes}m 🔴"

# ===== BOT COMMANDS =====
@bot.tree.command(name="redeem", description="Redeem an access key for 12-hour special role access")
async def redeem(interaction: discord.Interaction, key: str, key_type: str = "free"):
    """Redeem a key for 12-hour access"""
    await interaction.response.defer(ephemeral=True)
    
    # Validate key type and convert to server's expected format
    server_key_type = key_type.lower()
    if server_key_type == "free":
        server_key_type = "code"
    
    if server_key_type not in ["code", "premium", "ultra", "zeroad"]:
        valid_types = ", ".join([f"`{k}`" for k in ROLE_IDS.keys()])
        embed = create_error_embed(
            "Invalid Key Type",
            f"Please use one of the following key types:\n{valid_types}"
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_failed_attempt(interaction.user, key, f"Invalid key type: {key_type}")
        return
    
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "key": key,
                "keytype": server_key_type,
                "user_id": str(interaction.user.id)
            }
            
            print(f"Sending request to {SERVER_URL}/api/redeem with payload: {payload}")
            
            async with session.post(f"{SERVER_URL}/api/redeem", json=payload, timeout=30) as response:
                print(f"Server response status: {response.status}")
                response_text = await response.text()
                print(f"Server response: {response_text}")
                
                if response.status == 200:
                    try:
                        data = await response.json()
                    except:
                        print(f"Failed to parse JSON response: {response_text}")
                        raise Exception("Invalid server response")
                        
                    if data.get("success"):
                        # Key is valid - assign role
                        role = await assign_role(interaction, ROLE_IDS[key_type.lower()], key_type.capitalize())
                        
                        # Parse expiration - now always 12 hours
                        expires_str = data.get("expires")
                        expiration = None
                        if expires_str:
                            try:
                                expiration = datetime.fromisoformat(expires_str)
                                if expiration.tzinfo is None:
                                    expiration = expiration.replace(tzinfo=timezone.utc)
                                
                                # Verify it's 12 hours from now (with small tolerance)
                                expected_expiration = datetime.now(timezone.utc) + timedelta(hours=12)
                                time_diff = abs((expiration - expected_expiration).total_seconds())
                                if time_diff > 300:  # 5 minutes tolerance
                                    print(f"Warning: Expiration time differs from expected 12 hours: {time_diff}s")
                                    
                            except ValueError as e:
                                print(f"Error parsing expiration date: {e}")
                                # Fallback to 12 hours if parsing fails
                                expiration = datetime.now(timezone.utc) + timedelta(hours=12)
                        else:
                            # Default to 12 hours if no expiration provided
                            expiration = datetime.now(timezone.utc) + timedelta(hours=12)
                        
                        # Update user data
                        user_id = str(interaction.user.id)
                        user_data_dict[user_id] = {
                            'user_id': user_id,
                            'username': str(interaction.user),
                            'role_id': role.id,
                            'role_name': role.name,
                            'key_type': key_type,
                            'key': key,
                            'expiration': expiration,
                            'last_redeemed': datetime.now(timezone.utc),
                            'active': True
                        }
                        
                        # Track used key
                        used_keys[key] = user_id
                        
                        # Save data
                        save_user_data()
                        save_used_keys(used_keys)
                        
                        # Log the claim
                        await log_key_claim(interaction.user, key, key_type, expiration)
                        
                        # Create success response with 12-hour notice
                        embed = create_success_embed(
                            "Key Successfully Redeemed! ⏰",
                            f"Welcome to **{role.name}**! Your access has been activated for **12 hours**.",
                            user=interaction.user,
                            key_type=key_type,
                            expiration=expiration
                        )
                        
                        # Add time remaining info
                        time_left = format_time_left(expiration)
                        embed.add_field(
                            name="⏳ Access Duration",
                            value=f"**12 hours**\nTime remaining: **{time_left}**",
                            inline=False
                        )
                        
                        await interaction.followup.send(embed=embed, ephemeral=True)
                    else:
                        error_msg = data.get("error", "Unknown error")
                        embed = create_error_embed(
                            "Invalid Key",
                            f"The key you entered is invalid or has already been used.\n\n**Reason:** {error_msg}"
                        )
                        await interaction.followup.send(embed=embed, ephemeral=True)
                        await log_failed_attempt(interaction.user, key, f"Server error: {error_msg}")
                else:
                    embed = create_error_embed(
                        "Server Error",
                        f"Unable to validate key at this time. Please try again later.\n\n**Status Code:** {response.status}"
                    )
                    await interaction.followup.send(embed=embed, ephemeral=True)
                    await log_failed_attempt(interaction.user, key, f"Server error: Status {response.status}")
    except asyncio.TimeoutError:
        embed = create_error_embed(
            "Connection Timeout",
            "The server took too long to respond. Please try again later."
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_failed_attempt(interaction.user, key, "Connection timeout")
    except Exception as e:
        print(f"Error in redeem command: {str(e)}")
        embed = create_error_embed(
            "Redemption Failed",
            f"An unexpected error occurred while processing your key.\n\n**Error:** {str(e)}"
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_failed_attempt(interaction.user, key, f"Error: {str(e)}")

@bot.tree.command(name="stats", description="View comprehensive bot statistics and system information")
async def stats(interaction: discord.Interaction):
    """Display comprehensive bot statistics"""
    await interaction.response.defer(ephemeral=True)
    
    embed = create_stats_embed()
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="wipeusers", description="🚨 Delete all user database data (admin only)")
async def wipeusers(interaction: discord.Interaction):
    if interaction.user.id != 1187422645902377103:
        await interaction.response.send_message(
            embed=create_error_embed(
                "Permission Denied",
                "You do not have permission to use this command."
            ),
            ephemeral=True
        )
        return
    
    # Get stats before wipe for confirmation
    stats_before = get_bot_stats()
    
    wipe_user_data()
    
    embed = create_success_embed(
        "Database Wiped Successfully",
        "All user data has been completely cleared from the system."
    )
    
    embed.add_field(
        name="📊 Data Cleared",
        value=(
            f"• **Active Users:** {stats_before['active_users']} → 0\n"
            f"• **Used Keys:** {stats_before['total_keys_used']} → 0\n"
            f"• **Role Assignments:** {sum(stats_before['role_breakdown'].values())} → 0"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⚠️ Warning",
        value="All user access has been revoked and keys are no longer tracked.",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="listactiveusers", description="View all active users with their roles and time left")
async def listactiveusers(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    guild = bot.get_guild(GUILD_ID)
    if not guild:
        await interaction.followup.send(
            embed=create_error_embed("Error", "Guild not found."),
            ephemeral=True
        )
        return

    active_users = {uid: data for uid, data in user_data_dict.items() if data.get('active', False)}
    embed = create_user_list_embed(active_users, guild)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="cleanupexpired", description="🔧 Force cleanup of expired roles and data (admin only)")
async def cleanupexpired(interaction: discord.Interaction):
    if interaction.user.id != 1187422645902377103:
        await interaction.response.send_message(
            embed=create_error_embed(
                "Permission Denied",
                "You do not have permission to use this command."
            ),
            ephemeral=True
        )
        return
    
    await interaction.response.defer(ephemeral=True)
    
    # Get stats before cleanup
    stats_before = get_bot_stats()
    
    # Run cleanup
    await update_user_roles()
    
    # Get stats after cleanup
    stats_after = get_bot_stats()
    
    embed = create_success_embed(
        "Cleanup Completed",
        "System maintenance completed successfully. Expired 12-hour access roles have been removed."
    )
    
    changes = stats_before['active_users'] - stats_after['active_users']
    
    embed.add_field(
        name="🔄 Changes Made",
        value=(
            f"• **Expired Users Removed:** {changes}\n"
            f"• **New Active Count:** {stats_after['active_users']}\n"
            f"• **Memory Usage:** {stats_after['memory_usage']:.1f} MB"
        ),
        inline=False
    )
    
    if changes > 0:
        embed.add_field(
            name="🎭 Role Changes",
            value="\n".join([f"• **{role}:** {stats_before['role_breakdown'].get(role, 0)} → {stats_after['role_breakdown'].get(role, 0)}" 
                           for role in set(stats_before['role_breakdown'].keys()) | set(stats_after['role_breakdown'].keys())]),
            inline=False
        )
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="myinfo", description="View your current access status and time remaining")
async def myinfo(interaction: discord.Interaction):
    """Show user's current access information"""
    await interaction.response.defer(ephemeral=True)
    
    user_id = str(interaction.user.id)
    user_data = user_data_dict.get(user_id)
    
    if not user_data or not user_data.get('active', False):
        embed = create_info_embed(
            "No Active Access",
            "You don't have any active key redemptions.\nUse `/redeem` to activate a key and get 12-hour access!"
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    role_name = user_data.get('role_name', 'Unknown')
    expiration = user_data.get('expiration')
    key_type = user_data.get('key_type', 'Unknown')
    redeemed_date = user_data.get('last_redeemed')
    
    embed = discord.Embed(
        title="🎫 Your Access Information",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    embed.add_field(name="👤 User", value=f"{interaction.user.mention}\n`{interaction.user.id}`", inline=True)
    embed.add_field(name="🎭 Current Role", value=role_name, inline=True)
    embed.add_field(name="🔑 Key Type", value=key_type.capitalize(), inline=True)
    
    if redeemed_date:
        embed.add_field(name="🕒 Redeemed On", value=redeemed_date.strftime("%Y-%m-%d %H:%M UTC"), inline=True)
    
    if expiration:
        embed.add_field(name="⏰ Expires On", value=expiration.strftime("%Y-%m-%d %H:%M UTC"), inline=True)
        time_left = format_time_left(expiration)
        embed.add_field(name="⏳ Time Remaining", value=f"**{time_left}**", inline=True)
    
    # Add progress bar for time remaining
    if expiration and redeemed_date:
        total_duration = timedelta(hours=12)  # Fixed 12-hour duration
        time_passed = datetime.now(timezone.utc) - redeemed_date
        progress_percent = min((time_passed.total_seconds() / total_duration.total_seconds()) * 100, 100)
        
        # Create visual progress bar
        bars = 20
        filled_bars = int(progress_percent / 100 * bars)
        progress_bar = "█" * filled_bars + "░" * (bars - filled_bars)
        
        embed.add_field(
            name="📊 12-Hour Access Progress",
            value=f"`{progress_bar}` {progress_percent:.1f}%",
            inline=False
        )
    
    embed.set_footer(text="Key Management System • 12-Hour Access Status")
    await interaction.followup.send(embed=embed, ephemeral=True)

# ===== BACKGROUND TASKS =====
@tasks.loop(minutes=5)  # Check every 5 minutes for expired roles
async def check_expired_roles():
    """Check for expired roles every 5 minutes"""
    await update_user_roles()

@check_expired_roles.before_loop
async def before_expiry_check():
    await bot.wait_until_ready()

# ===== BOT EVENTS =====
@bot.event
async def on_ready():
    print(f"Bot connected as {bot.user.name} (ID: {bot.user.id})")
    
    await check_expired_roles_on_restart()
    
    try:
        await bot.tree.sync()
        check_expired_roles.start()
        
        # Print startup stats
        stats = get_bot_stats()
        print(f"Bot startup completed! Active users: {stats['active_users']}, Memory: {stats['memory_usage']:.1f}MB")
        print(f"12-hour access system activated - checking every 5 minutes for expired roles")
        
    except Exception as e:
        print(f"Error during startup: {e}")

@bot.event
async def on_disconnect():
    print("Bot disconnected from Discord")

@bot.event
async def on_resumed():
    print("Bot connection resumed")
    # Update stats on resume
    stats = get_bot_stats()
    print(f"Connection resumed. Active users: {stats['active_users']}")

# ===== ERROR HANDLING =====
@bot.event
async def on_error(event, *args, **kwargs):
    print(f"Error in event {event}: {sys.exc_info()}")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"Command error: {error}")

async def main():
    retry_handler = RetryConnection(max_retries=5, base_delay=2)
    success = await retry_handler.connect_with_retry()
    
    if not success:
        print("Failed to establish connection to Discord. Please check your network connection.")

if __name__ == "__main__":
    asyncio.run(main())
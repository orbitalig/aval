import random
import discord
from discord.ext import commands
import config
import openai
import sqlite3 

TOKEN = config,token

bot = commands.Bot(
    command_prefix='.',
    help_command=None, 
    case_insensitive=True
)

BOT_ID = 1146334272412717117
DEFAULT_ADMINS = [211143646081187850, 623326198763618307, 1146334272412717117]
DATABASE_FILE = 'bot_data.db'

current_status = discord.Status.do_not_disturb
current_activity = discord.Game(name="with poop")
ai_enabled = False
commands_locked = False

def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            user_id INTEGER PRIMARY KEY
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS disabled_commands (
            command_name TEXT PRIMARY KEY
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS strikes (
            user_id INTEGER,
            count INTEGER,
            reason TEXT,
            PRIMARY KEY (user_id, reason)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_users (
            user_id INTEGER PRIMARY KEY
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            user_id INTEGER PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

initialize_database()

def is_admin(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM admins WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def is_blacklisted(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM blacklist WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_to_blacklist(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO blacklist (user_id) VALUES (?)', (user_id,))
    conn.commit()
    conn.close()

def remove_from_blacklist(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blacklist WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_blacklisted_users():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM blacklist')
    result = cursor.fetchall()
    conn.close()
    return [row[0] for row in result]

@bot.command()
async def blacklist(ctx, user: discord.User):
    """Toggle blacklisting a user from using commands."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")

    if is_blacklisted(user.id):
        remove_from_blacklist(user.id)
        await ctx.reply(f'{user.mention} has been removed from the blacklist and can now use commands.')
    else:
        add_to_blacklist(user.id)
        await ctx.reply(f'{user.mention} has been blacklisted from using commands.')


@bot.check
async def globally_block_commands(ctx: commands.Context):
    """Check if the command is locked and if the user is an admin or blacklisted."""
    if is_admin(ctx.author.id):
        return True

    if is_blacklisted(ctx.author.id):
        return False

    return True


def initialize_lock_tables():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_chat_lock (
            id INTEGER PRIMARY KEY,
            locked BOOLEAN NOT NULL CHECK (locked IN (0, 1))
        )
    ''')
    cursor.execute('''
        INSERT OR IGNORE INTO group_chat_lock (id, locked) VALUES (1, 0)
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands_lock (
            id INTEGER PRIMARY KEY,
            locked BOOLEAN NOT NULL CHECK (locked IN (0, 1))
        )
    ''')
    cursor.execute('''
        INSERT OR IGNORE INTO commands_lock (id, locked) VALUES (1, 0)
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS individual_command_lock (
            command_name TEXT PRIMARY KEY,
            locked BOOLEAN NOT NULL CHECK (locked IN (0, 1))
        )
    ''')
    conn.commit()
    conn.close()

initialize_lock_tables()


initialize_lock_tables()

def add_default_admins():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    for admin_id in DEFAULT_ADMINS:
        cursor.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (admin_id,))
    conn.commit()
    conn.close()

add_default_admins()

def is_commands_locked():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT locked FROM commands_lock WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] == 1

def set_commands_locked(locked):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE commands_lock SET locked = ? WHERE id = 1', (locked,))
    conn.commit()
    conn.close()

def is_command_locked(command_name):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT locked FROM individual_command_lock WHERE command_name = ?', (command_name,))
    result = cursor.fetchone()
    conn.close()
    return result[0] == 1 if result else False

def set_command_locked(command_name, locked):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO individual_command_lock (command_name, locked) VALUES (?, ?)', (command_name, locked))
    cursor.execute('UPDATE individual_command_lock SET locked = ? WHERE command_name = ?', (locked, command_name))
    conn.commit()
    conn.close()


def is_admin(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM admins WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_initial_commands_locked():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT locked FROM commands_lock WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] == 1

def get_initial_command_locks():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT command_name, locked FROM individual_command_lock')
    result = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] == 1 for row in result}

commands_locked = get_initial_commands_locked()
command_locks = get_initial_command_locks()

def get_admin_list():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM admins')
    result = cursor.fetchall()
    conn.close()
    return [row[0] for row in result]

def add_admin(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (user_id,))
    conn.commit()
    conn.close()

def remove_admin(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM admins WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def get_disabled_commands():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT command_name FROM disabled_commands')
    result = cursor.fetchall()
    conn.close()
    return [row[0] for row in result]

def disable_command(command_name):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO disabled_commands (command_name) VALUES (?)', (command_name,))
    conn.commit()
    conn.close()

def enable_command(command_name):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM disabled_commands WHERE command_name = ?', (command_name,))
    conn.commit()
    conn.close()

def get_strikes(user_id=None):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    if user_id:
        cursor.execute('SELECT count FROM strikes WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else 0
    else:
        cursor.execute('SELECT user_id, count FROM strikes')
        result = cursor.fetchall()
        conn.close()
        return {row[0]: row[1] for row in result}

def add_strike(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO strikes (user_id, count) VALUES (?, 0)', (user_id,))
    cursor.execute('UPDATE strikes SET count = count + 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def remove_strike(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE strikes SET count = count - 1 WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM strikes WHERE user_id = ? AND count <= 0', (user_id,))
    conn.commit()
    conn.close()

def clear_strikes(user_id=None):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    if user_id:
        cursor.execute('DELETE FROM strikes WHERE user_id = ?', (user_id,))
    else:
        cursor.execute('DELETE FROM strikes')
    conn.commit()
    conn.close()

def get_banned_users():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM banned_users')
    result = cursor.fetchall()
    conn.close()
    return [row[0] for row in result]

def ban_user(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO banned_users (user_id) VALUES (?)', (user_id,))
    conn.commit()
    conn.close()

def unban_user(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

@bot.command()
async def ban(ctx: commands.Context, user: discord.User):
    """Ban a user from the group chat."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if user.id == bot.user.id:
        return await ctx.reply("I can't ban myself!")
    if user.id in get_banned_users():
        return await ctx.reply(f'{user.mention} is already banned.')
    ban_user(user.id)
    await ctx.reply(f'{user.mention} has been banned from the group chat.')
    channel = ctx.channel
    if isinstance(channel, discord.GroupChannel):
        try:
            await channel.remove_recipients(user)
            await ctx.send(f"{user.mention} was removed because they are banned from the group chat.")
        except discord.Forbidden:
            await ctx.reply(f"Failed to remove banned user {user.mention} from the group chat.")
        except discord.NotFound:
            await ctx.reply(f"User {user.mention} not found in the group chat.")

@bot.event
async def on_group_join(channel, user):
    if user.id in get_banned_users() and user.id != bot.user.id:
        try:
            await channel.remove_recipients(user)
            await channel.send(f"{user.mention} was removed because they are banned from the group chat.")
        except discord.Forbidden:
            print(f"Failed to remove banned user {user.mention} because of insufficient permissions.")
        except discord.NotFound:
            print(f"User {user.mention} not found in the group chat.")
    elif is_group_chat_locked() and user.id != bot.user.id:
        try:
            await channel.remove_recipients(user)
            await channel.send(f"{user.mention} was removed because the group chat is currently locked.")
        except discord.Forbidden:
            print(f"Failed to remove user {user.mention} because of insufficient permissions.")
        except discord.NotFound:
            print(f"User {user.mention} not found in the group chat.")


@bot.command()
async def unban(ctx: commands.Context, user: discord.User):
    """Unban a user from the group chat."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if user.id not in get_banned_users():
        return await ctx.reply(f'{user.mention} is not banned.')
    unban_user(user.id)
    await ctx.reply(f'{user.mention} has been unbanned from the group chat.')


import sqlite3

def is_command_locked(command_name):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT locked FROM individual_command_lock WHERE command_name = ?', (command_name,))
    result = cursor.fetchone()
    conn.close()
    return result[0] == 1 if result else False


def set_command_locked(command_name, locked):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO individual_command_lock (command_name, locked) VALUES (?, ?)', (command_name, locked))
    cursor.execute('UPDATE individual_command_lock SET locked = ? WHERE command_name = ?', (locked, command_name))
    conn.commit()
    conn.close()

@bot.command()
async def lockcommand(ctx: commands.Context, command_name: str):
    """Lock or unlock a specific command for non-admin users."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")

    command = bot.get_command(command_name)
    if command is None:
        return await ctx.reply(f"The command {command_name} does not exist.")

    current_lock_state = is_command_locked(command_name)
    new_lock_state = not current_lock_state
    set_command_locked(command_name, new_lock_state)
    state = "locked" if new_lock_state else "unlocked"
    await ctx.reply(f'The command {command_name} has been {state}.')

@bot.check
async def globally_block_commands(ctx: commands.Context):
    """Check if the command is locked and if the user is an admin."""
    if is_admin(ctx.author.id):
        return True

    if commands_locked:
        await ctx.reply("Commands are currently locked by an admin.")
        return False

    if is_command_locked(ctx.command.name):
        await ctx.reply(f"The command {ctx.command.name} is currently locked for non-admin users.")
        return False

    return True


def is_group_chat_locked():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT locked FROM group_chat_lock WHERE id = 1')
    result = cursor.fetchone()
    conn.close()
    return result[0] == 1

def toggle_group_chat_lock():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    new_status = 0 if is_group_chat_locked() else 1
    cursor.execute('UPDATE group_chat_lock SET locked = ? WHERE id = 1', (new_status,))
    conn.commit()
    conn.close()


def unban_user(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def is_group_chat(ctx):
    if isinstance(ctx.channel, discord.GroupChannel):
        return True
    elif isinstance(ctx.channel, discord.DMChannel):
        raise commands.CheckFailure("This command can only be used in group chats.")
    else:
        raise commands.CheckFailure("This command cannot be used here.")
import aiohttp
import atexit
import requests

WEBHOOK_URL = 'https://discord.com/api/webhooks/1259704395520671806/cQUg2N9M3HRdxiHNAAtoPx5TJgaC3W_btOinulUYCN8uE0jdafwQBoQqI5tBO9PX9X1O'

async def send_webhook_notification(message):
    payload = {
        "content": f"<@&1264278811277656165> {message}"
    }
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json=payload)


@bot.event
async def on_ready():
    print(f'-------------------- Bot is ready! --------------------')
    print(f'Logged in as {bot.user}'.center(55))
    print(f'-------------------------------------------------------')
    await bot.change_presence(activity=current_activity, status=current_status)
    await send_webhook_notification("Bot is now online!")

async def notify_shutdown():
    await send_webhook_notification("Bot is going offline!")
    await bot.close()

@bot.event
@commands.is_owner()
async def shutdown(ctx):
    """Shuts down the bot."""
    await notify_shutdown()

def on_exit():
    payload = {
        "content": f"<@&1264278811277656165> Bot has gone offline!"
    }
    try:
        requests.post(WEBHOOK_URL, json=payload)
    except Exception as e:
        print(f"Failed to send webhook notification on exit: {e}")

atexit.register(on_exit)




@bot.command()
async def lockgc(ctx: commands.Context):
    """Toggle locking the group chat for new users."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    
    toggle_group_chat_lock()
    state = "locked" if is_group_chat_locked() else "unlocked"
    await ctx.reply(f'The group chat has been {state}.')





@bot.command()
async def remove(ctx: commands.Context, *, user: discord.User):
    """Remove a user from the group chat."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if user.id == bot.user.id:
        return await ctx.reply("I can't remove myself from the group chat!")

    channel = ctx.channel
    if not isinstance(channel, discord.GroupChannel):
        return

    try:
        await channel.remove_recipients(user)
    except discord.Forbidden:
        return await ctx.reply(f'I am not able to remove {user.mention} from this group chat!')
    except discord.NotFound:
        return await ctx.reply(f'{user.mention} is not in this group chat!')
    except discord.HTTPException:
        pass



@bot.command()
async def help(ctx: commands.Context):
    """Show this help message."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    general_commands = "**Here are the available commands:**\n\n"
    admin_commands = "**Here are the available admin commands:**\n\n"

    for command in bot.commands:
        if command.name not in get_disabled_commands() or is_admin(ctx.author.id):
            if command.name in ["lockcommands", "addadmin", "removeadmin", "addstrike", "removestrike", "clearstrikes", "ban", "unban", "remove", "lockgc", "lockcommand", "addrule", "removerule", "editrule", "blacklist"]:
                admin_commands += f".{command.name} - {command.help}\n"
            else:
                general_commands += f".{command.name} - {command.help}\n"

    full_message = f"{general_commands}\n{admin_commands}"
    split_messages = [full_message[i:i + 2000] for i in range(0, len(full_message), 2000)]
    
    for message in split_messages:
        await ctx.reply(message)


def initialize_rules_table():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

initialize_rules_table()


def get_rules():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, rule FROM rules ORDER BY id')
    rules = cursor.fetchall()
    conn.close()
    return rules

def add_rule(rule):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO rules (rule) VALUES (?)', (rule,))
    conn.commit()
    conn.close()

def remove_rule(rule_index):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM rules WHERE id = (SELECT id FROM rules ORDER BY id LIMIT 1 OFFSET ?)', (rule_index-1,))
    conn.commit()
    cursor.execute('''
        UPDATE rules
        SET id = id - 1
        WHERE id > ?
    ''', (rule_index,))
    conn.commit()
    conn.close()

def edit_rule(rule_index, new_rule):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE rules SET rule = ? WHERE id = (SELECT id FROM rules ORDER BY id LIMIT 1 OFFSET ?)', (new_rule, rule_index-1))
    conn.commit()
    conn.close()

@bot.command()
async def addrule(ctx, *, rule: str):
    """Add a new rule to the rules list."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    
    add_rule(rule)
    await ctx.reply("Rule added successfully.")

@bot.command()
async def removerule(ctx, rule_index: int):
    """Remove a rule from the rules list by its index."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    
    remove_rule(rule_index)
    await ctx.reply("Rule removed successfully.")

@bot.command()
async def editrule(ctx, rule_index: int, *, new_rule: str):
    """Edit an existing rule by its index."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    
    edit_rule(rule_index, new_rule)
    await ctx.reply("Rule edited successfully.")

@bot.command()
async def rules(ctx: commands.Context):
    """Shows the group chat rules."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    rules = get_rules()
    if not rules:
        return await ctx.reply("No rules have been set.")
    
    rules_list = "\n".join([f"{i + 1}. {rule_text}" for i, (rule_id, rule_text) in enumerate(rules)])
    await ctx.reply(f"**RULES**\n{rules_list}\n\n**If you get 3 strikes, you will be removed from the group chat.**")


import time
import asyncio

dmall_cooldown = commands.CooldownMapping.from_cooldown(1, 60.0, commands.BucketType.user)

GUILD_ID = 1259633952017350656
CHANNEL_ID = 1264279182934933616

def initialize_optout_table():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS optout (
            user_id INTEGER PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

initialize_optout_table()

def optout_user(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO optout (user_id) VALUES (?)', (user_id,))
    conn.commit()
    conn.close()

def optin_user(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM optout WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def is_opted_out(user_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM optout WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_opted_out_users():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM optout')
    result = cursor.fetchall()
    conn.close()
    return [row[0] for row in result]

def is_admin(user_id):
    return user_id in DEFAULT_ADMINS

@bot.command()
async def optout(ctx: commands.Context):
    """Toggle opt-out status for certain features."""
    if ctx.guild is None or ctx.guild.id != GUILD_ID:
        return await ctx.reply(
            "In order to opt out of features, please join our official Discord server and redirect yourself to the 'opt out' category.\n\n"
            "Join our Discord: https://discord.gg/rRfFjARzup"
        )

    if ctx.channel.id == CHANNEL_ID:
        if is_opted_out(ctx.author.id):
            optin_user(ctx.author.id)
            await ctx.send(f"{ctx.author.mention} has opted back in to receiving DMs sent via .dmall.")
            log_channel = bot.get_channel(CHANNEL_LOG_ID)
            if log_channel:
                await log_channel.send(f"{ctx.author.mention} has opted back in to receiving DMs.")
        else:
            optout_user(ctx.author.id)
            await ctx.send(f"{ctx.author.mention} has opted out of receiving DMs sent via .dmall.")
            log_channel = bot.get_channel(CHANNEL_LOG_ID)
            if log_channel:
                await log_channel.send(f"{ctx.author.mention} has opted out of receiving DMs.")
        await update_optout_message()

        await ctx.message.delete()
    else:
        await ctx.reply("This command can only be used in the designated channel.")




@bot.command()
async def dmall(ctx, *, message: str):
    """Send a message to all members in the group chat or all users in DMs."""
    if is_opted_out(ctx.author.id):
        return await ctx.reply("You cannot use this command because you have opted out.")
    
    if not isinstance(ctx.channel, (discord.GroupChannel, discord.DMChannel)):
        return await ctx.reply("This command can only be used in group chats or DMs.")
    
    sender = ctx.author
    sent_count = 0
    failed_users = []
    captcha_users = []
    rate_limit_users = []


    is_sender_admin = is_admin(ctx.author.id)

    mention = None
    message_content = message


    if is_sender_admin and message.startswith('<@') and '>' in message:
        mention_end = message.index('>') + 1
        mention = message[:mention_end]
        message_content = message[mention_end:].strip()
    if isinstance(ctx.channel, discord.GroupChannel):
        recipients = ctx.channel.recipients
    else:
        recipients = [friend for friend in bot.user.friends if friend != bot.user]

    for user in recipients:
        if user.id != bot.user.id and not is_opted_out(user.id):
            try:
                final_message = message_content
                if is_sender_admin and mention:
                    final_message = f"{message_content}\n\nThis message has been sent by {mention} using **.dmall** on **Aval**."
                else:
                    final_message = f"{message_content}\n\nThis message was sent by {sender.mention} using **.dmall** on **Aval**.\nTo opt out of recieving these messages, type **.optout**"

                await user.send(final_message)
                sent_count += 1
                print(f"Sent message to {user.name}#{user.discriminator}")
            except discord.Forbidden:
                failed_users.append(user)
            except discord.errors.CaptchaRequired:
                captcha_users.append(user)
            except discord.HTTPException as e:
                if e.status == 429: 
                    rate_limit_users.append(user)
                    retry_after = int(e.response.headers.get("Retry-After", 60))
                    await asyncio.sleep(retry_after)
                else:
                    raise e

    reply_message = f"Message sent to {sent_count} user{'s' if sent_count != 1 else ''}."
    if not failed_users and not captcha_users and not rate_limit_users:
        reply_message += " No errors found."
    else:
        if failed_users:
            reply_message += f" Failed to send to {len(failed_users)} user{'s' if len(failed_users) != 1 else ''} due to permissions: {', '.join(user.mention for user in failed_users)}."
        if captcha_users:
            reply_message += f" CAPTCHA required for {len(captcha_users)} user{'s' if len(captcha_users) != 1 else ''}, unable to send: {', '.join(user.mention for user in captcha_users)}."
        if rate_limit_users:
            reply_message += f" Rate limited for {len(rate_limit_users)} user{'s' if len(rate_limit_users) != 1 else ''}, retry after a while: {', '.join(user.mention for user in rate_limit_users)}."

    await ctx.send(reply_message)

@bot.event
async def on_message(message):
    if message.guild and message.guild.id == GUILD_ID and message.channel.id == CHANNEL_ID:
        if not is_admin(message.author.id) and bot.user.id != message.author.id and ".optout" not in message.content:
            try:
                await message.delete()
                await message.channel.send(f"{message.author.mention}, your message was deleted because it did not include '.optout'.")
            except discord.Forbidden:
                print(f"Failed to delete message from {message.author.mention} due to insufficient permissions.")
            except discord.HTTPException as e:
                print(f"Failed to delete message from {message.author.mention}: {e}")

    await bot.process_commands(message)


    reply_message = f"Message sent to {sent_count} user{'s' if sent_count != 1 else ''}."
    if opt_out_users:
        reply_message += f" {len(opt_out_users)} user{'s have' if len(opt_out_users) != 1 else ' has'} opted out of receiving DMs."
    if failed_users:
        reply_message += f" Failed to send to {len(failed_users)} user{'s' if len(failed_users) != 1 else ''} due to permissions."
    if rate_limit_users:
        reply_message += f" Rate limited for {len(rate_limit_users)} user{'s' if len(rate_limit_users) != 1 else ''}, retry after a while."

    await ctx.send(reply_message)










@bot.command()
async def setgame(ctx: commands.Context, *, game: str):
    """Change the bot's game status."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    global current_activity
    current_activity = discord.Game(name=game)
    await bot.change_presence(activity=current_activity, status=discord.Status.online if current_status is None else current_status)
    await ctx.reply(f'Bot game status changed to: {game}')

@bot.command()
async def setstatus(ctx: commands.Context, status: str):
    """Set the bot's status to online, dnd (Do Not Disturb), idle, or invisible (offline)."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    global current_status

    status_dict = {
        'online': discord.Status.online,
        'dnd': discord.Status.do_not_disturb,
        'idle': discord.Status.idle,
        'invisible': discord.Status.invisible
    }

    new_status = status_dict.get(status.lower())

    if new_status is None:
        await ctx.reply('Invalid status! Please choose from: online, dnd, idle, invisible.')
        return

    if current_status == new_status:
        await ctx.reply(f'The bot is already set to {status} status!')
        return

    current_status = new_status
    await bot.change_presence(activity=current_activity, status=current_status)
    await ctx.reply(f'Bot status changed to: {status}')


@remove.error
async def remove_error(ctx: commands.Context, error: commands.CommandError):
    """Handles errors for the .remove command."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    if isinstance(error, commands.MissingRequiredArgument):
        return await ctx.reply('You need to specify a user to remove!')
    if isinstance(error, commands.UserNotFound):
        return await ctx.reply(f'User {error.argument} not found!')
    raise error

@bot.command()
async def say(ctx: commands.Context, *, message: str):
    """Repeats the user's message."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    await ctx.send(message)

USER_ID_TO_REMOVE = 211143646081187850
@bot.event
async def on_member_join(member):
    if member.id == USER_ID_TO_REMOVE:
        try:
            await member.kick(reason="Auto-removed by bot")
            print(f'Removed user {member.id} from the group chat')
        except discord.Forbidden:
            print(f"Failed to remove user {member.id}: insufficient permissions")
        except discord.HTTPException as e:
            print(f"Failed to remove user {member.id}: {e}")


@bot.command()
async def joke(ctx: commands.Context):
    """Send a random joke!"""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    with open('jokes.txt') as file:
        jokes = [line.strip() for line in file.readlines() if line.strip()]
    await ctx.reply(random.choice(jokes))

@bot.command()
async def toggleai(ctx: commands.Context):
    """Toggle the AI response feature on or off."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    global ai_enabled
    ai_enabled = not ai_enabled
    state = "enabled" if ai_enabled else "disabled"
    await ctx.reply(f'AI response feature has been {state}.')

@bot.command()
async def lockcommands(ctx: commands.Context):
    """Toggle locking commands for non-admin users."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    global commands_locked
    commands_locked = not commands_locked
    state = "locked" if commands_locked else "unlocked"
    await ctx.reply(f'Commands have been {state} for non-admin users.')

@bot.command()
async def addadmin(ctx: commands.Context, user: discord.User):
    """Add a user to the admin list."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if is_admin(user.id):
        return await ctx.reply(f'{user.mention} is already an admin.')
    add_admin(user.id)
    await ctx.reply(f'{user.mention} has been added as an admin.')

@bot.command()
async def removeadmin(ctx: commands.Context, user: discord.User):
    """Remove a user from the admin list."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if not is_admin(user.id):
        return await ctx.reply(f'{user.mention} is not an admin.')
    remove_admin(user.id)
    await ctx.reply(f'{user.mention} has been removed as an admin.')


@bot.command()
async def addstrike(ctx: commands.Context, user: discord.User):
    """Add a strike to a user."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if is_admin(user.id):
        return await ctx.reply(f'Admins cannot receive strikes.')
    add_strike(user.id)
    await ctx.reply(f'{user.mention} has been given a strike. They now have {get_strikes(user.id)} {"strike" if get_strikes(user.id) == 1 else "strikes"}.')

@bot.command()
async def removestrike(ctx: commands.Context, user: discord.User):
    """Remove a strike from a user."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if get_strikes(user.id) == 0:
        return await ctx.reply(f'{user.mention} does not have any strikes.')
    remove_strike(user.id)
    await ctx.reply(f'{user.mention} has had a strike removed. They now have {get_strikes(user.id)} {"strike" if get_strikes(user.id) == 1 else "strikes"}.')

@bot.command()
async def clearstrikes(ctx: commands.Context, user: discord.User = None):
    """Clear all strikes or strikes for a specific user."""
    if not is_admin(ctx.author.id):
        return await ctx.reply("You do not have permission to use this command.")
    if user:
        if get_strikes(user.id) > 0:
            clear_strikes(user.id)
            await ctx.reply(f'{user.mention}\'s strikes have been cleared.')
        else:
            await ctx.reply(f'{user.mention} has no strikes to clear.')
    else:
        clear_strikes()
        await ctx.reply('All strikes have been cleared.')

@bot.command()
async def viewstrikes(ctx: commands.Context):
    """View the number of strikes for all users."""
    strikes = get_strikes()
    if not strikes:
        return await ctx.reply("No users have any strikes.")

    sorted_strikes = sorted(strikes.items(), key=lambda x: x[1], reverse=True)
    strike_list = "\n".join([f"<@{user_id}>: {count} {'strike' if count == 1 else 'strikes'}" for user_id, count in sorted_strikes])
    await ctx.reply(f"**Strike List**\n{strike_list}")

import aiohttp

@bot.command()
async def meme(ctx: commands.Context):
    """Fetches a random meme."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://meme-api.com/gimme') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch meme.')
            data = await resp.json()
    
    await ctx.reply(data['url'])

@meme.error
async def meme_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the meme. Please try again later.")
    raise error

import aiohttp

@bot.command()
async def define(ctx: commands.Context, *, word: str):
    """Fetches the definition of a word."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get(f'https://api.urbandictionary.com/v0/define?term={word}') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch definition.')
            data = await resp.json()
    
    if not data['list']:
        return await ctx.reply(f'No definition found for {word}.')
    
    definition = data['list'][0]['definition']
    example = data['list'][0]['example']
    await ctx.reply(f'**{word}**\n\n{definition}\n\n*Example:*\n{example}')

@define.error
async def define_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply('You need to specify a word to define.')
    elif isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the definition. Please try again later.")
    raise error

import aiohttp

@bot.command()
async def catfact(ctx: commands.Context):
    """Fetches a random cat fact."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://catfact.ninja/fact') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch cat fact.')
            data = await resp.json()
    
    await ctx.reply(data['fact'])

import asyncio

@bot.command()
async def remind(ctx: commands.Context, time: int, *, reminder: str):
    """Sets a reminder for the user. Usage: .remind <time_in_seconds> <reminder>"""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    await ctx.reply(f"Reminder set! I'll remind you in {time} seconds.")
    await asyncio.sleep(time)
    await ctx.reply(f"⏰ Reminder: {reminder}")

@remind.error
async def remind_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply('You need to specify the time in seconds and the reminder text.')
    elif isinstance(error, commands.BadArgument):
        await ctx.reply('Invalid time format. Please enter the time in seconds.')
    elif isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while setting the reminder. Please try again later.")
    raise error

@bot.command()
async def countdown(ctx: commands.Context, seconds: int):
    """Starts a countdown from the specified number of seconds."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    if seconds <= 0:
        return await ctx.reply("The number of seconds must be positive.")
    
    message = await ctx.reply(f"Countdown: {seconds} seconds")
    while seconds > 0:
        await asyncio.sleep(1)
        seconds -= 1
        await message.edit(content=f"Countdown: {seconds} seconds")
    
    await message.edit(content="Countdown complete! ⏰")

@countdown.error
async def countdown_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply('You need to specify the number of seconds for the countdown.')
    elif isinstance(error, commands.BadArgument):
        await ctx.reply('Invalid time format. Please enter the time in seconds.')
    elif isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while starting the countdown. Please try again later.")
    raise error

@bot.command()
async def compliment(ctx: commands.Context, *, user: discord.User = None):
    """Sends a random compliment to a specified user or the command invoker."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    compliments = [
        "You're an awesome friend.",
        "You are the most perfect you there is.",
        "You are enough.",
        "You're strong.",
        "You deserve a hug right now.",
        "You have a great sense of humor.",
        "You light up the room.",
        "You deserve a break.",
        "You should be proud of yourself.",
        "You are amazing!"
    ]
    
    user = user or ctx.author
    await ctx.reply(f'{user.mention}, {random.choice(compliments)}')

@compliment.error
async def compliment_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while sending the compliment. Please try again later.")
    raise error

import aiohttp

@bot.command()
async def trivia(ctx: commands.Context):
    """Asks a random trivia question."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://opentdb.com/api.php?amount=1&type=multiple') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch trivia question.')
            data = await resp.json()
    
    question = data['results'][0]['question']
    correct_answer = data['results'][0]['correct_answer']
    all_answers = data['results'][0]['incorrect_answers'] + [correct_answer]
    random.shuffle(all_answers)
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    await ctx.reply(f'**Trivia Question:** {question}\n\n{", ".join(all_answers)}')
    
    try:
        answer = await bot.wait_for('message', check=check, timeout=15.0)
    except asyncio.TimeoutError:
        return await ctx.reply(f'Time is up! The correct answer was: {correct_answer}')
    
    if answer.content.lower() == correct_answer.lower():
        await ctx.reply('Correct! 🎉')
    else:
        await ctx.reply(f'Wrong! The correct answer was: {correct_answer}')

@trivia.error
async def trivia_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the trivia question. Please try again later.")
    raise error

import aiohttp

@bot.command()
async def randomfact(ctx: commands.Context):
    """Sends a random fact."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://uselessfacts.jsph.pl/random.json?language=en') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch random fact.')
            data = await resp.json()
    
    await ctx.reply(data['text'])

@randomfact.error
async def randomfact_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the random fact. Please try again later.")
    raise error

import aiohttp

@bot.command()
async def riddle(ctx: commands.Context):
    """Sends a random riddle and waits for the user's answer."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    riddles = {
        "What has keys but can't open locks?": "Piano",
        "I speak without a mouth and hear without ears. I have no body, but I come alive with the wind. What am I?": "Echo",
        "What can travel around the world while staying in a corner?": "Stamp",
        "What gets wetter as it dries?": "Towel",
        "What has many teeth but can't bite?": "Comb"
    }
    
    question, answer = random.choice(list(riddles.items()))
    
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
    
    await ctx.reply(f'**Riddle:** {question}')
    
    try:
        user_answer = await bot.wait_for('message', check=check, timeout=30.0)
    except asyncio.TimeoutError:
        return await ctx.reply(f'Time is up! The correct answer was: {answer}')
    
    if user_answer.content.lower() == answer.lower():
        await ctx.reply('Correct! 🎉')
    else:
        await ctx.reply(f'Wrong! The correct answer was: {answer}')

@riddle.error
async def riddle_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the riddle. Please try again later.")
    raise error



import aiohttp

@bot.command()
async def dadjoke(ctx: commands.Context):
    """Sends a random dad joke."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    headers = {'Accept': 'application/json'}
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://icanhazdadjoke.com/', headers=headers) as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch dad joke.')
            data = await resp.json()
    
    await ctx.reply(data['joke'])

@dadjoke.error
async def dadjoke_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the dad joke. Please try again later.")
    raise error


@bot.command()
async def avatar(ctx: commands.Context, *, user: discord.User = None):
    """Fetches the avatar of a specified user or the command invoker."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    try:
        user = user or ctx.author
        print(f"Fetching avatar for user: {user.name}#{user.discriminator} ({user.id})")
        avatar_url = user.display_avatar.url
        print(f"Avatar URL: {avatar_url}")
        await ctx.reply(avatar_url)
    except Exception as e:
        print(f"Error fetching avatar for user {user}: {e}")
        await ctx.reply("An error occurred while fetching the avatar. Please try again later.")

@avatar.error
async def avatar_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.UserNotFound):
        await ctx.reply(f'User {error.argument} not found!')
    elif isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the avatar. Please try again later.")
    raise error


@catfact.error
async def catfact_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the cat fact. Please try again later.")
    raise error
import aiohttp

@bot.command()
async def dog(ctx: commands.Context):
    """Fetches a random dog image."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    async with aiohttp.ClientSession() as session:
        async with session.get('https://dog.ceo/api/breeds/image/random') as resp:
            if resp.status != 200:
                return await ctx.reply('Failed to fetch dog image.')
            data = await resp.json()
    
    await ctx.reply(data['message'])

@dog.error
async def dog_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while fetching the dog image. Please try again later.")
    raise error

@bot.command()
async def roast(ctx: commands.Context, *, user: discord.User = None):
    """Sends a random roast to a specified user or the command invoker."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    roasts = [
        "You're like a cloud. When you disappear, it's a beautiful day.",
        "I'd agree with you, but then we'd both be wrong.",
        "You're not stupid; you just have bad luck thinking.",
        "If I had a face like yours, I'd sue my parents.",
        "You're proof that even evolution can go in reverse.",
        "You bring everyone a lot of joy when you leave the room."
    ]
    
    user = user or ctx.author
    await ctx.reply(f'{user.mention}, {random.choice(roasts)}')

@roast.error
async def roast_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while sending the roast. Please try again later.")
    raise error


@bot.command()
async def coinflip(ctx: commands.Context):
    """Flip a coin and get heads or tails."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    result = random.choice(["Heads", "Tails"])
    await ctx.reply(f"The coin landed on: **{result}**")

@coinflip.error
async def coinflip_error(ctx: commands.Context, error: commands.CommandError):
    """Handles errors for the .coinflip command."""
    if isinstance(error, commands.CommandInvokeError):
        await ctx.reply("An error occurred while trying to flip the coin. Please try again later.")
    raise error

@bot.command()
async def roll(ctx: commands.Context, dice: str):
    """Rolls a specified number of dice with a specified number of sides. Usage: .roll 2d6"""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    try:
        rolls, limit = map(int, dice.split('d'))
    except Exception:
        return await ctx.reply('Format has to be in NdN!')

    result = ', '.join(str(random.randint(1, limit)) for _ in range(rolls))
    await ctx.reply(f'You rolled: {result}')

@roll.error
async def roll_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply('You need to specify the dice format (e.g., 2d6).')
    elif isinstance(error, commands.BadArgument):
        await ctx.reply('Invalid dice format. Please use the NdN format (e.g., 2d6).')
    else:
        raise error
@bot.command(name='8ball')
async def eight_ball(ctx: commands.Context, *, question: str):
    """Ask the magic 8-ball a yes/no question."""
    if commands_locked and not is_admin(ctx.author.id):
        return await ctx.reply("Commands are currently locked by an admin.")
    
    responses = [
        "It is certain.", "It is decidedly so.", "Without a doubt.",
        "Yes – definitely.", "You may rely on it.", "As I see it, yes.",
        "Most likely.", "Outlook good.", "Yes.", "Signs point to yes.",
        "Reply hazy, try again.", "Ask again later.", "Better not tell you now.",
        "Cannot predict now.", "Concentrate and ask again.",
        "Don't count on it.", "My reply is no.", "My sources say no.",
        "Outlook not so good.", "Very doubtful."
    ]
    response = random.choice(responses)
    await ctx.reply(f'🎱 {response}')

@eight_ball.error
async def eight_ball_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.reply('You need to ask a yes/no question.')
    else:
        raise error

@bot.command()
async def viewbans(ctx: commands.Context):
    """View the list of banned users."""
    banned_users = get_banned_users()
    if not banned_users:
        return await ctx.reply("No users are currently banned.")

    banned_list = "\n".join([f"<@{user_id}>" for user_id in banned_users])
    await ctx.reply(f"**Banned Users:**\n{banned_list}")

@bot.event
async def on_message(message):
    if message.guild and message.guild.id == GUILD_ID and message.channel.id == CHANNEL_ID:
        print(f"Message in target channel by {message.author.name}: {message.content}")
        if message.author.id != bot.user.id:
            try:
                await message.delete()
                print(f"Deleted message from {message.author.name}")
            except discord.Forbidden:
                print(f"Failed to delete message from {message.author.name} due to insufficient permissions.")
            except discord.HTTPException as e:
                print(f"Failed to delete message from {message.author.name} due to HTTPException: {e}")
            except Exception as e:
                print(f"An unexpected error occurred while deleting message from {message.author.name}: {e}")

    await bot.process_commands(message)

bot.run(config.token)

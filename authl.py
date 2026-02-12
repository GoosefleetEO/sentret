#######################################################
#                     digital_pet                     #
#                   p r e s e n t s                   #
#   A fucking something awful authbot fucking shit.   #
#######################################################

###
# Imports
###
import logging
import asyncio
import os
import re
from stoat.ext import commands
import sqlite3
import crypt
import traceback
from configparser import ConfigParser
from awfulpy import *
from contextlib import closing
from datetime import datetime
from pprint import pp

###
# Config
###

secrets = ConfigParser()
secrets.read('secrets.ini')
config = ConfigParser()
config.read('config.ini')

bbuserid = secrets['SAForums']['bbuserid']
bbpassword = secrets['SAForums']['bbpassword']
sessionid = secrets['SAForums']['sessionid']
sessionhash = secrets['SAForums']['sessionhash']
bottoken = secrets['Stoat']['token']

dbfile=config['Database']['file']

goonrole=config['Stoat']['roleID']
guildid=config['Stoat']['guildID']
bschan=config['Stoat']['botspamID']

###
# instantiate awful scraper and bot
###

profile = AwfulProfile(bbuserid, bbpassword, sessionid, sessionhash)

bot = commands.Bot(command_prefix=commands.when_mentioned_or('!'))
bot.token = bottoken

###
# Setup logging
###

loglevelDict = {
    'debug' : logging.DEBUG,
    'info' : logging.INFO,
    'warning' : logging.WARNING,
    'error' : logging.ERROR,
    'critical' : logging.CRITICAL}

logging.basicConfig(
    format="%(asctime)s %(levelname)-10s %(message)s",
    filename=config['Logging']['file'], 
    encoding='utf-8', 
    level=loglevelDict[config['Logging']['level']], 
    datefmt='%Y-%m-%d %H:%M:%S')

###
# db wrapper for parameterized queries
###

def query(db_name, querystring, params):
    with closing(sqlite3.connect(db_name)) as con, con, closing(con.cursor()) as cur:
        cur.execute(querystring, params)
        return cur.fetchall()    

###
# Auth worker loop
###

async def auth_processor():

    get_query = '''SELECT * FROM goons WHERE is_banned=0 AND is_authed=0 AND is_sus=0'''
    get_params = {}
    
    auth_query = '''UPDATE goons SET is_authed=1 WHERE userID=:userid LIMIT 1'''
    err_query = '''UPDATE goons SET is_sus=1 WHERE userID=:userid LIMIT 1'''

    await asyncio.sleep(10)

    botspamchannel = await bot.fetch_channel(bschan)
    
    server = await bot.fetch_server(guildid)

    role = await server.fetch_role(goonrole)

    while True:
        await asyncio.sleep(10)
        logging.info("auth worker running")
        results = query(dbfile, get_query, get_params)
        if results:
            success = ""
            displaymessage = False
            for r in results:
                userid = r[0]
                try:
                    user = await server.fetch_member(r[1])
                except Exception:
                    user = None
                    logging.error("Error encountered finding user", exc_info=True)
                if user is None:
                    logging.info(f"User with discord id {r[1]} is not in the server, skipping.")
                    err_params = {"userid":userid}
                    query(dbfile, err_query, err_params)
                    await botspamchannel.send(f"User https://forums.somethingawful.com/member.php?action=getinfo&userid={userid} left discord, please unsus if they rejoin.")
                    continue

                
                result = await profile.fetch_profile_by_id(userid)
                fulltext = result.biography
                
                position = fulltext.find(r[2])
                if position > -1:
                    auth_params = {"userid":userid}
                    try:
                        if role in user.roles:
                            query(dbfile, auth_query, auth_params)
                            continue
                        
                        newroles = []
                        for r in user.roles:
                            newroles.append(r)
                        
                        newroles.append(role)
                        
                        await user.edit(roles=newroles)
 
                        success = success + "\n" + user.mention
                        
                        displaymessage = True
                        
                        query(dbfile, auth_query, auth_params)
                    
                    except Exception:
                        logging.error("Could not auth user", exc_info=True)
                        await botspamchannel.send(f"Authenticating user {user.mention} failed.")
                        await asyncio.sleep(10)
                        continue
                await asyncio.sleep(10)
                
            if displaymessage:
                await botspamchannel.send(f"Gave goon role to the following users {success}")
                    
        logging.info("auth worker waiting")
        await asyncio.sleep(50)



###
#   Exceptions that may be encountered during authentication
###

class DuplicateEntry(Exception):
    pass
class UserMismatch(Exception):
    pass
class DiscordMismatch(Exception):
    pass
class BannedUser(Exception):
    pass

###
#   Authentication functions
###

async def get_profile(userid = None, username = None):
    if userid:
        return await profile.fetch_profile_by_id(userid)
    elif username:
        return await profile.fetch_profile(username)
    else:
        raise ArgumentError("get_profile called without userid or username")


async def get_userid(username):
    user_profile = await get_profile(username=username)
    return user_profile.userid

async def get_username(userid):
    user_profile = await get_profile(userid=userid)
    return user_profile.username
    
async def calculate_suspicion(userid):
    user_profile = await get_profile(userid=userid)

    sus = 0
    
    #sub 300 postcount is sus

    postcount = user_profile.posts
    
    if abs(postcount) < 300:
        sus = 1
     
    #regdate less than 3 months is sus

    regdate = datetime.utcfromtimestamp(user_profile.joindate)
    
    threshhold = datetime.timestamp(datetime.now()) - (2629800*3)
 
    if datetime.timestamp(regdate) > threshhold:
        sus = 1
    
    return sus
    
async def get_user(userid,discordid):
    
    get_query = '''SELECT * FROM goons WHERE userID=:userid OR discordID=:discordid'''
    get_params = {"userid": userid, "discordid":discordid}
    
    kos_check_query = '''SELECT * FROM kos WHERE userID=:userid LIMIT 1'''
    kos_params = {"userid":userid}
    
    results = query(dbfile, get_query, get_params)
    if len(results) > 1:
        raise DuplicateEntry(f"Expected 1 result, got {len(results)}")
    
    if not results:
    
        #If there isn't an existing user, add it.
        sus = await calculate_suspicion(userid)

        # TODO: log in botspam if sus

        secret = crypt.crypt(f"{discordid}{userid}")
        minsecret = "HONK!" + secret[20:32]
        
        ban = 1 if len(query(dbfile,kos_check_query,kos_params)) else 0
        
        ins_query = '''INSERT INTO goons values (:userid,:discordid,:secret,:ban,0,:sus,"")'''
        ins_params = {"userid": userid,"discordid": discordid,"secret":minsecret,"ban":ban,"sus":sus}
        
        query(dbfile, ins_query,ins_params)
        results = query(dbfile, get_query, get_params)
    
    if results[0][0] != str(userid):
        logging.error("UserMismatch - " + str(results))
        raise UserMismatch(f"User provided {userid}, db contained {results[0][0]}")
    
    if results[0][1] != discordid:
        logging.error("DiscordMismatch - " + str(results))
        raise DiscordMismatch(f"User provided {discordid}, db contained {results[0][1]}")
    
    if results[0][3]:
        logging.error("BannedUser - " + str(results))
        raise BannedUser("User is banned!")
    
    return results


class SentretBot(commands.Gear):
    def __init__(self, bot):
        self.bot = bot

    ###
    # Bot events
    ###


    @commands.Gear.listener()
    async def on_member_join(self, event):
        member = event.member
        server = member.server
        
        role = await server.fetch_role(goonrole)
        log_channel = await server.get_channel(bschan)

        logging.info("User joined")

        get_query = '''SELECT is_banned, is_authed FROM goons WHERE discordID=:discordid'''
        get_params = {"discordid":str(member.id)}

        try:
            results = query(dbfile, get_query, get_params)
        except Exception:
            logging.error("Error encountered finding user", exc_info=True)
            return

        if results[0][0]:
        #    try:
        #        await user.ban(guildid,reason="You're banned!")
        #    except Exception:
        #        #log error
        #        pass
            logging.info("User is banned, not granting role")
            return

        if results[0][1]:
            try:
                await member.edit(roles=member.roles.append(role))
            except Exception:
                logging.error("Error encountered giving user role", exc_info=True)
                pass
            return

        if not results:
            logging.info("User not registered as goon")
            return  

    #authme
    @commands.command()
    async def authme(self, ctx, username):

        if not username:
            ctx.send("You must specify your forums handle.")
            
        botspamchannel = ctx.server.get_channel(bschan)

        response = ""
        userid = await get_userid(username)
        if userid is None:
            response = f"{username} is not registered on SA.\n\nIf you want to be registered on SA you can spend :10bux: at https://forums.somethingawful.com. Otherwise, please honk in \#spambot-prison until we give you a role."
            await ctx.send(response)
            return
        
        response = f"Found {username} with ID {userid}"
        
        try:
            results = await get_user(userid,str(ctx.author.id))
        except BannedUser:
            response = "You are banned! Contact leadership if you wish to appeal your ban."
            await ctx.send(response)
            return
        
        except UserMismatch:
            response = "An error occured. Please ping leadership."
            await ctx.send(response)
            return

        except DiscordMismatch:
            response = "An error occured. Please ping leadership."
            await ctx.send(response)
            return
        except DuplicateEntry:
            response = "A duplicate entry was encountered. This should never happen. The database is corrupted."
            await ctx.send(response)
            return
        
        response = f"{response}\nPut the following key in your SA profile \"about me\" section: {results[0][2]}\nDo not put it in ICQ number or homepage or any other field."
        
        if results[0][5]:
            await botspamchannel.send("User " + ctx.author.mention + " needs attention to complete authentication.")
            response = response + "\n\nA member of leadership may contact you to complete your authentication."
        else:
            response = response + "\n\nYou will be automatically authenticated within 24 hours."
        
        await ctx.send(response)

    #authem
    #TODO

    #whois
    #TODO
    
    #listsus
    @commands.command()
    async def listsus(self, ctx):
        
        if not ctx.author.server_permissions.kick_members:
            return
        
        querystr = '''SELECT * FROM goons WHERE is_sus = 1 AND is_banned = 0'''

        params = {}

        result = query(dbfile, querystr, params)
        
        if result:
            response = str(len(result)) + " goons are sus:"
            for r in result:
                try: 
                    user = await ctx.server.fetch_member(r[1])
                except Exception:
                    user = False
                userid = r[0]
                username = await get_username(r[0])
                try:
                    response = f"{response}\n{user.mention} (ID: {userid}, Handle: {username})"
                except Exception:
                    response = f"{response}\nUser not in discord (ID: {userid}, Handle: {username})"

        else:
            response = "No goons are currently being sus."
        
        await ctx.send(response)
    
    #listunauth
    @commands.command()
    async def listunauth(self, ctx):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''SELECT * FROM goons WHERE is_authed = 0 AND is_sus = 0 AND is_banned = 0'''

        params = {}

        result = query(dbfile, querystr, params)
        
        if result:
            response = str(len(result)) + " goons haven't put the code in:"
            for r in result:
                try: 
                    user = await ctx.server.fetch_member(r[1])
                except Exception:
                    user = False
                userid = r[0]
                username = await get_username(r[0])
                try:
                    response = f"{response}\n{user.mention} (ID: {userid}, Handle: {username})"
                except Exception:
                    response = f"{response}\nUser not in discord (ID: {userid}, Handle: {username})"

        else:
            response = "All the goons have followed instructions."
        
        await ctx.send(response)
    
    #listban
    @commands.command()
    async def listban(self, ctx):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''SELECT * FROM goons WHERE is_banned = 1'''

        params = {}
        result = query(dbfile, querystr, params)
        if result:
            response = str(len(result)) + " goons are banned:"
            for r in result:
                try: 
                    user = await ctx.server.fetch_member(r[1])
                except Exception:
                    user = False
                userid = r[0]
                username = await get_username(r[0])
                try:
                    response = f"{response}\n{user.mention} (ID: {userid}, Handle: {username}, Reason: {r[6]})"
                except Exception:
                    response = f"{response}\nUser not in discord (ID: {userid}, Handle: {username}, Reason: {r[6]})"
        
        else:

            response = "Nobody's banned!"
        
        await ctx.send(response)

    #listkline
    @commands.command()
    async def listkline(self, ctx):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''SELECT * FROM kos'''

        params = {}
        result = query(dbfile, querystr, params)
        if result:
            response = str(len(result)) + " goons are klined:"
            for r in result:
                
                userid = r[0]
                username = await get_username(r[0])
                reason = r[1]
                response = f"{response}\nID: {userid}, Handle: {username}, Reason: {reason}"
        
        else:

            response = "Nobody's klined!"
        
        await ctx.send(response)
    
    #unsus
    @commands.command()
    async def unsus(self, ctx, username: str):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''UPDATE goons SET is_sus = 0 WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)

        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid}
        
        query(dbfile, querystr, params)

        response  = f"{str(username)} with id {userid} has been cleared to authenticate."
        
        await ctx.send(response)

    #roleupall
    #TODO
    
    #unauth
    @commands.command()
    async def unauth(self, ctx, username: str):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''UPDATE goons SET is_authed = 0 WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)

        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid}
        
        query(dbfile, querystr, params)

        response  = f"{str(username)} with id {userid} will be reauthenticated."
        
        await ctx.send(response)
    
    #purge
    @commands.command()
    async def purge(self, ctx, username: str):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''DELETE FROM goons WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)

        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid}
        
        query(dbfile, querystr, params)

        response  = f"{str(username)} with id {userid} has been purged from the database."
        
        await ctx.send(response)
    
    #kline
    @commands.command()
    async def kline(self, ctx, username: str, reason: str):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''INSERT INTO kos VALUES (:userid, :reason)'''

        response = ""
        userid = await get_userid(username)

        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid, "reason": reason}
        
        query(dbfile, querystr, params)

        response  = f"{str(username)} with id {userid} has been klined."
        
        await ctx.send(response)
    
    #unkline
    @commands.command()
    async def unkline(self, ctx, username: str):

        if not ctx.author.server_permissions.kick_members:
            return
            
        querystr = '''DELETE FROM kos WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)

        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid}
        
        query(dbfile, querystr, params)

        response  = f"{str(username)} with id {userid} has been unklined."
        
        await ctx.send(response)
    
    #bangoon
    @commands.command()
    async def bangoon(self, ctx, username: str, reason: str):

        if not ctx.author.server_permissions.kick_members:
            return

        server = await bot.fetch_server(guildid)

        role = await server.fetch_role(goonrole)

        querystr = '''UPDATE goons SET is_banned = 1, is_authed=0, ban_reason=:reason WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)
        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return

        params = {"userid": userid, "reason": reason}
        
        query(dbfile, querystr, params)

        querystr = '''SELECT * FROM goons WHERE userID=:userid LIMIT 1'''
        
        result = query(dbfile, querystr, params)

        for r in result:
            try:
                user = await server.fetch_member(r[1])
                newroles = []
                for rl in user.roles:
                    if rl != role:
                        newroles.append(rl)
                
                await user.edit(roles=newroles)
                
            except Exception:
                user = None
                logging.error("Error encountered finding user", exc_info=True)
            if user is None:
                logging.info(f"User with discord id {r[1]} is not in the server, skipping.")
                continue

        response  = f"{username} with id {userid} is banned."
        
        await ctx.send(response)
    
    #unbangoon
    @commands.command()
    async def unbangoon(self, ctx, username: str):

        if not ctx.author.server_permissions.kick_members:
            return

        querystr = '''UPDATE goons SET is_banned = 0 WHERE userID=:userid LIMIT 1'''

        response = ""
        userid = await get_userid(username)
        if userid is None:
            response = f"{username} is not registered on SA."
            await ctx.send(response)
            return
            
        params = {"userid": userid}

        query(dbfile, querystr, params)
        
        response  = f"{username} with id {userid} is unbanned."
        
        await ctx.send(response) 

###
# Main program starts here
###

async def main():

    #logging.info('===Startup===')

    def handle_exception(loop,context):
        msg = context.get(message)
        e = context.get(exception)
        traceback = ''.join(traceback.format_exception(e))
        logging.error(f"{msg}\n{traceback}")
        print("Please wait, crashing...")    
        os._exit(3)

    loop = asyncio.get_running_loop()
    loop.set_exception_handler(handle_exception)
    
    bot.http.with_credentials(bot.token, bot=bot)
    bot.shard.with_credentials(bot.token, bot=bot)

    background = asyncio.create_task(auth_processor())
    foreground = asyncio.create_task(bot.start())
    
    await bot.add_gear(SentretBot(bot))
    
    done, pending = await asyncio.wait(
        [background, foreground],
        return_when=asyncio.FIRST_EXCEPTION
    )
    
    for task in pending:
        task.cancel()
    
    for task in done:
        if task.exception():
            logging.error(''.join(traceback.format_exception(task.exception())))

try:
    retval = 0

    asyncio.run(main())
except KeyboardInterrupt:
    print('\nCtrl-C received, quitting immediately')
    logging.critical('Ctrl-C received, quitting immediately')
    retval = 1
except Exception:
    print("Please wait, crashing...")
    logging.critical("Fatal error in main loop", exc_info=True)
    retval = 2
finally:
    os._exit(retval)

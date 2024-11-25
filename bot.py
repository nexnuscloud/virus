import discord
from discord.ext import commands
import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve token and API key from environment variables
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Define the command prefix
PREFIX = "!"

# Initialize bot with command prefix
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

# Event: Bot is ready
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")

# Example command
@bot.command()
async def ping(ctx):
    await ctx.send("Pong!")

# Command: Scan file
@bot.command()
async def scan(ctx):
    if ctx.message.attachments:
        for attachment in ctx.message.attachments:
            await ctx.send(f"Scanning `{attachment.filename}` for viruses...")

            # Download the file locally
            file_path = f"./{attachment.filename}"
            await attachment.save(file_path)

            # Upload the file to VirusTotal
            with open(file_path, "rb") as file:
                files = {"file": file}
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files
                )

            os.remove(file_path)

            # Handle VirusTotal response
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                await ctx.send(f"File uploaded successfully! Analysis ID: `{analysis_id}`")

                # Check scan results
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)

                if analysis_response.status_code == 200:
                    result = analysis_response.json()
                    stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values())

                    if malicious > 0:
                        await ctx.send(f"⚠️ `{attachment.filename}` is flagged as malicious by `{malicious}/{total}` scanners.")
                    else:
                        await ctx.send(f"✅ `{attachment.filename}` is clean.")
                else:
                    await ctx.send("⚠️ Failed to fetch scan results.")
            else:
                await ctx.send("⚠️ Failed to upload file to VirusTotal.")
    else:
        await ctx.send("⚠️ No attachments found.")

# Run the bot
bot.run(TOKEN)

import os
import hmac
import aiohttp

import discord
from aiohttp import web
from dotenv import load_dotenv


load_dotenv()

DISCORD_TOKEN = os.environ["DISCORD_TOKEN"]
DISCORD_USER_ID = int(os.environ["DISCORD_USER_ID"])
TINES_SECRET = os.environ["TINES_SECRET"]
TINES_DECISION_WEBHOOK = os.environ["TINES_DECISION_WEBHOOK"]
TINES_DECISION_SECRET = os.environ["TINES_DECISION_SECRET"]

PORT = int(os.getenv("PORT", "8080"))

intents = discord.Intents.none()
bot = discord.Client(intents=intents)

runner = None


def safe_value(data, key):
    value = data.get(key)

    if value is None or value == "":
        return "brak"

    return str(value)[:1000]


async def send_decision_to_tines(action, sid, host, oid, interaction):
    payload = {
        "action": action,
        "sid": sid,
        "host": host,
        "oid": oid,
        "discord_user_id": str(interaction.user.id),
        "discord_user": str(interaction.user)
    }

    headers = {
        "Authorization": f"Bearer {TINES_DECISION_SECRET}",
        "Content-Type": "application/json"
    }

    timeout = aiohttp.ClientTimeout(total=10)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            TINES_DECISION_WEBHOOK,
            json=payload,
            headers=headers
        ) as response:

            response_text = await response.text()

            if response.status >= 300:
                raise RuntimeError(
                    f"Tines error {response.status}: {response_text}"
                )


class IsolationView(discord.ui.View):

    def __init__(self, sid, host, oid):
        super().__init__(timeout=600)

        self.sid = sid
        self.host = host
        self.oid = oid
        self.decided = False

    async def check_user(self, interaction):
        if interaction.user.id != DISCORD_USER_ID:
            await interaction.response.send_message(
                "❌ Nie masz uprawnień do wykonania tej akcji."
            )
            return False

        return True

    def disable_buttons(self):
        for item in self.children:
            item.disabled = True

    @discord.ui.button(
        label="Izoluj maszynę",
        style=discord.ButtonStyle.danger,
        emoji="🔒"
    )
    async def isolate_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):

        if not await self.check_user(interaction):
            return

        if self.decided:
            await interaction.response.send_message(
                "Decyzja dla tego alertu została już podjęta."
            )
            return

        try:
            await send_decision_to_tines(
                "isolate",
                self.sid,
                self.host,
                self.oid,
                interaction
            )

            self.decided = True
            self.disable_buttons()

            await interaction.response.edit_message(
                view=self
            )

            await interaction.followup.send(
                f"🔒 Wysłano żądanie izolacji hosta **{self.host}** do Tines."
            )

            self.stop()

        except Exception as e:

            await interaction.response.send_message(
                f"❌ Nie udało się wysłać decyzji do Tines:\n`{e}`"
            )

    @discord.ui.button(
        label="Nie izoluj",
        style=discord.ButtonStyle.success,
        emoji="✅"
    )
    async def no_isolate_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):

        if not await self.check_user(interaction):
            return

        if self.decided:
            await interaction.response.send_message(
                "Decyzja dla tego alertu została już podjęta."
            )
            return

        try:
            await send_decision_to_tines(
                "no_isolate",
                self.sid,
                self.host,
                self.oid,
                interaction
            )

            self.decided = True
            self.disable_buttons()

            await interaction.response.edit_message(
                view=self
            )

            await interaction.followup.send(
                f"✅ Host **{self.host}** nie zostanie odizolowany."
            )

            self.stop()

        except Exception as e:

            await interaction.response.send_message(
                f"❌ Nie udało się wysłać decyzji do Tines:\n`{e}`"
            )


async def tines_alert(request):

    # Sprawdzenie sekretu
    received_secret = request.headers.get("X-Tines-Secret", "")

    if not hmac.compare_digest(received_secret, TINES_SECRET):
        return web.json_response(
            {"error": "unauthorized"},
            status=401
        )

    try:
        data = await request.json()
    except Exception:
        return web.json_response(
            {"error": "invalid json"},
            status=400
        )

    print("Odebrano alert z Tines:")
    print(data)

    embed = discord.Embed(
        title="🚨 Suspicious File Execution",
        description="Tines wykrył uruchomienie podejrzanego pliku.",
        colour=discord.Colour.red()
    )

    embed.add_field(
        name="🖥 Host",
        value=safe_value(data, "host"),
        inline=True
    )

    embed.add_field(
        name="👤 User",
        value=safe_value(data, "user"),
        inline=True
    )

    embed.add_field(
        name="⚠ Severity",
        value=safe_value(data, "severity"),
        inline=True
    )

    embed.add_field(
        name="📄 File",
        value=safe_value(data, "file"),
        inline=False
    )

    embed.add_field(
        name="📁 Path",
        value=safe_value(data, "path"),
        inline=False
    )

    embed.add_field(
        name="🔑 SHA256",
        value=safe_value(data, "sha256"),
        inline=False
    )

    embed.add_field(
        name="⚙ Command Line",
        value=safe_value(data, "command_line"),
        inline=False
    )

    embed.add_field(
        name="🔗 Parent Process",
        value=safe_value(data, "parent_process"),
        inline=False
    )

    embed.add_field(
        name="🛡 Source",
        value=safe_value(data, "source"),
        inline=True
    )

    try:
        user = await bot.fetch_user(DISCORD_USER_ID)

        sid = data.get("sensor_sid")
        oid = data.get("oid")
        host = data.get("host", "Unknown host")

        if sid:
            view = IsolationView(
                sid=sid,
                host=host,
                oid=oid
            )

            await user.send(
                embed=embed,
                view=view
            )
        else:
            await user.send(embed=embed)

    except discord.Forbidden:
        return web.json_response(
            {"error": "Discord DM blocked"},
            status=500
        )

    except discord.HTTPException as e:
        return web.json_response(
            {"error": str(e)},
            status=500
        )

    return web.json_response({
        "status": "alert_sent"
    })


@bot.event
async def on_ready():
    global runner

    print(f"✅ Discord bot zalogowany jako: {bot.user}")

    if runner is None:
        app = web.Application()

        app.router.add_post(
            "/tines-alert",
            tines_alert
        )

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(
            runner,
            "0.0.0.0",
            PORT
        )

        await site.start()

        print(f"✅ API działa na porcie {PORT}")
        print(f"Endpoint: /tines-alert")


bot.run(DISCORD_TOKEN)

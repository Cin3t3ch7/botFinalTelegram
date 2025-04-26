# monitor_bot.py
import asyncio
import logging
import sys
import subprocess
import time
import os
import psutil
from datetime import datetime
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

# Configuración de logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='logs/monitor_bot.log'
)

# Reducir logging de las bibliotecas externas
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('telegram').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Configuración
MONITOR_BOT_TOKEN = "7703828582:AAGoZaPoo6FTi4gmgzkF_iBDArzhwY7PrSQ"
ADMIN_IDS = [1516580367]  # Super Admin ID
SYSTEMD_SERVICE = "telegram-bot.service"

# Estado de los bots
bot_status = {}
last_health_check = {}

# Verificar autorización
async def check_auth(update: Update):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("⛔ No estás autorizado para usar este bot de monitoreo.")
        return False
    return True

# Comando /start
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    await update.message.reply_text(
        "🤖 Bot de Monitoreo y Control\n\n"
        "Comandos disponibles:\n"
        "/status - Ver estado de todos los bots\n"
        "/system - Ver información del sistema\n"
        "/restart - Reiniciar todos los bots\n"
        "/restart_service - Reiniciar el servicio completo\n"
        "/logs - Ver últimos logs de error\n"
        "/clean - Limpiar conexiones IMAP y BD\n"
        "/kill - Terminar instancias problemáticas\n"
        "/help - Ver esta ayuda"
    )

# Comando /status
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    await gather_bot_status()
    
    message = "📊 Estado de los bots:\n\n"
    
    if not bot_status:
        message += "❓ No hay información de estado disponible.\n"
    else:
        for token, status in bot_status.items():
            token_short = token[:10] + "..."
            last_check = last_health_check.get(token, "Nunca")
            if isinstance(last_check, datetime):
                last_check = last_check.strftime("%Y-%m-%d %H:%M:%S")
            
            status_emoji = "✅" if status.get("active", False) else "❌"
            uptime = status.get("uptime", "Desconocido")
            
            message += f"{status_emoji} Bot {token_short}\n"
            message += f"⏱️ Tiempo activo: {uptime}\n"
            message += f"🕒 Último reporte: {last_check}\n\n"
    
    keyboard = [
        [InlineKeyboardButton("🔄 Actualizar", callback_data="refresh_status")],
        [InlineKeyboardButton("🔧 Reiniciar todos", callback_data="restart_all")]
    ]
    
    await update.message.reply_text(
        message, 
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

# Comando /system
async def system_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    info = get_system_info()
    
    message = "💻 Información del sistema:\n\n"
    message += f"🔄 CPU: {info['cpu_percent']}%\n"
    message += f"🧠 Memoria: {info['memory_percent']}% (Disponible: {info['memory_available']})\n"
    message += f"💾 Disco: {info['disk_percent']}% (Libre: {info['disk_free']})\n"
    
    # Procesos Python
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        if "python" in proc.info['name'].lower():
            processes.append(proc.info)
    
    if processes:
        message += "\n📋 Procesos Python:\n"
        for proc in sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:5]:
            message += f"PID: {proc['pid']}, Memoria: {proc['memory_percent']:.2f}%\n"
    
    # Información de locks
    lock_files = []
    if os.path.exists("locks"):
        lock_files = [f for f in os.listdir("locks") if f.endswith(".lock")]
    
    if lock_files:
        message += "\n🔒 Archivos de bloqueo activos:\n"
        for lock_file in lock_files:
            try:
                with open(os.path.join("locks", lock_file), 'r') as f:
                    pid = f.read().strip()
                    is_running = "✅" if psutil.pid_exists(int(pid)) else "❌"
                    message += f"{is_running} {lock_file} (PID: {pid})\n"
            except:
                message += f"❓ {lock_file} (error al leer)\n"
    
    await update.message.reply_text(message)

# Obtener información del sistema
def get_system_info():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_available": f"{memory.available / (1024 * 1024):.2f} MB",
        "disk_percent": disk.percent,
        "disk_free": f"{disk.free / (1024 * 1024 * 1024):.2f} GB"
    }

# Comando /restart
async def restart_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    keyboard = [
        [
            InlineKeyboardButton("✅ Sí, reiniciar todos", callback_data="confirm_restart_all"),
            InlineKeyboardButton("❌ Cancelar", callback_data="cancel_restart")
        ]
    ]
    
    await update.message.reply_text(
        "⚠️ ¿Estás seguro de que deseas reiniciar todos los bots?",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

# Comando /restart_service
async def restart_service_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    keyboard = [
        [
            InlineKeyboardButton("✅ Sí, reiniciar servicio", callback_data="confirm_restart_service"),
            InlineKeyboardButton("❌ Cancelar", callback_data="cancel_restart")
        ]
    ]
    
    await update.message.reply_text(
        "⚠️ ¿Estás seguro de que deseas reiniciar el servicio completo? (systemctl restart telegram-bot.service)",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

# Comando /logs
async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    try:
        # Obtener últimos logs de error
        process = subprocess.run(
            ["tail", "-n", "50", "logs/error.log"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        logs = process.stdout
        
        if not logs:
            logs = "No hay logs disponibles o el archivo está vacío."
        
        # Si los logs son demasiado largos, enviar como archivo
        if len(logs) > 4000:
            await update.message.reply_document(
                document=logs.encode('utf-8'),
                filename="latest_errors.log",
                caption="📋 Últimos logs de error"
            )
        else:
            await update.message.reply_text(f"📋 Últimos logs de error:\n\n```\n{logs}\n```", parse_mode="Markdown")
            
    except Exception as e:
        await update.message.reply_text(f"❌ Error al obtener logs: {str(e)}")

# Comando /clean
async def clean_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    keyboard = [
        [
            InlineKeyboardButton("✅ Sí, limpiar conexiones", callback_data="confirm_clean"),
            InlineKeyboardButton("❌ Cancelar", callback_data="cancel_clean")
        ]
    ]
    
    await update.message.reply_text(
        "⚠️ ¿Deseas limpiar todas las conexiones IMAP y BD persistentes?",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

# Comando /kill - Para terminar procesos problemáticos
async def kill_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    
    # Verificar argumentos
    args = context.args
    if not args:
        # Mostrar lista de procesos del bot si no se especifica PID
        bot_processes = []
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and len(cmdline) >= 3 and 'run_single_bot.py' in cmdline[1]:
                    token = cmdline[2][:10] if len(cmdline) > 2 else "unknown"
                    bot_processes.append((proc.info['pid'], token))
            except:
                pass
        
        if not bot_processes:
            await update.message.reply_text("No se encontraron procesos de bot en ejecución.")
            return
        
        message = "📋 Procesos de bot en ejecución:\n\n"
        for pid, token in bot_processes:
            message += f"PID: {pid} - Token: {token}...\n"
        
        message += "\nPara terminar un proceso: /kill <PID>"
        
        await update.message.reply_text(message)
        return
    
    try:
        # Intentar terminar el proceso especificado
        pid = int(args[0])
        
        try:
            process = psutil.Process(pid)
            process_name = ' '.join(process.cmdline()) if hasattr(process, 'cmdline') else process.name()
            
            # Verificar si es un proceso de bot
            is_bot_process = False
            cmdline = process.cmdline() if hasattr(process, 'cmdline') else []
            if cmdline and len(cmdline) >= 2 and 'run_single_bot.py' in cmdline[1]:
                is_bot_process = True
                
            if not is_bot_process:
                await update.message.reply_text(
                    f"⚠️ El proceso {pid} no parece ser un proceso de bot.\n"
                    f"Comando: {process_name}\n\n"
                    "¿Estás seguro de que quieres terminarlo?",
                    reply_markup=InlineKeyboardMarkup([
                        [
                            InlineKeyboardButton("✅ Sí, terminar", callback_data=f"confirm_kill_{pid}"),
                            InlineKeyboardButton("❌ No, cancelar", callback_data="cancel_kill")
                        ]
                    ])
                )
                return
            
            # Si es un proceso de bot, terminarlo directamente
            process.terminate()
            await update.message.reply_text(f"✅ Señal de terminación enviada al proceso {pid}.")
            
            # Esperar un momento para ver si el proceso termina
            await asyncio.sleep(2)
            
            # Verificar si el proceso sigue en ejecución
            if psutil.pid_exists(pid):
                await update.message.reply_text(
                    f"⚠️ El proceso {pid} sigue en ejecución. ¿Deseas forzar su terminación?",
                    reply_markup=InlineKeyboardMarkup([
                        [
                            InlineKeyboardButton("✅ Sí, forzar", callback_data=f"force_kill_{pid}"),
                            InlineKeyboardButton("❌ No, esperar", callback_data="cancel_kill")
                        ]
                    ])
                )
            else:
                # Si el proceso terminó, eliminar su archivo de bloqueo
                for lock_file in os.listdir("locks"):
                    if lock_file.endswith(".lock"):
                        try:
                            with open(os.path.join("locks", lock_file), 'r') as f:
                                lock_pid = int(f.read().strip())
                                if lock_pid == pid:
                                    os.remove(os.path.join("locks", lock_file))
                                    await update.message.reply_text(f"🔓 Archivo de bloqueo {lock_file} eliminado.")
                        except:
                            pass
        
        except psutil.NoSuchProcess:
            await update.message.reply_text(f"❌ El proceso {pid} no existe.")
        except psutil.AccessDenied:
            await update.message.reply_text(f"❌ Acceso denegado al proceso {pid}.")
        except Exception as e:
            await update.message.reply_text(f"❌ Error al terminar el proceso {pid}: {str(e)}")
    
    except ValueError:
        await update.message.reply_text("❌ PID inválido. Debe ser un número.")

# Manejador de callbacks
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "refresh_status":
        await query.edit_message_text("🔄 Actualizando estado... Por favor espera.")
        await gather_bot_status()
        await status_command(update, context)
        
    elif query.data == "restart_all":
        await restart_command(update, context)
        
    elif query.data == "confirm_restart_all":
        await query.edit_message_text("🔄 Reiniciando todos los bots... Por favor espera.")
        success = await restart_all_bots()
        if success:
            await query.edit_message_text("✅ Todos los bots han sido reiniciados correctamente.")
        else:
            await query.edit_message_text("❌ Ocurrió un error al reiniciar los bots. Revisa los logs.")
            
    elif query.data == "confirm_restart_service":
        await query.edit_message_text("🔄 Reiniciando el servicio... Por favor espera.")
        success = restart_systemd_service()
        if success:
            await query.edit_message_text("✅ El servicio ha sido reiniciado correctamente.")
        else:
            await query.edit_message_text("❌ Ocurrió un error al reiniciar el servicio. Revisa los logs.")
            
    elif query.data == "cancel_restart" or query.data == "cancel_clean" or query.data == "cancel_kill":
        await query.edit_message_text("❌ Operación cancelada.")
        
    elif query.data == "confirm_clean":
        await query.edit_message_text("🔄 Limpiando conexiones... Por favor espera.")
        success = await clean_connections()
        if success:
            await query.edit_message_text("✅ Conexiones limpiadas correctamente.")
        else:
            await query.edit_message_text("❌ Ocurrió un error al limpiar las conexiones. Revisa los logs.")
    
    elif query.data.startswith("confirm_kill_"):
        pid = int(query.data.split("_")[2])
        try:
            process = psutil.Process(pid)
            process.terminate()
            await query.edit_message_text(f"✅ Señal de terminación enviada al proceso {pid}.")
            
            # Esperar un momento para ver si el proceso termina
            await asyncio.sleep(2)
            
            # Verificar si el proceso sigue en ejecución
            if psutil.pid_exists(pid):
                await query.edit_message_text(
                    f"⚠️ El proceso {pid} sigue en ejecución. ¿Deseas forzar su terminación?",
                    reply_markup=InlineKeyboardMarkup([
                        [
                            InlineKeyboardButton("✅ Sí, forzar", callback_data=f"force_kill_{pid}"),
                            InlineKeyboardButton("❌ No, esperar", callback_data="cancel_kill")
                        ]
                    ])
                )
            else:
                await query.edit_message_text(f"✅ Proceso {pid} terminado correctamente.")
                # Eliminar archivo de bloqueo
                clean_lock_files_for_pid(pid)
        except Exception as e:
            await query.edit_message_text(f"❌ Error al terminar el proceso {pid}: {str(e)}")
    
    elif query.data.startswith("force_kill_"):
        pid = int(query.data.split("_")[2])
        try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                process.kill()
                await query.edit_message_text(f"✅ Proceso {pid} terminado forzosamente.")
                # Eliminar archivo de bloqueo
                clean_lock_files_for_pid(pid)
            else:
                await query.edit_message_text(f"✅ El proceso {pid} ya ha terminado.")
        except Exception as e:
            await query.edit_message_text(f"❌ Error al forzar terminación del proceso {pid}: {str(e)}")

# Eliminar archivos de bloqueo para un PID específico
def clean_lock_files_for_pid(pid):
    """Elimina los archivos de bloqueo asociados a un PID específico"""
    if not os.path.exists("locks"):
        return
    
    for lock_file in os.listdir("locks"):
        if lock_file.endswith(".lock"):
            try:
                with open(os.path.join("locks", lock_file), 'r') as f:
                    lock_pid = int(f.read().strip())
                    if lock_pid == pid:
                        os.remove(os.path.join("locks", lock_file))
                        logger.info(f"Archivo de bloqueo {lock_file} eliminado para PID {pid}")
            except:
                pass

# Obtener estado de los bots
async def gather_bot_status():
    """Recopila información sobre el estado de los bots"""
    global bot_status, last_health_check
    
    try:
        # Buscar procesos de los bots
        bot_processes = []
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and len(cmdline) >= 3 and 'run_single_bot.py' in cmdline[1]:
                    token = cmdline[2]
                    bot_processes.append((proc, token))
            except:
                pass
                
        # Actualizar estado
        current_time = datetime.now()
        for proc, token in bot_processes:
            try:
                process = psutil.Process(proc.info['pid'])
                create_time = datetime.fromtimestamp(process.create_time())
                uptime = current_time - create_time
                
                # Formatear tiempo activo
                days, remainder = divmod(uptime.total_seconds(), 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
                
                bot_status[token] = {
                    "active": True,
                    "pid": proc.info['pid'],
                    "uptime": uptime_str,
                    "cpu_percent": process.cpu_percent(interval=0.1),
                    "memory_percent": process.memory_percent()
                }
                last_health_check[token] = current_time
                
            except:
                bot_status[token] = {"active": False}
                
    except Exception as e:
        logger.error(f"Error al recopilar estado de los bots: {e}")

# Reiniciar todos los bots
async def restart_all_bots():
    """Reinicia todos los bots sin reiniciar el servicio completo"""
    try:
        # Terminar procesos de bot
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and len(cmdline) >= 2 and 'run_single_bot.py' in cmdline[1]:
                    process = psutil.Process(proc.info['pid'])
                    logger.info(f"Terminando proceso de bot con PID {proc.info['pid']}")
                    process.terminate()
            except:
                pass
        
        # Esperar a que terminen
        time.sleep(5)
        
        # Verificar y matar procesos restantes
        for proc in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and len(cmdline) >= 2 and 'run_single_bot.py' in cmdline[1]:
                    process = psutil.Process(proc.info['pid'])
                    logger.info(f"Forzando terminación del proceso {proc.info['pid']}")
                    process.kill()
            except:
                pass
        
        # Limpiar archivos de bloqueo antes de reiniciar
        if os.path.exists("locks"):
            for lock_file in os.listdir("locks"):
                if lock_file.startswith("bot_") and lock_file.endswith(".lock"):
                    try:
                        os.remove(os.path.join("locks", lock_file))
                        logger.info(f"Eliminado archivo de bloqueo: {lock_file}")
                    except:
                        pass
        
        # Iniciar script principal
        logger.info("Iniciando main.py para reiniciar los bots")
        subprocess.Popen([sys.executable, "main.py"], 
                        stdout=open("logs/restart.log", "a"),
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL)
        
        return True
    except Exception as e:
        logger.error(f"Error al reiniciar bots: {e}")
        return False

# Reiniciar servicio systemd
def restart_systemd_service():
    """Reinicia el servicio systemd del bot"""
    try:
        logger.info(f"Reiniciando servicio {SYSTEMD_SERVICE}")
        result = subprocess.run(
            ["sudo", "systemctl", "restart", SYSTEMD_SERVICE],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"Servicio reiniciado: {result.stdout}")
        return True
    except Exception as e:
        logger.error(f"Error al reiniciar servicio: {e}")
        return False

# Limpiar conexiones
async def clean_connections():
    """Envía señal a todos los bots para limpiar conexiones IMAP y BD"""
    try:
        # Crear archivo señalizador
        with open("clean_connections.signal", "w") as f:
            f.write(str(int(time.time())))
        
        # Esperar un poco
        time.sleep(2)
        
        # Eliminar archivo de señal
        if os.path.exists("clean_connections.signal"):
            os.remove("clean_connections.signal")
            
        return True
    except Exception as e:
        logger.error(f"Error al limpiar conexiones: {e}")
        return False

# Función principal
async def main():
    """Función principal para el bot de monitoreo"""
    # Inicializar aplicación
    application = ApplicationBuilder().token(MONITOR_BOT_TOKEN).build()
    
    # Registrar manejadores
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("system", system_command))
    application.add_handler(CommandHandler("restart", restart_command))
    application.add_handler(CommandHandler("restart_service", restart_service_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("clean", clean_command))
    application.add_handler(CommandHandler("kill", kill_command))
    application.add_handler(CommandHandler("help", start_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Recolectar estado inicial
    await gather_bot_status()
    
    # Iniciar bot
    await application.initialize()
    await application.start()
    await application.updater.start_polling()
    
    logger.info("Bot de monitoreo iniciado")
    
    # Actualización periódica
    try:
        while True:
            await gather_bot_status()
            await asyncio.sleep(60)  # Actualizar cada minuto
    except (KeyboardInterrupt, SystemExit):
        logger.info("Deteniendo bot de monitoreo")
        await application.updater.stop()
        await application.stop()
        await application.shutdown()

if __name__ == "__main__":
    # Crear directorio de logs
    os.makedirs("logs", exist_ok=True)
    
    # Crear directorio de locks si no existe
    os.makedirs("locks", exist_ok=True)
    
    # Ejecutar bot
    asyncio.run(main())
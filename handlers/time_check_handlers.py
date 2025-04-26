from telegram import Update
import os
from telegram.ext import ContextTypes
from datetime import datetime
from handlers.admin_handlers import admin_required
from utils.permission_manager import PermissionManager

@admin_required
async def check_user_time(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comando para verificar y diagnosticar el tiempo de un usuario"""
    try:
        if not context.args:
            await update.message.reply_text("❌ Uso: /checktime <user_id>")
            return
            
        user_id = int(context.args[0])
        permission_manager = PermissionManager()
        
        # Usar la función check_and_log_time_issues para diagnóstico
        is_valid = permission_manager.check_and_log_time_issues(user_id)
        
        # Obtener información detallada
        info = permission_manager.get_user_expiration_info(user_id)
        
        if info:
            message = (
                f"📊 *Diagnóstico de tiempo para usuario {user_id}*\n\n"
                f"⏰ Estado actual: {'Activo ✅' if is_valid else 'Expirado ❌'}\n"
                f"📅 Fecha de registro: {info['created_at'].strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                f"⌛️ Fecha de expiración: {info['expiration'].strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                f"⏳ Tiempo restante: {info['days_remaining']}d {info['hours_remaining']}h\n"
                f"💎 Créditos: {info['credits']}\n\n"
                f"🔄 Hora actual: {info['current_time'].strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
        else:
            message = f"❌ No se encontró información para el usuario {user_id}"
        
        await update.message.reply_text(message, parse_mode='Markdown')
        
    except ValueError:
        await update.message.reply_text("❌ El ID de usuario debe ser un número")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def check_time_all(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Comando para verificar el tiempo de todos los usuarios con problemas
    Uso: /checktimeall
    """
    try:
        permission_manager = PermissionManager()
        users_with_issues = []
        users_ok = []
        
        # Revisar todos los archivos de usuario
        for filename in os.listdir('users'):
            if filename.endswith('.json') and not any(x in filename for x in ['_admin', '_emails', '_netflix']):
                try:
                    user_id = int(filename.split('.')[0])
                    
                    # Verificar tiempo y obtener info
                    is_valid = permission_manager.check_and_log_time_issues(user_id)
                    info = permission_manager.get_user_expiration_info(user_id)
                    
                    if info:
                        user_status = {
                            'id': user_id,
                            'valid': is_valid,
                            'days_remaining': info['days_remaining'],
                            'hours_remaining': info['hours_remaining'],
                            'expiration': info['expiration']
                        }
                        
                        if not is_valid or info['days_remaining'] < 2:  # Mostrar usuarios expirados o próximos a expirar
                            users_with_issues.append(user_status)
                        else:
                            users_ok.append(user_status)
                            
                except Exception as e:
                    continue
        
        # Preparar mensaje
        message = "📊 *Estado de tiempo de usuarios*\n\n"
        
        if users_with_issues:
            message += "⚠️ *Usuarios con problemas:*\n"
            for user in users_with_issues:
                status = "❌ Expirado" if not user['valid'] else "⚠️ Próximo a expirar"
                message += (
                    f"👤 ID: `{user['id']}`\n"
                    f"📌 Estado: {status}\n"
                    f"⏳ Tiempo: {user['days_remaining']}d {user['hours_remaining']}h\n"
                    f"📅 Expira: {user['expiration'].strftime('%Y-%m-%d %H:%M')}\n\n"
                )
        
        message += f"✅ Usuarios activos sin problemas: {len(users_ok)}"
        
        await update.message.reply_text(message, parse_mode='Markdown')
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")
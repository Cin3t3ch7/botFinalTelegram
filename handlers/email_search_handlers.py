import imaplib
import email
import re
import logging
import time
import socket
from email.header import decode_header
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)

# Patrones regex para diferentes búsquedas
REGEX_PATTERNS = {
    'disney': r'<td[^>]*>\s*(\d+)\s*</td>',
    'disney_household': r'15 min[\s\S]*?updated Household[\s\S]*?<td[^>]*>\s*(\d{6})\s*</td>',
    'disney_mydisney': r'id=(?:3D)?"otp_code"[^>]*>\s*(\d+)\s*<',
    'netflix_reset': r'https:\/\/www\.netflix\.com\/password\?g=[^"\s<>]+',
    'netflix_update_home': r'https:\/\/www\.netflix\.com\/account\/update-primary-location\?nftoken=[a-zA-Z0-9%+=&\/]+',
    'netflix_home_code': r'https:\/\/www\.netflix\.com\/account\/travel\/verify\?nftoken=[a-zA-Z0-9%+=\/]+',
    'netflix_login_code': r'lrg-number[^>]*>\s*(\d{4})\s*<\/td>',
    'crunchyroll': r'data-t="new-password-link"\s+href="(https://links\.mail\.crunchyroll\.com/ls/click\?[^"]+)"',
    'prime': r'<p>\s*(\d{6})\s*<\/p>',
    'max': r'https:\/\/auth\.max\.com\/set-new-password\?passwordResetToken=[a-zA-Z0-9_\-=]+',
    'netflix_country': r'_(\w{2})_EVO',  # Para capturar el código de país
    'netflix_activation': r'https:\/\/www\.netflix\.com\/ilum\?code=[a-zA-Z0-9%+=&\/]+'  # Para link de activación
}

FROM_ADDRESSES = {
    'disney': [
        'disneyplus@trx.mail2.disneyplus.com',
    ],
    'disney_mydisney': [
        'member.services@disneyaccount.com'
    ],
    'netflix': [
        'info@account.netflix.com'
    ],
    'crunchyroll': [
        'hello@info.crunchyroll.com'
    ],
    'prime': [
        'account-update@primevideo.com',
        'account-update@amazon.com'
    ],
    'max': [
        'no-reply@marketing.max.com',
        'no-reply@message.max.com'
    ]
}

# Configuraciones IMAP de respaldo
IMAP_CONFIG = {}

class EmailSearchService:
    def __init__(self):
        """Inicializa el servicio de búsqueda de correos con conexiones persistentes"""
        self._connections = {}  # Almacena conexiones IMAP activas
        self._last_used = {}    # Registra cuando se usó por última vez una conexión
        self._connection_timeout = 40  # Tiempo de expiración de conexiones en segundos
        
    def get_imap_config(self, email_addr, bot_token=None):
        """Obtiene la configuración IMAP apropiada para un correo"""
        # Si se proporciona token, buscar primero en la base de datos
        if bot_token:
            try:
                from database.connection import execute_query
                
                # Obtener todas las configuraciones IMAP para este bot
                configs = execute_query(
                    "SELECT domain, email, password, imap_server FROM imap_config WHERE bot_token = %s",
                    (bot_token,)
                )
                
                # Si hay configuraciones para este bot
                if configs and len(configs) > 0:
                    local_part = None
                    domain = None
                    gmail_config = None
                    
                    # Almacenar la configuración de Gmail si existe (para usar como respaldo)
                    for config in configs:
                        if config[0] == 'gmail.com':
                            gmail_config = config
                            break
                    
                    # Determinar la parte local y el dominio del correo proporcionado
                    if '@' in email_addr:
                        local_part, domain = email_addr.split('@', 1)
                    else:
                        local_part = email_addr  # Si no hay @, todo es parte local
                        
                    # 1. PRIMERA PRIORIDAD: Si tiene +, buscar por la parte antes del +
                    if '+' in local_part:
                        plus_prefix = local_part.split('+', 1)[0]
                        logger.info(f"Correo con +: buscando configuración para prefijo: {plus_prefix}")
                        
                        # Buscar prefijo exacto
                        for config_domain, config_email, config_password, config_server in configs:
                            if config_domain == plus_prefix:
                                logger.info(f"Usando configuración para prefijo: {plus_prefix}")
                                return {
                                    'EMAIL_ACCOUNT': config_email,
                                    'PASSWORD': config_password,
                                    'IMAP_SERVER': config_server,
                                    'IMAP_PORT': 993
                                }
                    
                    # 2. SEGUNDA PRIORIDAD: Buscar configuración para el dominio específico
                    logger.info(f"Buscando configuración para dominio: {domain}")
                    for config_domain, config_email, config_password, config_server in configs:
                        if config_domain == domain:
                            logger.info(f"Usando configuración para dominio específico: {domain}")
                            return {
                                'EMAIL_ACCOUNT': config_email,
                                'PASSWORD': config_password,
                                'IMAP_SERVER': config_server,
                                'IMAP_PORT': 993
                            }
                    
                    # 3. TERCERA PRIORIDAD: Si el dominio es gmail.com y no tiene +
                    if domain == 'gmail.com' and '+' not in local_part and gmail_config:
                        logger.info(f"Correo de Gmail sin +, usando configuración para gmail.com")
                        _, config_email, config_password, config_server = gmail_config
                        return {
                            'EMAIL_ACCOUNT': config_email,
                            'PASSWORD': config_password,
                            'IMAP_SERVER': config_server,
                            'IMAP_PORT': 993
                        }
                    
                    # 4. ÚLTIMA PRIORIDAD: Usar la configuración de Gmail como respaldo
                    if gmail_config:
                        logger.warning(f"No se encontró configuración específica para {email_addr}, usando Gmail como respaldo")
                        _, config_email, config_password, config_server = gmail_config
                        return {
                            'EMAIL_ACCOUNT': config_email,
                            'PASSWORD': config_password,
                            'IMAP_SERVER': config_server,
                            'IMAP_PORT': 993
                        }
                    
                    # Si no hay configuración de Gmail, usar la primera disponible
                    logger.warning(f"No hay configuración de Gmail, usando la primera disponible")
                    domain, email, password, server = configs[0]
                    return {
                        'EMAIL_ACCOUNT': email,
                        'PASSWORD': password,
                        'IMAP_SERVER': server,
                        'IMAP_PORT': 993
                    }
            except Exception as e:
                logger.error(f"Error al obtener configuración IMAP de la BD: {e}")
                # Continuar con el método tradicional si hay error
        
        # Método tradicional (respaldo) si no hay token o no se encontró configuración en la BD
        if '@' in email_addr:
            local_part, domain = email_addr.split('@', 1)
            
            # 1. PRIMERA PRIORIDAD: Si tiene +, buscar por la parte antes del +
            if '+' in local_part:
                plus_prefix = local_part.split('+', 1)[0]
                if plus_prefix in IMAP_CONFIG:
                    logger.info(f"Usando configuración para prefijo: {plus_prefix}")
                    return IMAP_CONFIG[plus_prefix]
            
            # 2. SEGUNDA PRIORIDAD: Buscar configuración para el dominio específico
            if domain in IMAP_CONFIG:
                logger.info(f"Usando configuración para dominio: {domain}")
                return IMAP_CONFIG[domain]
                
            # 3. TERCERA PRIORIDAD: Si el dominio es gmail.com y no tiene +
            if domain == 'gmail.com' and '+' not in local_part and 'gmail.com' in IMAP_CONFIG:
                logger.info(f"Usando configuración específica para gmail.com")
                return IMAP_CONFIG['gmail.com']
                
            # 4. ÚLTIMA PRIORIDAD: Usar Gmail como respaldo general
            if 'gmail.com' in IMAP_CONFIG:
                logger.warning(f"Usando Gmail como configuración de respaldo para: {email_addr}")
                return IMAP_CONFIG['gmail.com']
        else:
            # Si el correo no tiene @, buscar por el valor exacto
            if email_addr in IMAP_CONFIG:
                return IMAP_CONFIG[email_addr]
            
            # Si no se encuentra, intentar usar Gmail como respaldo
            if 'gmail.com' in IMAP_CONFIG:
                logger.warning(f"Usando Gmail como respaldo para correo sin dominio: {email_addr}")
                return IMAP_CONFIG['gmail.com']
        
        # Respaldo final: devolver la primera configuración disponible solo si no hay Gmail
        if IMAP_CONFIG:
            logger.warning(f"No hay configuración de Gmail ni específica, usando la primera disponible")
            return next(iter(IMAP_CONFIG.values()))
            
        raise ValueError(f"No se encontró configuración IMAP para el correo: {email_addr}")

    def connect_to_imap(self, config):
        """Establece una conexión IMAP usando la configuración proporcionada"""
        try:
            # Establecer un tiempo de espera más corto para prevenir bloqueos
            socket.setdefaulttimeout(15)  # Reducido de 30 a 15 segundos
            
            conn = imaplib.IMAP4_SSL(config['IMAP_SERVER'], config['IMAP_PORT'])
            
            # Intentar login con reintentos
            max_retries = 2
            for attempt in range(max_retries + 1):
                try:
                    conn.login(config['EMAIL_ACCOUNT'], config['PASSWORD'])
                    break
                except imaplib.IMAP4.error as e:
                    if attempt < max_retries and ("try again" in str(e).lower() or "too many connections" in str(e).lower()):
                        logger.warning(f"Error temporal en login IMAP. Reintentando... ({attempt+1}/{max_retries})")
                        time.sleep(1)  # Reducido de 2 a 1 segundo
                        continue
                    raise  # Re-lanzar la excepción si agotamos los intentos
            
            # Configurar tiempos de espera para comandos
            conn.socket().settimeout(10)  # Reducido de 20 a 10 segundos
            
            return conn
        except Exception as e:
            raise Exception(f"Error de conexión IMAP: {str(e)}")
    
    def get_connection(self, config):
        """Obtiene una conexión existente o crea una nueva"""
        # Crear una clave única para esta configuración
        config_key = f"{config['IMAP_SERVER']}_{config['EMAIL_ACCOUNT']}"
        current_time = time.time()
        
        # Limpiar conexiones viejas (inactivas por más de 40 segundos)
        for key in list(self._connections.keys()):
            if current_time - self._last_used.get(key, 0) > self._connection_timeout:
                try:
                    self._connections[key].logout()
                except:
                    pass
                try:
                    del self._connections[key]
                    del self._last_used[key]
                except KeyError:
                    pass
        
        # Crear o reutilizar conexión
        if config_key in self._connections:
            conn = self._connections[config_key]
            try:
                # Verificar si la conexión sigue activa
                conn.noop()
                self._last_used[config_key] = current_time
                return conn
            except:
                # Si la conexión falló, eliminarla y crear una nueva
                try:
                    del self._connections[config_key]
                except KeyError:
                    pass
        
        # Crear nueva conexión
        conn = self.connect_to_imap(config)
        self._connections[config_key] = conn
        self._last_used[config_key] = current_time
        return conn
    
    def search_with_retry(self, conn, criteria, max_retries=2):
        """Busca con reintentos en caso de error temporal"""
        for attempt in range(max_retries + 1):
            try:
                status, messages = conn.search(None, criteria)
                return status, messages
            except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as e:
                if attempt < max_retries and ("try again" in str(e).lower() or "timeout" in str(e).lower()):
                    logger.warning(f"Error temporal en búsqueda IMAP. Reintentando... ({attempt+1}/{max_retries})")
                    time.sleep(1)  # Esperar un segundo antes de reintentar
                    continue
                raise Exception(f"Error en búsqueda IMAP después de {max_retries} intentos: {str(e)}")
            except Exception as e:
                raise Exception(f"Error en búsqueda IMAP: {str(e)}")
    
    def fetch_with_retry(self, conn, msg_id, format_string, max_retries=2):
        """Recupera un mensaje con reintentos en caso de error temporal"""
        for attempt in range(max_retries + 1):
            try:
                status, data = conn.fetch(msg_id, format_string)
                return status, data
            except (imaplib.IMAP4.abort, imaplib.IMAP4.error) as e:
                if attempt < max_retries and ("try again" in str(e).lower() or "timeout" in str(e).lower()):
                    logger.warning(f"Error temporal en fetch IMAP. Reintentando... ({attempt+1}/{max_retries})")
                    time.sleep(1)
                    continue
                raise Exception(f"Error en fetch IMAP después de {max_retries} intentos: {str(e)}")
            except Exception as e:
                raise Exception(f"Error en fetch IMAP: {str(e)}")
    
    def list_folders(self, email_addr, bot_token=None):
        """Lista las carpetas disponibles en la cuenta IMAP"""
        config = self.get_imap_config(email_addr, bot_token)
        
        # Intentar usar una conexión persistente
        try:
            conn = self.get_connection(config)
        except Exception as e:
            logger.error(f"Error al obtener conexión IMAP: {e}")
            conn = self.connect_to_imap(config)
        
        try:
            status, folder_list = conn.list()
            
            if status != 'OK':
                raise Exception("Error al obtener la lista de carpetas")
            
            folders = []
            for folder_info in folder_list:
                if isinstance(folder_info, bytes):
                    folder_info = folder_info.decode('utf-8')
                    # Extraer el nombre de la carpeta
                    match = re.search(r'"([^"]*)"$', folder_info)
                    if match:
                        folder_name = match.group(1)
                        folders.append(folder_name)
            
            return folders
        finally:
            # No cerramos la conexión aquí para mantenerla persistente
            pass
    
    def search_emails(self, email_addr, service, regex_type=None, folder="INBOX", days_back=1, bot_token=None, user_id=None):
        """Busca correos usando una expresión regular según el servicio y devuelve el resultado"""
        start_time = time.time()
        logger.info(f"Iniciando búsqueda para {service} ({regex_type or 'default'}) en {email_addr}")
        
        # Verificación de acceso
        if user_id and bot_token:
            try:
                from database.connection import execute_query
                
                # Verificar si el usuario es superadmin o admin
                from config import ADMIN_ID
                if user_id == ADMIN_ID:
                    pass  # El superadmin siempre tiene acceso
                else:
                    # Verificar si es admin
                    admin_result = execute_query("""
                    SELECT r.name FROM users u
                    JOIN roles r ON u.role_id = r.id
                    WHERE u.id = %s AND u.bot_token = %s
                    """, (user_id, bot_token))
                    
                    is_admin = admin_result and admin_result[0][0] in ['admin', 'super_admin']
                    
                    if not is_admin:
                        # Verificar si tiene acceso libre
                        free_result = execute_query("""
                        SELECT free_access FROM users
                        WHERE id = %s AND bot_token = %s
                        """, (user_id, bot_token))
                        
                        has_free_access = free_result and free_result[0][0]
                        
                        if not has_free_access:
                            # Verificar si tiene este correo asignado
                            email_result = execute_query("""
                            SELECT id FROM user_emails
                            WHERE user_id = %s AND bot_token = %s AND email = %s
                            """, (user_id, bot_token, email_addr))
                            
                            if not email_result:
                                raise ValueError(f"No tienes acceso al correo {email_addr}")
            except ImportError:
                logger.warning("No se pudo verificar acceso a través de la base de datos")
        
        # Determinar el servicio y los remitentes
        service_lower = service.lower()
        # Calcular la clave regex primero
        regex_key = f"{service_lower}_{regex_type}" if regex_type else service_lower

        # Usar regex_key como from_key si existe en FROM_ADDRESSES
        if regex_key in FROM_ADDRESSES:
            from_key = regex_key
        else:
            service_mapping = {
                'netflix': 'netflix',
                'disney': 'disney',
                'disney_mydisney': 'disney_mydisney',
                'max': 'max', 
                'prime': 'prime',
                'crunchyroll': 'crunchyroll'
            }
            from_key = service_mapping.get(service_lower, service_lower)

        if from_key not in FROM_ADDRESSES:
            raise ValueError(f"Servicio no reconocido: {service}")

        from_addresses = FROM_ADDRESSES[from_key]
        
        # Determinar qué regex usar
        regex_key = f"{service_lower}_{regex_type}" if regex_type else service_lower
        if regex_key not in REGEX_PATTERNS:
            raise ValueError(f"No hay patrón regex para el servicio: {regex_key}")
        
        regex_pattern = REGEX_PATTERNS[regex_key]
        
        # Obtener configuración IMAP
        config = self.get_imap_config(email_addr, bot_token)
        
        # Usar conexión persistente o crear una nueva
        conn = None
        try:
            try:
                conn = self.get_connection(config)
                logger.debug(f"Usando conexión IMAP persistente para {config['IMAP_SERVER']}")
            except Exception as e:
                logger.warning(f"No se pudo usar conexión persistente, creando nueva: {e}")
                conn = self.connect_to_imap(config)
            
            # Seleccionar carpeta (siempre recargar la carpeta para buscar nuevos correos)
            try:
                status, messages = conn.select(folder, readonly=True)
                if status != 'OK':
                    raise Exception(f"Error al seleccionar la carpeta {folder}")
            except Exception as e:
                # Si falla, podría ser un problema de conexión, intentar reconectar
                logger.warning(f"Error al seleccionar carpeta, reconectando: {e}")
                conn = self.connect_to_imap(config)
                status, messages = conn.select(folder, readonly=True)
                if status != 'OK':
                    raise Exception(f"Error al seleccionar la carpeta {folder} después de reconexión")
            
            # Construir fecha para búsqueda (reducir días para búsqueda más eficiente)
            days_back = min(days_back, 3)  # Limitar a máximo 3 días para búsquedas más rápidas
            date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
            
            # Optimizar búsqueda: combinar FROM y TO en una sola consulta
            search_criteria = []
            
            # Crear criterio para remitentes
            for from_addr in from_addresses:
                if '@' in email_addr:
                    # Búsqueda combinada de remitente y destinatario para mayor precisión
                    search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')
                else:
                    search_criteria.append(f'(FROM "{from_addr}" SINCE {date_since})')
            
            # Combinar criterios con OR
            if len(search_criteria) > 1:
                combined_criteria = f'OR {" ".join(search_criteria)}'
            else:
                combined_criteria = search_criteria[0]
            
            # Realizar la búsqueda con reintentos
            try:
                status, messages = self.search_with_retry(conn, combined_criteria)
            except Exception as e:
                logger.error(f"Error en búsqueda IMAP: {e}")
                
                # Intentar una búsqueda más simple como último recurso
                fallback_criteria = f'SINCE {date_since}'
                logger.info(f"Intentando búsqueda simplificada: {fallback_criteria}")
                try:
                    status, messages = self.search_with_retry(conn, fallback_criteria)
                except Exception as e2:
                    logger.error(f"Error en búsqueda simplificada: {e2}")
                    raise Exception(f"Error en búsqueda IMAP: {str(e)}")
            
            if not messages[0]:
                logger.info(f"No se encontraron correos para el criterio: {combined_criteria}")
                end_time = time.time()
                logger.info(f"Búsqueda completada en {end_time - start_time:.2f} segundos (sin resultados)")
                return None
            
            # Compilar expresión regular para cuerpo
            try:
                body_regex = re.compile(regex_pattern, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                raise Exception(f"Error en la expresión regular: {str(e)}")
            
            # Variable para almacenar el resultado más reciente
            latest_result = None
            
            # Procesar mensajes más recientes primero (limitar a 10 para mayor velocidad)
            message_ids = messages[0].split()
            message_ids.reverse()  # Ordenar de más recientes a más antiguos
            message_ids = message_ids[:10]  # Procesar solo los 10 más recientes
            
            logger.info(f"Procesando {len(message_ids)} mensajes recientes para {email_addr}")
            
            # Procesamiento optimizado: verificar directamente los mensajes más recientes
            for msg_id in message_ids:
                # Recuperar mensaje con encabezados primero para validación rápida
                try:
                    status, msg_data = self.fetch_with_retry(conn, msg_id, '(BODY.PEEK[HEADER])')
                    if status != 'OK':
                        continue
                except Exception as e:
                    logger.error(f"Error al recuperar encabezado: {e}")
                    continue
                
                # Validar remitente y destinatario
                raw_headers = msg_data[0][1]
                email_headers = email.message_from_bytes(raw_headers)
                
                # Verificar remitente
                from_value = email_headers.get('From', '')
                from_match = any(addr.lower() in from_value.lower() for addr in from_addresses)
                if not from_match:
                    continue
                
                # Verificar destinatario si se especificó un correo
                if '@' in email_addr:
                    to_value = email_headers.get('To', '')
                    email_addr_lower = email_addr.lower()
                    
                    # Verificación simplificada del destinatario
                    if email_addr_lower not in to_value.lower():
                        # Verificar si es un correo con formato user+tag@domain
                        if '+' in email_addr_lower:
                            base_email = email_addr_lower.split('@')[0].split('+')[0]
                            domain = email_addr_lower.split('@')[1]
                            pattern = f"{base_email}+[^@]*@{domain}"
                            if not re.search(pattern, to_value.lower()):
                                continue
                        else:
                            continue
                
                # Si pasa las validaciones, recuperar el mensaje completo
                try:
                    status, msg_data = self.fetch_with_retry(conn, msg_id, '(RFC822)')
                    if status != 'OK':
                        continue
                except Exception as e:
                    logger.error(f"Error al recuperar mensaje completo: {e}")
                    continue
                
                raw_email = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                # Extraer asunto para registro
                subject = self.decode_email_subject(email_message.get('Subject', ''))
                
                # Búsqueda optimizada en el cuerpo del mensaje
                if email_message.is_multipart():
                    # Primero en HTML (más común tener los códigos/enlaces aquí)
                    for part in email_message.walk():
                        if part.get_content_type() == "text/html":
                            try:
                                body = part.get_payload(decode=True).decode('utf-8', 'ignore')
                                match = body_regex.search(body)
                                if match:
                                    result = match.group(1) if match.groups() else match.group(0)
                                    result = result.replace('amp;', '')
                                    
                                    latest_result = {
                                        'result': result,
                                        'is_link': result.startswith('http'),
                                        'subject': subject,
                                        'date': email_message.get('Date', ''),
                                        'from': email_message.get('From', '')
                                    }
                                    # Encontramos un resultado, romper ciclo externo
                                    break
                            except Exception as e:
                                logger.error(f"Error al procesar parte HTML: {e}")
                    
                    # Si no se encontró en HTML y aún no tenemos resultado, buscar en texto plano
                    if not latest_result:
                        for part in email_message.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    body = part.get_payload(decode=True).decode('utf-8', 'ignore')
                                    match = body_regex.search(body)
                                    if match:
                                        result = match.group(1) if match.groups() else match.group(0)
                                        result = result.replace('amp;', '')
                                        
                                        latest_result = {
                                            'result': result,
                                            'is_link': result.startswith('http'),
                                            'subject': subject,
                                            'date': email_message.get('Date', ''),
                                            'from': email_message.get('From', '')
                                        }
                                        break
                                except Exception as e:
                                    logger.error(f"Error al procesar parte texto: {e}")
                else:
                    # No es multiparte, procesar directamente
                    try:
                        body = email_message.get_payload(decode=True).decode('utf-8', 'ignore')
                        match = body_regex.search(body)
                        if match:
                            result = match.group(1) if match.groups() else match.group(0)
                            result = result.replace('amp;', '')
                            
                            latest_result = {
                                'result': result,
                                'is_link': result.startswith('http'),
                                'subject': subject,
                                'date': email_message.get('Date', ''),
                                'from': email_message.get('From', '')
                            }
                    except Exception as e:
                        logger.error(f"Error al procesar mensaje no multiparte: {e}")
                
                # Si encontramos un resultado, terminar la búsqueda
                if latest_result:
                    break
            
            end_time = time.time()
            logger.info(f"Búsqueda completada en {end_time - start_time:.2f} segundos")
            
            # Devolver el resultado más reciente, o None si no se encontró nada
            return latest_result
                    
        finally:
            # No cerramos la conexión para mantenerla persistente
            # Las conexiones inactivas se limpiarán en la próxima búsqueda
            pass

    def decode_email_subject(self, subject):
        """Decodifica el asunto del correo"""
        if not subject:
            return ""
            
        decoded_list = decode_header(subject)
        result = ''
        for decoded_string, charset in decoded_list:
            if isinstance(decoded_string, bytes):
                if charset:
                    result += decoded_string.decode(charset, 'ignore')
                else:
                    result += decoded_string.decode('utf-8', 'ignore')
            else:
                result += decoded_string
        return result
    
    def cleanup(self):
        """Cierra todas las conexiones IMAP abiertas"""
        for key, conn in list(self._connections.items()):
            try:
                conn.logout()
                logger.debug(f"Conexión IMAP cerrada para {key}")
            except:
                pass
        
        self._connections.clear()
        self._last_used.clear()

# Instancia global del servicio
email_service = EmailSearchService()

# Funciones handler para Telegram

async def handle_netflix_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == 'netflix_reset_link':
        context.user_data['search_state'] = 'netflix_reset'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Netflix", callback_data='netflix_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el enlace de restablecimiento de contraseña de Netflix:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'netflix_update_home':
        context.user_data['search_state'] = 'netflix_home'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Netflix", callback_data='netflix_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el enlace de actualización de hogar de Netflix:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'netflix_home_code':
        context.user_data['search_state'] = 'netflix_home_code'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Netflix", callback_data='netflix_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código de hogar de Netflix:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'netflix_login_code':
        context.user_data['search_state'] = 'netflix_login'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Netflix", callback_data='netflix_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código de inicio de sesión de Netflix:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'netflix_country':
        context.user_data['search_state'] = 'netflix_country'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Netflix", callback_data='netflix_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el país de la cuenta de Netflix:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def handle_disney_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == 'disney_code':
        context.user_data['search_state'] = 'disney_code'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Disney", callback_data='disney_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código de verificación de Disney:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'disney_home':
        context.user_data['search_state'] = 'disney_household'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Disney", callback_data='disney_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código de actualización de hogar de Disney:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data == 'disney_mydisney':  # Nuevo manejador
        context.user_data['search_state'] = 'disney_mydisney'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver al Disney", callback_data='disney_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código OTP de My Disney:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def handle_crunchyroll_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.data == 'crunchyroll_reset':
        context.user_data['search_state'] = 'crunchyroll_reset'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver a Crunchyroll", callback_data='crunchyroll_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el enlace de restablecimiento de Crunchyroll:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def handle_prime_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.data == 'prime_otp':
        context.user_data['search_state'] = 'prime_otp'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver a Prime", callback_data='prime_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el código OTP de Prime Video:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def handle_max_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.data == 'max_reset':
        context.user_data['search_state'] = 'max_reset'
        keyboard = [
            [InlineKeyboardButton("↩️ Volver a Max", callback_data='max_menu')],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await query.edit_message_text(
            "Por favor, envía la dirección de correo para buscar el enlace de restablecimiento de Max:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

# Función auxiliar para enviar mensajes de forma segura
async def safe_send_message(update: Update, text: str, reply_markup=None, parse_mode=None):
    """
    Envía mensajes de forma segura verificando la existencia de los objetos necesarios
    """
    try:
        if update.callback_query:
            if reply_markup:
                return await update.callback_query.edit_message_text(
                    text=text,
                    reply_markup=reply_markup,
                    parse_mode=parse_mode
                )
            else:
                return await update.callback_query.answer(
                    text=text,
                    show_alert=True
                )
        elif update.message:
            return await update.message.reply_text(
                text=text,
                reply_markup=reply_markup,
                parse_mode=parse_mode
            )
        else:
            logger.error(f"No suitable message object found in update: {update}")
            return None
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return None

async def handle_email_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
        
    email_addr = update.message.text.strip().lower()
    search_state = context.user_data.get('search_state')
    
    if not search_state:
        keyboard = [[InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]]
        await safe_send_message(
            update,
            "Por favor, selecciona primero una opción del menú.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # Validate user's access to this email using database
    from database.connection import execute_query
    from config import ADMIN_ID
    
    user_id = update.effective_user.id
    bot_token = context.bot.token
    
    # Check if the user is superadmin or admin
    is_allowed = False
    
    if user_id == ADMIN_ID:
        is_allowed = True
    else:
        try:
            # Check if the user is admin
            admin_check = execute_query("""
            SELECT r.name FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s AND u.bot_token = %s
            """, (user_id, bot_token))
            
            if admin_check and admin_check[0][0] in ['admin', 'super_admin']:
                is_allowed = True
            else:
                # Check if the user has free access
                free_check = execute_query("""
                SELECT free_access FROM users
                WHERE id = %s AND bot_token = %s
                """, (user_id, bot_token))
                
                if free_check and free_check[0][0]:
                    is_allowed = True
                else:
                    # Check if the user has this email assigned
                    email_check = execute_query("""
                    SELECT id FROM user_emails
                    WHERE user_id = %s AND bot_token = %s AND email = %s
                    """, (user_id, bot_token, email_addr))
                    
                    if email_check:
                        is_allowed = True
        except Exception as e:
            logger.error(f"Error checking email permissions: {e}")
            is_allowed = False
    
    if not is_allowed:
        keyboard = [
            [InlineKeyboardButton("↩️ Volver", callback_data=f"{search_state.split('_')[0]}_menu")],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await safe_send_message(
            update,
            "❌ No tienes autorización para usar este correo.\n"
            "📧 Solo puedes usar los correos asignados a tu cuenta.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # Mostrar mensaje de búsqueda
    status_message = await update.message.reply_text("🔍 Buscando...")
    
    try:
        # Determinar el servicio y tipo de regex basado en el estado de búsqueda
        service_mapping = {
            'disney_code': ('disney', None),
            'disney_household': ('disney', 'household'),
            'disney_mydisney': ('disney', 'mydisney'),  # Nueva opción
            'netflix_reset': ('netflix', 'reset'),
            'netflix_home': ('netflix', 'update_home'),
            'netflix_home_code': ('netflix', 'home_code'),
            'netflix_login': ('netflix', 'login_code'),
            'netflix_country': ('netflix', 'country'),
            'crunchyroll_reset': ('crunchyroll', None),
            'prime_otp': ('prime', None),
            'max_reset': ('max', None)
        }
        
        if search_state not in service_mapping:
            await status_message.edit_text(f"❌ Estado de búsqueda no válido: {search_state}")
            return
        
        service, regex_type = service_mapping[search_state]
        
        # Actualizar mensaje con el tipo de búsqueda
        search_description = {
            'disney_code': "código de Disney",
            'disney_household': "código de actualización de hogar Disney",
            'disney_mydisney': "código OTP de My Disney",  # Nueva descripción
            'netflix_reset': "enlace de restablecimiento de Netflix",
            'netflix_home': "enlace de actualización de hogar Netflix",
            'netflix_home_code': "código de hogar Netflix",
            'netflix_login': "código de inicio de sesión Netflix",
            'netflix_country': "país de la cuenta Netflix",
            'crunchyroll_reset': "enlace de reset de Crunchyroll",
            'prime_otp': "código OTP de Prime",
            'max_reset': "enlace de reset de Max"
        }
        
        await status_message.edit_text(f"🔍 Buscando {search_description.get(search_state, 'información')}...")
        
        # Realizar la búsqueda
        result = email_service.search_emails(
            email_addr=email_addr,
            service=service,
            regex_type=regex_type,
            bot_token=bot_token,
            user_id=user_id
        )
        
        # Crear teclado base para todos los resultados
        service_menu_name = service + "_menu"
        keyboard_base = [
            [InlineKeyboardButton(f"↩️ Volver al {service.capitalize()}", callback_data=service_menu_name)],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        
        # Procesar resultado
        if result:
            result_value = result['result']
            is_link = result['is_link']
            
            if is_link:
                # Es un enlace, añadir botón para abrirlo
                keyboard = [
                    [InlineKeyboardButton("🔗 Abrir URL", url=result_value)],
                    *keyboard_base
                ]
                await status_message.edit_text(
                    f"✅ {search_description.get(search_state, 'Resultado')} encontrado:",
                    reply_markup=InlineKeyboardMarkup(keyboard)
                )
            else:
                # Es un código u otro valor
                await status_message.edit_text(
                    f"✅ {search_description.get(search_state, 'Resultado')}: {result_value}",
                    reply_markup=InlineKeyboardMarkup(keyboard_base)
                )
        else:
            # No se encontró nada
            await status_message.edit_text(
                f"❌ No se encontró ningún {search_description.get(search_state, 'resultado')} en los correos recientes.",
                reply_markup=InlineKeyboardMarkup(keyboard_base)
            )
            
    except Exception as e:
        logger.error(f"Error en handle_email_input: {str(e)}")
        keyboard = [
            [InlineKeyboardButton("↩️ Volver", callback_data=f"{search_state.split('_')[0]}_menu")],
            [InlineKeyboardButton("🏠 Menú Principal", callback_data='main_menu')]
        ]
        await status_message.edit_text(
            f"❌ Error al procesar la solicitud: {str(e)}",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def handle_url_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle URL-related button callbacks"""
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith('url_'):
        url_hash = query.data
        if hasattr(update, 'url_cache') and url_hash in update.url_cache:
            url = update.url_cache[url_hash]
            await query.answer("¡URL copiada al portapapeles!", show_alert=True)
    elif query.data == 'back_to_menu':
        from handlers.user_handlers import handle_menu_selection
        await handle_menu_selection(update, context)
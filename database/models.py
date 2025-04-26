import logging
from database.connection import execute_query, check_table_exists
from config import ADMIN_ID, DEFAULT_SERVICES
from datetime import datetime

# Configurar logging
logger = logging.getLogger(__name__)

def verify_table_columns(table_name, expected_columns):
    """Verifica que una tabla tenga todas las columnas esperadas y las añade si faltan"""
    try:
        # Obtener columnas existentes
        existing_columns = execute_query("""
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = %s
        """, (table_name,))
        
        if not existing_columns:
            logger.warning(f"No se encontraron columnas para la tabla {table_name}")
            return False
            
        existing_column_names = [col[0] for col in existing_columns]
        
        # Verificar cada columna esperada
        for col_name, col_def in expected_columns.items():
            if col_name not in existing_column_names:
                logger.info(f"Añadiendo columna {col_name} a la tabla {table_name}")
                execute_query(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")
                
        return True
    except Exception as e:
        logger.error(f"Error verificando columnas para {table_name}: {e}")
        return False

def init_db():
    """Inicializa las tablas en la base de datos si no existen"""
    logger.info("Verificando estructura de la base de datos...")
    
    # Verificar y crear cada tabla individualmente
    
    # Tabla de roles
    if not check_table_exists('roles'):
        logger.info("Creando tabla de roles...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE
        )
        """)
        
        # Insertar roles predefinidos
        logger.info("Insertando roles predefinidos...")
        for role in ['super_admin', 'admin', 'reseller', 'user']:
            execute_query("""
            INSERT INTO roles (name) VALUES (%s)
            ON CONFLICT (name) DO NOTHING
            """, (role,))
    
    # Tabla de usuarios
    if not check_table_exists('users'):
        logger.info("Creando tabla de usuarios...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT,
            username VARCHAR(100),
            role_id INTEGER REFERENCES roles(id),
            bot_token VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            access_until TIMESTAMP,
            free_access BOOLEAN DEFAULT FALSE,
            created_by BIGINT,
            PRIMARY KEY (id, bot_token)
        )
        """)
    
    # Tabla de servicios
    if not check_table_exists('services'):
        logger.info("Creando tabla de servicios...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS services (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            color_bg VARCHAR(10) DEFAULT '#ddd',
            color_text VARCHAR(10) DEFAULT '#333',
            is_active BOOLEAN DEFAULT TRUE,
            sort_order INTEGER DEFAULT 0,
            bot_token VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(name, bot_token)
        )
        """)
    
    # Tabla de opciones de servicios
    if not check_table_exists('service_options'):
        logger.info("Creando tabla de opciones de servicios...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS service_options (
            id SERIAL PRIMARY KEY,
            service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            price DECIMAL(10, 2),
            is_active BOOLEAN DEFAULT TRUE
        )
        """)
    
    # Tabla de configuración de resellers
    if not check_table_exists('reseller_config'):
        logger.info("Creando tabla de configuración de resellers...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS reseller_config (
            id SERIAL PRIMARY KEY,
            reseller_id BIGINT,
            bot_token VARCHAR(100) NOT NULL,
            service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
            can_access BOOLEAN DEFAULT TRUE,
            profit_margin DECIMAL(5, 2) DEFAULT 0,
            FOREIGN KEY (reseller_id, bot_token) REFERENCES users(id, bot_token) ON DELETE CASCADE
        )
        """)
    
    # Tabla para configuraciones IMAP
    if not check_table_exists('imap_config'):
        logger.info("Creando tabla de configuraciones IMAP...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS imap_config (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            password VARCHAR(100) NOT NULL,
            imap_server VARCHAR(100) NOT NULL,
            bot_token VARCHAR(100) NOT NULL,
            UNIQUE(domain, bot_token)
        )
        """)
    
    # Tabla de correos asociados a usuarios
    if not check_table_exists('user_emails'):
        logger.info("Creando tabla de correos de usuarios...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS user_emails (
            id SERIAL PRIMARY KEY,
            user_id BIGINT,
            bot_token VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id, bot_token) REFERENCES users(id, bot_token) ON DELETE CASCADE,
            UNIQUE(user_id, bot_token, email)
        )
        """)

    # Tabla para almacenar registros de garantía
    if not check_table_exists('warranty_records'):
        logger.info("Creando tabla de registros de garantía...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS warranty_records (
            id SERIAL PRIMARY KEY,
            user_id BIGINT,
            bot_token VARCHAR(100) NOT NULL,
            old_email VARCHAR(255) NOT NULL,
            new_email VARCHAR(255) NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            changed_by BIGINT,
            FOREIGN KEY (user_id, bot_token) REFERENCES users(id, bot_token) ON DELETE CASCADE
        )
        """)
    
    # Tabla para opciones de servicio específicas por reseller
    if not check_table_exists('reseller_service_options'):
        logger.info("Creando tabla de opciones de servicio para resellers...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS reseller_service_options (
            id SERIAL PRIMARY KEY,
            reseller_id BIGINT,
            bot_token VARCHAR(100) NOT NULL,
            service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
            option_type VARCHAR(50) NOT NULL,
            can_access BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (reseller_id, bot_token) REFERENCES users(id, bot_token) ON DELETE CASCADE,
            UNIQUE(reseller_id, bot_token, service_id, option_type)
        )
        """)
    
    # Verificar y añadir columnas necesarias
    # Columna free_access en users
    try:
        column_exists = execute_query("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'free_access'
        )
        """)
        
        if not column_exists[0][0]:
            logger.info("Añadiendo columna free_access a tabla users...")
            execute_query("ALTER TABLE users ADD COLUMN free_access BOOLEAN DEFAULT FALSE")
    except Exception as e:
        logger.warning(f"Error al verificar columna free_access: {e}")
    
    # Columna created_by en users
    try:
        column_exists = execute_query("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'created_by'
        )
        """)
        
        if not column_exists[0][0]:
            logger.info("Añadiendo columna created_by a tabla users...")
            execute_query("ALTER TABLE users ADD COLUMN created_by BIGINT")
    except Exception as e:
        logger.warning(f"Error al verificar columna created_by: {e}")
    
    # Verificar y añadir columna display_name en services
    try:
        column_exists = execute_query("""
        SELECT EXISTS (
            SELECT FROM information_schema.columns 
            WHERE table_name = 'services' AND column_name = 'display_name'
        )
        """)
        
        if not column_exists[0][0]:
            logger.info("Añadiendo columna display_name a tabla services...")
            execute_query("ALTER TABLE services ADD COLUMN display_name VARCHAR(100)")
            
            # Actualizar valores existentes para que display_name sea igual a name
            execute_query("UPDATE services SET display_name = name WHERE display_name IS NULL")
    except Exception as e:
        logger.warning(f"Error al verificar/añadir columna display_name: {e}")
    
    logger.info("Verificación de la base de datos completada")

def ensure_roles_exist():
    """Verifica que todos los roles predefinidos existan y los crea si no"""
    predefined_roles = ['super_admin', 'admin', 'reseller', 'user']
    
    # Verificar si la tabla roles existe
    if not check_table_exists('roles'):
        logger.info("Creando tabla de roles...")
        execute_query("""
        CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) NOT NULL UNIQUE
        )
        """)
    
    # Verificar cada rol y crearlo si no existe
    for role in predefined_roles:
        role_exists = execute_query("SELECT id FROM roles WHERE name = %s", (role,))
        if not role_exists:
            logger.warning(f"No se encontró el rol '{role}'. Creando...")
            try:
                execute_query("INSERT INTO roles (name) VALUES (%s)", (role,))
                logger.info(f"Rol '{role}' creado correctamente")
            except Exception as e:
                logger.error(f"Error al crear el rol '{role}': {e}")
                return False
    
    return True

def setup_super_admin(bot_token):
    """Configura el super admin para un bot específico"""
    # Asegurar que los roles existan
    ensure_roles_exist()
    
    # Obtener el ID del rol super_admin
    role_id_result = execute_query("SELECT id FROM roles WHERE name = 'super_admin'")
    if not role_id_result:
        logger.error("No se encontró el rol 'super_admin'")
        return False
    
    role_id = role_id_result[0][0]
    
    # Verificar si el super admin ya existe para este bot
    existing = execute_query(
        "SELECT id FROM users WHERE id = %s AND bot_token = %s", 
        (ADMIN_ID, bot_token)
    )
    
    if existing:
        # Actualizar si ya existe
        execute_query("""
        UPDATE users SET role_id = %s
        WHERE id = %s AND bot_token = %s
        """, (role_id, ADMIN_ID, bot_token))
        logger.info(f"Super admin actualizado para el bot {bot_token[:10]}...")
    else:
        # Insertar nuevo super admin
        execute_query("""
        INSERT INTO users (id, username, role_id, bot_token, access_until)
        VALUES (%s, %s, %s, %s, %s)
        """, (ADMIN_ID, "SuperAdmin", role_id, bot_token, datetime.max))
        logger.info(f"Super admin creado para el bot {bot_token[:10]}...")
    
    return True

def setup_default_services(bot_token):
    """Configura los servicios predeterminados para un bot"""
    try:
        # Verificar qué columnas existen en la tabla services
        columns_result = execute_query("""
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'services'
        """)
        
        if not columns_result:
            logger.error("No se pudieron obtener las columnas de la tabla services")
            return False
            
        columns = [col[0] for col in columns_result]
        has_display_name = 'display_name' in columns
        
        for service_name in DEFAULT_SERVICES:
            # Verificar si el servicio ya existe
            exists_result = execute_query(
                "SELECT id FROM services WHERE name = %s AND bot_token = %s",
                (service_name, bot_token)
            )
            
            if not exists_result:
                if has_display_name:
                    # Con display_name
                    execute_query(
                        "INSERT INTO services (name, display_name, bot_token) VALUES (%s, %s, %s)",
                        (service_name, service_name, bot_token)
                    )
                else:
                    # Sin display_name
                    execute_query(
                        "INSERT INTO services (name, bot_token) VALUES (%s, %s)",
                        (service_name, bot_token)
                    )
                    
                logger.info(f"Servicio '{service_name}' creado para el bot {bot_token[:10]}...")
        
        return True
        
    except Exception as e:
        logger.error(f"Error al configurar servicios predeterminados: {e}")
        
        # Intentar inserción mínima como último recurso
        try:
            for service_name in DEFAULT_SERVICES:
                execute_query(
                    "INSERT INTO services (name, bot_token) VALUES (%s, %s) ON CONFLICT (name, bot_token) DO NOTHING",
                    (service_name, bot_token)
                )
            return True
        except Exception as e2:
            logger.error(f"Error en inserción de emergencia: {e2}")
            return False

def can_user_access_email(user_id, bot_token, email):
    """Verifica si un usuario tiene acceso a un correo específico"""
    # El superadmin siempre tiene acceso
    if user_id == ADMIN_ID:
        return True
        
    try:
        # Verificar si es admin
        admin_result = execute_query("""
        SELECT r.name FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.id = %s AND u.bot_token = %s
        """, (user_id, bot_token))
        
        is_admin = admin_result and admin_result[0][0] in ['admin', 'super_admin']
        if is_admin:
            return True
            
        # Verificar si tiene acceso libre
        free_result = execute_query("""
        SELECT free_access FROM users
        WHERE id = %s AND bot_token = %s
        """, (user_id, bot_token))
        
        if free_result and free_result[0][0]:
            return True
            
        # Verificar si tiene este correo asignado
        email_result = execute_query("""
        SELECT id FROM user_emails
        WHERE user_id = %s AND bot_token = %s AND email = %s
        """, (user_id, bot_token, email.lower()))
        
        return bool(email_result)
        
    except Exception as e:
        logger.error(f"Error verificando acceso al correo {email} para usuario {user_id}: {e}")
        return False
import os
from dotenv import load_dotenv

# Cargar variables de entorno si existe .env
try:
    load_dotenv()
except ImportError:
    pass  # dotenv no está instalado, usamos valores predeterminados

# PostgreSQL
DB_USER = os.getenv('DB_USER', 'botuser')
DB_PASS = os.getenv('DB_PASS', 'Cinetech7')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'telegram_bot_db')

# Telegram Bot Tokens (separados por comas)
BOT_TOKENS = os.getenv('BOT_TOKENS', '7442150757:AAEehrRZLBmTbw5HyRYB-FN1F5GuffPoBiI,6763564836:AAFOXJ3f6cQYrZ1ux2wzr8awBkyK8PbF43s,7170255435:AAFfPObTbEMhQtD647ewffRqvKhvsTOdkw0,7164322067:AAE_D_aB2iNBqkGHKVQhIi3BxfAkN0PUku8,7510778971:AAF3Yl56OCDwO74hGinTihUNlBmLT-O9hZQ,7437738060:AAFMueUnUyNKWe6-EKZ9mb4yNyZgHOeWQ8Y,7462860227:AAEpy1SN-gyCBB0pHR7ZyqSyRBob2ELXg7s,7627477765:AAGTDEzkAMPXkU71aGwKvZfXkNGekDnWROo,8155456113:AAHeceWcJxVcfRpNizeSwmDGAngq2GQGjto,7777904177:AAHby_apem2vbSZA00inPsWhcQBg6rwN-ss,7823279779:AAEswdPpxqLQyLh_yA2G-GnzCmarDjxaNEU,7605475684:AAHqACIhkVJ6Z8LFYwLQa-jLQ_2mOj3YxUQ,7534730411:AAFU5aTW8DcADsHjBFqQX5TQ6F4I6MovDew,7694722936:AAFS73Y8KuVYtF0IuS75MGZD1HL-SqPlozY,8078614713:AAFG8kDVAcVN6V8bUuGELOhju6aPksHBl1A,7097638038:AAGPAmEAk7_4KdvcyKalWJPSc3dQaU0lmiA').split(',')

# ID del Super Admin
ADMIN_ID = int(os.getenv('SUPER_ADMIN_ID', '1516580367'))

# Configuraciones IMAP predeterminadas (se pueden sobrescribir en la BD)
DEFAULT_IMAP_CONFIG = {}

# Servicios disponibles por defecto
DEFAULT_SERVICES = ['Netflix', 'Disney', 'Max', 'Prime', 'Crunchyroll']
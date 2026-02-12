"""
JoulIAna - AI Powered IT Support Assistant
------------------------------------------
Autor: Jared Abarca (Red Team / IT Analyst)
Versión: 1.2.0 (Stable)
Descripción: 
    Agente de IA autónomo que monitorea servidores de correo POP3, 
    analiza contenido mediante Google Vertex AI (Gemini) y gestiona 
    respuestas y tickets de soporte vía Telegram.

Stack: Python 3.10+, Google Cloud Vertex AI, Telegram Bot API, SMTP/POP3.
"""

import os
import sys
import time
import logging
import threading
import smtplib
import poplib
import email
from email.mime.text import MIMEText
from email.header import decode_header
from typing import Tuple, Set, Dict, Optional, Any

# Librerías de Terceros
import telebot
import vertexai
from vertexai.generative_models import GenerativeModel
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# =============================================================================
# 1. CONFIGURACIÓN Y CONSTANTES
# =============================================================================

# Credenciales de Servicios
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Configuración de Servidor de Correo
EMAIL_SERVER = os.getenv("EMAIL_SERVER")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 995))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# Configuración Google Cloud AI
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")

# Validación de entorno
if not all([TELEGRAM_TOKEN, EMAIL_USER, EMAIL_PASS, PROJECT_ID]):
    print("CRITICAL: Faltan variables de entorno. Revise el archivo .env")
    sys.exit(1)

# =============================================================================
# 2. SISTEMA DE LOGS Y ESTADO GLOBAL
# =============================================================================

# Configuración de Logging Rotativo (Auditoría)
logger = logging.getLogger("JoulIAna")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')

# Handler: Archivo (Mantiene historial sin llenar disco)
file_handler = RotatingFileHandler('jouliana_system.log', maxBytes=5*1024*1024, backupCount=2, encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Handler: Consola (Salida en tiempo real)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logging.info("📝 Sistema de Logs iniciado correctamente.")

# Estado Global (Memoria de Corto Plazo)
# Nota: En producción escalar, esto debería ir a una BD
class BotState:
    ultimo_remitente: Optional[str] = None
    ultimo_asunto: Optional[str] = None
    modo_respuesta: bool = False
    modo_ticket: bool = False

state = BotState()

# Inicialización de Servicios
try:
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    model = GenerativeModel("gemini-2.5-flash")
    bot = telebot.TeleBot(TELEGRAM_TOKEN)
except Exception as e:
    logger.critical(f"Error inicializando servicios externos: {e}")
    sys.exit(1)


# =============================================================================
# 3. UTILIDADES DE PROCESAMIENTO DE CORREO
# =============================================================================

def decodificar_texto(texto: Any, encoding: str) -> str:
    """Decodifica bytes a string manejando errores comunes de charset."""
    if isinstance(texto, bytes):
        try:
            return texto.decode(encoding or 'utf-8')
        except UnicodeDecodeError:
            return texto.decode('latin-1', errors='ignore')
    return str(texto)

def obtener_asunto_y_remitente(msg: email.message.Message) -> Tuple[str, str]:
    """Extrae y decodifica el asunto y remitente de un objeto email."""
    subject_raw = msg["Subject"]
    subject_str = "(Sin Asunto)"
    
    if subject_raw:
        try:
            decoded_list = decode_header(subject_raw)
            subject_str, encoding = decoded_list[0]
            subject_str = decodificar_texto(subject_str, encoding)
        except Exception:
            subject_str = str(subject_raw)
            
    sender = msg.get("From", "Desconocido")
    return subject_str, sender

def obtener_cuerpo(msg: email.message.Message) -> str:
    """Extrae el cuerpo del mensaje priorizando texto plano."""
    body = "Sin contenido legible."
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset()
                    body = decodificar_texto(payload, charset)
                    break
        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset()
            body = decodificar_texto(payload, charset)
    except Exception as e:
        logger.error(f"Error parseando cuerpo del correo: {e}")
    return body

def obtener_lista_uids_con_mapa(pop_conn: poplib.POP3_SSL) -> Tuple[Set[str], Dict[str, int]]:
    """
    Obtiene mapa de UIDs del servidor POP3.
    Retorna: (Set de UIDs únicos, Diccionario {UID: Número_Mensaje})
    """
    resp, items, octets = pop_conn.uidl()
    uids = set()
    uid_map = {}
    for item in items:
        parts = item.decode().split(' ')
        if len(parts) >= 2:
            num = int(parts[0])
            uid = parts[1]
            uids.add(uid)
            uid_map[uid] = num
    return uids, uid_map


# =============================================================================
# 4. CAPA DE INTELIGENCIA ARTIFICIAL Y NETWORKING
# =============================================================================

def preguntar_a_gemini(prompt: str) -> str:
    """Interfaz con Google Vertex AI (Gemini Model)."""
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Fallo en API Vertex AI: {e}")
        return "⚠️ Error: La IA no está disponible en este momento."

def enviar_correo_respuesta(destinatario: str, asunto: str, cuerpo_ia: str) -> bool:
    """Envía correo vía SMTP con encriptación TLS."""
    try:
        msg = MIMEText(cuerpo_ia)
        msg['Subject'] = f"Re: {asunto}"
        msg['From'] = EMAIL_USER
        msg['To'] = destinatario

        # Conexión SMTP segura
        with smtplib.SMTP(EMAIL_SERVER, 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, destinatario, msg.as_string())
            
        logger.info(f"Correo enviado exitosamente a {destinatario}")
        return True
    except Exception as e:
        logger.error(f"Error SMTP al enviar correo: {e}")
        return False


# =============================================================================
# 5. CONTROLADOR DEL CHATBOT (TELEGRAM)
# =============================================================================

@bot.message_handler(func=lambda message: True)
def responder_chat(message: telebot.types.Message):
    """
    Manejador principal de mensajes. Implementa una máquina de estados simple:
    1. Modo Ticket (Demo)
    2. Modo Respuesta (Redacción de correo)
    3. Modo Chat (Consultas generales)
    """
    usuario_input = message.text.lower()
    chat_id = message.chat.id

    # --- ESTADO 1: DEMO TICKET SYSTEM ---
    if state.modo_ticket:
        if any(x in usuario_input for x in ["si", "sí", "claro", "por favor", "hazlo", "simon"]):
            bot.send_chat_action(chat_id, 'typing')
            time.sleep(1.5) # Simulación de latencia de API
            
            bot.reply_to(message, 
                "✨¡Entendido Jefe! Generando ticket...\n\n"
                "✅Ticket Creado\n"
                "🎫ID: #INC-2026-8492\n"
                "📌Categoría: Hardware / Periféricos\n"
                "👤Asignado a: Soporte Nivel 1\n"
                "📅SLA: 24 hrs\n\n"
                "Registrado en sistema. Le notificaré cambios de estatus."
            )
        else:
            bot.reply_to(message, "Comprendido. No se generó ticket.")
        
        state.modo_ticket = False 
        return 

    # --- ESTADO 2: MODO REDACCIÓN DE CORREO ---
    if state.modo_respuesta:
        bot.send_message(chat_id, "A la orden Jared, redactando su correo...")
        
        # Prompt Engineering para la personalidad de JoulIAna
        prompt = f"""
        ACTÚA COMO: JoulIAna, la asistente de IA de Jared Abarca (Analista TI).
        
        SITUACIÓN:
        Jared (tu jefe) te está dictando una respuesta para un correo que recibió.
        
        DATOS:
        - Destinatario: {state.ultimo_remitente}
        - Asunto Original: {state.ultimo_asunto}
        - LO QUE JARED DICE (Tu instrucción): "{message.text}"
        
        TU TAREA:
        Redactar el correo de respuesta transmitiendo el mensaje de Jared.
        NO asumas que el mensaje es para ti. Si Jared dice "funciona bien", significa que ÉL opina que funciona bien.
        
        FORMATO OBLIGATORIO:
        1. Saludo: "Le escribe JoulIAna en nombre de Jared."
        2. Cuerpo: "Jared comenta que [Aquí adapta lo que dijo Jared en tercera persona o transmitiendo su idea exacta]..."
        3. Cierre: "Atentamente, JoulIAna | IA Assistant".
        
        IMPORTANTE: No agradezcas feedback a menos que Jared te diga "Dile gracias". Solo transmite su mensaje.
        REGLA DE ORO:
        SOLO dame el CUERPO del correo. NO incluyas "Asunto:", "Para:", ni cabeceras. Empieza directo con el saludo.
        """
        cuerpo_final = preguntar_a_gemini(prompt)
        
        # Ejecución de envío
        exito = enviar_correo_respuesta(state.ultimo_remitente, state.ultimo_asunto, cuerpo_final)
        
        if exito:
            bot.reply_to(message, f"✅ ¡Listo Jefe! Enviado.\n\nCopia:\n---\n{cuerpo_final}\n---")
            
            # Detección de intención para Demo Ticket
            keywords = ["ticket", "incidencia", "soporte", "falla"]
            if any(k in cuerpo_final.lower() for k in keywords):
                time.sleep(1)
                bot.send_message(chat_id, 
                    "Sugerencia Proactiva:\n"
                    "Ofrecí levantar ticket en el correo.\n"
                    "¿Quiere que simulemos la creación del ticket ahora? (Sí / No)"
                )
                state.modo_ticket = True 
        else:
            bot.reply_to(message, "😰 Error de conexión SMTP. Revise los logs.")
        
        state.modo_respuesta = False 
        return

    # --- ESTADO 3: FLUJO GENERAL / COMANDOS ---
    if any(x in usuario_input for x in ["si", "sí", "claro", "responder", "ok", "simon"]):
        if state.ultimo_remitente:
            state.modo_respuesta = True
            bot.reply_to(message, f"📝Con gusto.\n¿Qué respondemos a {state.ultimo_remitente}?")
        else:
            bot.reply_to(message, "🤷‍♀️ No hay correos recientes en memoria.")
    
    elif any(x in usuario_input for x in ["no", "nel", "nop", "luego", "gracias"]):
        bot.reply_to(message, "👍 Enterado. Quedo a la espera.")
        
    else:
        # Chat genérico con personalidad (LLM)
        prompt_chat = (
            "Eres JoulIAna, asistente leal y eficiente de Jared (IT). "
            f"Input usuario: {message.text}. Responde con personalidad."
        )
        bot.reply_to(message, preguntar_a_gemini(prompt_chat))


# =============================================================================
# 6. HILO DE MONITOREO
# =============================================================================

def ciclo_correos():
    """
    Bucle infinito que monitorea el servidor POP3 cada 30 segundos.
    Detecta nuevos UIDs, descarga mensajes, analiza con IA y notifica.
    """
    logger.info("Iniciando servicio de vigilancia POP3...")
    uids_conocidos = set()
    primera_vuelta = True
    
    while True:
        try:
            # Conexión efímera (Best Practice para POP3)
            pop_conn = poplib.POP3_SSL(EMAIL_SERVER, EMAIL_PORT, timeout=10)
            pop_conn.user(EMAIL_USER)
            pop_conn.pass_(EMAIL_PASS)
            
            uids_actuales, uid_map = obtener_lista_uids_con_mapa(pop_conn)
            
            if primera_vuelta:
                uids_conocidos = uids_actuales
                primera_vuelta = False
                logger.info(f"Sincronización inicial completada. {len(uids_conocidos)} correos previos.")
            else:
                nuevos = uids_actuales - uids_conocidos
                
                if nuevos:
                    logger.info(f"Detectados {len(nuevos)} correos nuevos.")
                    for uid in nuevos:
                        msg_num = uid_map.get(uid)
                        if msg_num:
                            # Descarga y parseo
                            resp, lines, octets = pop_conn.retr(msg_num)
                            msg_content = b'\r\n'.join(lines)
                            msg = email.message_from_bytes(msg_content)
                            
                            asunto, remitente = obtener_asunto_y_remitente(msg)
                            cuerpo_mensaje = obtener_cuerpo(msg)
                            
                            # Sanitización básica de remitente
                            if "<" in remitente: 
                                email_limpio = remitente.split("<")[1].replace(">", "")
                            else: 
                                email_limpio = remitente
                                
                            # Actualizar Memoria Global
                            state.ultimo_remitente = email_limpio
                            state.ultimo_asunto = asunto
                            
                            # Análisis IA
                            prompt_resumen = f"""
                            Eres JoulIAna. Analiza para Jared:
                            De: {remitente} | Asunto: {asunto} | Cuerpo: {cuerpo_mensaje[:1500]}
                            Dame un resumen EJECUTIVO y CORTO (máx 6 líneas).
                            """
                            resumen_ia = preguntar_a_gemini(prompt_resumen)

                            # Notificación Push
                            alerta = (
                                f"✨Hola Jefe, tienes correo nuevo\n"
                                f"📧De: `{remitente}`\n"
                                f"📝Asunto: {asunto}\n"
                                f"------------------\n"
                                f"{resumen_ia}\n"
                                f"------------------\n"
                                f"¿Le gustaría responder ahora?"
                            )
                            bot.send_message(TELEGRAM_CHAT_ID, alerta)

                    uids_conocidos = uids_actuales
            
            pop_conn.quit()
        except Exception as e:
            logger.error(f"Error en ciclo de vigilancia: {e}")
        
        time.sleep(30) # Wait period

# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════╗
    ║       JOULIANA AI ASSISTANT v1.2       ║
    ║      System Online & Listening...      ║
    ╚════════════════════════════════════════╝
    """)
    
    # Iniciar Hilo de Vigilancia (Daemon)
    t = threading.Thread(target=ciclo_correos, name="EmailPoller")
    t.daemon = True
    t.start()
    
    # Iniciar Bucle de Telegram (Blocking)
    logger.info("Bot de Telegram escuchando...")
    bot.infinity_polling()
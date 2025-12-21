"""
Servidor MCP para gestionar Gmail
Requiere: uv pip install fastmcp google-auth-oauthlib google-api-python-client
"""

from fastmcp import FastMCP
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText
import os.path
import pickle

# Configuración
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 
          'https://www.googleapis.com/auth/gmail.send']

mcp = FastMCP("Gmail Manager")

def get_gmail_service():
    """Obtiene el servicio de Gmail autenticado"""
    creds = None
    
    # Token guardado previamente
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    # Si no hay credenciales válidas, solicita login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Guarda las credenciales para la próxima vez
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    return build('gmail', 'v1', credentials=creds)

@mcp.tool()
def list_emails(max_results: int = 10, query: str = "") -> list[dict]:
    """
    Lista los emails recientes del usuario
    
    Args:
        max_results: Número máximo de emails a retornar (default: 10)
        query: Filtro de búsqueda de Gmail (ej: "from:juan@example.com", "is:unread")
    
    Returns:
        Lista de emails con id, asunto, remitente y snippet
    """
    service = get_gmail_service()
    
    results = service.users().messages().list(
        userId='me', 
        maxResults=max_results,
        q=query
    ).execute()
    
    messages = results.get('messages', [])
    emails = []
    
    for msg in messages:
        # Obtener detalles del mensaje
        message = service.users().messages().get(userId='me', id=msg['id']).execute()
        headers = message['payload']['headers']
        
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sin asunto')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Desconocido')
        
        emails.append({
            'id': msg['id'],
            'subject': subject,
            'from': sender,
            'snippet': message['snippet']
        })
    
    return emails

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> dict:
    """
    Envía un email desde la cuenta del usuario
    
    Args:
        to: Dirección de email del destinatario
        subject: Asunto del email
        body: Cuerpo del mensaje en texto plano
    
    Returns:
        Confirmación con el ID del mensaje enviado
    """
    service = get_gmail_service()
    
    # Crear el mensaje
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    
    # Codificar en base64
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    
    # Enviar
    sent_message = service.users().messages().send(
        userId='me',
        body={'raw': raw}
    ).execute()
    
    return {
        'status': 'sent',
        'message_id': sent_message['id'],
        'to': to,
        'subject': subject
    }


if __name__ == "__main__":
    mcp.run()
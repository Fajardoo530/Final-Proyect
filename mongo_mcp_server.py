"""
Servidor MCP para gestionar MongoDB
Requiere: uv pip install fastmcp pymongo dnspython pyjwt
"""

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from pymongo import MongoClient
from bson import json_util
import os.path
import json
import jwt
import time
from pydantic import SecretStr
from typing import Any, Optional, Union


# ==================== AUTH / KEYPAIR ====================

def get_or_create_keypair():
    """Obtiene o crea el par de claves RSA para JWT"""
    keypair_file = "mcp_keypair.json"
    if os.path.exists(keypair_file):
        with open(keypair_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return RSAKeyPair(
            private_key=SecretStr(data["private_key"]),
            public_key=data["public_key"]
        )

    keypair = RSAKeyPair.generate()
    with open(keypair_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "private_key": keypair.private_key.get_secret_value(),
                "public_key": keypair.public_key
            },
            f,
            indent=2
        )
    return keypair


# Generar/cargar el par de claves
keypair = get_or_create_keypair()


# Crear token para el cliente manualmente (expira en 1 año para integraciones como n8n)
def create_long_lived_token(keypair, subject, issuer, audience, expiration_days=365):
    """Crea un token JWT con expiración personalizada"""
    now = int(time.time())
    payload = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + (expiration_days * 24 * 60 * 60),
        "scope": ["mcp:access"]
    }

    private_key = keypair.private_key.get_secret_value()
    return jwt.encode(payload, private_key, algorithm="RS256")


client_token = create_long_lived_token(
    keypair=keypair,
    subject="mongo-client",
    issuer="mongo-mcp-server",
    audience="mongo-mcp",
    expiration_days=365
)

# Guardar token para el cliente en disco
with open('client_token.txt', 'w', encoding="utf-8") as f:
    f.write(client_token)

print(f"🔑 Token generado y guardado en client_token.txt")
print(f"Token: {client_token}")


# Configurar auth con JWTVerifier
public_key_str = keypair.public_key

auth = JWTVerifier(
    public_key=public_key_str,
    issuer="mongo-mcp-server",
    audience="mongo-mcp"
)

mcp = FastMCP("MongoDB MCP", auth=auth)


# ==================== MONGODB ====================

_mongo_client = None
_mongo_db = None

def get_mongo_db():
    """Obtiene la DB de MongoDB conectada (cacheada)."""
    global _mongo_client, _mongo_db

    if _mongo_db is not None:
        return _mongo_db

    mongo_uri = os.environ.get("MONGODB_URI", "").strip()
    mongo_db_name = os.environ.get("MONGODB_DB", "").strip()

    if not mongo_uri or not mongo_db_name:
        raise RuntimeError("Faltan variables de entorno: MONGODB_URI y/o MONGODB_DB")

    _mongo_client = MongoClient(mongo_uri)
    _mongo_db = _mongo_client[mongo_db_name]
    return _mongo_db


# ==================== TOOLS ====================

@mcp.tool()
def mongo_find(
    max_results: int = 10,
    query: str = "",
    # campos extra típicos de Slack / n8n (opcionales)
    type: str = "",
    user: str = "",
    ts: str = "",
    client_msg_id: str = "",
    text: str = "",
    team: str = "",
    blocks: Union[str, list[dict[str, Any]]] = "",
    channel: str = "",
    event_ts: str = "",
    channel_type: str = "",
    sessionId: str = "",
    action: str = "",
    chatInput: str = "",
    toolCallId: str = ""
) -> list[dict]:
    """
    (MongoDB) Devuelve documentos de una colección.

    NOTA: Mantengo el nombre/firmas del tool para que sea “igual” al original.
    - query debe ser un JSON string con:
        {"collection": "<nombre>", "filter": {...}}  (filter es opcional)
    - max_results limita el número de documentos devueltos.
    """
    db = get_mongo_db()

    # query esperado: {"collection":"users","filter":{"name":"Sr"}}
    if query:
        q = json.loads(query)
    else:
        q = {}

    collection = q.get("collection")
    if not collection:
        raise ValueError('En "query" debes indicar {"collection":"<nombre>"} (y opcional "filter").')

    filt = q.get("filter", {}) or {}

    docs = list(db[collection].find(filt).limit(int(max_results)))

    # Convertir ObjectId/fechas a JSON serializable
    return json.loads(json_util.dumps(docs))


@mcp.tool()
def mongo_insert(
    to: str,
    subject: str,
    body: str,
    type: str = "",
    user: str = "",
    ts: str = "",
    client_msg_id: str = "",
    text: str = "",
    team: str = "",
    blocks: Union[str, list[dict[str, Any]]] = "",
    channel: str = "",
    event_ts: str = "",
    channel_type: str = "",
    sessionId: str = "",
    action: str = "",
    chatInput: str = "",
    toolCallId: str = ""
) -> dict:
    """
    (MongoDB) Inserta un documento en una colección.

    NOTA: Mantengo el nombre/firmas del tool para que sea “igual” al original.
    Se mapea así:
    - to      -> nombre de la colección
    - subject -> opcional (se guarda como campo)
    - body    -> JSON string del documento a insertar (obligatorio)
    """
    db = get_mongo_db()

    collection = to.strip()
    if not collection:
        raise ValueError('El parámetro "to" debe contener el nombre de la colección.')

    # body esperado: {"a":1,"b":"x"}
    doc = json.loads(body) if body else {}
    if not isinstance(doc, dict):
        raise ValueError('El "body" debe ser un JSON objeto (dict).')

    # Guardamos subject como metadata si viene
    if subject:
        doc["_subject"] = subject

    res = db[collection].insert_one(doc)

    return {
        "status": "inserted",
        "collection": collection,
        "inserted_id": str(res.inserted_id)
    }


# ==================== RESOURCES ====================

@mcp.resource("mongodb://profile")
def get_profile() -> dict:
    """Devuelve info básica del servidor MCP MongoDB."""
    mongo_db_name = os.environ.get("MONGODB_DB", "").strip()
    return {
        "name": "MongoDB MCP",
        "db": mongo_db_name,
        "endpoint": "/mcp",
        "auth": "JWT Bearer"
    }


@mcp.resource("docs://setup-manual/{version}")
def get_setup_manual(version: str) -> str:
    return f"""
# MongoDB MCP - Setup Manual (v{version})

## Variables de entorno necesarias
- MONGODB_URI: cadena de conexión a MongoDB (Atlas o local)
- MONGODB_DB: nombre de la base de datos

## Tools disponibles
### mongo_find (MongoDB find)
- max_results: límite de documentos
- query: JSON string con:
  {{"collection":"<nombre>", "filter": {{...}}}}

Ejemplo query:
{{"collection":"users","filter":{{"active":true}}}}

### mongo_insert (MongoDB insert_one)
- to: nombre de la colección
- subject: opcional (se guarda como _subject)
- body: JSON string del documento a insertar

Ejemplo:
to="logs"
subject="insert"
body={{"event":"test","ok":true}}
""".strip()


# ==================== PROMPTS ====================

@mcp.prompt()
def daily_email_summary() -> list[dict]:
    """Prompt de ejemplo (mantengo el nombre para que sea igual al original)."""
    prompt_text = (
        "Eres un asistente experto en MongoDB. Usa las tools disponibles para consultar datos "
        "y devolver respuestas claras. Si necesitas leer datos, usa mongo_find con un query JSON "
        'que incluya {"collection": "...", "filter": {...}}.'
    )
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": prompt_text
            }
        }
    ]


@mcp.prompt()
def compose_professional_email(recipient: str = "", topic: str = "") -> list[dict]:
    """Prompt de ejemplo (mantengo estructura/idea)."""
    prompt_text = (
        "Genera una consulta MongoDB (filtro) en JSON para buscar documentos relevantes. "
        f"Colección sugerida: {recipient}. Tema: {topic}. "
        'Devuelve un JSON para usarlo como query en mongo_find: {"collection":"...","filter":{...}}'
    )
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": prompt_text
            }
        }
    ]


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000, path="/mcp")
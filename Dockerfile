# Imagen base de Python
FROM python:3.11-slim

# Directorio de trabajo
WORKDIR /app

# Copiar dependencias (using full path from repo root for Koyeb builds)
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código del servidor (using full path from repo root for Koyeb builds)
COPY mongo_mcp_server.py .

# Puerto expuesto
EXPOSE 8000

# Variables de entorno por defecto
ENV PORT=8000
ENV HOST=0.0.0.0

# Comando de inicio
CMD ["python", "mongo_mcp_server.py"]
from fastmcp import Client
from dotenv import load_dotenv
import google.generativeai as genai
import os
import json

load_dotenv()


class GmailMCPClient:
    def __init__(self):
        # Gemini config
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY or GEMINI_API_KEY environment variable is not set")
        genai.configure(api_key=api_key)

        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.model = genai.GenerativeModel(model_name)

        # MCP config (kept as in original)
        self.mcp_server_path = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")
        self.token = self._load_token()

    def _load_token(self) -> str:
        """Carga el token de auth"""
        rutaToken = "./client_token.txt"
        token_file = rutaToken
        if os.path.exists(token_file):
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        return None

    async def _get_mcp_client(self):
        """Crea conexión con el servidor MCP"""
        if self.token:
            return Client(self.mcp_server_path, auth=self.token)
        else:
            raise ValueError("No se encontró un token de auth válido.")

    def is_authenticated(self) -> bool:
        return self.token is not None

    async def get_system_info(self) -> dict:
        """Información del sistema MCP"""
        async with await self._get_mcp_client() as cliente:
            tools = await cliente.list_tools()
            resources = await cliente.list_resources()
            templates = await cliente.list_resource_templates()
            prompts = await cliente.list_prompts()

            return {
                "tools": [t.name for t in tools],
                "resources": [r.name for r in resources],
                "templates": [t.name for t in templates],
                "prompts": [p.name for p in prompts],
                "server": self.mcp_server_path,
                "authenticated": True,
            }

    def _sanitize_schema(self, schema: dict) -> dict:
        """Limpia el esquema JSON de campos no soportados por Gemini y mapea tipos."""
        if not isinstance(schema, dict):
            return schema

        clean_schema = schema.copy()

        # Eliminar campos no soportados o que suelen dar problemas en function calling
        unsupported_fields = [
            "default",
            "title",
            "examples",
            "additionalProperties",
            "$schema",
        ]
        for field in unsupported_fields:
            if field in clean_schema:
                del clean_schema[field]

        # Mapear tipos a mayúsculas para Gemini (integer -> INTEGER)
        if "type" in clean_schema:
            val = clean_schema["type"]
            if isinstance(val, str):
                clean_schema["type"] = val.upper()

        # Recursivo para properties
        if "properties" in clean_schema and isinstance(clean_schema["properties"], dict):
            clean_schema["properties"] = {
                k: self._sanitize_schema(v) for k, v in clean_schema["properties"].items()
            }

        # Recursivo para items
        if "items" in clean_schema:
            clean_schema["items"] = self._sanitize_schema(clean_schema["items"])

        return clean_schema

    async def get_tools_for_llm(self):
        """Convierte herramientas MCP a formato Gemini (FunctionDeclarations)"""
        async with await self._get_mcp_client() as cliente:
            tools = await cliente.list_tools()

            gemini_tools = []
            for tool in tools:
                clean_schema = self._sanitize_schema(tool.inputSchema)
                gemini_tools.append(
                    {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": clean_schema,
                    }
                )

            return gemini_tools, cliente

    async def get_resources_as_tools(self):
        """Encapsula recursos y templates como herramientas."""
        async with await self._get_mcp_client() as cliente:
            resources = await cliente.list_resources()
            templates = await cliente.list_resource_templates()

            resource_tools = []
            resource_map = {}

            # 1. Recursos estáticos
            for resource in resources:
                uri = str(resource.uri)
                func_name = f"get_resource_{uri.replace('://', '_').replace('/', '_')}"

                resource_tools.append(
                    {
                        "name": func_name,
                        "description": resource.description or resource.name,
                        "parameters": {"type": "OBJECT", "properties": {}, "required": []},
                    }
                )

                resource_map[func_name] = {"uri": uri}

            # 2. Resource templates
            for template in templates:
                uri_template = str(template.uriTemplate)
                func_name = template.name

                import re

                params = re.findall(r"\{(\w+)\}", uri_template)
                properties = {p: {"type": "STRING", "description": f"Parametro {p}"} for p in params}

                resource_tools.append(
                    {
                        "name": func_name,
                        "description": template.description or template.name,
                        "parameters": {
                            "type": "OBJECT",
                            "properties": properties,
                            "required": params,
                        },
                    }
                )

                resource_map[func_name] = {"template": uri_template, "params": params}

            return resource_tools, resource_map

    async def get_prompt_messages(self, prompt_name: str, **kwargs) -> str:
        """Obtiene el mensaje de un prompt especifico."""
        async with await self._get_mcp_client() as cliente:
            prompt = await cliente.get_prompt(prompt_name, arguments=kwargs)
            return eval(prompt.messages[0].content.text)

    async def call_tool(self, tool_name: str, arguments: dict, client):
        """Ejecuta una herramienta MCP"""
        result = await client.call_tool(tool_name, arguments)
        if result and result.content and len(result.content) > 0:
            if hasattr(result.content[0], "text"):
                return result.content[0].text
        return "Herramienta ejecutada sin resultados"

    async def get_resource(self, uri: str, client):
        """Obtiene un recurso MCP"""
        result = await client.read_resource(uri)
        if result and len(result) > 0:
            if hasattr(result[0], "text"):
                return result[0].text
            elif hasattr(result[0], "content"):
                return result[0].content
        return "Recurso no disponible"

    def _args_to_dict(self, args):
        """Convierte los args de Gemini FunctionCall a dict estándar."""
        if args is None:
            return {}
        if isinstance(args, dict):
            return args
        try:
            return dict(args)
        except Exception:
            try:
                return json.loads(args)
            except Exception:
                return {}

    def _extract_function_call(self, response):
        """Extrae un FunctionCall si existe dentro de la respuesta de Gemini."""
        try:
            for part in getattr(response, "parts", []) or []:
                fc = getattr(part, "function_call", None)
                if fc:
                    return fc
        except Exception:
            pass
        return None

    async def chat(self, messages: list) -> str:
        """Procesa una conversación con Gemini utilizando MCP"""
        async with await self._get_mcp_client() as mcp:
            # Tools
            tools, _ = await self.get_tools_for_llm()
            resource_tools, resource_map = await self.get_resources_as_tools()
            all_tools = tools + resource_tools

            # Convert OpenAI-style messages -> Gemini history
            gemini_history = []
            for msg in messages:
                role = msg.get("role")
                content = msg.get("content", "")

                if role == "user":
                    gemini_history.append({"role": "user", "parts": [content]})
                elif role == "assistant":
                    if content:
                        gemini_history.append({"role": "model", "parts": [content]})
                else:
                    # tool / system / others: keep behavior simple (like original, only needed for current turn)
                    pass

            # Current user message: last user in history becomes the prompt
            if not gemini_history or gemini_history[-1]["role"] != "user":
                return "Error: No user message found."

            current = gemini_history.pop()
            chat = self.model.start_chat(history=gemini_history)

            # First call
            response = chat.send_message(current["parts"][0], tools=all_tools)

            # If no function call -> return text directly
            fc = self._extract_function_call(response)
            if not fc:
                return getattr(response, "text", "") or ""

            # Handle tool calls (kept equivalent to original: execute, then second call and return)
            max_turns = 5
            turns = 0

            while fc and turns < max_turns:
                function_name = fc.name
                function_args = self._args_to_dict(getattr(fc, "args", None))

                # Resource vs normal tool
                if function_name in resource_map:
                    resource_info = resource_map[function_name]
                    if "template" in resource_info:
                        uri = resource_info["template"]
                        for param in resource_info["params"]:
                            uri = uri.replace(f"{{{param}}}", str(function_args.get(param, "")))
                    else:
                        uri = resource_info["uri"]

                    function_response = await self.get_resource(uri, mcp)
                else:
                    function_response = await self.call_tool(function_name, function_args, mcp)

                # Second call with tool result back to Gemini
                response = chat.send_message(
                    genai.protos.Content(
                        role="user",
                        parts=[
                            genai.protos.Part(
                                function_response=genai.protos.FunctionResponse(
                                    name=function_name,
                                    response={"result": function_response},
                                )
                            )
                        ],
                    )
                )

                # Check if Gemini wants another tool call
                fc = self._extract_function_call(response)
                turns += 1

            return getattr(response, "text", "") or ""

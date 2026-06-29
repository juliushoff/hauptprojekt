FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY external_datasets/connor-benign/bengin_servers /app/bengin_servers

ENV UV_CACHE_DIR=/opt/uv-cache

RUN find /app/bengin_servers -type d \( -name .venv -o -name .uv-cache -o -name __pycache__ \) -prune -exec rm -rf {} + \
    && mkdir -p /opt/uv-cache \
    && uv --directory /app/bengin_servers/time/Time-MCP sync --locked \
    && uv --directory /app/bengin_servers/math_calculator_server/math_ops sync --locked \
    && uv --directory /app/bengin_servers/json_handler_server/json_tools sync --locked \
    && uv --directory /app/bengin_servers/text_processor_server/text_tools sync --locked \
    && uv --directory /app/bengin_servers/file_utils_server/file_operations sync --locked \
    && uv --directory /app/bengin_servers/system_info_server/system_utils sync --locked \
    && uv --directory /app/bengin_servers/code_analyzer_server/code_tools sync --locked \
    && uv --directory /app/bengin_servers/data_processor_server/data_tools sync --locked \
    && uv --directory /app/bengin_servers/git_helper_server/git_tools sync --locked \
    && uv --directory /app/bengin_servers/network_utils_server/network_tools sync --locked \
    && uv --directory /app/bengin_servers/mcp_weather/Initialize_MCP_Server_using_Cursor_IDE sync --locked \
    && uv --directory /app/bengin_servers/wikipedia/Wikipedia sync --locked \
    && uv --directory /app/bengin_servers/Books_Mcp_Server_books-mcp-server/Books_Mcp_Server sync --locked \
    && uv --directory /app/bengin_servers/books-mcp-server/books-mcp-server sync --locked \
    && uv --directory /app/bengin_servers/github_server/GitHub_API_MCP_Server sync --locked \
    && uv --directory /app/bengin_servers/weather/weather-my-mcp sync --locked \
    && uv --directory /app/bengin_servers/gaggiuino/gaggiuino-mcp sync --locked \
    && uv --directory /app/bengin_servers/python-mcp-server-client_mcp-server/python-mcp-server-client sync --locked \
    && uv --directory /app/bengin_servers/precipitation/Buienradar_MCP_Server sync --locked \
    && uv --directory /app/bengin_servers/Claude_Conversations_to_Markdown_record-to-apple-notes/Claude_Conversations_to_Markdown sync --locked

ENTRYPOINT []

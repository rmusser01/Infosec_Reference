FROM mitmproxy/mitmproxy:12.3.0@sha256:c8a3753de11fd8266afeb103e163f7b7ac6a4a568a707fa2e15b23d20acf4eba
RUN pip install --no-cache-dir warcio==1.8.1 six==1.17.0

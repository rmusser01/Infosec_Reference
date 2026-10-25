FROM infosec-archive-proxy:12.3.0-warcio1.8.1
COPY fixture_proxy.py /fixture_proxy.py
RUN mv /usr/local/bin/mitmdump /usr/local/bin/mitmdump-real && printf '%s\n' '#!/bin/sh' 'exec /usr/local/bin/mitmdump-real "$@" -s /fixture_proxy.py' > /usr/local/bin/mitmdump && chmod +x /usr/local/bin/mitmdump

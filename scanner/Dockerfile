FROM python:3.11-slim

WORKDIR /scanner

# small deps: pip, npm for JS installs, yara (optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    npm \
    yara \
    && rm -rf /var/lib/apt/lists/*

COPY scan_package.py /scanner/scan_package.py
COPY rules.yar /scanner/rules.yar

RUN pip install --no-cache-dir yara-python

RUN chmod +x /scanner/scan_package.py

ENTRYPOINT ["/usr/local/bin/python", "/scanner/scan_package.py"]

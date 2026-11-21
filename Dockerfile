# Python + Node.js dono (taaki Python aur Node.js bots chal sakein).
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/bot_files && chmod 711 /app/bot_files

ENV PYTHONUNBUFFERED=1
# Root se chalta hai taaki har bot ko alag Linux user (uid) mil sake (isolation).
# --workers 1 hi rakho: bots ek hi process ke andar track hote hain.
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 8 --timeout 120"]

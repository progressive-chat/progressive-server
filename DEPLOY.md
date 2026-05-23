# Deploying Progressive Server

## Quick Start (Docker Compose)

```bash
# Generate config
docker compose run --rm progressive ./build/src/progressive-server --generate-config > homeserver.yaml
# Edit server_name and database settings
vim homeserver.yaml
# Start
docker compose up -d
```

## Production Deployment

### 1. Build
```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPROGRESSIVE_BUILD_TESTS=OFF
cmake --build build -j$(nproc)
sudo cp build/src/progressive-server /usr/local/bin/
```

### 2. Configure
```bash
sudo mkdir -p /etc/progressive /var/lib/progressive/media /var/lib/progressive/data
sudo chown -R progressive:progressive /etc/progressive /var/lib/progressive
progressive-server --generate-config > /etc/progressive/homeserver.yaml
```

Edit `homeserver.yaml`:
```yaml
server_name: "matrix.example.com"
public_baseurl: "https://matrix.example.com/"
listeners:
  - port: 8008
    bind_addresses:
      - "127.0.0.1"
    type: http

database:
  name: psycopg2
  args:
    user: progressive
    password: your-password
    host: localhost
    database: progressive
```

### 3. Systemd
```bash
sudo cp contrib/systemd/progressive-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now progressive-server
```

### 4. Nginx reverse proxy
```nginx
server {
    listen 443 ssl http2;
    server_name matrix.example.com;

    ssl_certificate     /etc/letsencrypt/live/matrix.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.example.com/privkey.pem;

    location /_matrix {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 60s;
    }

    location /.well-known/matrix/server {
        return 200 '{"m.server": "matrix.example.com:443"}';
        add_header Content-Type application/json;
    }

    location /.well-known/matrix/client {
        return 200 '{"m.homeserver": {"base_url": "https://matrix.example.com"}}';
        add_header Content-Type application/json;
    }
}
```

### 5. Let's Encrypt
```bash
sudo certbot certonly --nginx -d matrix.example.com
sudo systemctl reload nginx
```

### 6. Health check
```bash
curl https://matrix.example.com/health
# {"status":"ok","version":"0.1.0"}
```

# Deploy GigaChad GRC to Oracle Cloud (Free Forever)

Oracle Cloud offers an **Always Free Tier** that's perfect for running GigaChad GRC at no cost.

## Free Resources You Get

- **4 ARM Ampere A1 cores** (can split into multiple VMs)
- **24 GB RAM** (can split into multiple VMs)
- **200 GB Block Storage**
- **10 TB/month outbound data transfer**
- **Truly free forever** (no credit card expiration)

## Step 1: Create Oracle Cloud Account (5 minutes)

1. Go to [https://www.oracle.com/cloud/free/](https://www.oracle.com/cloud/free/)
2. Click **Start for free**
3. Fill out registration form
4. Verify email and phone
5. Add credit card (required but won't be charged on Always Free tier)

## Step 2: Create VM Instance (5 minutes)

1. Log into Oracle Cloud Console
2. Navigate to **Compute** → **Instances**
3. Click **Create Instance**

### Instance Configuration:
```
Name: gigachad-grc
Image: Ubuntu 22.04 Minimal
Shape: VM.Standard.A1.Flex
OCPUs: 2
Memory: 12 GB
Boot Volume: 100 GB
```

4. **Networking**:
   - Create new VCN (Virtual Cloud Network) or use existing
   - Assign a public IP
   
5. **SSH Keys**:
   - Generate new SSH key pair or upload existing
   - **Download the private key** (you'll need this!)

6. Click **Create**

Wait 2-3 minutes for the instance to provision.

## Step 3: Configure Firewall (2 minutes)

### In Oracle Cloud Console:

1. Go to **Networking** → **Virtual Cloud Networks**
2. Click your VCN → **Security Lists** → **Default Security List**
3. Click **Add Ingress Rules** and add:

```
Source: 0.0.0.0/0
Destination Port: 80
Description: HTTP

Source: 0.0.0.0/0
Destination Port: 443
Description: HTTPS

Source: 0.0.0.0/0
Destination Port: 8090
Description: Traefik Dashboard
```

## Step 4: SSH Into VM (1 minute)

```bash
# Replace with your VM's public IP and private key path
chmod 400 ~/Downloads/ssh-key.key
ssh -i ~/Downloads/ssh-key.key ubuntu@<PUBLIC_IP>
```

## Step 5: Install Docker (3 minutes)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker ubuntu
newgrp docker

# Install Docker Compose
sudo apt install docker-compose-plugin -y

# Verify installation
docker --version
docker compose version
```

## Step 6: Configure VM Firewall (1 minute)

```bash
# Allow HTTP/HTTPS through Ubuntu firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8090/tcp
sudo ufw allow 22/tcp
sudo ufw --force enable
```

## Step 7: Clone and Configure GigaChad GRC (3 minutes)

```bash
# Clone your fork
cd ~
git clone https://github.com/mewitt74/gigachad-grc.git
cd gigachad-grc

# Copy and configure environment
cp env.development .env

# Edit environment with your VM's public IP
nano .env
```

Update these values in `.env`:
```bash
APP_DOMAIN=<YOUR_VM_PUBLIC_IP>
NODE_ENV=development

# Generate secrets (run these commands)
echo "JWT_SECRET=$(openssl rand -base64 32)"
echo "SESSION_SECRET=$(openssl rand -base64 32)"
echo "POSTGRES_PASSWORD=$(openssl rand -base64 20)"
```

## Step 8: Deploy Application (5-10 minutes)

```bash
# Start all services
docker compose up -d

# Wait for services to start (2-3 minutes)
docker compose ps

# Check logs
docker compose logs -f
```

## Step 9: Access Your Application

Open in browser:
- **Application**: `http://<YOUR_VM_PUBLIC_IP>`
- **Traefik Dashboard**: `http://<YOUR_VM_PUBLIC_IP>:8090`
- **Keycloak Admin**: `http://<YOUR_VM_PUBLIC_IP>/auth`

### Default Login Credentials:
```
Username: admin@gigachad.com
Password: admin123
```

## Useful Commands

```bash
# View all container logs
docker compose logs -f

# View specific service logs
docker compose logs -f frontend

# Restart all services
docker compose restart

# Stop all services
docker compose down

# Update code and redeploy
git pull
docker compose up -d --build

# Check resource usage
docker stats
```

## Troubleshooting

### Services won't start - Out of memory:
```bash
# Check memory usage
free -h

# Reduce services or increase VM memory in Oracle Cloud
```

### Can't access application:
```bash
# Check if services are running
docker compose ps

# Check firewall rules
sudo ufw status

# Check Oracle Cloud ingress rules
```

### Services keep restarting:
```bash
# Check logs for errors
docker compose logs --tail=100

# Check disk space
df -h
```

## Cost Breakdown

**Total Monthly Cost: $0.00** ✅

Oracle Cloud Always Free Tier covers:
- ✅ VM compute (2 OCPUs, 12GB RAM)
- ✅ Storage (100 GB)
- ✅ Network egress (10 TB)
- ✅ Public IP address

## Next Steps

1. **Set up domain** (optional): Point your domain to the VM's public IP
2. **Enable SSL**: Use Certbot for Let's Encrypt certificates
3. **Set up backups**: Use the built-in backup scripts in `/deploy`
4. **Configure monitoring**: Enable Prometheus and Grafana dashboards
5. **Production hardening**: Follow [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)

## Support

- Oracle Cloud Docs: https://docs.oracle.com/en-us/iaas/
- GigaChad GRC Issues: https://github.com/grcengineering/gigachad-grc/issues
- Deployment Troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

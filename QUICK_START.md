# Quick Start Guide

Get the refactored ControlGate backend running in 5 minutes.

---

## Prerequisites

- Docker & Docker Compose installed
- Python 3.9+ installed
- Git

---

## 1️⃣ Setup Environment (1 min)

```bash
# Navigate to project
cd d:\final\ControlGate\controlgate-backend

# Copy environment template
copy .env.template .env

# OR on Mac/Linux:
cp .env.template .env
```

**Note:** Default credentials in `.env` are fine for local development.

---

## 2️⃣ Start MongoDB (30 sec)

```bash
# Start MongoDB container
docker-compose up -d

# Verify it's running
docker-compose ps
```

Expected output:
```
NAME          STATUS
controlgate-mongo  Up 2 seconds
```

---

## 3️⃣ Install & Run Backend (2 min)

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Mac/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend
uvicorn app.main:app --reload
```

Server running on: **http://localhost:8000**

---

## 4️⃣ Test It (30 sec)

### Option A: Browser
Visit: http://localhost:8000/docs (Swagger UI with all endpoints)

### Option B: Command Line

**Check health:**
```bash
curl http://localhost:8000/health
```

**Register user:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "test123456",
    "full_name": "Test User"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "test123456"
  }'
```

This returns `access_token`. Copy it for next step.

**Get current user:**
```bash
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <paste_token_here>"
```

---

## 🎯 What's New?

✅ **Three User Roles:** admin, premium, normal
✅ **MongoDB:** Production-ready database
✅ **Secure Auth:** bcrypt + JWT tokens
✅ **User Ownership:** Scans tied to users
✅ **Error Handling:** Custom exceptions
✅ **RBAC:** Role-based access control

---

## 📚 Full Docs

- **[REFACTORING_COMPLETE.md](REFACTORING_COMPLETE.md)** - Complete documentation
- **[DATABASE_MIGRATION.md](DATABASE_MIGRATION.md)** - Database setup guide
- **[REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)** - What changed

---

## 🔑 Key Credentials

**Default Admin Account:**
- Email: `admin@controlgate.ai`
- Password: `admin123!`
- Role: `admin` ✅

Auto-created on first startup.

---

## 📍 Common Tasks

### View API Documentation
```
http://localhost:8000/docs
```

### Connect to MongoDB
```bash
docker-compose exec mongo mongosh -u controlgate_user -p secure_password_here --authenticationDatabase admin
```

### View Logs
```bash
# MongoDB logs
docker-compose logs mongo

# Backend logs (in terminal where you ran uvicorn)
# Just watch the output
```

### Restart MongoDB
```bash
docker-compose restart mongo
```

### Stop Everything
```bash
docker-compose down  # Keeps data
docker-compose down -v  # Deletes data
Ctrl+C  # Stop backend
```

---

## 🐛 Troubleshooting

**Port already in use:**
```bash
# Change port in command:
uvicorn app.main:app --reload --port 8001
```

**MongoDB connection failed:**
```bash
# Check status
docker-compose ps

# Restart
docker-compose restart mongo

# Check logs
docker-compose logs mongo
```

**Module not found:**
```bash
# Reinstall requirements
pip install -r requirements.txt
```

---

## ✨ Features

### Authentication
- `POST /api/v1/auth/register` - Create account
- `POST /api/v1/auth/login` - Get JWT token
- `GET /api/v1/auth/me` - Current user profile
- `POST /api/v1/auth/refresh` - New token

### Scans (User-Owned)
- `POST /api/v1/scans/start` - Start scan
- `GET /api/v1/scans/{scan_id}/status` - Check progress
- `GET /api/v1/scans/{scan_id}/logs` - View logs
- `GET /api/v1/scans/{scan_id}/summary` - Results
- `POST /api/v1/scans/{scan_id}/cancel` - Cancel scan

**Access Control:**
- Users: Can access own scans only
- Admins: Can access any scan

---

## 🚀 Production Checklist

Before deploying to production:

1. **Change Secrets:**
   - [ ] Update JWT_SECRET with random value
   - [ ] Change MONGO_PASSWORD
   - [ ] Change DEFAULT_ADMIN_PASSWORD

2. **Docker:**
   - [ ] Use environment-specific docker-compose.yml
   - [ ] Mount volumes properly
   - [ ] Configure resource limits
   - [ ] Setup health checks

3. **Security:**
   - [ ] Enable HTTPS (reverse proxy)
   - [ ] Setup firewall rules
   - [ ] Database backups configured
   - [ ] Monitoring/alerting setup

4. **Verification:**
   - [ ] All endpoints tested
   - [ ] Error handling working
   - [ ] Logs capturing properly
   - [ ] Load test passed

---

**Ready to go! 🎉**

For detailed documentation, see REFACTORING_COMPLETE.md

from fastapi import FastAPI, APIRouter, HTTPException, File, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import hashlib
import base64
import json
import asyncio
import aiofiles
import io

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="VNC Management System", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# VNC Configuration
VNC_PASSWORD = "vnc123pass"  # Статичный пароль для всех подключений
VNC_PORT = 5900

# ================== MODELS ==================

class VNCConnection(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    ip_address: str
    location: str
    country: str = "Russia"
    city: str = "Moscow"
    status: str = "inactive"  # active, inactive, installing
    last_seen: Optional[datetime] = None
    installation_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    vnc_port: int = VNC_PORT
    vnc_password: str = VNC_PASSWORD

class VNCConnectionCreate(BaseModel):
    name: str
    location: str
    country: str = "Russia"
    city: str = "Moscow"

class InstallationKey(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    key: str
    machine_name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    used: bool = False
    used_at: Optional[datetime] = None
    connection_id: Optional[str] = None

class FileTransfer(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    connection_id: str
    filename: str
    file_size: int
    file_path: str
    transfer_type: str  # upload, download
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checksum: str

class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    connection_id: str
    action: str  # connect, disconnect, file_transfer, status_check
    details: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None

class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

# ================== HELPER FUNCTIONS ==================

def generate_installation_key():
    """Генерирует уникальный ключ установки"""
    return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]

def generate_powershell_script(installation_key: str):
    """Генерирует PowerShell скрипт для установки TightVNC"""
    script_content = f'''# VNC Auto-Installation Script
# Generated for University IT Support
# Installation Key: {installation_key}

# Configuration
$VNC_PASSWORD = "{VNC_PASSWORD}"
$INSTALLATION_KEY = "{installation_key}"
$SERVER_URL = "{os.environ.get('SERVER_URL', 'localhost:8001')}"

Write-Host "Starting VNC Installation..." -ForegroundColor Green

# Download TightVNC
$TightVNC_URL = "https://www.tightvnc.com/download/2.8.59/tightvnc-2.8.59-gpl-setup-64bit.msi"
$TempPath = "$env:TEMP\\tightvnc-setup.msi"

try {{
    Write-Host "Downloading TightVNC..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $TightVNC_URL -OutFile $TempPath -UseBasicParsing
    
    # Silent installation
    Write-Host "Installing TightVNC..." -ForegroundColor Yellow
    Start-Process msiexec.exe -ArgumentList "/i `"$TempPath`" /quiet /norestart SET_USEVNCAUTHENTICATION=1 SET_PASSWORD=$VNC_PASSWORD SET_USECONTROLAUTHENTICATION=1 SET_CONTROLPASSWORD=$VNC_PASSWORD" -Wait
    
    # Configure VNC Server
    Write-Host "Configuring VNC Server..." -ForegroundColor Yellow
    
    # Set password in registry
    $RegPath = "HKLM:\\SOFTWARE\\TightVNC\\Server"
    if (Test-Path $RegPath) {{
        Set-ItemProperty -Path $RegPath -Name "Password" -Value (ConvertTo-SecureString $VNC_PASSWORD -AsPlainText -Force | ConvertFrom-SecureString)
    }}
    
    # Start VNC Service
    Write-Host "Starting VNC Service..." -ForegroundColor Yellow
    Start-Service -Name "tvnserver"
    Set-Service -Name "tvnserver" -StartupType Automatic
    
    # Register with server
    Write-Host "Registering with management server..." -ForegroundColor Yellow
    $MachineName = $env:COMPUTERNAME
    $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{$_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual"}} | Select-Object -First 1).IPAddress
    
    $RegistrationData = @{{
        installation_key = $INSTALLATION_KEY
        machine_name = $MachineName
        ip_address = $IPAddress
        status = "active"
    }}
    
    $JsonData = ConvertTo-Json $RegistrationData
    
    try {{
        Invoke-RestMethod -Uri "http://$SERVER_URL/api/register-machine" -Method POST -Body $JsonData -ContentType "application/json"
        Write-Host "Registration successful!" -ForegroundColor Green
    }} catch {{
        Write-Host "Registration failed, but VNC is installed and running" -ForegroundColor Yellow
    }}
    
    # Clean up
    Remove-Item $TempPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "VNC Installation completed successfully!" -ForegroundColor Green
    Write-Host "VNC Password: $VNC_PASSWORD" -ForegroundColor Cyan
    Write-Host "Installation Key: $INSTALLATION_KEY" -ForegroundColor Cyan
    
}} catch {{
    Write-Host "Installation failed: $_" -ForegroundColor Red
    exit 1
}}

# Hide tray icon (optional)
$TrayRegPath = "HKLM:\\SOFTWARE\\TightVNC\\Server"
try {{
    Set-ItemProperty -Path $TrayRegPath -Name "ShowTrayIcon" -Value 0
}} catch {{
    Write-Host "Could not hide tray icon" -ForegroundColor Yellow
}}

Write-Host "Installation complete. VNC Server is now running." -ForegroundColor Green
pause
'''
    return script_content

async def log_activity(connection_id: str, action: str, details: str, ip_address: str = None):
    """Логирование действий"""
    log_entry = ActivityLog(
        connection_id=connection_id,
        action=action,
        details=details,
        ip_address=ip_address
    )
    await db.activity_logs.insert_one(log_entry.dict())

# ================== API ROUTES ==================

# Basic routes
@api_router.get("/")
async def root():
    return {"message": "VNC Management System API", "version": "1.0.0"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# VNC Connections Management
@api_router.post("/connections", response_model=VNCConnection)
async def create_connection(connection_data: VNCConnectionCreate):
    """Создать новое VNC соединение"""
    installation_key = generate_installation_key()
    
    connection = VNCConnection(
        **connection_data.dict(),
        installation_key=installation_key
    )
    
    # Сохранить соединение
    await db.vnc_connections.insert_one(connection.dict())
    
    # Создать ключ установки
    install_key = InstallationKey(
        key=installation_key,
        machine_name=connection_data.name,
        connection_id=connection.id
    )
    await db.installation_keys.insert_one(install_key.dict())
    
    return connection

@api_router.get("/connections", response_model=List[VNCConnection])
async def get_connections():
    """Получить все VNC соединения"""
    connections = await db.vnc_connections.find().to_list(1000)
    return [VNCConnection(**conn) for conn in connections]

@api_router.get("/connections/{connection_id}", response_model=VNCConnection)
async def get_connection(connection_id: str):
    """Получить конкретное соединение"""
    connection = await db.vnc_connections.find_one({"id": connection_id})
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    return VNCConnection(**connection)

@api_router.put("/connections/{connection_id}/status")
async def update_connection_status(connection_id: str, status: str):
    """Обновить статус соединения"""
    valid_statuses = ["active", "inactive", "installing", "error"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    update_data = {
        "status": status,
        "last_seen": datetime.utcnow()
    }
    
    result = await db.vnc_connections.update_one(
        {"id": connection_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    await log_activity(connection_id, "status_update", f"Status changed to {status}")
    
    return {"message": "Status updated successfully"}

@api_router.delete("/connections/{connection_id}")
async def delete_connection(connection_id: str):
    """Удалить соединение"""
    result = await db.vnc_connections.delete_one({"id": connection_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    # Удалить связанные ключи установки
    await db.installation_keys.delete_many({"connection_id": connection_id})
    
    await log_activity(connection_id, "connection_deleted", "Connection removed from system")
    
    return {"message": "Connection deleted successfully"}

# Installation Scripts
@api_router.get("/generate-installer/{connection_id}")
async def generate_installer(connection_id: str):
    """Генерировать PowerShell установщик для соединения"""
    connection = await db.vnc_connections.find_one({"id": connection_id})
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    script_content = generate_powershell_script(connection["installation_key"])
    
    # Создать файл скрипта
    filename = f"vnc_installer_{connection['name'].replace(' ', '_')}.ps1"
    
    await log_activity(connection_id, "installer_generated", f"PowerShell installer generated: {filename}")
    
    return StreamingResponse(
        io.StringIO(script_content),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@api_router.post("/register-machine")
async def register_machine(registration_data: dict):
    """Регистрация машины после установки VNC"""
    installation_key = registration_data.get("installation_key")
    machine_name = registration_data.get("machine_name")
    ip_address = registration_data.get("ip_address")
    status = registration_data.get("status", "active")
    
    if not installation_key:
        raise HTTPException(status_code=400, detail="Installation key required")
    
    # Найти ключ установки
    install_key = await db.installation_keys.find_one({"key": installation_key})
    if not install_key:
        raise HTTPException(status_code=404, detail="Invalid installation key")
    
    if install_key["used"]:
        raise HTTPException(status_code=400, detail="Installation key already used")
    
    # Обновить соединение
    connection_id = install_key["connection_id"]
    update_data = {
        "ip_address": ip_address,
        "status": status,
        "last_seen": datetime.utcnow()
    }
    
    await db.vnc_connections.update_one(
        {"id": connection_id},
        {"$set": update_data}
    )
    
    # Отметить ключ как использованный
    await db.installation_keys.update_one(
        {"key": installation_key},
        {"$set": {"used": True, "used_at": datetime.utcnow()}}
    )
    
    await log_activity(connection_id, "machine_registered", f"Machine {machine_name} registered with IP {ip_address}")
    
    return {"message": "Machine registered successfully", "connection_id": connection_id}

# VNC Control
@api_router.post("/connect/{connection_id}")
async def start_vnc_session(connection_id: str):
    """Начать VNC сессию"""
    connection = await db.vnc_connections.find_one({"id": connection_id})
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    if connection["status"] != "active":
        raise HTTPException(status_code=400, detail="Connection is not active")
    
    await log_activity(connection_id, "vnc_connect", f"VNC session started to {connection['ip_address']}")
    
    # Возвращаем данные для подключения к VNC
    return {
        "connection_id": connection_id,
        "ip_address": connection["ip_address"],
        "port": connection["vnc_port"],
        "password": connection["vnc_password"],
        "websocket_url": f"ws://localhost:6080/websockify?token={connection_id}"
    }

# Activity Logs
@api_router.get("/logs", response_model=List[ActivityLog])
async def get_activity_logs(limit: int = 100):
    """Получить логи активности"""
    logs = await db.activity_logs.find().sort("timestamp", -1).limit(limit).to_list(limit)
    return [ActivityLog(**log) for log in logs]

@api_router.get("/logs/{connection_id}", response_model=List[ActivityLog])
async def get_connection_logs(connection_id: str, limit: int = 50):
    """Получить логи для конкретного соединения"""
    logs = await db.activity_logs.find({"connection_id": connection_id}).sort("timestamp", -1).limit(limit).to_list(limit)
    return [ActivityLog(**log) for log in logs]

# Statistics
@api_router.get("/stats")
async def get_statistics():
    """Получить статистику системы"""
    total_connections = await db.vnc_connections.count_documents({})
    active_connections = await db.vnc_connections.count_documents({"status": "active"})
    inactive_connections = await db.vnc_connections.count_documents({"status": "inactive"})
    
    # Активность за последние 24 часа
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_activity = await db.activity_logs.count_documents({"timestamp": {"$gte": yesterday}})
    
    return {
        "total_connections": total_connections,
        "active_connections": active_connections,
        "inactive_connections": inactive_connections,
        "recent_activity_24h": recent_activity,
        "timestamp": datetime.utcnow()
    }

# Legacy status endpoints (for compatibility)
@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, validator
from datetime import datetime, timedelta
import secrets
import argon2
from pymongo import MongoClient
import smtplib
from email.mime.text import MIMEText
from fastapi.middleware.cors import CORSMiddleware
import logging
import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional, List
from bson import ObjectId
import hashlib
import base64
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("void-kye-api")
logger.info("Starting Void Kye API")

# Configuration (replace with your actual values)
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "Auth_db"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "voidkey01@gmail.com"
SMTP_PASSWORD = "inmh rdbd wufb gpzm"
SENDER_EMAIL = "voidkey01@gmail.com"

# JWT Security
SECRET_KEY = "voidkye_secure_jwt_secret_key"  # Should be changed in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# MongoDB setup
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_collection = db["users"]

# Create TTL index for automatic cleanup of unverified users after 1 day (86400 seconds)
try:
    users_collection.create_index(
        [("created_at", 1)],
        expireAfterSeconds=86400,
        partialFilterExpression={"is_verified": False}
    )
    logger.info("TTL index created for automatic cleanup of unverified users")
except Exception as e:
    logger.warning(f"Failed to create TTL index: {str(e)}")

# Password hasher
ph = argon2.PasswordHasher()

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login-verify")

# Models
class UserRegister(BaseModel):
    full_name: str
    email: EmailStr

class VerifyOTP(BaseModel):
    email: EmailStr
    otp: str

class CompleteRegistration(BaseModel):
    email: EmailStr
    master_password: str
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'master_password' in values and v != values['master_password']:
            raise ValueError('passwords do not match')
        return v

class UserLogin(BaseModel):
    email: EmailStr

class LoginVerify(BaseModel):
    email: EmailStr
    otp: str
    master_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('passwords do not match')
        return v

class DeleteAccountRequest(BaseModel):
    email: EmailStr
    otp: str
    master_password: str

class PasswordEntryCreate(BaseModel):
    website: str
    username: str
    password: str
    category: Optional[str] = "other"
    master_password: str
    strength: Optional[str] = None  # weak/medium/strong

class PasswordEntryOut(BaseModel):
    id: str
    website: str
    username: str
    password: str  # Will be decrypted before returning
    category: str
    strength: Optional[str] = None
    created_at: datetime
    updated_at: datetime

# Add this helper class for encryption
class AES256Encryptor:
    @staticmethod
    def generate_salt() -> str:
        return base64.b64encode(os.urandom(16)).decode('utf-8')
    
    @staticmethod
    def derive_key(master_password: str, salt: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            master_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,
            dklen=32  # 32 bytes = 256 bits
        )
    
    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> str:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        return base64.b64encode(iv + ct_bytes).decode('utf-8')
    
    @staticmethod
    def decrypt(key: bytes, encrypted_data: str) -> str:
        data = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Helper functions
def generate_otp() -> str:
    return str(secrets.randbelow(10**6)).zfill(6)

def hash_otp(otp: str) -> str:
    return ph.hash(otp)

def verify_otp(otp: str, hashed_otp: str) -> bool:
    try:
        ph.verify(hashed_otp, otp)
        return True
    except:
        return False

def hash_password(password: str) -> str:
    return ph.hash(password)

def send_email(to_email: str, subject: str, body: str, recipient_name: str = None):
    try:
        # Create HTML version of email
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h2 style="color: #4361ee;">Void Kye - Secure Password Manager</h2>
                <p>Hi {recipient_name or 'there'},</p>
                <p>{body}</p>
                <p>This code expires in 5 minutes.</p>
                <p>If you didn't request this code, please ignore this email.</p>
                <p>Thanks,<br>Void Kye Team</p>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEText(html_body, 'html')  # Use HTML formatting
        msg['Subject'] = f"Void Kye: {subject}"  # Descriptive subject
        msg['From'] = "Void Kye Security <" + SENDER_EMAIL + ">"  # Friendly sender name
        msg['To'] = to_email
        msg['X-Priority'] = '1'  # High priority

        logger.info(f"Attempting to send email to {to_email} with subject: {subject}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email: {str(e)}"
        )

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        logger.warning("Invalid JWT token")
        raise credentials_exception
        
    user = users_collection.find_one({"email": email, "is_verified": True})
    if user is None:
        logger.warning(f"User not found for token: {email}")
        raise credentials_exception
    
    return user

# Routes
@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(user: UserRegister, request: Request):
    # Check if email exists AND is already verified
    existing_user = users_collection.find_one({"email": user.email, "is_verified": True})
    if existing_user:
        logger.warning(f"Attempted registration with existing verified email: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Delete any previous unverified registration attempts
    users_collection.delete_one({"email": user.email, "is_verified": False})
    logger.info(f"Deleted previous unverified registration for email: {user.email}")

    # Generate OTP for verification
    logger.info(f"Registering new user with email: {user.email}")
    otp = generate_otp()
    temp_user = {
        "full_name": user.full_name,
        "email": user.email,
        "otp": hash_otp(otp),
        "otp_expires_at": datetime.utcnow() + timedelta(minutes=5),
        "is_verified": False,
        "registration_stage": "otp_verification",
        "created_at": datetime.utcnow()
    }
    
    users_collection.insert_one(temp_user)
    logger.info(f"Initial registration data stored for email: {user.email}")

    # Send OTP
    email_subject = "Verification Code"
    email_body = f"""Your verification code is: <strong>{otp}</strong>"""
    send_email(user.email, email_subject, email_body, user.full_name)

    return {"message": "OTP sent to your email. Verify to continue registration."}

@app.post("/verify-otp")
@limiter.limit("5/minute")
async def verify_registration_otp(otp_data: VerifyOTP, request: Request):
    # Find unverified record
    user = users_collection.find_one({
        "email": otp_data.email,
        "is_verified": False,
        "registration_stage": "otp_verification"
    })
    
    if not user:
        logger.warning(f"OTP verification attempted for non-existent or already verified user: {otp_data.email}")
        raise HTTPException(status_code=404, detail="User not found or already verified")

    if not user.get("otp"):
        logger.error(f"No OTP found for user: {otp_data.email}")
        raise HTTPException(status_code=400, detail="No OTP found for user")
        
    if datetime.utcnow() > user.get("otp_expires_at", datetime.min):
        logger.warning(f"Expired OTP verification attempted for user: {otp_data.email}")
        raise HTTPException(status_code=400, detail="OTP expired")

    logger.info(f"Received OTP: {otp_data.otp}, stored hashed OTP exists: {bool(user.get('otp'))}")
    if not verify_otp(otp_data.otp, user["otp"]):
        logger.warning(f"Invalid OTP provided for user: {otp_data.email}")
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # OTP verified, update registration stage
    users_collection.update_one(
        {"email": otp_data.email},
        {
            "$set": {
                "registration_stage": "password_creation",
                "otp": None,  # Clear OTP after verification
                "otp_expires_at": None
            }
        }
    )
    logger.info(f"OTP verified for user: {otp_data.email}, updated to password creation stage")

    return {"message": "Email verified successfully. Please set your master password."}

@app.post("/complete-registration")
@limiter.limit("5/minute")
async def complete_registration(registration_data: CompleteRegistration, request: Request):
    # Find the user in password_creation stage
    user = users_collection.find_one({
        "email": registration_data.email,
        "is_verified": False,
        "registration_stage": "password_creation"
    })
    
    if not user:
        logger.warning(f"Complete registration attempted for non-existent or wrong stage user: {registration_data.email}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or already verified. Please start registration again."
        )
    
    # Hash the password
    hashed_password = hash_password(registration_data.master_password)
    
    # Generate encryption salt
    salt = AES256Encryptor.generate_salt()
    
    # Complete registration
    result = users_collection.update_one(
        {"email": registration_data.email, "is_verified": False},
        {
            "$set": {
                "master_password": hashed_password,
                "encryption_salt": salt,  # Store the salt
                "is_verified": True,
                "registration_stage": "completed",
                "verified_at": datetime.utcnow()
            }
        }
    )
    
    if result.modified_count == 0:
        logger.error(f"Failed to complete registration for user: {registration_data.email}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete registration"
        )
    
    logger.info(f"Registration completed successfully for user: {registration_data.email}")
    return {"message": "Registration completed successfully!"}

@app.post("/login")
@limiter.limit("5/minute")
async def login(login_data: UserLogin, request: Request):
    # Only allow verified users to login
    user = users_collection.find_one({"email": login_data.email, "is_verified": True})
    if not user:
        logger.warning(f"Login attempted for non-existent or unverified user: {login_data.email}")
        raise HTTPException(status_code=404, detail="User not found or not verified")

    otp = generate_otp()
    hashed_otp = hash_otp(otp)
    otp_expires_at = datetime.utcnow() + timedelta(minutes=5)

    users_collection.update_one(
        {"email": login_data.email},
        {"$set": {"login_otp": hashed_otp, "login_otp_expires_at": otp_expires_at}}
    )
    logger.info(f"Login OTP generated for user: {login_data.email}")

    email_subject = "Login Verification Code"
    email_body = f"""Your login verification code is: <strong>{otp}</strong>"""
    send_email(login_data.email, email_subject, email_body, user.get("full_name"))

    return {"message": "Verification code sent to your email. Verify to continue."}

@app.post("/login-verify")
@limiter.limit("5/minute")
async def login_verify(verify_data: LoginVerify, request: Request):
    # Only allow verified users to login
    user = users_collection.find_one({"email": verify_data.email, "is_verified": True})
    if not user:
        logger.warning(f"Login verification attempted for non-existent or unverified user: {verify_data.email}")
        raise HTTPException(status_code=404, detail="User not found or not verified")

    if not user.get("login_otp"):
        logger.error(f"No OTP found for login verification: {verify_data.email}")
        raise HTTPException(status_code=400, detail="No active login request found")
        
    if datetime.utcnow() > user.get("login_otp_expires_at", datetime.min):
        logger.warning(f"Expired OTP for login verification: {verify_data.email}")
        raise HTTPException(status_code=400, detail="OTP expired")

    if not verify_otp(verify_data.otp, user["login_otp"]):
        logger.warning(f"Invalid OTP provided for login: {verify_data.email}")
        raise HTTPException(status_code=400, detail="Invalid OTP")

    try:
        logger.info(f"Verifying password for login: {verify_data.email}")
        ph.verify(user["master_password"], verify_data.master_password)
    except Exception as e:
        logger.warning(f"Incorrect password during login: {verify_data.email}")
        raise HTTPException(status_code=401, detail="Incorrect password")

    users_collection.update_one(
        {"email": verify_data.email},
        {"$unset": {"login_otp": "", "login_otp_expires_at": ""}}
    )
    logger.info(f"Login successful for user: {verify_data.email}")
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=access_token_expires
    )
    
    return {
        "message": "Login successful",
        "user": {
            "email": user["email"],
            "full_name": user["full_name"]
        },
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(request: Request, data: ForgotPasswordRequest):
    # Find verified user
    user = users_collection.find_one({"email": data.email, "is_verified": True})
    if not user:
        logger.warning(f"Password reset attempted for non-existent user: {data.email}")
        raise HTTPException(status_code=404, detail="Account not found")

    # Generate and store reset OTP
    otp = generate_otp()
    otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    users_collection.update_one(
        {"email": data.email},
        {"$set": {
            "reset_otp": hash_otp(otp),
            "reset_otp_expires_at": otp_expires_at
        }}
    )
    logger.info(f"Password reset OTP generated for user: {data.email}")

    # Send OTP email
    email_subject = "Password Reset Verification Code"
    email_body = f"""Your password reset verification code is: <strong>{otp}</strong>"""
    send_email(data.email, email_subject, email_body, user.get("full_name"))

    return {"message": "Verification code sent to your email. Use it to reset your password."}

@app.post("/reset-password")
@limiter.limit("3/hour")
async def reset_password(request: Request, data: ResetPasswordRequest):
    # Find verified user
    user = users_collection.find_one({"email": data.email, "is_verified": True})
    if not user:
        logger.warning(f"Password reset verification attempted for non-existent user: {data.email}")
        raise HTTPException(status_code=404, detail="Account not found")

    # Verify OTP
    if not user.get("reset_otp"):
        logger.error(f"No reset OTP found for user: {data.email}")
        raise HTTPException(status_code=400, detail="No active password reset request found")
        
    if datetime.utcnow() > user.get("reset_otp_expires_at", datetime.min):
        logger.warning(f"Expired reset OTP for user: {data.email}")
        raise HTTPException(status_code=400, detail="Verification code expired")

    if not verify_otp(data.otp, user["reset_otp"]):
        logger.warning(f"Invalid reset OTP provided for user: {data.email}")
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Update password
    hashed_password = hash_password(data.new_password)
    
    # Generate new encryption salt if needed
    salt = user.get("encryption_salt")
    if not salt:
        salt = AES256Encryptor.generate_salt()
    
    result = users_collection.update_one(
        {"email": data.email},
        {"$set": {
            "master_password": hashed_password,
            "encryption_salt": salt,
            "password_updated_at": datetime.utcnow()
        },
        "$unset": {
            "reset_otp": "",
            "reset_otp_expires_at": ""
        }}
    )
    
    if result.modified_count == 0:
        logger.error(f"Failed to update password for user: {data.email}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )
    
    logger.info(f"Password updated successfully for user: {data.email}")
    return {"message": "Password updated successfully"}

@app.post("/delete-account")
@limiter.limit("2/hour")
async def delete_account(request: Request, data: DeleteAccountRequest):
    # Find verified user
    user = users_collection.find_one({"email": data.email, "is_verified": True})
    if not user:
        logger.warning(f"Account deletion attempted for non-existent user: {data.email}")
        raise HTTPException(status_code=404, detail="Account not found")

    # Check if deletion process has been initiated (OTP sent)
    if not user.get("delete_account_otp"):
        # First request - send OTP
        otp = generate_otp()
        otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        users_collection.update_one(
            {"email": data.email},
            {"$set": {
                "delete_account_otp": hash_otp(otp),
                "delete_account_otp_expires_at": otp_expires_at
            }}
        )
        logger.info(f"Account deletion OTP generated for user: {data.email}")

        # Send OTP email
        email_subject = "Account Deletion Verification"
        email_body = f"""
        <p>You have requested to delete your Void Kye account.</p>
        <p>Your verification code is: <strong>{otp}</strong></p>
        <p>If you did not request this, please secure your account immediately.</p>
        """
        send_email(data.email, email_subject, email_body, user.get("full_name"))
        
        return {"message": "Verification code sent to your email. Please confirm deletion with the code and your master password."}
    
    # Verify OTP
    if datetime.utcnow() > user.get("delete_account_otp_expires_at", datetime.min):
        logger.warning(f"Expired deletion OTP for user: {data.email}")
        raise HTTPException(status_code=400, detail="Verification code expired")

    if not verify_otp(data.otp, user["delete_account_otp"]):
        logger.warning(f"Invalid deletion OTP provided for user: {data.email}")
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Verify master password
    try:
        ph.verify(user["master_password"], data.master_password)
    except Exception as e:
        logger.warning(f"Incorrect master password during account deletion: {data.email}")
        raise HTTPException(status_code=401, detail="Incorrect master password")

    # Delete the account
    result = users_collection.delete_one({"email": data.email})
    if result.deleted_count == 0:
        logger.error(f"Failed to delete account for user: {data.email}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete account"
        )
    
    logger.info(f"Account deleted successfully for user: {data.email}")
    return {"message": "Account deleted successfully"}

@app.get("/user-profile")
async def get_user_profile(current_user: dict = Depends(get_current_user)):
    """Get the profile of the logged-in user"""
    return {
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "is_verified": current_user["is_verified"],
        "verified_at": current_user.get("verified_at")
    }

def encrypt_data(data: str, master_password: str, salt: str) -> str:
    """Encrypt data using master password and user's salt with AES-256"""
    key = AES256Encryptor.derive_key(master_password, salt)
    return AES256Encryptor.encrypt(key, data)

def decrypt_data(encrypted_data: str, master_password: str, salt: str) -> str:
    """Decrypt data using master password and user's salt with AES-256"""
    key = AES256Encryptor.derive_key(master_password, salt)
    return AES256Encryptor.decrypt(key, encrypted_data)

@app.post("/passwords", response_model=PasswordEntryOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def store_password(
    password_data: PasswordEntryCreate,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Store a new encrypted password"""
    try:
        # First verify the master password
        try:
            ph.verify(current_user["master_password"], password_data.master_password)
        except Exception as e:
            logger.error(f"Master password verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid master password"
            )

        # Get the user's encryption salt
        user = users_collection.find_one({"email": current_user["email"]})
        if not user:
            logger.error(f"User not found: {current_user['email']}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        if not user.get("encryption_salt"):
            logger.error(f"User missing encryption_salt: {current_user['email']}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User encryption configuration missing. Please use /fix-encryption-direct endpoint to fix."
            )
        
        # Calculate password strength
        strength = "weak"
        if len(password_data.password) >= 12 and any(c.isdigit() for c in password_data.password) and any(not c.isalnum() for c in password_data.password):
            strength = "strong"
        elif len(password_data.password) >= 8:
            strength = "medium"
        
        # Encrypt the password using the master password and salt
        encrypted_password = encrypt_data(password_data.password, password_data.master_password, user["encryption_salt"])
        
        password_doc = {
            "user_email": current_user["email"],
            "website": password_data.website,
            "username": password_data.username,
            "encrypted_password": encrypted_password,
            "category": password_data.category,
            "strength": strength,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        try:
            result = db.passwords.insert_one(password_doc)
            password_doc["_id"] = result.inserted_id
            password_doc["id"] = str(result.inserted_id)
            password_doc["password"] = password_data.password  # Return decrypted version
            
            logger.info(f"Password stored successfully for user: {current_user['email']}")
            return PasswordEntryOut(**password_doc)
        except Exception as e:
            logger.error(f"Failed to store password: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to store password: {str(e)}"
            )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Catch any other exceptions
        logger.error(f"Unexpected error in store_password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )

@app.get("/passwords", response_model=List[PasswordEntryOut])
@limiter.limit("10/minute")
async def get_passwords(
    request: Request,
    master_password: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all passwords for the current user"""
    # Check if master_password is provided
    if not master_password:
        logger.error("master_password query parameter missing in request")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Master password is required as a query parameter"
        )
        
    try:
        # Verify master password first
        try:
            ph.verify(current_user["master_password"], master_password)
        except Exception as e:
            logger.error(f"Master password verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid master password"
            )

        # Get the user's encryption salt
        user = users_collection.find_one({"email": current_user["email"]})
        if not user:
            logger.error(f"User not found: {current_user['email']}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        if not user.get("encryption_salt"):
            logger.error(f"User missing encryption_salt: {current_user['email']}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User encryption configuration missing. Please use /fix-encryption-direct endpoint to fix."
            )

        # Build query
        query = {"user_email": current_user["email"]}
        if category:
            query["category"] = category
        if search:
            query["website"] = {"$regex": search, "$options": "i"}

        passwords = []
        try:
            for doc in db.passwords.find(query).sort("created_at", -1):
                try:
                    # Decrypt each password
                    decrypted_password = decrypt_data(doc["encrypted_password"], master_password, user["encryption_salt"])
                    passwords.append({
                        "id": str(doc["_id"]),
                        "website": doc["website"],
                        "username": doc["username"],
                        "password": decrypted_password,
                        "category": doc["category"],
                        "strength": doc.get("strength", "medium"),
                        "created_at": doc["created_at"],
                        "updated_at": doc["updated_at"]
                    })
                except Exception as e:
                    logger.error(f"Failed to decrypt password {doc['_id']}: {str(e)}")
                    # Continue with other passwords
            
            logger.info(f"Retrieved {len(passwords)} passwords for user: {current_user['email']}")
            return passwords
        except Exception as e:
            logger.error(f"Failed to retrieve passwords: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve passwords: {str(e)}"
            )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Catch any other exceptions
        logger.error(f"Unexpected error in get_passwords: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )

@app.delete("/passwords/{password_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def delete_password(
    password_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Delete a stored password"""
    if not ObjectId.is_valid(password_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password ID"
        )
    
    try:
        result = db.passwords.delete_one({
            "_id": ObjectId(password_id),
            "user_email": current_user["email"]
        })
        
        if result.deleted_count == 0:
            logger.warning(f"Password not found for deletion: {password_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password not found"
            )
            
        logger.info(f"Password deleted successfully: {password_id}")
    except Exception as e:
        logger.error(f"Failed to delete password: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete password"
        )

# Fix missing encryption salt endpoint
@app.post("/fix-encryption")
async def fix_encryption(
    email: str,
    master_password: str,
    current_user: dict = Depends(get_current_user)
):
    """Fix missing encryption salt for user"""
    # Only allow for the user's own account
    if email != current_user["email"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only fix your own account"
        )
        
    # Verify the master password
    try:
        ph.verify(current_user["master_password"], master_password)
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )
    
    # Check if encryption_salt exists
    user = users_collection.find_one({"email": email})
    if user and user.get("encryption_salt"):
        return {"message": "Encryption salt already exists"}
    
    # Generate a new encryption salt
    salt = AES256Encryptor.generate_salt()
    
    # Update the user document
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"encryption_salt": salt}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to set encryption salt"
        )
    
    logger.info(f"Encryption salt set for user: {email}")
    return {"message": "Encryption salt set successfully"}

@app.post("/fix-encryption-direct")
@limiter.limit("3/hour")
async def fix_encryption_direct(request: Request, email: str, master_password: str):
    """Fix missing encryption salt for user without requiring login"""
    # Find the user
    user = users_collection.find_one({"email": email, "is_verified": True})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or not verified"
        )
    
    # Verify the master password
    try:
        ph.verify(user["master_password"], master_password)
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )
    
    # Check if encryption_salt exists
    if user.get("encryption_salt"):
        return {"message": "Encryption salt already exists"}
    
    # Generate a new encryption salt
    salt = AES256Encryptor.generate_salt()
    
    # Update the user document
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"encryption_salt": salt}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to set encryption salt"
        )
    
    logger.info(f"Encryption salt set directly for user: {email}")
    return {"message": "Encryption salt set successfully"}

@app.post("/debug-payload")
async def debug_payload(request: Request):
    """Debug endpoint to show the raw request payload"""
    try:
        body = await request.json()
        logger.info(f"DEBUG: Received payload: {body}")
        return {
            "received_payload": body,
            "has_master_password": "master_password" in body,
            "fields_present": list(body.keys())
        }
    except Exception as e:
        logger.error(f"Error parsing request: {str(e)}")
        return {"error": str(e)}

@app.post("/debug-password", status_code=status.HTTP_200_OK)
async def debug_password(request: Request):
    """Debug endpoint to check password request data"""
    try:
        # Log the raw request body
        raw_body = await request.body()
        body_str = raw_body.decode()
        logger.info(f"Debug password raw request: {body_str}")
        
        # Try to parse as JSON
        try:
            json_data = await request.json()
            logger.info(f"Debug password JSON data: {json_data}")
            logger.info(f"Debug password fields: {list(json_data.keys())}")
            
            # Check for password field
            has_password = "password" in json_data
            password_value = json_data.get("password", "MISSING")
            
            return {
                "success": True, 
                "message": "Request received",
                "has_password": has_password,
                "password_value": "***" if has_password else "MISSING",
                "fields_present": list(json_data.keys())
            }
        except Exception as e:
            logger.error(f"Debug password JSON parse error: {str(e)}")
            return {"success": False, "error": f"JSON parse error: {str(e)}", "raw_data": body_str}
            
    except Exception as e:
        logger.error(f"Debug password error: {str(e)}")
        return {"success": False, "error": str(e)}

# Add this for development
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 
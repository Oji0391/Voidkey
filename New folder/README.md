# Void Kye Extension

A secure browser extension for password management and data encryption.

## Setup Instructions

### 1. Backend Setup

#### Install Dependencies
```bash
pip install -r requirements.txt
```

#### MongoDB Setup
Make sure MongoDB is installed and running on your system.
By default, the application will try to connect to MongoDB at `mongodb://localhost:27017`.

#### Run the Backend Server
```bash
python app.py
```

The backend server will run on http://localhost:8000

### 2. Frontend Setup

The frontend is a static HTML, CSS, and JavaScript application.
Simply open the `index.html` file in your browser to use the application.

For the best experience, make sure the backend server is running before using the frontend.

## Features

- User registration with email verification via OTP
- Secure password storage with Argon2 hashing
- Email-based login with OTP verification
- Modern UI with smooth animations

## API Endpoints

- `POST /register` - Register a new user
- `POST /verify-otp` - Verify email with OTP
- `POST /login` - Request login OTP
- `POST /login-verify` - Verify login with OTP and password 
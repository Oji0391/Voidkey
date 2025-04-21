// Helper Functions - Moved outside for global scope
function getInitials(name) {
    if (!name) return 'U';
    return name
        .split(' ')
        .map(part => part.charAt(0))
        .join('')
        .toUpperCase()
        .substring(0, 2);
}

function formatDate(date) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return date.toLocaleDateString('en-US', options);
}

function formatTime(date) {
    const options = { hour: 'numeric', minute: 'numeric', hour12: true };
    return date.toLocaleTimeString('en-US', options);
}

// Add a dedicated function to navigate to profile page
function navigateToProfile() {
    console.log("Navigating to profile page");
    
    // Get profile page element
    const profilePage = document.getElementById('profilePage');
    if (!profilePage) {
        console.error("Profile page element not found!");
        return;
    }
    
    // Get dashboard page element
    const dashboardPage = document.getElementById('dashboardPage');
    
    // Hide all other pages
    const pages = document.querySelectorAll('.container');
    pages.forEach(page => {
        page.style.display = 'none';
    });
    
    // Show profile page
    profilePage.style.display = 'block';
    
    // Get user data from localStorage 
    const userFullName = localStorage.getItem('userFullName') || 'John Doe';
    const userEmail = localStorage.getItem('userEmail') || 'user@example.com';
    
    // Set user data
    try {
        document.getElementById('profileFullName').textContent = userFullName;
        document.getElementById('profileEmail').textContent = userEmail;
        document.getElementById('profileInitials').textContent = getInitials(userFullName);
        document.getElementById('userInitials').textContent = getInitials(userFullName);
        
        // Set dummy account created date
        const randomDate = new Date();
        randomDate.setMonth(randomDate.getMonth() - Math.floor(Math.random() * 6));
        document.getElementById('accountCreated').textContent = formatDate(randomDate);
        
        // Set last login to now
        document.getElementById('lastLogin').textContent = 'Today, ' + formatTime(new Date());
    } catch (error) {
        console.error("Error updating profile data:", error);
    }
}

// Direct profile navigation function for debugging
function navigateToProfileDirect() {
    console.log("DIRECT NAVIGATION: Going to profile page");
    
    // Get the profile page element
    const profilePage = document.getElementById('profilePage');
    if (!profilePage) {
        console.error("Profile page not found!");
        return;
    }
    
    // Hide all other pages first
    document.querySelectorAll('.container').forEach(page => {
        if (page.id !== 'profilePage') {
            page.style.display = 'none';
        }
    });
    
    // Show profile page with inline styles to ensure visibility
    profilePage.style.display = 'block';
    profilePage.style.opacity = '1';
    profilePage.style.visibility = 'visible';
    
    // Fill in user data
    document.getElementById('profileFullName').textContent = localStorage.getItem('userFullName') || 'Test User';
    document.getElementById('profileEmail').textContent = localStorage.getItem('userEmail') || 'test@example.com';
    document.getElementById('profileInitials').textContent = getInitials(localStorage.getItem('userFullName') || 'Test User');
    document.getElementById('accountCreated').textContent = 'January 1, 2023';
    
    console.log("Profile page should now be visible");
}

// Initialize page on DOM content loaded
document.addEventListener('DOMContentLoaded', function() {
    // API Endpoint
    const API_BASE_URL = 'http://localhost:8000';
    
    // Initialize logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
            logout();
        });
    }
    
    // Store user email for registration steps
    window.registrationData = {
        email: '',
        fullName: ''
    };
    
    // Store login data
    window.loginData = {
        email: ''
    };
    
    // Store the source of reset password request (login page or dashboard)
    window.resetPasswordSource = "dashboard";
    
    // Initialize style properties for animations
    document.getElementById('mainPage').style.opacity = '1';
    document.getElementById('mainPage').style.transform = 'translateY(0)';
    document.getElementById('registerPage').style.opacity = '0';
    document.getElementById('registerPage').style.transform = 'translateY(10px)';
    
    // OTP input numeric only
    const otpInputs = document.querySelectorAll('#email-otp, #login-otp');
    otpInputs.forEach(input => {
        if (input) {
            input.addEventListener('input', function(e) {
                // Remove any non-numeric characters
                this.value = this.value.replace(/\D/g, '');
                
                // Limit to 6 digits
                if (this.value.length > 6) {
                    this.value = this.value.slice(0, 6);
                }
            });
        }
    });
    
    // Step 1: Send OTP Button handler
    const step1Form = document.getElementById('step1Form');
    if (step1Form) {
        step1Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fullNameInput = document.getElementById('fullname');
            const emailInput = document.getElementById('email');
            const fullNameValue = fullNameInput.value.trim();
            const emailValue = emailInput.value.trim();
            
            // Form validation
            if (!fullNameValue) {
                showInputError(fullNameInput, 'Please enter your full name');
                return;
            }
            
            if (!emailValue || !isValidEmail(emailValue)) {
                showInputError(emailInput, 'Please enter a valid email address');
                return;
            }
            
            // Store data for later steps
            window.registrationData.email = emailValue;
            window.registrationData.fullName = fullNameValue;
            
            // Send OTP
            const sendOtpBtn = document.getElementById('sendOtpBtn');
            try {
                // Disable button while request is in progress
                sendOtpBtn.disabled = true;
                sendOtpBtn.textContent = 'Sending...';
                
                // Make API call to register endpoint
                const response = await fetch(`${API_BASE_URL}/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        full_name: fullNameValue,
                        email: emailValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Registration failed');
                }
                
                // Show notification and go to step 2
                showNotification(data.message || 'Verification code sent to your email', 'success');
                showOtpVerificationPage();
                
            } catch (error) {
                console.error('Registration error:', error);
                showNotification(error.message, 'error');
                sendOtpBtn.disabled = false;
                sendOtpBtn.textContent = 'Send Verification Code';
            }
        });
    }
    
    // Resend OTP button handler
    const resendOtpBtn = document.getElementById('resendOtpBtn');
    if (resendOtpBtn) {
        resendOtpBtn.addEventListener('click', async function() {
            if (!window.registrationData.email || !window.registrationData.fullName) {
                showNotification('Missing registration data. Please go back and try again.', 'error');
                return;
            }
            
            try {
                // Disable button while request is in progress
                this.disabled = true;
                this.textContent = 'Sending...';
                
                // Make API call to register endpoint again
                const response = await fetch(`${API_BASE_URL}/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        full_name: window.registrationData.fullName,
                        email: window.registrationData.email
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Failed to resend verification code');
                }
                
                // Setup countdown timer
                let countdown = 30;
                this.textContent = `Wait (${countdown}s)`;
                
                const countdownInterval = setInterval(() => {
                    countdown--;
                    if (countdown <= 0) {
                        clearInterval(countdownInterval);
                        this.textContent = 'Resend Code';
                        this.disabled = false;
                    } else {
                        this.textContent = `Wait (${countdown}s)`;
                    }
                }, 1000);
                
                showNotification(data.message || 'Verification code resent', 'success');
            } catch (error) {
                console.error('Resend OTP error:', error);
                showNotification(error.message, 'error');
                this.disabled = false;
                this.textContent = 'Resend Code';
            }
        });
    }
    
    // Step 2: Verify OTP form handler
    const step2Form = document.getElementById('step2Form');
    if (step2Form) {
        step2Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const otpInput = document.getElementById('email-otp');
            const otpValue = otpInput.value.trim();
            
            if (!otpValue || otpValue.length < 6) {
                showInputError(otpInput, 'Please enter a valid 6-digit verification code');
                return;
            }
            
            if (!window.registrationData.email) {
                showNotification('Missing email. Please go back and try again.', 'error');
                return;
            }
            
            const verifyOtpBtn = document.getElementById('verifyOtpBtn');
            try {
                // Disable button while request is in progress
                verifyOtpBtn.disabled = true;
                verifyOtpBtn.textContent = 'Verifying...';
                
                // Make API call to verify OTP
                const response = await fetch(`${API_BASE_URL}/verify-otp`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: window.registrationData.email,
                        otp: otpValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'OTP verification failed');
                }
                
                // Show notification and go to step 3
                showNotification(data.message || 'Email verified successfully!', 'success');
                showCreatePasswordPage();
                
            } catch (error) {
                console.error('Verification error:', error);
                showNotification(error.message, 'error');
                verifyOtpBtn.disabled = false;
                verifyOtpBtn.textContent = 'Verify';
            }
        });
    }
    
    // Step 3: Complete registration form handler
    const step3Form = document.getElementById('step3Form');
    if (step3Form) {
        step3Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const passwordInput = document.getElementById('password');
            const confirmPasswordInput = document.getElementById('confirm-password');
            const termsCheckbox = document.getElementById('terms');
            
            // Validate form
            let isValid = true;
            
            if (!passwordInput.value) {
                showInputError(passwordInput, 'Please enter a master password');
                isValid = false;
            }
            
            if (passwordInput.value !== confirmPasswordInput.value) {
                showInputError(confirmPasswordInput, 'Passwords do not match');
                showInputError(passwordInput, 'Passwords do not match');
                isValid = false;
            }
            
            if (!termsCheckbox.checked) {
                showNotification('Please agree to the Terms & Conditions', 'error');
                isValid = false;
            }
            
            if (!window.registrationData.email) {
                showNotification('Missing email. Please start registration again.', 'error');
                return;
            }
            
            if (!isValid) return;
            
            const submitBtn = document.querySelector('.register-submit-btn');
            try {
                // Disable button while request is in progress
                submitBtn.disabled = true;
                submitBtn.textContent = 'Processing...';
                
                // Make API call to complete registration
                const response = await fetch(`${API_BASE_URL}/complete-registration`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: window.registrationData.email,
                        master_password: passwordInput.value,
                        confirm_password: confirmPasswordInput.value
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Registration completion failed');
                }
                
                // Show success notification
                showNotification(data.message || 'Registration completed successfully!', 'success');
                
                // Reset form and return to main page after brief delay
                setTimeout(() => {
                    // Clear registration data
                    window.registrationData = {
                        email: '',
                        fullName: ''
                    };
                    
                    // Reset all forms
                    document.getElementById('step1Form').reset();
                    document.getElementById('step2Form').reset();
                    document.getElementById('step3Form').reset();
                    
                    // Return to main page
                    showMainPage();
                }, 1500);
                
            } catch (error) {
                console.error('Complete registration error:', error);
                showNotification(error.message, 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Complete Registration';
            }
        });
    }
    
    // Login Step 1: Send OTP Button handler
    const loginStep1Form = document.getElementById('loginStep1Form');
    if (loginStep1Form) {
        loginStep1Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const emailInput = document.getElementById('login-email');
            const emailValue = emailInput.value.trim();
            
            // Form validation
            if (!emailValue || !isValidEmail(emailValue)) {
                showInputError(emailInput, 'Please enter a valid email address');
                return;
            }
            
            // Store data for later steps
            window.loginData.email = emailValue;
            
            // Send OTP
            const loginSendOtpBtn = document.getElementById('loginSendOtpBtn');
            try {
                // Disable button while request is in progress
                loginSendOtpBtn.disabled = true;
                loginSendOtpBtn.textContent = 'Sending...';
                
                // Make API call to login endpoint
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: emailValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Login request failed');
                }
                
                // Show notification and go to verify page
                showNotification(data.message || 'Verification code sent to your email', 'success');
                showLoginVerifyPage();
                
            } catch (error) {
                console.error('Login error:', error);
                showNotification(error.message, 'error');
                loginSendOtpBtn.disabled = false;
                loginSendOtpBtn.textContent = 'Send Verification Code';
            }
        });
    }
    
    // Login Step 2: Verify OTP and password
    const loginStep2Form = document.getElementById('loginStep2Form');
    if (loginStep2Form) {
        loginStep2Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const otpInput = document.getElementById('login-otp');
            const passwordInput = document.getElementById('login-password');
            const otpValue = otpInput.value.trim();
            const passwordValue = passwordInput.value.trim();
            
            // Validate form
            if (!otpValue || otpValue.length < 6) {
                showInputError(otpInput, 'Please enter a valid 6-digit verification code');
                return;
            }
            
            if (!passwordValue) {
                showInputError(passwordInput, 'Please enter your master password');
                return;
            }
            
            if (!window.loginData.email) {
                showNotification('Missing email. Please go back and try again.', 'error');
                return;
            }
            
            const loginVerifyBtn = document.getElementById('loginVerifyBtn');
            try {
                // Disable button while request is in progress
                loginVerifyBtn.disabled = true;
                loginVerifyBtn.textContent = 'Verifying...';
                
                // Make API call to verify login
                const response = await fetch(`${API_BASE_URL}/login-verify`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: window.loginData.email,
                        otp: otpValue,
                        master_password: passwordValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Login verification failed');
                }
                
                // Store user data
                localStorage.setItem('userFullName', data.user.full_name);
                localStorage.setItem('userEmail', data.user.email);
                
                // Store JWT token
                if (data.access_token) {
                    localStorage.setItem('accessToken', data.access_token);
                    localStorage.setItem('tokenType', data.token_type);
                }
                
                // Show success notification and go to dashboard
                showNotification(data.message || 'Login successful!', 'success');
                
                // Reset form fields
                otpInput.value = '';
                passwordInput.value = '';
                
                // Show dashboard after a short delay
                setTimeout(() => {
                    showDashboardPage();
                }, 1000);
                
            } catch (error) {
                console.error('Login verification error:', error);
                showNotification(error.message, 'error');
                loginVerifyBtn.disabled = false;
                loginVerifyBtn.textContent = 'Login';
            }
        });
    }
    
    // Login Resend OTP button handler
    const loginResendOtpBtn = document.getElementById('loginResendOtpBtn');
    if (loginResendOtpBtn) {
        loginResendOtpBtn.addEventListener('click', async function() {
            if (!window.loginData.email) {
                showNotification('Missing email. Please go back and try again.', 'error');
                return;
            }
            
            try {
                // Disable button while request is in progress
                this.disabled = true;
                this.textContent = 'Sending...';
                
                // Make API call to login endpoint again
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: window.loginData.email
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Failed to resend verification code');
                }
                
                // Setup countdown timer
                let countdown = 30;
                this.textContent = `Wait (${countdown}s)`;
                
                const countdownInterval = setInterval(() => {
                    countdown--;
                    if (countdown <= 0) {
                        clearInterval(countdownInterval);
                        this.textContent = 'Resend Code';
                        this.disabled = false;
                    } else {
                        this.textContent = `Wait (${countdown}s)`;
                    }
                }, 1000);
                
                showNotification(data.message || 'Verification code resent', 'success');
            } catch (error) {
                console.error('Resend login OTP error:', error);
                showNotification(error.message, 'error');
                this.disabled = false;
                this.textContent = 'Resend Code';
            }
        });
    }
    
    // Check if user is already logged in
    if (localStorage.getItem('userEmail') && localStorage.getItem('userFullName')) {
        showDashboardPage();
    }

    // Forgot Password link
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Auto-fill email if available from login form
            const loginEmail = document.getElementById('login-email');
            const resetEmail = document.getElementById('reset-email');
            
            if (loginEmail && resetEmail && loginEmail.value.trim()) {
                resetEmail.value = loginEmail.value.trim();
            }
            
            // Set source as login page
            window.resetPasswordSource = "login";
            
            showResetPasswordPage();
        });
    }

    // Dashboard buttons
    const resetPasswordBtn = document.getElementById('resetPasswordBtn');
    if (resetPasswordBtn) {
        resetPasswordBtn.addEventListener('click', function() {
            const resetEmailInput = document.getElementById('reset-email');
            if (resetEmailInput) {
                resetEmailInput.value = localStorage.getItem('userEmail') || '';
            }
            
            // Set source as dashboard
            window.resetPasswordSource = "dashboard";
            
            showResetPasswordPage();
        });
    }

    const deleteAccountBtn = document.getElementById('deleteAccountBtn');
    if (deleteAccountBtn) {
        deleteAccountBtn.addEventListener('click', function() {
            showDeleteAccountPage();
        });
    }

    // Reset Password back button
    const resetPasswordBackBtn = document.getElementById('resetPasswordBackBtn');
    if (resetPasswordBackBtn) {
        resetPasswordBackBtn.addEventListener('click', function() {
            if (window.resetPasswordSource === "login") {
                showLoginPage();
            } else {
                showDashboardPage();
            }
        });
    }

    // Reset Password Step 1: Request reset code
    const resetPasswordStep1Form = document.getElementById('resetPasswordStep1Form');
    if (resetPasswordStep1Form) {
        resetPasswordStep1Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const emailInput = document.getElementById('reset-email');
            const emailValue = emailInput.value.trim();
            
            // Form validation
            if (!emailValue || !isValidEmail(emailValue)) {
                showInputError(emailInput, 'Please enter a valid email address');
                return;
            }
            
            // Store email for step 2
            window.resetData = {
                email: emailValue
            };
            
            const resetSendOtpBtn = document.getElementById('resetSendOtpBtn');
            try {
                // Disable button while request is in progress
                resetSendOtpBtn.disabled = true;
                resetSendOtpBtn.textContent = 'Sending...';
                
                // Make API call to forgot-password endpoint
                const response = await fetchWithAuth(`${API_BASE_URL}/forgot-password`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: emailValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Failed to request password reset');
                }
                
                // Show notification and go to verify page
                showNotification(data.message || 'Verification code sent to your email', 'success');
                showResetVerifyPage();
                
            } catch (error) {
                console.error('Password reset request error:', error);
                showNotification(error.message, 'error');
                resetSendOtpBtn.disabled = false;
                resetSendOtpBtn.textContent = 'Send Verification Code';
            }
        });
    }

    // Reset Password Step 2: Verify and reset
    const resetPasswordStep2Form = document.getElementById('resetPasswordStep2Form');
    if (resetPasswordStep2Form) {
        resetPasswordStep2Form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const otpInput = document.getElementById('reset-otp');
            const newPasswordInput = document.getElementById('new-password');
            const confirmPasswordInput = document.getElementById('confirm-new-password');
            
            const otpValue = otpInput.value.trim();
            const newPasswordValue = newPasswordInput.value.trim();
            const confirmPasswordValue = confirmPasswordInput.value.trim();
            
            // Validate form
            let isValid = true;
            
            if (!otpValue || otpValue.length < 6) {
                showInputError(otpInput, 'Please enter a valid 6-digit verification code');
                isValid = false;
            }
            
            if (!newPasswordValue) {
                showInputError(newPasswordInput, 'Please enter a new master password');
                isValid = false;
            }
            
            if (newPasswordValue !== confirmPasswordValue) {
                showInputError(confirmPasswordInput, 'Passwords do not match');
                showInputError(newPasswordInput, 'Passwords do not match');
                isValid = false;
            }
            
            if (!window.resetData || !window.resetData.email) {
                showNotification('Missing email. Please go back and try again.', 'error');
                return;
            }
            
            if (!isValid) return;
            
            const resetPasswordBtn = document.getElementById('resetPasswordBtn');
            try {
                // Disable button while request is in progress
                resetPasswordBtn.disabled = true;
                resetPasswordBtn.textContent = 'Processing...';
                
                // Make API call to reset-password endpoint
                const response = await fetchWithAuth(`${API_BASE_URL}/reset-password`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: window.resetData.email,
                        otp: otpValue,
                        new_password: newPasswordValue,
                        confirm_password: confirmPasswordValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Password reset failed');
                }
                
                // Show success notification
                showNotification(data.message || 'Password reset successfully!', 'success');
                
                // Reset form and return to dashboard
                resetPasswordStep2Form.reset();
                window.resetData = {};
                
                // Force logout after password change
                setTimeout(() => {
                    logout();
                    showNotification('Please login with your new password', 'info');
                }, 1500);
                
            } catch (error) {
                console.error('Password reset error:', error);
                showNotification(error.message, 'error');
                resetPasswordBtn.disabled = false;
                resetPasswordBtn.textContent = 'Reset Password';
            }
        });
    }

    // Delete Account: Request OTP button
    const requestDeleteOtpBtn = document.getElementById('requestDeleteOtpBtn');
    if (requestDeleteOtpBtn) {
        requestDeleteOtpBtn.addEventListener('click', async function() {
            const userEmail = localStorage.getItem('userEmail');
            if (!userEmail) {
                showNotification('You must be logged in to delete your account', 'error');
                return;
            }
            
            try {
                // Disable button while request is in progress
                this.disabled = true;
                this.textContent = 'Sending...';
                
                // Make initial call to delete-account endpoint (this will send OTP)
                const response = await fetchWithAuth(`${API_BASE_URL}/delete-account`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: userEmail,
                        otp: '', // Empty since we're just requesting the OTP
                        master_password: '' // Empty since we're just requesting the OTP
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Failed to request verification code');
                }
                
                // Show notification
                showNotification(data.message || 'Verification code sent to your email', 'success');
                
                // Setup countdown timer
                let countdown = 30;
                this.textContent = `Wait (${countdown}s)`;
                
                const countdownInterval = setInterval(() => {
                    countdown--;
                    if (countdown <= 0) {
                        clearInterval(countdownInterval);
                        this.textContent = 'Request Verification Code';
                        this.disabled = false;
                    } else {
                        this.textContent = `Wait (${countdown}s)`;
                    }
                }, 1000);
                
            } catch (error) {
                console.error('Delete account OTP request error:', error);
                showNotification(error.message, 'error');
                this.disabled = false;
                this.textContent = 'Request Verification Code';
            }
        });
    }

    // Delete Account: Confirm deletion
    const deleteAccountForm = document.getElementById('deleteAccountForm');
    if (deleteAccountForm) {
        deleteAccountForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const otpInput = document.getElementById('delete-otp');
            const passwordInput = document.getElementById('delete-password');
            
            const otpValue = otpInput.value.trim();
            const passwordValue = passwordInput.value.trim();
            
            // Validate form
            let isValid = true;
            
            if (!otpValue || otpValue.length < 6) {
                showInputError(otpInput, 'Please enter a valid 6-digit verification code');
                isValid = false;
            }
            
            if (!passwordValue) {
                showInputError(passwordInput, 'Please enter your master password');
                isValid = false;
            }
            
            const userEmail = localStorage.getItem('userEmail');
            if (!userEmail) {
                showNotification('You must be logged in to delete your account', 'error');
                return;
            }
            
            if (!isValid) return;
            
            // Ask for final confirmation
            if (!confirm("WARNING: This action cannot be undone. Are you sure you want to permanently delete your account?")) {
                return;
            }
            
            const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
            try {
                // Disable button while request is in progress
                confirmDeleteBtn.disabled = true;
                confirmDeleteBtn.textContent = 'Processing...';
                
                // Make API call to delete-account endpoint
                const response = await fetchWithAuth(`${API_BASE_URL}/delete-account`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: userEmail,
                        otp: otpValue,
                        master_password: passwordValue
                    })
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.detail || 'Account deletion failed');
                }
                
                // Show success notification
                showNotification(data.message || 'Account deleted successfully', 'success');
                
                // Reset form, clear all user data and go to main page
                deleteAccountForm.reset();
                logout();
                
            } catch (error) {
                console.error('Account deletion error:', error);
                showNotification(error.message, 'error');
                confirmDeleteBtn.disabled = false;
                confirmDeleteBtn.textContent = 'Permanently Delete Account';
            }
        });
    }

    // DOM Elements - Profile Section
    const profileButton = document.getElementById('profileButton');
    const profileSection = document.getElementById('profileSection');
    const closeProfileBtn = document.getElementById('closeProfileBtn');
    const twoFactorToggle = document.getElementById('twoFactorToggle');
    const securityStatus = document.getElementById('securityStatus');
    const securityStatusText = document.getElementById('securityStatusText');

    // Profile Section Toggle
    if (profileButton) {
        profileButton.addEventListener('click', () => {
            profileSection.classList.add('active');
            
            // Populate profile data from localStorage if available
            const userData = JSON.parse(localStorage.getItem('user') || '{}');
            if (userData.full_name) {
                document.getElementById('profileFullName').textContent = userData.full_name;
                document.getElementById('profileInitials').textContent = getInitials(userData.full_name);
                document.getElementById('userInitials').textContent = getInitials(userData.full_name);
            }
            
            if (userData.email) {
                document.getElementById('profileEmail').textContent = userData.email;
            }
            
            // Set dummy account created date if not available
            if (!userData.created_at) {
                const randomDate = new Date();
                randomDate.setMonth(randomDate.getMonth() - Math.floor(Math.random() * 6));
                document.getElementById('accountCreated').textContent = formatDate(randomDate);
            } else {
                document.getElementById('accountCreated').textContent = formatDate(new Date(userData.created_at));
            }
            
            // Set last login to now
            document.getElementById('lastLogin').textContent = 'Today, ' + formatTime(new Date());
            
            // Check 2FA status
            const has2FA = userData.has_2fa || false;
            twoFactorToggle.checked = has2FA;
            
            // Update security status based on 2FA
            updateSecurityStatus(has2FA);
        });
    }

    if (closeProfileBtn) {
        closeProfileBtn.addEventListener('click', () => {
            profileSection.classList.remove('active');
        });
    }

    // 2FA Toggle Handler
    if (twoFactorToggle) {
        twoFactorToggle.addEventListener('change', (e) => {
            const isEnabled = e.target.checked;
            
            // Here you would typically make an API call to enable/disable 2FA
            // For now we'll just update the UI
            updateSecurityStatus(isEnabled);
            
            // Update local storage
            const userData = JSON.parse(localStorage.getItem('user') || '{}');
            userData.has_2fa = isEnabled;
            localStorage.setItem('user', JSON.stringify(userData));
            
            // Show success message (temporary alert for demo)
            alert(isEnabled ? '2FA has been enabled' : '2FA has been disabled');
        });
    }

    // Helper Functions
    function updateSecurityStatus(has2FA) {
        if (has2FA) {
            securityStatus.textContent = 'Enhanced';
            securityStatus.classList.add('enhanced');
            securityStatusText.textContent = '2FA Enabled';
        } else {
            securityStatus.textContent = 'Basic';
            securityStatus.classList.remove('enhanced');
            securityStatusText.textContent = '2FA Disabled';
        }
    }

    // Reset Password Handler (from profile)
    if (document.getElementById('resetPasswordBtn')) {
        document.getElementById('resetPasswordBtn').addEventListener('click', () => {
            const resetEmailInput = document.getElementById('reset-email');
            if (resetEmailInput) {
                resetEmailInput.value = localStorage.getItem('userEmail') || '';
            }
            
            // Set source as dashboard
            window.resetPasswordSource = "profile";
            
            showResetPasswordPage();
        });
    }

    // Delete Account Handler
    if (document.getElementById('deleteAccountBtn')) {
        document.getElementById('deleteAccountBtn').addEventListener('click', () => {
            showDeleteAccountPage();
        });
    }

    // Logout Handler
    function logout() {
        // Clear user data and token from localStorage
        localStorage.removeItem('user');
        localStorage.removeItem('token');
        localStorage.removeItem('userFullName');
        localStorage.removeItem('userEmail');
        localStorage.removeItem('accessToken');
        localStorage.removeItem('tokenType');
        
        // Clear any form data
        window.loginData = {
            email: ''
        };
        
        // Reset login forms if they exist
        const loginStep1Form = document.getElementById('loginStep1Form');
        if (loginStep1Form) loginStep1Form.reset();
        
        const loginStep2Form = document.getElementById('loginStep2Form');
        if (loginStep2Form) loginStep2Form.reset();
        
        // Show notification if function exists
        if (typeof showNotification === 'function') {
            showNotification('You have been logged out successfully', 'info');
        }
        
        // Return to main page directly using the showMainPage function
        hideAllPages();
        setTimeout(() => {
            const mainPage = document.getElementById('mainPage');
            if (mainPage) {
                mainPage.style.display = 'block';
                mainPage.style.opacity = '1';
                mainPage.style.transform = 'translateY(0)';
            }
        }, 300);
    }

 
    // Cancel Delete Button
    const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
    if (cancelDeleteBtn) {
        cancelDeleteBtn.addEventListener('click', function() {
            hideElement('deleteModal');
        });
    }

    // Close Delete Modal Button
    const closeDeleteModal = document.getElementById('closeDeleteModal');
    if (closeDeleteModal) {
        closeDeleteModal.addEventListener('click', function() {
            hideElement('deleteModal');
        });
    }

    // Cancel Verification Button
    const cancelVerificationBtn = document.getElementById('cancelVerificationBtn');
    if (cancelVerificationBtn) {
        cancelVerificationBtn.addEventListener('click', function() {
            hideElement('masterPasswordVerification');
        });
    }

    // Search Passwords
    const searchInput = document.getElementById('searchPasswords');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            filterPasswords();
        });
    }

    // Category Filter
    const categoryFilter = document.getElementById('categoryFilter');
    if (categoryFilter) {
        categoryFilter.addEventListener('change', function() {
            filterPasswords();
        });
    }

    // Sort Options
    const sortOptions = document.getElementById('sortOptions');
    if (sortOptions) {
        sortOptions.addEventListener('change', function() {
            sortPasswords();
        });
    }

    // Table Header Sorting
    const tableHeaders = document.querySelectorAll('.passwords-table th[data-sort]');
    tableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const sortBy = this.getAttribute('data-sort');
            sortPasswords(sortBy);
        });
    });

    // On dashboard load, ask for master password
    const dashboardObserver = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.target.id === 'dashboardPage' && 
                mutation.target.style.display === 'block') {
                // Check if we have passwords
                showElement('masterPasswordVerification');
            }
        });
    });

    const dashboardPage = document.getElementById('dashboardPage');
    if (dashboardPage) {
        dashboardObserver.observe(dashboardPage, { attributes: true, attributeFilter: ['style'] });
    }
});

// Add CSS for the shake animation
document.addEventListener('DOMContentLoaded', function() {
    const style = document.createElement('style');
    style.textContent = `
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
            20%, 40%, 60%, 80% { transform: translateX(5px); }
        }
    `;
    document.head.appendChild(style);
});

// Function to show input error with shake animation
function showInputError(inputElement, message) {
    inputElement.style.borderColor = '#f72585';
    inputElement.style.animation = 'shake 0.5s';
    setTimeout(() => {
        inputElement.style.animation = '';
    }, 500);
    showNotification(message, 'error');
}

// Function to show notification
function showNotification(message, type = 'info') {
    // Clear any existing notifications first
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notif => {
        notif.remove();
    });
    
    // Create new notification
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${message}</span>
            <button class="notification-close">&times;</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Add close button functionality
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', function() {
        notification.remove();
    });
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        if (document.body.contains(notification)) {
            notification.classList.add('fade-out');
            setTimeout(() => {
                if (document.body.contains(notification)) {
                    notification.remove();
                }
            }, 500);
        }
    }, 5000);
}

// Email validation function
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Function to show registration page with animation
function showRegisterPage() {
    const mainPage = document.getElementById('mainPage');
    const registerPage = document.getElementById('registerPage');
    
    hideAllPages();
    
    mainPage.style.opacity = '0';
    mainPage.style.transform = 'translateY(-10px)';
    
    setTimeout(() => {
        mainPage.style.display = 'none';
        registerPage.style.display = 'block';
        
        // Trigger reflow
        void registerPage.offsetWidth;
        
        registerPage.style.opacity = '1';
        registerPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show login page with animation
function showLoginPage() {
    const mainPage = document.getElementById('mainPage');
    const loginPage = document.getElementById('loginPage');
    
    hideAllPages();
    
    mainPage.style.opacity = '0';
    mainPage.style.transform = 'translateY(-10px)';
    
    setTimeout(() => {
        mainPage.style.display = 'none';
        loginPage.style.display = 'block';
        
        // Trigger reflow
        void loginPage.offsetWidth;
        
        loginPage.style.opacity = '1';
        loginPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show login verify page with animation
function showLoginVerifyPage() {
    const loginPage = document.getElementById('loginPage');
    const loginVerifyPage = document.getElementById('loginVerifyPage');
    
    hideAllPages();
    
    setTimeout(() => {
        loginVerifyPage.style.display = 'block';
        
        // Trigger reflow
        void loginVerifyPage.offsetWidth;
        
        loginVerifyPage.style.opacity = '1';
        loginVerifyPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show dashboard page with animation
function showDashboardPage() {
    const dashboardPage = document.getElementById('dashboardPage');
    
    // Set the user's name
    document.getElementById('userFullName').textContent = localStorage.getItem('userFullName') || 'User';
    
    hideAllPages();
    
    setTimeout(() => {
        dashboardPage.style.display = 'block';
        
        // Trigger reflow
        void dashboardPage.offsetWidth;
        
        dashboardPage.style.opacity = '1';
        dashboardPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show OTP verification page with animation
function showOtpVerificationPage() {
    const registerPage = document.getElementById('registerPage');
    const otpVerificationPage = document.getElementById('otpVerificationPage');
    
    hideAllPages();
    
    setTimeout(() => {
        otpVerificationPage.style.display = 'block';
        
        // Trigger reflow
        void otpVerificationPage.offsetWidth;
        
        otpVerificationPage.style.opacity = '1';
        otpVerificationPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show create password page with animation
function showCreatePasswordPage() {
    const otpVerificationPage = document.getElementById('otpVerificationPage');
    const createPasswordPage = document.getElementById('createPasswordPage');
    
    hideAllPages();
    
    setTimeout(() => {
        createPasswordPage.style.display = 'block';
        
        // Trigger reflow
        void createPasswordPage.offsetWidth;
        
        createPasswordPage.style.opacity = '1';
        createPasswordPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show main page with animation
function showMainPage() {
    const mainPage = document.getElementById('mainPage');
    
    hideAllPages();
    
    setTimeout(() => {
        mainPage.style.display = 'block';
        
        // Trigger reflow
        void mainPage.offsetWidth;
        
        mainPage.style.opacity = '1';
        mainPage.style.transform = 'translateY(0)';
    }, 300);
}

// Helper function to hide all pages
function hideAllPages() {
    const pages = [
        document.getElementById('mainPage'),
        document.getElementById('registerPage'),
        document.getElementById('otpVerificationPage'),
        document.getElementById('createPasswordPage'),
        document.getElementById('loginPage'),
        document.getElementById('loginVerifyPage'),
        document.getElementById('dashboardPage'),
        document.getElementById('resetPasswordPage'),
        document.getElementById('resetVerifyPage'),
        document.getElementById('deleteAccountPage'),
        document.getElementById('profilePage')
    ];
    
    pages.forEach(page => {
        if (page) {
            page.style.opacity = '0';
            page.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                page.style.display = 'none';
            }, 300);
        }
    });
}

// Add these new functions for working with authentication tokens
function getAuthHeader() {
    const token = localStorage.getItem('accessToken');
    const tokenType = localStorage.getItem('tokenType') || 'bearer';
    
    if (token) {
        return `${tokenType.charAt(0).toUpperCase() + tokenType.slice(1)} ${token}`;
    }
    return null;
}

async function fetchWithAuth(url, options = {}) {
    const authHeader = getAuthHeader();
    if (authHeader) {
        options.headers = {
            ...options.headers,
            'Authorization': authHeader
        };
    }
    return fetch(url, options);
}

// Add a profile function to test protected routes
async function getUserProfile() {
    try {
        const response = await fetchWithAuth(`${API_BASE_URL}/user-profile`);
        
        if (!response.ok) {
            if (response.status === 401) {
                // Token expired or invalid
                showNotification('Session expired. Please login again.', 'error');
                logout();
                return null;
            }
            throw new Error('Failed to fetch user profile');
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching user profile:', error);
        return null;
    }
}

// Function to show reset password page
function showResetPasswordPage() {
    const resetPasswordPage = document.getElementById('resetPasswordPage');
    
    hideAllPages();
    
    setTimeout(() => {
        resetPasswordPage.style.display = 'block';
        
        // Trigger reflow
        void resetPasswordPage.offsetWidth;
        
        resetPasswordPage.style.opacity = '1';
        resetPasswordPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show reset verify page
function showResetVerifyPage() {
    const resetVerifyPage = document.getElementById('resetVerifyPage');
    
    hideAllPages();
    
    setTimeout(() => {
        resetVerifyPage.style.display = 'block';
        
        // Trigger reflow
        void resetVerifyPage.offsetWidth;
        
        resetVerifyPage.style.opacity = '1';
        resetVerifyPage.style.transform = 'translateY(0)';
    }, 300);
}

// Function to show delete account page
function showDeleteAccountPage() {
    const deleteAccountPage = document.getElementById('deleteAccountPage');
    
    hideAllPages();
    
    setTimeout(() => {
        deleteAccountPage.style.display = 'block';
        
        // Trigger reflow
        void deleteAccountPage.offsetWidth;
        
        deleteAccountPage.style.opacity = '1';
        deleteAccountPage.style.transform = 'translateY(0)';
    }, 300);
}

// Show Profile Page Function
function showProfilePage() {
    console.log("Opening profile page");
    const profilePage = document.getElementById('profilePage');
    
    // Update profile data
    updateProfileData();
    
    // Hide all pages first
    hideAllPages();
    
    // Show profile page
    setTimeout(() => {
        profilePage.style.display = 'block';
        
        // Trigger reflow
        void profilePage.offsetWidth;
        
        profilePage.style.opacity = '1';
        profilePage.style.transform = 'translateY(0)';
    }, 300);
}

// Update Profile Data
function updateProfileData() {
    // Get user data from localStorage
    const userFullName = localStorage.getItem('userFullName') || 'User';
    const userEmail = localStorage.getItem('userEmail') || 'user@example.com';
    const userData = JSON.parse(localStorage.getItem('user') || '{}');
    
    // Set user's name and email
    document.getElementById('profileFullName').textContent = userFullName;
    document.getElementById('profileEmail').textContent = userEmail;
    
    // Set profile initials
    const initials = getInitials(userFullName);
    document.getElementById('profileInitials').textContent = initials;
    document.getElementById('userInitials').textContent = initials;
    
    // Set dummy account created date if not available
    if (!userData.created_at) {
        const randomDate = new Date();
        randomDate.setMonth(randomDate.getMonth() - Math.floor(Math.random() * 6));
        document.getElementById('accountCreated').textContent = formatDate(randomDate);
    } else {
        document.getElementById('accountCreated').textContent = formatDate(new Date(userData.created_at));
    }
    
    // Set last login to now
    document.getElementById('lastLogin').textContent = 'Today, ' + formatTime(new Date());
    
    // Check 2FA status
    const has2FA = userData.has_2fa || false;
    const twoFactorToggle = document.getElementById('twoFactorToggle');
    if (twoFactorToggle) {
        twoFactorToggle.checked = has2FA;
    }
    
    // Update security status based on 2FA
    updateSecurityStatus(has2FA);
}

// Dark Mode Toggle Handler
const darkModeToggle = document.getElementById('darkModeToggle');
if (darkModeToggle) {
    // Check for saved dark mode preference
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    darkModeToggle.checked = isDarkMode;
    if (isDarkMode) {
        document.body.classList.add('dark-mode');
    }
    

}

// Password management functions
const API_PASSWORD_URL = 'http://localhost:8000/passwords';
let currentPasswords = [];
let passwordIdBeingEdited = null;

// Toggle password visibility in modal
document.addEventListener('DOMContentLoaded', function() {
    // Toggle password visibility
    const togglePassword = document.getElementById('togglePassword');
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.innerHTML = `<svg class="eye-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 6C15.79 6 19.17 8.13 20.82 12C19.17 15.87 15.79 18 12 18C8.21 18 4.83 15.87 3.18 12C4.83 8.13 8.21 6 12 6ZM12 4C7 4 2.73 7.11 1 12C2.73 16.89 7 20 12 20C17 20 21.27 16.89 23 12C21.27 7.11 17 4 12 4ZM12 9C13.38 9 14.5 10.12 14.5 11.5C14.5 12.88 13.38 14 12 14C10.62 14 9.5 12.88 9.5 11.5C9.5 10.12 10.62 9 12 9ZM12 7C9.52 7 7.5 9.02 7.5 11.5C7.5 13.98 9.52 16 12 16C14.48 16 16.5 13.98 16.5 11.5C16.5 9.02 14.48 7 12 7Z" fill="currentColor"/>
                </svg>`;
            } else {
                passwordInput.type = 'password';
                this.innerHTML = `<svg class="eye-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 6C15.79 6 19.17 8.13 20.82 12C19.17 15.87 15.79 18 12 18C8.21 18 4.83 15.87 3.18 12C4.83 8.13 8.21 6 12 6ZM12 4C7 4 2.73 7.11 1 12C2.73 16.89 7 20 12 20C17 20 21.27 16.89 23 12C21.27 7.11 17 4 12 4ZM12 9C13.38 9 14.5 10.12 14.5 11.5C14.5 12.88 13.38 14 12 14C10.62 14 9.5 12.88 9.5 11.5C9.5 10.12 10.62 9 12 9ZM12 7C9.52 7 7.5 9.02 7.5 11.5C7.5 13.98 9.52 16 12 16C14.48 16 16.5 13.98 16.5 11.5C16.5 9.02 14.48 7 12 7Z" fill="currentColor"/>
                </svg>`;
            }
        });
    }});

    // Password validation and strength meter
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }

    // Add Password Button
    const addPasswordBtn = document.getElementById('addPasswordBtn');
    if (addPasswordBtn) {
        addPasswordBtn.addEventListener('click', function() {
            // Reset form and show modal
            passwordIdBeingEdited = null;
            document.getElementById('passwordForm').reset();
            document.getElementById('passwordModalTitle').textContent = 'Add New Password';
            document.getElementById('savePasswordBtn').textContent = 'Save Password';
            showElement('passwordModal');
            
            // Reset password strength meter
            updatePasswordStrength('');
        });
    }


// Display helpers for modals
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    }
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = ''; // Restore scrolling
    }
}

// Function to show element
function showElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        if (element.classList.contains('modal') || elementId === 'masterPasswordVerification') {
            element.style.display = 'flex';
        } else {
            element.style.display = 'block';
        }
    }
}

// Function to hide element
function hideElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = 'none';
    }
}





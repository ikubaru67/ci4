# Tutorial: Membangun CodeIgniter 4 Enterprise Application

## Pendahuluan

Tutorial ini akan memandu Anda membangun aplikasi enterprise-grade dari template dasar CodeIgniter 4. Anda akan belajar membuat sistem authentication, menambahkan security features, membuat UI modern dengan particle background, dan mengimplementasikan best practices untuk pengembangan web modern.

## Hasil Akhir yang Akan Dicapai

- ✅ Sistem login dengan role-based access (Admin/User)
- ✅ Security features (CSRF, XSS Protection, CSP Headers)
- ✅ Modern UI dengan glass morphism design
- ✅ Interactive particle background (Among Us theme)
- ✅ Responsive mobile-first design
- ✅ Component-based architecture

## Prerequisites

- PHP 8.1+
- Composer
- Web server (Apache/Nginx) atau Laragon/XAMPP
- Text editor (VS Code recommended)
- Basic knowledge PHP, HTML, CSS, JavaScript

---

## Langkah 1: Setup Proyek CodeIgniter 4

### 1.1 Install CodeIgniter 4
```bash
composer create-project codeigniter4/appstarter ci4_enterprise
cd ci4_enterprise
```

### 1.2 Konfigurasi Environment
Copy file `env` menjadi `.env`:
```bash
cp env .env
```

Edit file `.env`:
```env
CI_ENVIRONMENT = development

app.baseURL = 'http://localhost/ci4_enterprise/public/'
app.indexPage = ''

# Untuk development
app.forceGlobalSecureRequests = false
```

### 1.3 Test Setup
Akses `http://localhost/ci4_enterprise/public/` - pastikan welcome page CodeIgniter muncul.

---

## Langkah 2: Membuat Sistem Authentication

### 2.1 Buat User Model

Buat file `app/Models/UserModel.php`:
```php
<?php

namespace App\Models;

use CodeIgniter\Model;

class UserModel extends Model
{
    protected $table = 'users'; // Tidak digunakan karena static data
    
    // Static user data untuk demo
    private $users = [
        [
            'id' => 1,
            'username' => 'admin',
            'password' => 'admin123', // In production, use password_hash()
            'role' => 'admin',
            'email' => 'admin@example.com',
            'fullname' => 'Administrator'
        ],
        [
            'id' => 2,
            'username' => 'user',
            'password' => 'user123',
            'role' => 'user',
            'email' => 'user@example.com',
            'fullname' => 'Regular User'
        ]
    ];
    
    public function findUserByUsername($username)
    {
        foreach ($this->users as $user) {
            if ($user['username'] === $username) {
                return $user;
            }
        }
        return null;
    }
    
    public function verifyPassword($username, $password)
    {
        $user = $this->findUserByUsername($username);
        if ($user && $user['password'] === $password) {
            return $user;
        }
        return false;
    }
    
    public function getAllUsers()
    {
        return $this->users;
    }
}
```

### 2.2 Buat Form Controller

Buat file `app/Controllers/FormController.php`:
```php
<?php

namespace App\Controllers;

use App\Models\UserModel;

class FormController extends BaseController
{
    protected $userModel;
    
    public function __construct()
    {
        $this->userModel = new UserModel();
    }
    
    public function login()
    {
        // Jika sudah login, redirect ke dashboard
        if (session()->get('isLoggedIn')) {
            $role = session()->get('role');
            return redirect()->to('/dashboard/' . $role);
        }
        
        return view('auth/login_simple');
    }
    
    public function processLogin()
    {
        $rules = [
            'username' => 'required|min_length[3]|max_length[20]',
            'password' => 'required|min_length[6]|max_length[255]'
        ];
        
        if (!$this->validate($rules)) {
            return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
        }
        
        $username = $this->request->getPost('username');
        $password = $this->request->getPost('password');
        
        // Security: Validate input dengan regex
        if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            return redirect()->back()->with('error', 'Username mengandung karakter tidak valid');
        }
        
        // XSS Prevention
        $username = esc($username);
        $password = esc($password);
        
        $user = $this->userModel->verifyPassword($username, $password);
        
        if ($user) {
            // Set session data
            $sessionData = [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'role' => $user['role'],
                'email' => $user['email'],
                'fullname' => $user['fullname'],
                'isLoggedIn' => true
            ];
            
            session()->set($sessionData);
            
            // Redirect berdasarkan role
            return redirect()->to('/dashboard/' . $user['role'])->with('success', 'Login berhasil!');
        } else {
            return redirect()->back()->with('error', 'Username atau password salah');
        }
    }
    
    public function logout()
    {
        session()->destroy();
        return redirect()->to('/login')->with('success', 'Logout berhasil');
    }
    
    public function userDashboard()
    {
        if (!session()->get('isLoggedIn') || session()->get('role') !== 'user') {
            return redirect()->to('/login')->with('error', 'Akses ditolak');
        }
        
        return view('dashboard/user');
    }
    
    public function adminDashboard()
    {
        if (!session()->get('isLoggedIn') || session()->get('role') !== 'admin') {
            return redirect()->to('/login')->with('error', 'Akses ditolak');
        }
        
        $data['users'] = $this->userModel->getAllUsers();
        return view('dashboard/admin', $data);
    }
}
```

### 2.3 Update BaseController untuk Security Headers

Edit file `app/Controllers/BaseController.php`, tambahkan method di dalam class:
```php
    public function initController(\CodeIgniter\HTTP\RequestInterface $request, \CodeIgniter\HTTP\ResponseInterface $response, \Psr\Log\LoggerInterface $logger)
    {
        parent::initController($request, $response, $logger);
        
        // Set security headers
        $this->setSecurityHeaders();
    }
    
    protected function setSecurityHeaders()
    {
        // Prevent MIME type sniffing
        header("X-Content-Type-Options: nosniff");
        
        // Prevent clickjacking
        header("X-Frame-Options: SAMEORIGIN");
        
        // XSS Protection
        header("X-XSS-Protection: 1; mode=block");
        
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; img-src 'self' data: cdn.jsdelivr.net; font-src 'self' cdnjs.cloudflare.com; object-src 'none';");
    }
```

### 2.4 Update Routes

Edit file `app/Config/Routes.php`, ganti isi dengan:
```php
<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');

// Authentication routes
$routes->get('/login', 'FormController::login');
$routes->post('/login', 'FormController::processLogin');
$routes->get('/logout', 'FormController::logout');

// Dashboard routes
$routes->get('/dashboard/user', 'FormController::userDashboard');
$routes->get('/dashboard/admin', 'FormController::adminDashboard');

// Other routes
$routes->get('/about', 'About::index');
$routes->get('/hello/(:any)', 'Hello::index/$1');
```

---

## Langkah 3: Membuat Views dengan Modern UI

### 3.1 Buat Login View

Buat file `app/Views/auth/login_simple.php`:
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - CI4 Enterprise</title>
    
    <!-- Bootstrap 5.1.3 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome 6.0 -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- Animate.css -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            max-width: 400px;
            width: 100%;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h2 {
            color: #333;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        .form-control {
            background: rgba(255, 255, 255, 0.8);
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 10px;
            padding: 12px 15px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            background: rgba(255, 255, 255, 0.95);
            border-color: #667eea;
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px 30px;
            border-radius: 10px;
            color: white;
            font-weight: 600;
            width: 100%;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
            margin-bottom: 20px;
        }
        
        #particles-js {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
        }
        
        @media (max-width: 576px) {
            .login-card {
                padding: 30px 20px;
                margin: 10px;
            }
        }
    </style>
</head>
<body>
    <!-- Particles Background -->
    <div id="particles-js"></div>
    
    <div class="login-container">
        <div class="login-card animate__animated animate__fadeInUp">
            <div class="login-header">
                <h2><i class="fas fa-shield-alt text-primary"></i> CI4 Enterprise</h2>
                <p class="text-muted">Silakan login untuk melanjutkan</p>
            </div>
            
            <!-- Alert Messages -->
            <?php if (session()->getFlashdata('error')): ?>
                <div class="alert alert-danger alert-dismissible fade show animate__animated animate__shakeX" role="alert">
                    <i class="fas fa-exclamation-triangle"></i>
                    <?= esc(session()->getFlashdata('error')) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if (session()->getFlashdata('success')): ?>
                <div class="alert alert-success alert-dismissible fade show animate__animated animate__bounceIn" role="alert">
                    <i class="fas fa-check-circle"></i>
                    <?= esc(session()->getFlashdata('success')) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if (session()->getFlashdata('errors')): ?>
                <div class="alert alert-warning alert-dismissible fade show animate__animated animate__headShake" role="alert">
                    <i class="fas fa-exclamation-circle"></i>
                    <ul class="mb-0">
                        <?php foreach (session()->getFlashdata('errors') as $error): ?>
                            <li><?= esc($error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <!-- Login Form -->
            <?= form_open('/login', ['id' => 'loginForm']) ?>
                <div class="mb-3">
                    <label for="username" class="form-label">
                        <i class="fas fa-user"></i> Username
                    </label>
                    <input type="text" class="form-control" id="username" name="username" 
                           placeholder="Masukkan username" value="<?= old('username') ?>" required>
                </div>
                
                <div class="mb-3">
                    <label for="password" class="form-label">
                        <i class="fas fa-lock"></i> Password
                    </label>
                    <input type="password" class="form-control" id="password" name="password" 
                           placeholder="Masukkan password" required>
                </div>
                
                <button type="submit" class="btn btn-login">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            <?= form_close() ?>
            
            <!-- Demo Accounts Info -->
            <div class="mt-4 text-center">
                <small class="text-muted">
                    <strong>Demo Accounts:</strong><br>
                    Admin: admin/admin123<br>
                    User: user/user123
                </small>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <!-- tsParticles -->
    <script src="https://cdn.jsdelivr.net/npm/tsparticles@2.12.0/tsparticles.bundle.min.js"></script>
    
    <script>
        // Auto-dismiss alerts after 3 seconds
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    setTimeout(() => {
                        if (alert.parentNode) {
                            alert.remove();
                        }
                    }, 500);
                }, 3000);
            });
        });
        
        // Initialize particles background (simple version for now)
        tsParticles.load("particles-js", {
            background: {
                color: {
                    value: "transparent",
                },
            },
            fpsLimit: 120,
            particles: {
                color: {
                    value: "#ffffff",
                },
                move: {
                    direction: "none",
                    enable: true,
                    outModes: {
                        default: "bounce",
                    },
                    random: false,
                    speed: 1,
                    straight: false,
                },
                number: {
                    density: {
                        enable: true,
                        area: 800,
                    },
                    value: 50,
                },
                opacity: {
                    value: 0.3,
                },
                shape: {
                    type: "circle",
                },
                size: {
                    value: { min: 1, max: 3 },
                },
            },
            detectRetina: true,
        });
    </script>
</body>
</html>
```

### 3.2 Buat Navbar Component

Buat folder `app/Views/components/` dan file `navbar.php`:
```php
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <div class="container">
        <a class="navbar-brand" href="#">
            <i class="fas fa-shield-alt"></i> CI4 Enterprise
        </a>
        
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/">
                        <i class="fas fa-home"></i> Home
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/about">
                        <i class="fas fa-info-circle"></i> About
                    </a>
                </li>
            </ul>
            
            <ul class="navbar-nav">
                <?php if (session()->get('isLoggedIn')): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i> <?= esc(session()->get('fullname')) ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li>
                                <a class="dropdown-item" href="/dashboard/<?= session()->get('role') ?>">
                                    <i class="fas fa-tachometer-alt"></i> Dashboard
                                </a>
                            </li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <a class="dropdown-item" href="/logout">
                                    <i class="fas fa-sign-out-alt"></i> Logout
                                </a>
                            </li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="/login">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<style>
.navbar {
    background: rgba(33, 37, 41, 0.95) !important;
    backdrop-filter: blur(10px);
    box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
}

.navbar-brand {
    font-weight: 600;
    color: #fff !important;
}

.nav-link {
    transition: all 0.3s ease;
}

.nav-link:hover {
    color: #007bff !important;
    transform: translateY(-1px);
}

.dropdown-menu {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: 10px;
}
</style>
```

### 3.3 Buat Dashboard Views

Buat file `app/Views/dashboard/user.php`:
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard - CI4 Enterprise</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding-top: 80px;
        }
        
        .dashboard-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .stats-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .stats-card i {
            font-size: 3rem;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <?= view('components/navbar') ?>
    
    <div class="container">
        <div class="row">
            <div class="col-12">
                <div class="dashboard-card animate__animated animate__fadeInUp">
                    <h2><i class="fas fa-user text-primary"></i> User Dashboard</h2>
                    <p class="text-muted">Selamat datang, <?= esc(session()->get('fullname')) ?>!</p>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-4">
                <div class="stats-card animate__animated animate__fadeInLeft">
                    <i class="fas fa-user-circle"></i>
                    <h4>Profile</h4>
                    <p>Manage your profile information</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stats-card animate__animated animate__fadeInUp">
                    <i class="fas fa-chart-line"></i>
                    <h4>Statistics</h4>
                    <p>View your activity statistics</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stats-card animate__animated animate__fadeInRight">
                    <i class="fas fa-cog"></i>
                    <h4>Settings</h4>
                    <p>Configure your preferences</p>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-12">
                <div class="dashboard-card animate__animated animate__fadeInUp">
                    <h5><i class="fas fa-info-circle text-info"></i> User Information</h5>
                    <table class="table table-striped">
                        <tr>
                            <td><strong>User ID:</strong></td>
                            <td><?= esc(session()->get('user_id')) ?></td>
                        </tr>
                        <tr>
                            <td><strong>Username:</strong></td>
                            <td><?= esc(session()->get('username')) ?></td>
                        </tr>
                        <tr>
                            <td><strong>Full Name:</strong></td>
                            <td><?= esc(session()->get('fullname')) ?></td>
                        </tr>
                        <tr>
                            <td><strong>Email:</strong></td>
                            <td><?= esc(session()->get('email')) ?></td>
                        </tr>
                        <tr>
                            <td><strong>Role:</strong></td>
                            <td><span class="badge bg-primary"><?= esc(ucfirst(session()->get('role'))) ?></span></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

Buat file `app/Views/dashboard/admin.php`:
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - CI4 Enterprise</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding-top: 80px;
        }
        
        .dashboard-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .stats-card {
            background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .stats-card i {
            font-size: 3rem;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <?= view('components/navbar') ?>
    
    <div class="container">
        <div class="row">
            <div class="col-12">
                <div class="dashboard-card animate__animated animate__fadeInUp">
                    <h2><i class="fas fa-shield-alt text-danger"></i> Admin Dashboard</h2>
                    <p class="text-muted">Selamat datang, Administrator <?= esc(session()->get('fullname')) ?>!</p>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-3">
                <div class="stats-card animate__animated animate__fadeInLeft">
                    <i class="fas fa-users"></i>
                    <h4><?= count($users) ?></h4>
                    <p>Total Users</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card animate__animated animate__fadeInUp">
                    <i class="fas fa-user-shield"></i>
                    <h4>1</h4>
                    <p>Admins</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card animate__animated animate__fadeInUp">
                    <i class="fas fa-user"></i>
                    <h4>1</h4>
                    <p>Regular Users</p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card animate__animated animate__fadeInRight">
                    <i class="fas fa-check-circle"></i>
                    <h4>Active</h4>
                    <p>System Status</p>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-12">
                <div class="dashboard-card animate__animated animate__fadeInUp">
                    <h5><i class="fas fa-users text-primary"></i> User Management</h5>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Full Name</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?= esc($user['id']) ?></td>
                                    <td><?= esc($user['username']) ?></td>
                                    <td><?= esc($user['fullname']) ?></td>
                                    <td><?= esc($user['email']) ?></td>
                                    <td>
                                        <span class="badge <?= $user['role'] === 'admin' ? 'bg-danger' : 'bg-primary' ?>">
                                            <?= esc(ucfirst($user['role'])) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary">
                                            <i class="fas fa-edit"></i> Edit
                                        </button>
                                        <button class="btn btn-sm btn-outline-danger">
                                            <i class="fas fa-trash"></i> Delete
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

### 3.4 Update Home Page

Edit file `app/Views/welcome_message.php` (ganti seluruh isi):
```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CI4 Enterprise - Modern Authentication System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding-top: 80px;
        }
        
        .hero-section {
            padding: 100px 0;
            text-align: center;
            color: white;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 25px 45px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
        }
        
        .feature-card i {
            font-size: 3rem;
            color: #667eea;
            margin-bottom: 20px;
        }
        
        .btn-cta {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 15px 40px;
            border-radius: 10px;
            color: white;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
        }
        
        .btn-cta:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            color: white;
        }
    </style>
</head>
<body>
    <?= view('components/navbar') ?>
    
    <div class="hero-section">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <h1 class="display-4 animate__animated animate__fadeInDown">
                        <i class="fas fa-shield-alt"></i> CI4 Enterprise
                    </h1>
                    <p class="lead animate__animated animate__fadeInUp">
                        Modern Authentication System with Advanced Security Features
                    </p>
                    <a href="/login" class="btn-cta animate__animated animate__pulse animate__infinite">
                        <i class="fas fa-sign-in-alt"></i> Get Started
                    </a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="row">
            <div class="col-md-4">
                <div class="feature-card animate__animated animate__fadeInLeft">
                    <i class="fas fa-shield-alt"></i>
                    <h4>Advanced Security</h4>
                    <p>CSRF protection, XSS prevention, and secure headers implementation.</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="feature-card animate__animated animate__fadeInUp">
                    <i class="fas fa-mobile-alt"></i>
                    <h4>Responsive Design</h4>
                    <p>Mobile-first approach with modern glass morphism UI effects.</p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="feature-card animate__animated animate__fadeInRight">
                    <i class="fas fa-users-cog"></i>
                    <h4>Role Management</h4>
                    <p>Multi-level access control with admin and user dashboards.</p>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

---

## Langkah 4: Menambahkan Interactive Particle Background

### 4.1 Buat Struktur Folder Assets

Buat folder-folder berikut di dalam `public/`:
```
public/assets/
├── tsparticles/
│   └── amongus/
│       ├── config.js
│       ├── init.js
│       └── characters/
```

### 4.2 Buat Among Us Particle Configuration

Buat file `public/assets/tsparticles/amongus/config.js`:
```javascript
const amongUsConfig = {
    background: {
        color: {
            value: "transparent",
        },
    },
    fpsLimit: 120,
    particles: {
        color: {
            value: ["#ff0000", "#00ff00", "#0000ff", "#ffff00", "#ff00ff", "#00ffff", "#ffffff", "#000000"],
        },
        move: {
            direction: "none",
            enable: true,
            outModes: {
                default: "bounce",
            },
            random: true,
            speed: 2,
            straight: false,
        },
        number: {
            density: {
                enable: true,
                area: 800,
            },
            value: 30,
        },
        opacity: {
            value: 0.8,
        },
        shape: {
            type: "image",
            options: {
                image: [
                    {
                        src: "https://cdn.jsdelivr.net/gh/matteobruni/tsparticles@main/images/amongus_blue.png",
                        width: 32,
                        height: 32,
                    },
                    {
                        src: "https://cdn.jsdelivr.net/gh/matteobruni/tsparticles@main/images/amongus_red.png",
                        width: 32,
                        height: 32,
                    },
                    {
                        src: "https://cdn.jsdelivr.net/gh/matteobruni/tsparticles@main/images/amongus_green.png",
                        width: 32,
                        height: 32,
                    },
                ]
            }
        },
        size: {
            value: { min: 16, max: 32 },
        },
    },
    detectRetina: true,
    emitters: {
        direction: "top",
        life: {
            count: 0,
            duration: 0.1,
            delay: 0.1,
        },
        rate: {
            delay: 0.15,
            quantity: 1,
        },
        size: {
            width: 0,
            height: 0,
        },
    },
};
```

### 4.3 Buat Initialization Script

Buat file `public/assets/tsparticles/amongus/init.js`:
```javascript
function initAmongUsParticles(containerId) {
    if (typeof tsParticles !== 'undefined') {
        tsParticles.load(containerId, amongUsConfig).then((container) => {
            console.log("Among Us particles loaded successfully!");
        }).catch((error) => {
            console.error("Error loading Among Us particles:", error);
            // Fallback to simple particles
            initSimpleParticles(containerId);
        });
    } else {
        console.warn("tsParticles not loaded, using fallback");
        initSimpleParticles(containerId);
    }
}

function initSimpleParticles(containerId) {
    const simpleConfig = {
        background: {
            color: {
                value: "transparent",
            },
        },
        fpsLimit: 120,
        particles: {
            color: {
                value: "#ffffff",
            },
            move: {
                direction: "none",
                enable: true,
                outModes: {
                    default: "bounce",
                },
                random: false,
                speed: 1,
                straight: false,
            },
            number: {
                density: {
                    enable: true,
                    area: 800,
                },
                value: 50,
            },
            opacity: {
                value: 0.3,
            },
            shape: {
                type: "circle",
            },
            size: {
                value: { min: 1, max: 3 },
            },
        },
        detectRetina: true,
    };
    
    if (typeof tsParticles !== 'undefined') {
        tsParticles.load(containerId, simpleConfig);
    }
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const particlesContainer = document.getElementById('particles-js');
    if (particlesContainer) {
        // Try Among Us first, fallback to simple if needed
        if (typeof amongUsConfig !== 'undefined') {
            initAmongUsParticles('particles-js');
        } else {
            initSimpleParticles('particles-js');
        }
    }
});
```

### 4.4 Update Login View dengan Advanced Particles

Ganti bagian JavaScript di `app/Views/auth/login_simple.php` (bagian setelah tsParticles script):
```html
    <!-- Advanced Particles Scripts -->
    <script src="/assets/tsparticles/amongus/config.js"></script>
    <script src="/assets/tsparticles/amongus/init.js"></script>
    
    <script>
        // Auto-dismiss alerts after 3 seconds
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    setTimeout(() => {
                        if (alert.parentNode) {
                            alert.remove();
                        }
                    }, 500);
                }, 3000);
            });
            
            // Initialize Among Us particles
            setTimeout(() => {
                initAmongUsParticles('particles-js');
            }, 500);
        });
    </script>
```

---

## Langkah 5: Enhanced Security Implementation

### 5.1 Update Security Configuration

Edit file `app/Config/Security.php`, cari dan update:
```php
    /**
     * CSRF Token Name
     *
     * Token name for Cross Site Request Forgery protection.
     */
    public string $tokenName = 'csrf_test_name';

    /**
     * CSRF Header Name
     *
     * Header name for Cross Site Request Forgery protection.
     */
    public string $headerName = 'X-CSRF-TOKEN';

    /**
     * CSRF Cookie Name
     *
     * Cookie name for Cross Site Request Forgery protection.
     */
    public string $cookieName = 'csrf_cookie_name';

    /**
     * CSRF Expires
     *
     * Expiration time for Cross Site Request Forgery protection cookies.
     * Defaults to two hours (in seconds).
     */
    public int $expires = 7200;

    /**
     * CSRF Regenerate
     *
     * Regenerate CSRF Token on every request.
     */
    public bool $regenerate = true;
```

### 5.2 Enhanced FormController with Better Security

Update `app/Controllers/FormController.php`, tambahkan method logging:
```php
    private function logActivity($action, $username = null)
    {
        $username = $username ?? session()->get('username') ?? 'guest';
        $ip = $this->request->getIPAddress();
        $userAgent = $this->request->getUserAgent();
        
        log_message('info', "Security Log: {$action} | User: {$username} | IP: {$ip} | UserAgent: {$userAgent}");
    }
    
    public function processLogin()
    {
        // Log login attempt
        $username = $this->request->getPost('username');
        $this->logActivity('Login attempt', $username);
        
        $rules = [
            'username' => 'required|min_length[3]|max_length[20]',
            'password' => 'required|min_length[6]|max_length[255]'
        ];
        
        if (!$this->validate($rules)) {
            $this->logActivity('Login failed - validation error', $username);
            return redirect()->back()->withInput()->with('errors', $this->validator->getErrors());
        }
        
        $username = $this->request->getPost('username');
        $password = $this->request->getPost('password');
        
        // Enhanced Security: Multiple validation layers
        if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            $this->logActivity('Login failed - invalid characters', $username);
            return redirect()->back()->with('error', 'Username mengandung karakter tidak valid');
        }
        
        // Rate limiting simulation (in production, use proper rate limiting)
        $sessionKey = 'login_attempts_' . $this->request->getIPAddress();
        $attempts = session()->get($sessionKey) ?? 0;
        
        if ($attempts >= 5) {
            $this->logActivity('Login blocked - too many attempts', $username);
            return redirect()->back()->with('error', 'Terlalu banyak percobaan login. Coba lagi nanti.');
        }
        
        // XSS Prevention
        $username = esc($username);
        $password = esc($password);
        
        $user = $this->userModel->verifyPassword($username, $password);
        
        if ($user) {
            // Reset failed attempts
            session()->remove($sessionKey);
            
            // Set session data
            $sessionData = [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'role' => $user['role'],
                'email' => $user['email'],
                'fullname' => $user['fullname'],
                'isLoggedIn' => true,
                'login_time' => date('Y-m-d H:i:s')
            ];
            
            session()->set($sessionData);
            
            $this->logActivity('Login successful', $username);
            
            // Redirect berdasarkan role
            return redirect()->to('/dashboard/' . $user['role'])->with('success', 'Login berhasil!');
        } else {
            // Increment failed attempts
            session()->set($sessionKey, $attempts + 1);
            
            $this->logActivity('Login failed - invalid credentials', $username);
            return redirect()->back()->with('error', 'Username atau password salah');
        }
    }
    
    public function logout()
    {
        $username = session()->get('username');
        $this->logActivity('Logout', $username);
        
        session()->destroy();
        return redirect()->to('/login')->with('success', 'Logout berhasil');
    }
```

---

## Langkah 6: Testing dan Validasi

### 6.1 Testing Manual

**Test Authentication:**
1. Buka `http://localhost/ci4_enterprise/public/login`
2. Test dengan credentials:
   - Admin: `admin` / `admin123`
   - User: `user` / `user123`
3. Test invalid credentials untuk error handling
4. Test empty fields untuk validation

**Test Security:**
1. Test XSS: masukkan `<script>alert('xss')</script>` di form
2. Check browser console untuk error CSRF
3. Verify security headers di Network tab browser

**Test Responsive:**
1. Test di mobile view (F12 > Toggle device toolbar)
2. Test burger menu pada navbar
3. Verify glass morphism effects

### 6.2 Browser Testing

Test di berbagai browser:
- Chrome (recommended)
- Firefox
- Safari (jika di Mac)
- Edge

### 6.3 Performance Testing

Check loading times:
- CDN resources loading
- Particle animations smooth
- Page transitions responsive

---

## Langkah 7: Production Optimization

### 7.1 Environment Configuration

Update `.env` untuk production:
```env
CI_ENVIRONMENT = production

app.forceGlobalSecureRequests = true
app.CSPEnabled = true

# Database settings (jika menggunakan database)
# database.default.hostname = localhost
# database.default.database = ci4_enterprise
# database.default.username = your_username
# database.default.password = your_password
```

### 7.2 Security Hardening

**Update `app/Config/Security.php` untuk production:**
```php
    public string $csrfProtection = 'session';
    public bool $tokenRandomize = true;
    public bool $regenerate = true;
```

**Tambah Content Security Policy yang lebih ketat:**
```php
// In BaseController.php setSecurityHeaders method
header("Content-Security-Policy: default-src 'self'; script-src 'self' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; img-src 'self' data: cdn.jsdelivr.net; font-src 'self' cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self';");
```

### 7.3 Performance Optimization

**Minifikasi Assets (opsional):**
- Gunakan tools seperti webpack atau gulp
- Combine dan compress CSS/JS files
- Optimize gambar untuk web

**Caching Headers:**
```php
// Tambah di BaseController untuk static assets
header("Cache-Control: public, max-age=31536000");
```

---

## Troubleshooting Common Issues

### Issue 1: Particles Tidak Muncul
**Solusi:**
1. Check browser console untuk error JavaScript
2. Verify tsParticles CDN loaded correctly
3. Ensure config.js dan init.js accessible

### Issue 2: CSRF Token Mismatch
**Solusi:**
1. Pastikan `<?= csrf_field() ?>` ada di form
2. Check session configuration
3. Verify CSRF settings di Security.php

### Issue 3: Login Redirect Loop
**Solusi:**
1. Check session data properly set
2. Verify route configuration
3. Ensure no conflicting redirects

### Issue 4: Responsive Issues
**Solusi:**
1. Verify Bootstrap CSS loaded
2. Check viewport meta tag
3. Test media queries

---

## Deployment Guide

### Local Development (Laragon/XAMPP)
1. Copy project ke `htdocs` atau `www`
2. Set virtual host pointing to `public` folder
3. Update `.env` dengan correct baseURL

### Shared Hosting
1. Upload files to hosting
2. Point domain document root ke `public` folder
3. Update `.env` untuk production settings
4. Ensure PHP 8.1+ dan required extensions

### VPS/Dedicated Server
1. Setup web server (Apache/Nginx)
2. Configure virtual host
3. Setup SSL certificate
4. Configure proper file permissions
5. Setup logging dan monitoring

---

## Conclusion

Anda telah berhasil membangun aplikasi enterprise CodeIgniter 4 dengan fitur:

✅ **Modern Authentication System** - Login/logout dengan session management  
✅ **Advanced Security** - CSRF, XSS protection, security headers  
✅ **Beautiful UI** - Glass morphism design dengan animations  
✅ **Interactive Background** - Among Us particles dengan tsParticles  
✅ **Responsive Design** - Mobile-first approach  
✅ **Role-based Access** - Admin dan User dashboards  
✅ **Production Ready** - Logging, rate limiting, security hardening  

Aplikasi ini menggunakan best practices modern web development dengan fokus pada security, user experience, dan maintainable code architecture.

**Next Steps:**
- Implementasi database real (MySQL/PostgreSQL)
- Tambah fitur user registration
- Implementasi email verification
- Tambah two-factor authentication
- Setup automated testing
- Implementasi caching system

---

**Happy Coding! 🚀**

*Tutorial ini mendemonstrasikan pengembangan step-by-step dari template dasar CodeIgniter 4 menjadi aplikasi enterprise modern dengan fokus pada security dan user experience.*

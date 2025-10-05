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

## Langkah 2: Membuat Sistem Authentication

### 2.1 Buat User Model

Buat file `app/Models/UserModel.php`:
```php
<?php

namespace App\Models;

use CodeIgniter\Model;

/**
 * User Model - Versi Sederhana untuk Pemula
 * 
 * Model ini menggunakan static data untuk simulasi user
 * Mudah dipahami dan digunakan
 */
class UserModel extends Model
{
    // Data user sederhana - HANYA 2 ROLE: admin dan user
    private static $users = [
        [
            'id' => 1,
            'username' => 'ikubaru',
            'email' => 'admin@example.com',
            'password' => 'password',
            'role' => 'admin'
        ],
        [
            'id' => 2,
            'username' => 'ikhbal',
            'email' => 'user1@example.com',
            'password' => 'password',
            'role' => 'user'
        ],
        [
            'id' => 3,
            'username' => 'adira',
            'email' => 'user2@example.com',
            'password' => 'password',
            'role' => 'user'
        ]
    ];

    /**
     * Cek login user
     */
    public function checkLogin($username, $password)
    {
        foreach (self::$users as $user) {
            if ($user['username'] == $username && $user['password'] == $password) {
                return $user;
            }
        }
        return false;
    }

    /**
     * Ambil semua user
     */
    public function getAllUsers()
    {
        return self::$users;
    }

    /**
     * Cari user berdasarkan ID
     */
    public function getUserById($id)
    {
        foreach (self::$users as $user) {
            if ($user['id'] == $id) {
                return $user;
            }
        }
        return false;
    }
}
```

### 2.2 Buat Form Controller

Buat file `app/Controllers/FormController.php`:
```php
<?php

namespace App\Controllers;

use App\Models\UserModel;

/**
 * Form Controller - Versi Sederhana untuk Pemula
 * 
 * Controller ini menangani login, register, dan form lainnya
 * dengan cara yang sederhana dan mudah dipahami
 */
class FormController extends BaseController
{
    protected $userModel;

    public function __construct()
    {
        // Load model user
        $this->userModel = new UserModel();

        // Load helper
        helper(['form', 'url']);
    }

    /**
     * Halaman Home
     */
    public function home()
    {
        $data = [
            'title' => 'Home'
        ];

        return view('home/index', $data);
    }

    /**
     * Tampilkan halaman login
     */
    public function login()
    {
        // Jika sudah login, redirect ke dashboard
        if (session()->get('logged_in')) {
            return redirect()->to('/dashboard');
        }

        $data = [
            'title' => 'Login'
        ];

        return view('auth/login_simple', $data);
    }

    /**
     * Proses login dengan XSS Protection
     */
    public function processLogin()
    {
        // Validasi input dengan rules yang ketat
        $rules = [
            'username' => [
                'rules' => 'required|min_length[3]|max_length[20]|alpha_numeric_punct',
                'errors' => [
                    'required' => 'Username harus diisi!',
                    'min_length' => 'Username minimal 3 karakter!',
                    'max_length' => 'Username maksimal 20 karakter!',
                    'alpha_numeric_punct' => 'Username hanya boleh huruf, angka, dan underscore!'
                ]
            ],
            'password' => [
                'rules' => 'required|min_length[6]|max_length[255]',
                'errors' => [
                    'required' => 'Password harus diisi!',
                    'min_length' => 'Password minimal 6 karakter!',
                    'max_length' => 'Password terlalu panjang!'
                ]
            ]
        ];

        // Jalankan validasi
        if (!$this->validate($rules)) {
            $errors = $this->validator->getErrors();
            $errorMessage = implode(' ', $errors);
            session()->setFlashdata('error', $errorMessage);
            return redirect()->back()->withInput();
        }

        // Sanitasi input untuk mencegah XSS
        $username = strip_tags(trim($this->request->getPost('username')));
        $password = $this->request->getPost('password');

        // Validasi format username dengan regex (hanya alphanumeric dan underscore)
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            session()->setFlashdata('error', 'Username hanya boleh mengandung huruf, angka, dan underscore!');
            return redirect()->back();
        }

        // Escape untuk keamanan tambahan
        $username = esc($username, 'html');

        // Log percobaan login untuk monitoring
        log_message('info', 'Login attempt for username: ' . $username . ' from IP: ' . $this->request->getIPAddress());

        // Cek user di database (static data)
        $user = $this->userModel->checkLogin($username, $password);

        if ($user) {
            // Sanitasi data user sebelum disimpan ke session
            $sessionData = [
                'user_id' => (int) $user['id'],
                'username' => esc($user['username'], 'html'),
                'email' => esc($user['email'], 'html'),
                'role' => esc($user['role'], 'html'),
                'logged_in' => true,
                'login_time' => time()
            ];

            // Set session dengan data yang sudah di-sanitasi
            session()->set($sessionData);

            // Log successful login
            log_message('info', 'Successful login for user: ' . $username);

            session()->setFlashdata('success', 'Login berhasil! Selamat datang, ' . esc($user['username'], 'html'));

            // Redirect berdasarkan role (hanya admin dan user)
            if ($user['role'] == 'admin') {
                return redirect()->to('/admin');
            } else {
                return redirect()->to('/dashboard');
            }
        } else {
            // Log failed login
            log_message('warning', 'Failed login attempt for username: ' . $username . ' from IP: ' . $this->request->getIPAddress());
            
            session()->setFlashdata('error', 'Username atau password salah!');
            return redirect()->back();
        }
    }

    /**
     * Dashboard user biasa
     */
    public function dashboard()
    {
        // Cek apakah sudah login
        if (!session()->get('logged_in')) {
            session()->setFlashdata('error', 'Silakan login terlebih dahulu!');
            return redirect()->to('/login');
        }

        $data = [
            'title' => 'Dashboard',
            'user' => [
                'username' => session()->get('username'),
                'email' => session()->get('email'),
                'role' => session()->get('role')
            ]
        ];

        return view('dashboard/simple', $data);
    }

    /**
     * Dashboard admin
     */
    public function admin()
    {
        // Cek apakah sudah login dan role admin
        if (!session()->get('logged_in') || session()->get('role') != 'admin') {
            session()->setFlashdata('error', 'Akses ditolak! Hanya admin yang bisa mengakses halaman ini.');
            return redirect()->to('/login');
        }

        $data = [
            'title' => 'Admin Dashboard',
            'users' => $this->userModel->getAllUsers(),
            'user' => [
                'username' => session()->get('username'),
                'email' => session()->get('email'),
                'role' => session()->get('role')
            ]
        ];

        return view('dashboard/admin_simple', $data);
    }

    /**
     * Logout
     */
    public function logout()
    {
        // Hapus semua session
        session()->destroy();

        session()->setFlashdata('success', 'Logout berhasil!');
        return redirect()->to('/login');
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

// Default routes
$routes->get('/', 'FormController::home');

// Authentication Routes - ULTRA SEDERHANA
$routes->get('login', 'FormController::login');
$routes->post('login/process', 'FormController::processLogin');

// Dashboard Routes - HANYA ADMIN DAN USER
$routes->get('dashboard', 'FormController::dashboard');
$routes->get('admin', 'FormController::admin');

// Logout
$routes->get('logout', 'FormController::logout');
```

---

## Langkah 3: Membuat Views dengan Modern UI

### 3.1 Buat Login View

Buat file `app/Views/auth/login_simple.php`:
```php
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $title ?> - CI4 Simple</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- Animate.css -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <!-- Among Us Particles CSS -->
    <link href="<?= base_url('assets/tsparticles/amongus/style.css') ?>" rel="stylesheet">
    <style>
        /* Custom progress bar untuk auto-dismiss */
        .alert-progress {
            position: absolute;
            bottom: 0;
            left: 0;
            height: 3px;
            background: rgba(255,255,255,0.8);
            border-radius: 0 0 0.375rem 0.375rem;
            animation: progressBar 5s linear forwards;
        }
        
        @keyframes progressBar {
            0% { width: 100%; }
            100% { width: 0%; }
        }
        
        /* Hover effects */
        .alert:hover .alert-progress {
            animation-play-state: paused;
        }
    </style>
</head>
<body class="d-flex flex-column min-vh-100">
    <!-- Particles Background -->
    <div id="particles-js"></div>

    <?= view('components/navbar') ?>
    
    <main class="flex-grow-1 d-flex align-items-center">
        <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card hero-content">
                    <div class="card-header text-center bg-transparent border-0">
                        <h3 class="mb-0"><?= $title ?></h3>
                    </div>
                    <div class="card-body">
                        
                        <!-- Tampilkan pesan error dengan Animate.css dan XSS protection -->
                        <?php if (session()->getFlashdata('error')): ?>
                            <div id="errorAlert" class="alert alert-danger animate__animated animate__slideInDown animate__faster" role="alert">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-exclamation-triangle me-2 animate__animated animate__shakeX"></i>
                                    <span class="animate__animated animate__shakeX"><?= esc(session()->getFlashdata('error'), 'html') ?></span>
                                    <button type="button" class="btn-close ms-auto" onclick="dismissAlert('errorAlert')"></button>
                                </div>
                                <div class="alert-progress"></div>
                            </div>
                        <?php endif; ?>

                        <!-- Tampilkan pesan sukses dengan Animate.css dan XSS protection -->
                        <?php if (session()->getFlashdata('success')): ?>
                            <div id="successAlert" class="alert alert-success animate__animated animate__bounceInDown animate__faster" role="alert">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-check-circle me-2 animate__animated animate__pulse animate__infinite"></i>
                                    <span><?= esc(session()->getFlashdata('success'), 'html') ?></span>
                                    <button type="button" class="btn-close ms-auto" onclick="dismissAlert('successAlert')"></button>
                                </div>
                                <div class="alert-progress"></div>
                            </div>
                        <?php endif; ?>

                        <!-- Form Login dengan XSS Protection -->
                        <form action="<?= base_url('login/process') ?>" method="post">
                            <?= csrf_field() ?>
                            <div class="mb-3">
                                <label for="username" class="form-label">Username:</label>
                                <input type="text" name="username" id="username" 
                                       class="form-control" 
                                       required 
                                       minlength="3" 
                                       maxlength="20"
                                       pattern="[a-zA-Z0-9_]+"
                                       title="Username hanya boleh huruf, angka, dan underscore"
                                       value="<?= esc(old('username'), 'attr') ?>"
                                       autocomplete="username">
                                <div class="form-text">Gunakan huruf, angka, dan underscore saja (3-20 karakter)</div>
                            </div>
                            
                            <div class="mb-3">
                                <label for="password" class="form-label">Password:</label>
                                <input type="password" name="password" id="password" 
                                       class="form-control" 
                                       required 
                                       minlength="6" 
                                       maxlength="255"
                                       autocomplete="current-password">
                                <div class="form-text">Minimal 6 karakter</div>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login
                                </button>
                            </div>
                        </form>
                        
                        <hr>
                        
                        <!-- Link kembali ke home -->
                        <div class="text-center">
                            <a href="<?= base_url('/') ?>" class="btn btn-outline-secondary">
                                <i class="fas fa-arrow-left me-1"></i>Kembali ke Home
                            </a>
                        </div>
                        
                        <!-- Info akun demo -->
                        <div class="alert alert-info mt-3">
                            <strong>Akun Demo:</strong><br>
                            Admin: ikubaru / password<br>
                            User: ikhbal / password<br>
                            User: adira / password
                        </div>
                    </div>
                </div>
            </div>
        </div>
        </div>
    </main>

    <?= view('components/footer') ?>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript dengan Animate.css -->
    <script>
        // Auto dismiss alerts with Animate.css
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            
            alerts.forEach(function(alert) {
                // Auto dismiss after 5 seconds
                setTimeout(function() {
                    dismissAlert(alert.id);
                }, 5000);
                
                // Pause auto-dismiss on hover
                alert.addEventListener('mouseenter', function() {
                    const progressBar = this.querySelector('.alert-progress');
                    if (progressBar) {
                        progressBar.style.animationPlayState = 'paused';
                    }
                });
                
                alert.addEventListener('mouseleave', function() {
                    const progressBar = this.querySelector('.alert-progress');
                    if (progressBar) {
                        progressBar.style.animationPlayState = 'running';
                    }
                });
            });
        });
        
        // Function to dismiss alert with Animate.css
        function dismissAlert(alertId) {
            const alert = document.getElementById(alertId);
            if (alert) {
                alert.className = alert.className.replace(/animate__\\w+/g, '');
                alert.classList.add('animate__animated', 'animate__fadeOutUp', 'animate__faster');
                
                setTimeout(function() {
                    alert.remove();
                }, 600);
            }
        }
        
        // Enhanced form submission with animations
        document.querySelector('form').addEventListener('submit', function(e) {
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            
            // Add loading animation
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Logging in...';
            submitBtn.disabled = true;
            submitBtn.classList.add('animate__animated', 'animate__pulse', 'animate__infinite');
        });
    </script>

    <!-- tsParticles Library untuk Among Us -->
    <script src="https://cdn.jsdelivr.net/npm/tsparticles@2.12.0/tsparticles.bundle.min.js"></script>
    <!-- Among Us Particles Configuration -->
    <script src="<?= base_url('assets/tsparticles/amongus/config.js') ?>"></script>
</body>
</html>
```

### 3.2 Buat Navbar Component

Buat folder `app/Views/components/` dan file `navbar.php`:
```php
<!-- Navbar responsive dengan burger menu -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
        <!-- Brand -->
        <a class="navbar-brand" href="<?= base_url('/') ?>">
            <i class="fas fa-code me-2"></i>CI4 Ikubaru
        </a>
        
        <!-- Burger button untuk mobile -->
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" 
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        
        <!-- Menu items (collapsible) -->
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <?php if (session()->get('logged_in')): ?>
                    <!-- User info dengan explicit escaping -->
                    <li class="navbar-nav">
                        <span class="navbar-text me-lg-3 mb-2 mb-lg-0">
                            <i class="fas fa-user me-1"></i>
                            Halo, <strong><?= esc(session()->get('username'), 'html') ?></strong>
                            <span class="badge bg-primary ms-1"><?= esc(session()->get('role'), 'html') ?></span>
                        </span>
                    </li>
                    
                    <!-- Dashboard/Admin link -->
                    <?php if (session()->get('role') === 'admin'): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= base_url('admin') ?>">
                                <i class="fas fa-crown me-1"></i>Admin Panel
                            </a>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="<?= base_url('dashboard') ?>">
                                <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                            </a>
                        </li>
                    <?php endif; ?>
                    
                    <!-- Home link -->
                    <li class="nav-item">
                        <a class="nav-link" href="<?= base_url('/') ?>">
                            <i class="fas fa-home me-1"></i>Home
                        </a>
                    </li>
                    
                    <!-- Logout dengan confirm simple -->
                    <li class="nav-item">
                        <a class="nav-link text-warning" href="<?= base_url('logout') ?>" 
                           onclick="return confirm('Yakin ingin logout?')">
                            <i class="fas fa-sign-out-alt me-1"></i>Logout
                        </a>
                    </li>
                    
                <?php else: ?>
                    <!-- Not logged in -->
                    <li class="nav-item">
                        <a class="nav-link" href="<?= base_url('/') ?>">
                            <i class="fas fa-home me-1"></i>Home
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link text-success" href="<?= base_url('login') ?>">
                            <i class="fas fa-sign-in-alt me-1"></i>Login
                        </a>
                    </li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<!-- Custom styles untuk navbar -->
<style>
    /* Navbar improvements */
    .navbar-brand {
        font-weight: bold;
        font-size: 1.2rem;
    }
    
    .navbar-nav .nav-link {
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
        margin: 0.1rem 0.2rem;
        transition: all 0.3s ease;
    }
    
    .navbar-nav .nav-link:hover {
        background-color: rgba(255,255,255,0.1);
        transform: translateY(-2px);
    }
    
    .navbar-text {
        color: rgba(255,255,255,0.85) !important;
    }
    
    .navbar-text .badge {
        font-size: 0.65rem;
    }
    
    /* Mobile improvements */
    @media (max-width: 991.98px) {
        .navbar-collapse {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .navbar-nav .nav-item {
            margin: 0.2rem 0;
        }
        
        .navbar-text {
            display: block;
            padding: 0.5rem 1rem;
            margin-bottom: 0.5rem;
            background-color: rgba(255,255,255,0.1);
            border-radius: 0.375rem;
        }
    }
    
    /* Burger animation */
    .navbar-toggler {
        border: none;
        padding: 0.25rem 0.5rem;
    }
    
    .navbar-toggler:focus {
        box-shadow: none;
    }
    
    .navbar-toggler-icon {
        transition: transform 0.3s ease;
    }
    
    .navbar-toggler[aria-expanded="true"] .navbar-toggler-icon {
        transform: rotate(45deg);
    }
</style>

<script>
    // Auto-close navbar when clicking on links (mobile)
    document.addEventListener('DOMContentLoaded', function() {
        const navbarCollapse = document.getElementById('navbarNav');
        const navLinks = document.querySelectorAll('.nav-link');
        
        navLinks.forEach(link => {
            link.addEventListener('click', function() {
                if (window.innerWidth < 992) {
                    const bsCollapse = new bootstrap.Collapse(navbarCollapse, {
                        toggle: false
                    });
                    bsCollapse.hide();
                }
            });
        });
        
        // Add active state to current page
        const currentPath = window.location.pathname;
        navLinks.forEach(link => {
            if (link.getAttribute('href') === currentPath || 
                (currentPath.includes('admin') && link.href.includes('admin')) ||
                (currentPath.includes('dashboard') && link.href.includes('dashboard'))) {
                link.classList.add('active');
                link.style.backgroundColor = 'rgba(255,255,255,0.15)';
            }
        });
    });
</script>
```

### 3.3 Buat Dashboard Views

Buat file `app/Views/dashboard/simple.php`:
```php
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $title ?> - CI4 Simple</title>
    <!-- Bootstrap CSS sederhana -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome untuk icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- Animate.css untuk animasi -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <!-- Among Us Particles CSS -->
    <link href="<?= base_url('assets/tsparticles/amongus/style.css') ?>" rel="stylesheet">
    
    <!-- Custom CSS minimal -->
    <style>
        .alert-progress {
            position: absolute;
            bottom: 0;
            left: 0;
            height: 3px;
            background: rgba(255,255,255,0.8);
            border-radius: 0 0 0.375rem 0.375rem;
            animation: progressBar 4s linear forwards;
        }
        
        @keyframes progressBar {
            0% { width: 100%; }
            100% { width: 0%; }
        }
    </style>
</head>
<body class="d-flex flex-column min-vh-100">
    <!-- Particles Background -->
    <div id="particles-js"></div>
    
    <?= view('components/navbar') ?>

    <main class="flex-grow-1">
        <div class="container mt-4">
        <!-- Header -->
        <div class="row">
            <div class="col-12">
                <h2 class="text-white">Selamat datang, <?= esc($user['username'], 'html') ?>!</h2>
                <p class="text-white">Ini adalah dashboard untuk role: <strong><?= esc($user['role'], 'html') ?></strong></p>
            </div>
        </div>

        <!-- Tampilkan pesan dengan Animate.css -->
        <?php if (session()->getFlashdata('success')): ?>
            <div id="successAlert" class="alert alert-success animate__animated animate__bounceInDown animate__faster" role="alert">
                <div class="d-flex align-items-center">
                    <i class="fas fa-check-circle me-2 animate__animated animate__pulse animate__infinite"></i>
                    <span><?= esc(session()->getFlashdata('success'), 'html') ?></span>
                    <button type="button" class="btn-close ms-auto" onclick="dismissAlert('successAlert')"></button>
                </div>
                <div class="alert-progress"></div>
            </div>
        <?php endif; ?>

        <!-- Konten dashboard -->
        <div class="row mt-4">
            <div class="col-md-8">
                <div class="card hero-content">
                    <div class="card-header bg-transparent border-0">
                        <h5 class="mb-0">Informasi Akun</h5>
                    </div>
                    <div class="card-body">
                        <table class="table">
                            <tr>
                                <td><strong>Username:</strong></td>
                                <td><?= esc($user['username'], 'html') ?></td>
                            </tr>
                            <tr>
                                <td><strong>Email:</strong></td>
                                <td><?= esc($user['email'], 'html') ?></td>
                            </tr>
                            <tr>
                                <td><strong>Role:</strong></td>
                                <td><span class="badge bg-primary"><?= esc($user['role'], 'html') ?></span></td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card hero-content">
                    <div class="card-header bg-transparent border-0">
                        <h5 class="mb-0">Menu</h5>
                    </div>
                    <div class="card-body">
                        <div class="d-grid gap-2">
                            <a href="<?= base_url('logout') ?>" class="btn btn-outline-danger">Logout</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        </div>
    </main>

    <?= view('components/footer') ?>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- tsParticles Library untuk Among Us -->
    <script src="https://cdn.jsdelivr.net/npm/tsparticles@2.12.0/tsparticles.bundle.min.js"></script>
    <!-- Among Us Particles Configuration -->
    <script src="<?= base_url('assets/tsparticles/amongus/config.js') ?>"></script>
    
    <!-- Custom JavaScript dengan Animate.css -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            
            alerts.forEach(function(alert) {
                setTimeout(function() {
                    dismissAlert(alert.id);
                }, 4000);
            });
            
            // Add entrance animations to cards
            const cards = document.querySelectorAll('.card');
            cards.forEach((card, index) => {
                card.style.animationDelay = `${index * 0.2}s`;
                card.classList.add('animate__animated', 'animate__fadeInUp');
            });
        });
        
        function dismissAlert(alertId) {
            const alert = document.getElementById(alertId);
            if (alert) {
                alert.className = alert.className.replace(/animate__\\w+/g, '');
                alert.classList.add('animate__animated', 'animate__fadeOutUp', 'animate__faster');
                setTimeout(function() {
                    alert.remove();
                }, 600);
            }
        }
    </script>
</body>
</html>
```

### 3.4 Update Demo Accounts Information

Sesuai dengan UserModel, akun demo yang tersedia adalah:
- **Admin:** ikubaru / password
- **User:** ikhbal / password  
- **User:** adira / password

Semua password menggunakan "password" (tanpa tanda kutip).

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

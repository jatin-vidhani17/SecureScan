"""
SecureScan Recommendations Engine.
Provides detailed reasons, remediation tips, and code snippets tailored to the detected tech stack.
"""

from typing import List, Dict, Any

# Map backend/database names to recommendation keys
TECH_STACK_MAPPING = {
    "asp_net": "aspnet",
    "nodejs": "express",
    "express": "express",
    "laravel": "laravel",
    "django": "django",
    "flask": "flask",
    "php": "php",
    "react": "react",
    "wordpress": "wordpress",
}

RECOMMENDATIONS: Dict[str, Dict[str, Any]] = {
    "A01": {
        "default": {
            "reason": "Exposing directories or sensitive admin panels without authentication allows attackers to map out resources, download configuration files, or brute-force administrative interfaces.",
            "tips": [
                "Disable server directory listing (e.g., set 'Options -Indexes' in Apache or 'autoindex off' in Nginx).",
                "Restrict administrative path patterns using middleware or network firewalls.",
                "Enforce role-based access control (RBAC) checks on all server endpoints."
            ],
            "code_snippet": "# Nginx: Disable directory listing\nserver {\n    location / {\n        autoindex off;\n    }\n}"
        },
        "laravel": {
            "reason": "Exposing sensitive folders (like storage logs or artisan configurations) or not applying the 'auth' middleware on sensitive web routes allows anyone to view database configurations or application secrets.",
            "tips": [
                "Verify that the storage/ directory is not directly accessible online, and only the public/ folder is exposed as the web root.",
                "Enforce Laravel auth middleware on all administration and dashboard routes.",
                "Use Laravel Gates/Policies to enforce fine-grained access control on database records."
            ],
            "code_snippet": "// Route protection in routes/web.php\nRoute::middleware(['auth', 'can:admin-access'])->group(function () {\n    Route::get('/admin/dashboard', [AdminController::class, 'index']);\n});"
        },
        "django": {
            "reason": "Exposing the Django administration site (/admin/) to the open web without rate limiting or restricting access by IP makes it a high-value target for credential stuffing and unauthorized access.",
            "tips": [
                "Change the default '/admin/' URL to a secret custom URL inside urls.py.",
                "Use Django permissions or the @login_required and @permission_required decorators to guard views.",
                "Implement a library like django-admin-honeypot to track unauthorized dashboard access attempts."
            ],
            "code_snippet": "# urls.py - Avoid using the default '/admin/' path\nurlpatterns = [\n    path('secret-admin-portal-99/', admin.site.urls),\n]"
        },
        "express": {
            "reason": "Exposing node_modules or system files, or omitting authorization middleware from administrative endpoints, leaves Express routes vulnerable to privilege escalation.",
            "tips": [
                "Ensure only the public/dist directory is exposed via express.static.",
                "Enforce secure authentication and authorization middleware (e.g. Passport or custom RBAC middleware) on all sensitive routes.",
                "Apply rate-limiting middleware (like express-rate-limit) to admin and auth routes."
            ],
            "code_snippet": "// Protect route using Passport / Auth Middleware\napp.get('/api/admin/config', isAdminAuthenticated, (req, res) => {\n  res.json({ secret: process.env.DB_PASS });\n});"
        }
    },
    "A02": {
        "default": {
            "reason": "Missing HTTP security headers leaves browsers vulnerable to XSS injection, Clickjacking, MIME sniffing, and downgrade attacks.",
            "tips": [
                "Enable Content-Security-Policy (CSP) with restrictive directives (avoid '*' and 'unsafe-inline' where possible).",
                "Ensure Strict-Transport-Security (HSTS) is enabled with a long max-age.",
                "Enforce X-Content-Type-Options: nosniff and X-Frame-Options: DENY or SAMEORIGIN."
            ],
            "code_snippet": "# Recommended HTTP Security Headers\nContent-Security-Policy: default-src 'self'\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\nX-Content-Type-Options: nosniff\nX-Frame-Options: SAMEORIGIN"
        },
        "laravel": {
            "reason": "Standard HTTP headers like CSP, HSTS, and XCTO are missing. If not defined, browsers cannot enforce modern security boundaries against XSS or frame hijacking.",
            "tips": [
                "Install a middleware (like `spatie/laravel-csp`) to manage policies gracefully.",
                "Define custom middleware in Laravel to append security headers on every response.",
                "Ensure SSL/HTTPS settings are configured properly in config/app.php."
            ],
            "code_snippet": "// app/Http/Middleware/SecureHeaders.php\npublic function handle($request, Closure $next)\n{\n    $response = $next($request);\n    $response->headers->set('X-Content-Type-Options', 'nosniff');\n    $response->headers->set('X-Frame-Options', 'SAMEORIGIN');\n    $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');\n    return $response;\n}"
        },
        "django": {
            "reason": "Django has built-in security middlewares to set critical security headers, but they are disabled or misconfigured in settings.py.",
            "tips": [
                "Ensure `django.middleware.security.SecurityMiddleware` is active in the MIDDLEWARE list of settings.py.",
                "Enable Django HSTS settings in production settings.",
                "Add django-csp package to manage Content Security Policies dynamically."
            ],
            "code_snippet": "# settings.py security configuration\nSECURE_BROWSER_XSS_FILTER = True\nSECURE_CONTENT_TYPE_NOSNIFF = True\nSECURE_SSL_REDIRECT = True # Redirect HTTP to HTTPS\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True"
        },
        "express": {
            "reason": "Express does not set security headers by default, which exposes Node.js applications to web vulnerabilities.",
            "tips": [
                "Install the `helmet` npm package and include it in your app entrypoint.",
                "Configure helmet to use a strict Content Security Policy (CSP) customized for your frontend assets.",
                "Ensure cookies are marked with Secure, HttpOnly, and SameSite attributes."
            ],
            "code_snippet": "// App entrypoint (index.js / app.js)\nconst express = require('express');\nconst helmet = require('helmet');\nconst app = express();\n\napp.use(helmet()); // Sets nosniff, HSTS, xssFilter, frameguard, etc."
        }
    },
    "A03": {
        "default": {
            "reason": "Outdated client-side or server-side libraries often contain publicly known vulnerabilities (CVEs) that attackers can exploit to execute arbitrary code or bypass security constraints.",
            "tips": [
                "Upgrade client-side frameworks and libraries to their latest stable releases.",
                "Run periodic automated audits on dependencies (e.g. dependency check tools).",
                "Self-host dependencies rather than importing them from untrusted CDNs."
            ],
            "code_snippet": "# Audit your dependency directory\nnpm audit # for NodeJS\npip-audit # for Python"
        },
        "express": {
            "reason": "Using third-party npm modules with known security issues listed in the npm registry enables direct exploitation.",
            "tips": [
                "Run `npm audit` to check for insecure dependencies in package.json.",
                "Use `npm update` or `npm install <package>@latest` to apply patches.",
                "Integrate Dependabot or Snyk into your CI/CD pipeline to block building with compromised modules."
            ],
            "code_snippet": "# Check and fix npm security issues\nnpm audit\nnpm audit fix --force"
        }
    },
    "A04": {
        "default": {
            "reason": "Using plain HTTP allows network eavesdroppers to read or manipulate sensitive information (like credentials and session tokens). Loading HTTP content on HTTPS sites causes mixed-content warnings.",
            "tips": [
                "Redirect all HTTP traffic to HTTPS at the server configuration level.",
                "Acquire and install a valid SSL/TLS certificate (e.g., via Let's Encrypt).",
                "Ensure all media, script, and link elements load via HTTPS URLs."
            ],
            "code_snippet": "# Redirect HTTP to HTTPS in Nginx\nserver {\n    listen 80;\n    server_name example.com;\n    return 301 https://$server_name$request_uri;\n}"
        },
        "laravel": {
            "reason": "Serving your Laravel application over unencrypted HTTP exposes CSRF tokens, session IDs, and database inputs to packet sniffing.",
            "tips": [
                "Force HTTPS in production environments using Laravel's URL generator class.",
                "Configure HSTS (Strict-Transport-Security) in your environment configuration.",
                "Mark all session cookies as secure: `SESSION_SECURE_COOKIE=true` in .env."
            ],
            "code_snippet": "// App/Providers/AppServiceProvider.php\nuse Illuminate\\Support\\Facades\\URL;\n\npublic function boot()\n{\n    if (app()->environment('production')) {\n        URL::forceScheme('https');\n    }\n}"
        },
        "django": {
            "reason": "If Django is served over HTTP, session cookies and CSRF tokens are transmitted in plaintext, leaving users exposed to session hijacking.",
            "tips": [
                "Configure `SECURE_SSL_REDIRECT = True` in settings.py to force HTTPS redirects.",
                "Set cookie safety properties: `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True`.",
                "Ensure your application server uses TLS certificates."
            ],
            "code_snippet": "# settings.py configuration for HTTPS\nSECURE_SSL_REDIRECT = True\nSESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nCSRF_COOKIE_HTTPONLY = True"
        },
        "flask": {
            "reason": "Flask default development server does not support TLS. Running in production over HTTP exposes secure session cookies.",
            "tips": [
                "Deploy Flask behind an Nginx reverse proxy with TLS configurations.",
                "Use a WSGI server like Gunicorn or uWSGI and configure SSL redirects.",
                "Set `SESSION_COOKIE_SECURE = True` in the Flask app configuration."
            ],
            "code_snippet": "# flask_app.py configuration\napp.config.update(\n    SESSION_COOKIE_SECURE=True,\n    SESSION_COOKIE_HTTPONLY=True,\n    SESSION_COOKIE_SAMESITE='Lax'\n)"
        }
    },
    "A05": {
        "default": {
            "reason": "Untrusted user inputs are dynamically concatenated into database queries or reflected back in the page source without encoding, leading to SQL Injection or Cross-Site Scripting (XSS).",
            "tips": [
                "Use parameterized query bindings or ORMs instead of raw string interpolation for databases.",
                "Perform strict validation and sanitization on all incoming user parameters.",
                "Apply context-aware output encoding (like HTML entity encoding) before writing data to web documents."
            ],
            "code_snippet": "# Parameterized Database Query (Python sqlite3)\ncursor.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"
        },
        "laravel": {
            "reason": "Using raw query statements like `whereRaw()` with string interpolation, or utilizing unescaped Blade tags `{!! $variable !!}` on user input, leads to SQLi and XSS.",
            "tips": [
                "Always use standard Eloquent query builder methods which bind query parameters automatically.",
                "If writing raw queries, pass parameters as an array of arguments.",
                "Make sure all variables inside Blade templates use `{{ $variable }}` which automatically applies HTML escaping."
            ],
            "code_snippet": "// Safe SQL Eloquent query:\n$user = User::where('name', $request->name)->get();\n\n// Safe Raw Query binding:\n$results = DB::select('select * from users where id = ?', [$id]);"
        },
        "django": {
            "reason": "Direct execution of raw queries with string operations, or outputting user parameters with the `|safe` filter or `mark_safe()` in views, bypasses Django's safety checks.",
            "tips": [
                "Stick to the standard Django ORM methods (e.g. `filter()`, `exclude()`, `annotate()`).",
                "If using `cursor.execute()`, pass arguments in the execution parameters list.",
                "Avoid applying the `|safe` filter or using `mark_safe()` on untrusted input variables."
            ],
            "code_snippet": "# Safe ORM operation:\nuser = User.objects.filter(username=username).first()\n\n# Safe raw query binding:\nwith connection.cursor() as cursor:\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\", [user_id])"
        },
        "flask": {
            "reason": "String interpolation in SQL queries (via psycopg2/sqlite3), or using Jinja2 `|safe` filter on unsanitized inputs, allows remote attackers to compromise the database or inject browser scripts.",
            "tips": [
                "Implement SQLAlchemy and perform operations using standard ORM queries.",
                "Avoid using `|safe` inside Jinja templates for variables that originate from form entries or URL args.",
                "Filter and validate inputs using WTForms."
            ],
            "code_snippet": "# Safe SQLAlchemy Query:\nuser = User.query.filter_by(email=user_email).first()\n\n# Safe Parameterized SQL Query:\ndb.session.execute(text(\"SELECT * FROM users WHERE id = :id\"), {\"id\": user_id})"
        },
        "express": {
            "reason": "Using raw query string concatenation in databases (pg, mysql), or sending unescaped parameters in response HTML (or dangerouslySetInnerHTML in React), creates SQLi and XSS risks.",
            "tips": [
                "Use a trusted ORM/Query Builder like Sequelize, Prisma, or Knex.",
                "When writing raw database queries, utilize parameterized bindings (e.g., `$1` or `?`).",
                "Sanitize variables with package helpers like `escape-html` or `dompurify`."
            ],
            "code_snippet": "// Safe Parameterized Query (Node postgres):\nconst res = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);\n\n// Safe Sequelize Query:\nconst user = await User.findOne({ where: { username: inputName } });"
        },
        "php": {
            "reason": "Direct string interpolation in SQL statements (`mysqli_query` or PDO query) or echoing user inputs back to the browser without `htmlspecialchars` causes severe SQLi and XSS.",
            "tips": [
                "Utilize PDO prepared statements with `bindParam` or `execute` mappings.",
                "Encode variables before rendering them in the document using `htmlspecialchars($data, ENT_QUOTES, 'UTF-8')`.",
                "Enable PDO exception handling to avoid exposing database logs."
            ],
            "code_snippet": "<?php\n// Safe PDO statement:\n$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');\n$stmt->execute(['email' => $user_email]);\n$user = $stmt->fetch();\n\n// Safe output escaping:\necho htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');\n?>"
        },
        "react": {
            "reason": "Bypassing React's automatic string escaping mechanisms using properties like `dangerouslySetInnerHTML` allows XSS injections in your client application.",
            "tips": [
                "Avoid setting markup directly. Rely on React's standard element children rendering.",
                "If rendering markdown/HTML is required, sanitize the source payload first using `DOMPurify.sanitize(input)`.",
                "Never pass unchecked href values into standard `<a>` tags to avoid `javascript:` URI execution."
            ],
            "code_snippet": "// Safe HTML rendering in React\nimport DOMPurify from 'dompurify';\n\nconst SafeHTMLComponent = ({ untrustedHTML }) => {\n  const cleanHTML = DOMPurify.sanitize(untrustedHTML);\n  return <div dangerouslySetInnerHTML={{ __html: cleanHTML }} />;\n};"
        }
    },
    "A06": {
        "default": {
            "reason": "Exposing detailed application tracebacks, stack traces, or developer debugging outputs allows malicious actors to learn about structural components, SQL table definitions, and local source configurations.",
            "tips": [
                "Turn off application debugging flags inside production configuration files.",
                "Build standard, user-friendly error views for 404, 500, and database error conditions.",
                "Store diagnostic exceptions inside backend log systems rather than rendering them to users."
            ],
            "code_snippet": "# Configure production-safe error templates\n# Avoid exposing system stack traces"
        },
        "django": {
            "reason": "Having `DEBUG = True` in settings.py inside production environments exposes a highly detailed interactive debugger to anyone who encounters an error.",
            "tips": [
                "Set `DEBUG = False` inside settings.py for all production systems.",
                "Define custom 404 and 500 views inside your root urls.py file.",
                "Configure ALLOWED_HOSTS correctly to prevent host header injection."
            ],
            "code_snippet": "# settings.py configuration\nDEBUG = False\nALLOWED_HOSTS = ['yourdomain.com', 'api.yourdomain.com']"
        },
        "laravel": {
            "reason": "Having `APP_DEBUG=true` inside your environment file (.env) displays details of the framework codebase, configuration environment variables, and stack traces.",
            "tips": [
                "Change the env property to `APP_DEBUG=false` on production servers.",
                "Verify your `.env` file is excluded from public source repositories.",
                "Customize error rendering by editing the Exception handler in bootstrap/app.php or app/Exceptions/Handler.php."
            ],
            "code_snippet": "# .env configuration for production\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=https://yourdomain.com"
        },
        "flask": {
            "reason": "Running your Flask app in debug mode (`app.run(debug=True)`) opens an interactive python shell in the browser, allowing remote attackers to run arbitrary code on your server.",
            "tips": [
                "Never run `app.run(debug=True)` in live environments.",
                "Set the FLASK_ENV environment variable to 'production'.",
                "Implement custom error handlers using Flask's `@app.errorhandler` decorator."
            ],
            "code_snippet": "# flask_app.py production mode\n# Avoid app.run(debug=True)\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', port=5000) # Runs safely without debug shell"
        }
    },
    "A07": {
        "default": {
            "reason": "Unsecured login routes, weak session cookie attributes, or omitting CSRF verification on form submissions can lead to credential theft, session hijacking, or cross-site request forgery.",
            "tips": [
                "Implement unique CSRF tokens on all state-changing forms.",
                "Set HttpOnly, Secure, and SameSite=Lax flags on session cookies.",
                "Rate limit authentication routes to block brute-force credential inputs."
            ],
            "code_snippet": "# Example Secure Cookie attributes\nSet-Cookie: session_id=xyz123; Secure; HttpOnly; SameSite=Lax"
        },
        "laravel": {
            "reason": "Omitting the `@csrf` directive in HTML forms, or modifying middleware settings to skip CSRF validation, exposes active sessions to CSRF state-changing actions.",
            "tips": [
                "Include the `@csrf` Blade directive inside all POST, PUT, and DELETE forms.",
                "Verify that the `VerifyCsrfToken` middleware is enabled in app/Http/Kernel.php.",
                "Set secure session cookies properties inside config/session.php."
            ],
            "code_snippet": "<!-- Blade Template Form -->\n<form method=\"POST\" action=\"/update-profile\">\n    @csrf\n    <input type=\"text\" name=\"email\">\n    <button type=\"submit\">Save</button>\n</form>"
        },
        "django": {
            "reason": "Forms handling user authentication or DB writes that bypass CSRF validation (`@csrf_exempt`) are vulnerable to cross-site forgery.",
            "tips": [
                "Enable `django.middleware.csrf.CsrfViewMiddleware` inside settings.py.",
                "Include `{% csrf_token %}` within all POST form templates.",
                "Enforce rate-limiting on login views with libraries like django-ratelimit."
            ],
            "code_snippet": "<!-- Django template form -->\n<form method=\"post\" action=\"{% url 'login' %}\">\n    {% csrf_token %}\n    {{ form.as_p }}\n    <button type=\"submit\">Login</button>\n</form>"
        },
        "express": {
            "reason": "Express does not feature built-in CSRF validation, making custom state-changing API endpoints susceptible to request forgery.",
            "tips": [
                "Use a middleware package (like `csurf` or double submit cookie tokens) to handle validations.",
                "Configure your session store with secure settings (HttpOnly: true, Secure: true, SameSite: 'Lax').",
                "Adopt JSON Web Tokens (JWT) stored in HttpOnly cookies with strict domain scope."
            ],
            "code_snippet": "// App configuration with express-session\napp.use(session({\n  secret: 'app_secret_key',\n  cookie: {\n    httpOnly: true,\n    secure: true, // Requires HTTPS\n    sameSite: 'lax'\n  }\n}));"
        }
    },
    "A08": {
        "default": {
            "reason": "Loading external libraries (e.g. from CDNs) without verifying their hashes leaves your users open to attacks if the CDN is compromised and the script is altered.",
            "tips": [
                "Specify Subresource Integrity (SRI) hashes on all script/link elements loaded from external domains.",
                "Incorporate `crossorigin=\"anonymous\"` flags alongside integrity hashes.",
                "Consider downloading and hosting static assets locally on your own origin."
            ],
            "code_snippet": "<!-- Safe CDN Include with SRI -->\n<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\"\n        integrity=\"sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=\"\n        crossorigin=\"anonymous\"></script>"
        }
    },
    "A09": {
        "default": {
            "reason": "Insufficient logging of key events (authentication failures, access changes) or lack of transaction correlation headers prevents developers from detecting and diagnosing active security breaches.",
            "tips": [
                "Add request correlation tracking headers (like `X-Request-Id`) across systems.",
                "Log authentication failures, permission changes, and server validation errors.",
                "Ensure server headers hide detailed platform engine and software versions."
            ],
            "code_snippet": "# Hide Server details (Nginx configuration)\nserver_tokens off;"
        },
        "laravel": {
            "reason": "Default logging configuration does not capture enough context for security audits, or server signatures disclose software versions in headers.",
            "tips": [
                "Ensure critical security events are logged with warning/error levels (`Log::warning()`).",
                "Implement correlation IDs or add structured log contexts in middleware.",
                "Remove details in headers (avoid PHP version or server versions disclosure)."
            ],
            "code_snippet": "// app/Http/Middleware/LogSecurityEvent.php\nLog::warning('Unauthorized access attempt.', [\n    'user_id' => Auth::id(),\n    'ip' => $request->ip(),\n    'path' => $request->path()\n]);"
        },
        "django": {
            "reason": "Logging levels do not record security failures, or your deployment logs fail to structure correlation tokens.",
            "tips": [
                "Define explicit LOGGING configurations inside settings.py to log to a file or stream.",
                "Capture and log failed authentication events with user details.",
                "Hide django headers and restrict developer debugging patterns."
            ],
            "code_snippet": "# settings.py LOGGING configurations\nLOGGING = {\n    'version': 1,\n    'handlers': {\n        'file': {\n            'level': 'WARNING',\n            'class': 'logging.FileHandler',\n            'filename': '/var/log/django/security.log',\n        },\n    },\n}"
        }
    },
    "A10": {
        "default": {
            "reason": "Unhandled runtime exceptions, database connection errors, or missing catch blocks can cause application crashes or leakage of internal system details.",
            "tips": [
                "Implement global error catching middleware to capture unhandled exceptions.",
                "Never dump tracebacks or source codes in the HTTP response payload.",
                "Ensure your system responds with appropriate standard status codes (e.g. 500, 400)."
            ],
            "code_snippet": "# Safe exception handling block\ntry:\n    # execute database query\nexcept DatabaseError as e:\n    logger.error(f\"Database failed: {e}\")\n    return render_template(\"500.html\"), 500"
        },
        "laravel": {
            "reason": "Unhandled exceptions inside controllers bypass safety logic, causing Laravel to fail or present verbose details if debug configuration is enabled.",
            "tips": [
                "Use try-catch blocks around operations that interact with external services (APIs, DBs).",
                "Register dynamic error renders inside the Exception handler in bootstrap/app.php.",
                "Ensure default databases return standard error formats."
            ],
            "code_snippet": "// Safe execution in a Controller\ntry {\n    $payment = $gateway->charge($amount);\n} catch (PaymentException $e) {\n    Log::error('Payment failed: ' . $e->getMessage());\n    return redirect()->back()->withErrors('Failed to process payment.');\n}"
        },
        "django": {
            "reason": "Runtime database errors or syntax faults in views result in standard django server error blocks that could crash threads.",
            "tips": [
                "Wrap file system actions and network requests in try-except blocks.",
                "Configure production error templates (500.html) in your template paths.",
                "Ensure backend errors do not leak database schemas."
            ],
            "code_snippet": "# Safe view method\ntry:\n    data = external_api_call()\nexcept requests.RequestException as e:\n    logger.error(f\"API failed: {e}\")\n    raise Http404(\"Service temporarily unavailable\")"
        },
        "express": {
            "reason": "Unhandled promise rejections or database failures in async routes will crash the Node.js application process or leak stack traces to clients.",
            "tips": [
                "Always wrap async route handler content in try-catch structures and pass errors to next().",
                "Attach a global error-handling middleware at the bottom of your Express application routes.",
                "Listen to `unhandledRejection` and `uncaughtException` events on the Node process."
            ],
            "code_snippet": "// Safe Async Express handler\napp.post('/api/register', async (req, res, next) => {\n  try {\n    const user = await saveUser(req.body);\n    res.status(201).json(user);\n  } catch (err) {\n    next(err); // delegates to express global error handler\n  }\n});"
        }
    }
}


def enrich_owasp_results(owasp_results: List[Dict[str, Any]], tech_stack: str) -> List[Dict[str, Any]]:
    """
    Enriches the OWASP test results with framework-specific reasons, tips, and code snippets
    based on the target URL's detected tech stack.
    """
    if not tech_stack:
        tech_stack = "default"
        
    tech_key = TECH_STACK_MAPPING.get(tech_stack.lower(), "default")
    
    enriched = []
    for r in owasp_results:
        owasp_id = r.get("owasp_id")
        
        # Get category details
        category_recs = RECOMMENDATIONS.get(owasp_id, {})
        
        # Get tech-specific or fallback to default
        details = category_recs.get(tech_key, category_recs.get("default", {}))
        
        # Merge properties into result
        r_copy = dict(r)
        r_copy["reason"] = details.get("reason", "")
        r_copy["tips"] = details.get("tips", [])
        r_copy["code_snippet"] = details.get("code_snippet", "")
        
        enriched.append(r_copy)
        
    return enriched

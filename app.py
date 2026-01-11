

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import os
import time
from dotenv import load_dotenv

print("=== Flask App Initialization ===")

# # Load .env from project root
# current_dir = os.path.dirname(os.path.abspath(__file__))
# env_path = os.path.join(current_dir, '.env')

env_path = '/etc/secrets/taxcul.env'

print(f"📁 Loading .env from: {env_path}")
print(f"📁 File exists: {os.path.exists(env_path)}")

# load_dotenv(dotenv_path=env_path)

# Get API key
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

if not OPENAI_API_KEY:
    env_path = '/etc/secrets/taxcul.env'  # Your secure location
    print(f"📁 Loading .env from: {env_path}")
    print(f"📁 File exists: {os.path.exists(env_path)}")
    
    if os.path.exists(env_path):
        load_dotenv(dotenv_path=env_path)
        OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    else:
        print("❌ No .env file found")

# Verify the key
if not OPENAI_API_KEY:
    print("❌ ERROR: OPENAI_API_KEY not found in .env")
    raise ValueError("OPENAI_API_KEY missing")
else:
    print(f"✅ API Key loaded")

def create_app():
    app = Flask(__name__)
    
    # Store configuration in Flask app
    app.config.update(
        OPENAI_API_KEY=OPENAI_API_KEY,
        DEBUG=os.getenv('DEBUG', 'false').lower() == 'true',
        DATABASE_URL=os.getenv('DATABASE_URL', 'sqlite:///./local_test.db'),
        REDIS_URL=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
        # Add server configuration
        SERVER_NAME=os.getenv('SERVER_NAME', None),
        PREFERRED_URL_SCHEME=os.getenv('PREFERRED_URL_SCHEME', 'http')
    )
    
    # Enable CORS - Updated origins for production
    allowed_origins = [
        "http://localhost:3000", 
        "http://127.0.0.1:3000", 
        "https://www.taxcul.com",
        "https://api.taxculapi.com",
        "https://taxcul.com",
        "http://localhost:5000",  # For local testing
        "http://localhost:5001"   # For local testing
    ]
    
    # Add any additional origins from environment
    extra_origins = os.getenv('ALLOWED_ORIGINS', '').split(',')
    if extra_origins and extra_origins[0]:
        allowed_origins.extend([origin.strip() for origin in extra_origins])
    
    cors = CORS(app, resources={
        r"/*": {
            "origins": allowed_origins,
            "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization", "X-Elite-Client", "X-Requested-With"],
            "expose_headers": ["Content-Range", "X-Content-Range"],
            "supports_credentials": True,
            "max_age": 600
        }
    })
    
    # ============================================
    # RATE LIMITING WITH REDIS/DATABASE
    # ============================================
    print("🚀 Configuring rate limiting...")
    
    # Check if Redis is available for rate limiting
    REDIS_URL = app.config.get('REDIS_URL')
    
    if REDIS_URL and REDIS_URL.startswith('redis://'):
        print("✅ Using Redis for rate limiting")
        storage_uri = REDIS_URL
    else:
        print("⚠️ Redis not configured, using database for rate limiting")
        storage_uri = "memory://"  # Fallback to memory for now
    
    # Initialize rate limiter
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["30 per minute"],
        storage_uri=storage_uri,
        strategy="fixed-window",  # or "moving-window"
        on_breach=lambda _: jsonify({
            "error": "Rate limit exceeded. Please try again later."
        })
    )
    limiter.init_app(app)
    
    # ============================================
    # INITIALIZE DATABASE AND CACHE
    # ============================================
    print("📊 Initializing database and cache...")
    
    # Import and initialize database
    try:
        from database import db_manager
        print("✅ Database initialized")
    except Exception as e:
        print(f"⚠️ Database initialization warning: {e}")
        # Create a dummy db_manager for fallback
        class DummyDBManager:
            def count_active_sessions(self):
                return 0
            def get_analytics(self, period):
                return {}
        db_manager = DummyDBManager()
    
    # Import cache manager
    try:
        from cache_manager import cache_manager
        print(f"✅ Cache manager initialized ({cache_manager.get_stats()['cache_mode']})")
    except Exception as e:
        print(f"⚠️ Cache manager warning: {e}")
        # Create a dummy cache_manager for fallback
        class DummyCacheManager:
            def get_stats(self):
                return {'cache_mode': 'memory'}
        cache_manager = DummyCacheManager()
    
    # ============================================
    # IMPORT AND REGISTER BLUEPRINTS (ONCE!)
    # ============================================
    print("🔗 Registering blueprints...")
    
    # Import ask_route (main functionality)
    try:
        from routes.ask_route import ask_bp
        app.register_blueprint(ask_bp)
        print("   ✅ Ask routes registered")
    except Exception as e:
        print(f"   ❌ Failed to register ask routes: {e}")
    
    # Try to import analytics_route
    try:
        from routes.analytics_route import analytics_bp
        app.register_blueprint(analytics_bp)
        print("   ✅ Analytics routes registered")
    except ImportError as e:
        print(f"   ⚠️ Analytics routes not available: {e}")
    
    # Try to import admin_route
    try:
        from routes.admin_route import admin_bp
        app.register_blueprint(admin_bp)
        print("   ✅ Admin routes registered")
    except ImportError as e:
        print(f"   ⚠️ Admin routes not available: {e}")
    
    # ============================================
    # GLOBAL ERROR HANDLERS
    # ============================================
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            "error": "Rate limit exceeded",
            "message": "Please wait a minute before trying again",
            "code": 429
        }), 429
    
    @app.errorhandler(500)
    def server_error_handler(e):
        return jsonify({
            "error": "Internal server error",
            "message": "The server encountered an error processing your request",
            "code": 500
        }), 500
    
    # Handle preflight requests
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            response = jsonify({'status': 'ok'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', '*')
            response.headers.add('Access-Control-Allow-Methods', '*')
            return response
    
    # Health endpoint
    @app.route('/')
    def health():
        try:
            db_status = "connected"
            cache_stats = cache_manager.get_stats()
        except:
            db_status = "unknown"
            cache_stats = {'cache_mode': 'unknown'}
        
        return jsonify({
            'status': 'healthy',
            'service': 'TANA ELITE Tax Assistant',
            'version': '4.0.0',
            'config_loaded': bool(app.config.get('OPENAI_API_KEY')),
            'database': db_status,
            'cache': cache_stats.get('cache_mode', 'unknown'),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'port': os.getenv('PORT', 5000),
            'environment': 'production' if not app.debug else 'development'
        })
    
    # System status endpoint
    @app.route('/system-status')
    def system_status():
        try:
            analytics = db_manager.get_analytics('24h')
            active_sessions = db_manager.count_active_sessions()
            cache_stats = cache_manager.get_stats()
        except:
            analytics = {}
            active_sessions = 0
            cache_stats = {}
        
        return jsonify({
            'status': 'operational',
            'database': 'connected',
            'cache': cache_stats,
            'analytics': analytics,
            'active_sessions': active_sessions,
            'uptime': time.time() - app_start_time,
            'server_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'timezone': time.tzname
        })
    
    # Simple test endpoint
    @app.route('/test')
    def test_endpoint():
        return jsonify({
            'message': 'Server is running!',
            'server': 'Flask with Gunicorn',
            'status': 'active',
            'time': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return app

# Store app start time
app_start_time = time.time()

# Create app instance for Gunicorn
app = create_app()

if __name__ == '__main__':
    print("✅ Flask app configured successfully")
    
    # Get configuration
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print(f"🌐 Starting server on {host}:{port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🎯 Environment: {'production' if not debug else 'development'}")
    
    if debug:
        # Development server - Use Flask dev server
        app.run(debug=True, host=host, port=port, threaded=True)
    else:
        # Production server - Let Gunicorn handle it
        # This is just for running directly with python app.py in production
        # Normally you would use: gunicorn --bind 0.0.0.0:5000 app:app
        print("🚀 Production mode: Use Gunicorn to run this application")
        print("💡 Command: gunicorn --workers 3 --bind 0.0.0.0:5000 --timeout 120 app:app")
        print("📢 Starting with Flask dev server (use Gunicorn for production)")
        app.run(debug=False, host=host, port=port, threaded=True)

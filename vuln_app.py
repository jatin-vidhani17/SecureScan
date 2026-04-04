import os
from flask import Flask, request

app = Flask(__name__)

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_dummy_key_for_test")

@app.route('/')
def home():
    # Provide links so the crawler can discover the vulnerable pages
    return """
    <html>
        <head><title>Vulnerable Test Application</title></head>
        <body>
            <h1>SecureScan Dummy Vulnerable App</h1>
            <p>Welcome! This app is intentionally vulnerable for showcasing your scanner.</p>
            <ul>
                <li><a href="/sqli?id=1">Product Details (SQLi Vuln)</a></li>
                <li><a href="/xss?search=laptop">Search Products (XSS Vuln)</a></li>
                <li><a href="/about-us">About Us (Sensitive Data)</a></li>
            </ul>
        </body>
    </html>
    """

@app.route('/sqli')
def sqli():
    id_param = request.args.get('id', '')
    
    # Simulate a SQL Injection error if your scanner passes a quote '
    if "'" in id_param or '"' in id_param:
        return "Internal error: mysql error near line 1", 500
    
    return f"Product details for item #{id_param}"

@app.route('/xss')
def xss():
    search_param = request.args.get('search', '')
    
    # Simulate an XSS vulnerability by directly reflecting the search parameter
    return f"""
    <html>
        <body>
            <h2>Search Results</h2>
            <p>You searched for: {search_param}</p>
        </body>
    </html>
    """

@app.route('/about-us')
def about():
    # Simulate sensitive data exposure in the response text
    return f"""
    <html>
        <body>
            <h2>Contact Our Staff</h2>
            <p>Admin Email: admin.jatin@mycompany.com</p>
            <p>Support Phone: 9876543210</p>
            
            <!-- Dev Note: REMOVE BEFORE PRODUCTION -->
            <!-- AWS Dev Key: AKIATEST1234ABCD5678 -->
            <!-- Stripe Key: {STRIPE_SECRET_KEY} -->
        </body>
    </html>
    """

if __name__ == "__main__":
    print("Starting Vulnerable Test App on http://127.0.0.1:5001")
    app.run(port=5001, debug=True)

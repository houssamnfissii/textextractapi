from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import time
import logging
from datetime import datetime
import os
import pandas as pd

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============ Root Endpoint ============
@app.route('/')
def home():
    return jsonify({
        "message": "Welcome to TextExtract & IP Check API",
        "author": "Houssam Nfissi",
        "endpoints": {
            "/extract": {"method": "POST", "description": "Extract text from URL"},
            "/check-ips": {"method": "POST", "description": "Check IPs against blacklists"},
            "/health": {"method": "GET", "description": "Service health check"}
        },
        "note": "This service was created by Houssam Nfissi"
    })

# ============ Health Check ============
@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0",
        "maintainer": "Houssam Nfissi"
    })

# ============ Text Extraction ============
def extract_text_only(url):
    start_time = time.time()
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9'
        }

        logger.info(f"Fetching: {url}")
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()

        if 'text/html' not in response.headers.get('Content-Type', ''):
            raise ValueError("URL does not return HTML content")

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove unwanted elements
        for element in soup(['script', 'style', 'noscript', 'iframe', 'svg', 
                           'nav', 'footer', 'header', 'form', 'img', 'picture', 
                           'video', 'audio', 'canvas', 'aside', 'figure']):
            element.decompose()

        # Try to get main content first
        main_content = soup.find('main') or soup.find('article') or soup
        text = main_content.get_text(separator='\n', strip=True)
        clean_text = '\n'.join([line for line in text.split('\n') if line.strip()])

        return {
            "content": clean_text,
            "word_count": len(clean_text.split()),
            "status": "success",
            "processing_time": round(time.time() - start_time, 2),
            "url": url
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Request failed: {str(e)}",
            "status": "failed",
            "processing_time": round(time.time() - start_time, 2)
        }
    except Exception as e:
        return {
            "error": f"Processing error: {str(e)}",
            "status": "failed",
            "processing_time": round(time.time() - start_time, 2)
        }

@app.route('/extract', methods=['POST'])
def extract():
    start_time = time.time()
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                "error": "URL parameter is required",
                "status": "failed",
                "processing_time": round(time.time() - start_time, 2)
            }), 400

        url = data['url'].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result = extract_text_only(url)
        return jsonify(result), 200 if result["status"] == "success" else 400

    except Exception as e:
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "status": "failed",
            "processing_time": round(time.time() - start_time, 2)
        }), 500

# ============ IP Blacklist Check ============
def toggle_colorblind_mode(session, turn_off=True):
    try:
        mode_url = "https://www.bulkblacklist.com/toggle-colorblind-mode"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Origin': 'https://www.bulkblacklist.com',
            'Referer': 'https://www.bulkblacklist.com/'
        }
        response = session.post(mode_url, headers=headers)
        response.raise_for_status()
        if turn_off:
            session.post(mode_url, headers=headers)
        return True
    except Exception as e:
        logger.error(f"Colorblind mode toggle failed: {str(e)}")
        return False

def clean_value(text):
    text = str(text).strip()
    if not text or text == '✓':
        return 'No'
    text_lower = text.lower()
    if text_lower == 'yes':
        return 'Yes'
    if text_lower == 'no':
        return 'No'
    return text

def check_ips(ip_list):
    start_time = time.time()
    session = requests.Session()
    base_url = "https://www.bulkblacklist.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Origin': 'https://www.bulkblacklist.com',
        'Referer': 'https://www.bulkblacklist.com/'
    }

    try:
        if not toggle_colorblind_mode(session):
            logger.warning("Colorblind mode may not be disabled")

        response = session.post(
            base_url,
            data={'ips': '\n'.join(ip_list)},
            headers=headers,
            timeout=20
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', {'class': 'table'})
        if not table:
            raise ValueError("Results table not found")

        results = []
        for row in table.find_all('tr')[1:]:  # Skip header
            cells = row.find_all('td')
            if len(cells) >= 8:
                results.append({
                    'ip': cells[1].get_text(strip=True),
                    'ptr_record': cells[2].get_text(strip=True),
                    'spamcop': clean_value(cells[3].get_text()),
                    'spamhaus': clean_value(cells[4].get_text()),
                    'barracuda': clean_value(cells[5].get_text()),
                    'sender_score': cells[6].get_text(strip=True),
                    'sender_base': cells[7].get_text(strip=True),
                    'api': cells[8].get_text(strip=True) if len(cells) > 8 else 'N/A'
                })

        return {
            'status': 'success',
            'results': results,
            'ip_count': len(results),
            'processing_time': round(time.time() - start_time, 2)
        }

    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f"Network error: {str(e)}",
            'processing_time': round(time.time() - start_time, 2)
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'processing_time': round(time.time() - start_time, 2)
        }
    finally:
        session.close()

@app.route('/check-ips', methods=['POST'])
def check_ip_list():
    try:
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({
                "error": "IP list is required",
                "status": "failed"
            }), 400

        ip_list = data['ips']
        if not isinstance(ip_list, list) or len(ip_list) == 0:
            return jsonify({
                "error": "IPs must be provided as a non-empty array",
                "status": "failed"
            }), 400

        if len(ip_list) > 50:
            return jsonify({
                "error": "Maximum 50 IPs allowed per request",
                "status": "failed"
            }), 400

        result = check_ips(ip_list)
        return jsonify(result), 200 if result['status'] == 'success' else 400

    except Exception as e:
        return jsonify({
            "error": f"Internal server error: {str(e)}",
            "status": "failed"
        }), 500

# ============ Run Application ============
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)

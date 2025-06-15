from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import pandas as pd
import time
import logging
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------- Extract Text from URL -----------
def extract_text_only(url):
    start_time = time.time()
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        logger.info(f"Fetching: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        logger.info("Parsing content...")
        soup = BeautifulSoup(response.text, 'html.parser')

        # Remove unwanted elements
        for element in soup(['script', 'style', 'noscript', 'iframe', 'svg', 'nav', 'footer', 'header', 'form', 'img', 'picture', 'video', 'audio', 'canvas']):
            element.decompose()

        text_content = soup.get_text(separator='\n', strip=True)
        clean_text = '\n'.join([line for line in text_content.split('\n') if line.strip()])

        return {
            "content": clean_text,
            "word_count": len(clean_text.split()),
            "status": "success",
            "processing_time": time.time() - start_time
        }

    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "processing_time": time.time() - start_time
        }

@app.route('/extract', methods=['POST'])
def extract():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL required", "status": "failed"}), 400

    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = extract_text_only(url)
    return jsonify(result), 200 if result["status"] == "success" else 500

# ----------- Check IP Blacklists -----------
def toggle_colorblind_mode(session, headers, turn_off=True):
    try:
        mode_url = "https://www.bulkblacklist.com/toggle-colorblind-mode"
        response = session.post(mode_url, headers=headers)
        response.raise_for_status()
        if turn_off:
            response = session.post(mode_url, headers=headers)
        return True
    except Exception as e:
        logger.error(f"Error toggling colorblind mode: {str(e)}")
        return False

def clean_value(text):
    text = text.strip()
    if not text or text == '✓':
        return 'No'
    if text.lower() == 'yes':
        return 'Yes'
    if text.lower() == 'no':
        return 'No'
    return text

def check_ips(ip_list):
    base_url = "https://www.bulkblacklist.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Origin': 'https://www.bulkblacklist.com',
        'Referer': 'https://www.bulkblacklist.com/'
    }

    session = requests.Session()

    try:
        logger.info("Ensuring colorblind mode is off...")
        if not toggle_colorblind_mode(session, headers, turn_off=True):
            logger.warning("Could not verify colorblind mode status")

        ips_text = "\n".join(ip_list)
        form_data = {'ips': ips_text}

        logger.info(f"Submitting {len(ip_list)} IPs for checking...")
        response = session.post(base_url, data=form_data, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', {'class': 'table'})
        if not table:
            raise ValueError("Results table not found")

        rows = table.find_all('tr')
        if len(rows) < 2:
            raise ValueError("No data rows found")

        results = []
        for row in rows[1:]:
            cells = row.find_all('td')
            if len(cells) >= 8:
                row_data = {
                    'index': cells[0].get_text(strip=True),
                    'ip': cells[1].get_text(strip=True),
                    'ptr_record': cells[2].get_text(strip=True),
                    'spamcop': clean_value(cells[3].get_text()),
                    'spamhaus': clean_value(cells[4].get_text()),
                    'barracuda': clean_value(cells[5].get_text()),
                    'sender_score': cells[6].get_text(strip=True),
                    'sender_base': cells[7].get_text(strip=True),
                    'api': cells[8].get_text(strip=True) if len(cells) > 8 else 'N/A'
                }
                results.append(row_data)

        return {
            'status': 'success',
            'results': results,
            'ip_count': len(results)
        }

    except Exception as e:
        logger.error(f"Error processing IPs: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        session.close()

@app.route('/check-ips', methods=['POST'])
def check_ip_list():
    start_time = time.time()
    try:
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({
                'status': 'error',
                'message': 'IP list required',
                'processing_time': time.time() - start_time
            }), 400

        ip_list = data['ips']
        if not isinstance(ip_list, list):
            return jsonify({
                'status': 'error',
                'message': 'IPs must be provided as an array',
                'processing_time': time.time() - start_time
            }), 400

        if len(ip_list) == 0:
            return jsonify({
                'status': 'error',
                'message': 'No IP addresses provided',
                'processing_time': time.time() - start_time
            }), 400

        result = check_ips(ip_list)
        result['processing_time'] = time.time() - start_time

        status_code = 200 if result['status'] == 'success' else 500
        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Unexpected error in /check-ips: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'processing_time': time.time() - start_time
        }), 500

# ========================
# New Root Endpoint
# ========================
@app.route('/')
def home():
    return jsonify({
        "message": "Welcome to the API Service",
        "description": "This service provides text extraction and IP blacklist checking functionality",
        "endpoints": {
            "/extract": "POST - Extract text from a URL",
            "/check-ips": "POST - Check IPs against blacklists",
            "/health": "GET - Service health check"
        },
        "author": "Houssam Nfissi",
        "note": "This IP checking service was created by Houssam Nfissi"
    })

# ========================
# Updated Health Check Endpoint
# ========================
@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "maintained_by": "Houssam Nfissi",
        "timestamp": datetime.utcnow().isoformat()
    })

# ----------- Run the App -----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)

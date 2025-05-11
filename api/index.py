from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import time
import logging
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_text_only(url):
    start_time = time.time()
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        logger.info(f"Fetching: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raises exception for 4XX/5XX errors

        logger.info("Parsing content...")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove unwanted elements
        for element in soup(['script', 'style', 'noscript', 'iframe', 
                           'svg', 'nav', 'footer', 'header', 'form',
                           'img', 'picture', 'video', 'audio', 'canvas']):
            element.decompose()
        
        # Get clean text
        text_content = soup.get_text(separator='\n', strip=True)
        
        # Additional cleaning
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

@app.route("/health")
def health():
    return jsonify({"health": "good"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)

# TextExtract & IP Check API

## Features
- Extract clean text from web pages
- Check IPs against multiple blacklists
- Simple REST API interface

## Endpoints
- `GET /` - API documentation
- `GET /health` - Service health check
- `POST /extract` - Extract text from URL
- `POST /check-ips` - Check IP reputation

## Deployment
Deployed on Vercel: [https://textextractapi.vercel.app](https://textextractapi.vercel.app)

## Local Development
```bash
pip install -r requirements.txt
python api/index.py

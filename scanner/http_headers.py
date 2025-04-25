import requests

def analyze_headers(url):
    try:
        response = requests.get(url, timeout=15)
        return dict(response.headers)
    except Exception as e :
        return {"error": str(e)}
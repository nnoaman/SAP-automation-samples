import requests
import html
import re
from urllib.parse import urlparse

url = 'https://softwaredownloads.sap.com/file/0020000000488622025'
username = 'test_user'
password = 'test_password'

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
res = session.get(url, allow_redirects=True)
print(f"Step 1: {res.status_code} {res.url[:80]}...")

if 'document.forms[0].submit()' in res.text:
    print("Found JS redirect form...")
    action_match = re.search(r'action="([^"]+)"', res.text, re.IGNORECASE)
    if action_match:
        action_url = html.unescape(action_match.group(1))
        if action_url.startswith('/'):
            action_url = f"https://{urlparse(res.url).netloc}{action_url}"
        
        payload = {}
        for m in re.finditer(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', res.text, re.IGNORECASE):
            payload[html.unescape(m.group(1))] = html.unescape(m.group(2))
        
        print(f"Posting to {action_url[:80]}...")
        # Mock the credentials submission 
        payload['j_username'] = username
        payload['j_password'] = password
        
        res = session.post(action_url, data=payload)
        print(f"Step 2: {res.status_code} {res.url[:80]}...")


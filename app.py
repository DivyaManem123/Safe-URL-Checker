from flask import Flask, render_template, request
import pickle
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
import re
import socket

app = Flask(__name__)

# Load trained model
with open('model.pkl', 'rb') as f:
    catboost_model = pickle.load(f)

suspicious_keywords = [
    "free", "win", "password", "Limited", "lottery", "invest", "sale", "Limited-access",
    "prize", "reward", "bonus", "claim", "urgent", "verify", "login", "signin", "reset",
    "account", "update", "unlock", "secure", "paypal", "amazon", "apple", "microsoft",
    "bank", "tax", "offer", "gift", "cash", "money", "bitcoin", "crypto", "credentials",
    "blocked", "deactivate", "suspended", "support", "helpdesk", "confirm", "official",
    "user", "info", "details", "authenticate", "session", "token", "redirect", "click-here",
    "signin-page", "download", "plugin", "promo", "congratulations", "jackpot", "customer",
    "service", "grand", "lucky", "zip", "exe", "app", "fast", "hot", "try"
]

safe_links = {
    "paypal": "https://www.paypal.com",
    "amazon": "https://www.amazon.in",
    "microsoft": "https://www.microsoft.com",
    "google": "https://www.google.com",
    "apple": "https://www.apple.com",
    "bankofamerica": "https://www.bankofamerica.com",
    "facebook": "https://www.facebook.com"
}

def getLength(url):
    return 0 if len(url) < 54 else 1

def getDomain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    domain = urlparse(url).netloc
    return domain.replace("www.", "") if domain.startswith("www.") else domain

def get_domain_age(url):
    domain = getDomain(url)
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return 1
        age_in_months = (datetime.now() - creation_date).days // 30
        return 0 if age_in_months > 6 else 1
    except Exception:
        return 1

def get_domain_end_period(url):
    domain = getDomain(url)
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date is None:
            return 1
        remaining_months = (expiration_date - datetime.now()).days // 30
        return 0 if remaining_months >= 6 else 1
    except Exception:
        return 1

def check_dns_records(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def check_whois_data(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info.creation_date is not None and domain_info.registrar is not None
    except Exception:
        return False

def is_phishing(url):
    domain = getDomain(url)
    return 0 if check_dns_records(domain) and check_whois_data(domain) else 1

def check_empty_title(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            return 1 if title_tag is None or not title_tag.text.strip() else 0
        return 1
    except Exception:
        return 1

def haveAtSign(url):
    return 1 if "@" in url else 0

def getDepth(url):
    return len([segment for segment in urlparse(url).path.split('/') if segment])

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def tld_in_subdomain(url):
    ext = tldextract.extract(url)
    return 1 if ext.suffix in ext.subdomain else 0

def iframe(response):
    if not response:
        return 1
    return 0 if re.findall(r"[|]", response.text) else 1

def forwarding(response):
    if not response:
        return 1
    return 0 if len(response.history) <= 2 else 1

def get_safe_link(url):
    for keyword in safe_links:
        if keyword.lower() in url.lower():
            return safe_links[keyword]
    return None

def analyze_webpage_content(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return None
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = ' '.join([tag.get_text() for tag in soup.find_all(['p', 'span', 'a', 'title', 'meta'])])
        detected_keywords = [word for word in suspicious_keywords if word.lower() in text_content.lower()]
        suspicious_links = []
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if any(keyword in href.lower() for keyword in suspicious_keywords):
                suspicious_links.append(href)
        return {
            "suspicious keywords found": detected_keywords,
            "suspicious links": suspicious_links,
        }
    except Exception:
        return None

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form["url"]

    # Extract features
    features = {
        'URL_Length': getLength(url),
        'Domain_Age': get_domain_age(url),
        'Domain_end_period': get_domain_end_period(url),
        'dns_records': is_phishing(url),
        'empty_title': check_empty_title(url),
        'Have_At': haveAtSign(url),
        'URL_Depth': getDepth(url),
        'Prefix/Suffix': prefixSuffix(url),
        'tld_in_subdomain': tld_in_subdomain(url)
    }

    try:
        response = requests.get(url, timeout=10)
    except:
        response = None

    features['iFrame'] = iframe(response)
    features['Web_Forwards'] = forwarding(response)

    feature_order = ['URL_Length', 'Domain_Age', 'Domain_end_period', 'dns_records', 'empty_title',
                     'Have_At', 'URL_Depth', 'Prefix/Suffix', 'tld_in_subdomain', 'iFrame', 'Web_Forwards']

    feature_df = pd.DataFrame([[features[feature] for feature in feature_order]], columns=feature_order)
    prediction = catboost_model.predict(feature_df)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"

    analysis_result = analyze_webpage_content(url) or {}

    return render_template("index.html",
                           url=url,
                           result=result,
                           keywords=analysis_result.get("suspicious keywords found", []),
                           suspicious_links=analysis_result.get("suspicious links", []),
                           safe_suggestion=get_safe_link(url))

if __name__ == "__main__":
    app.run(debug=True)

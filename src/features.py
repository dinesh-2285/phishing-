import re
from urllib.parse import urlparse
import tldextract
import numpy as np

class FeatureExtractor:
    def __init__(self):
        # List of known shortening services
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                                   r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                                   r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                                   r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                                   r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                                   r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                                   r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                                   r"tr\.im|link\.zip\.net"

    def extract_features(self, url: str) -> list:
        """
        Extracts a feature vector from a URL string.
        Returns a list of numerical features.
        """
        features = []
        
        # 1. Using IP Address in URL
        features.append(self._having_ip_address(url))
        
        # 2. Length of URL
        features.append(self._url_length(url))
        
        # 3. Using Shortening Service
        features.append(self._shortening_service(url))
        
        # 4. Having '@' symbol
        features.append(1 if '@' in url else 0)
        
        # 5. Double slash redirect
        features.append(1 if url.rfind('//') > 7 else 0)
        
        # 6. Prefix/Suffix in domain (e.g. "google-login.com")
        features.append(self._prefix_suffix(url))
        
        # 7. Sub-domain and Multi-sub-domains
        features.append(self._sub_domains(url))
        
        # 8. HTTPS token in domain part
        features.append(self._https_token(url))

        return features

    def _having_ip_address(self, url):
        # Regex for IPv4 and IPv6
        ip_pattern = (
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' # IPv4 in Hex
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}' # IPv6
        )
        match = re.search(ip_pattern, url)
        return 1 if match else 0

    def _url_length(self, url):
        if len(url) < 54:
            return 0 # Legitimate
        elif len(url) >= 54 and len(url) <= 75:
            return 1 # Suspicious
        else:
            return 2 # Phishing

    def _shortening_service(self, url):
        match = re.search(self.shortening_services, url)
        return 1 if match else 0

    def _prefix_suffix(self, url):
        domain = urlparse(url).netloc
        return 1 if '-' in domain else 0

    def _sub_domains(self, url):
        ext = tldextract.extract(url)
        subdomain = ext.subdomain
        if subdomain.count('.') == 0:
            return 0 # Legitimate
        elif subdomain.count('.') == 1:
            return 1 # Suspicious
        else:
            return 2 # Phishing

    def _https_token(self, url):
        domain = urlparse(url).netloc
        return 1 if 'https' in domain else 0

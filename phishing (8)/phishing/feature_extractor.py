"""
Feature Extraction Module for Malicious Domain Detection
Extracts 30 features from a URL for the ML model
"""

import re
import socket
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
import time

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns.resolver = None


class FeatureExtractor:
    def __init__(self):
        self.features = {}
        
    def extract_features(self, url):
        """
        Extract all 30 features from the given URL
        Returns a list of 30 feature values
        """
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path.split('/')[0]
            
            # Extract all features
            self.features = {
                'UsingIP': self.using_ip(domain),
                'LongURL': self.long_url(url),
                'ShortURL': self.short_url(url),
                'Symbol@': self.symbol_at(url),
                'Redirecting//': self.redirecting(url),
                'PrefixSuffix-': self.prefix_suffix(domain),
                'SubDomains': self.sub_domains(domain),
                'HTTPS': self.https(url),
                'DomainRegLen': self.domain_reg_len(domain),
                'Favicon': self.favicon(url),
                'NonStdPort': self.non_std_port(parsed_url),
                'HTTPSDomainURL': self.https_domain_url(url, domain),
                'RequestURL': self.request_url(url),
                'AnchorURL': self.anchor_url(url),
                'LinksInScriptTags': self.links_in_script_tags(url),
                'ServerFormHandler': self.server_form_handler(url),
                'InfoEmail': self.info_email(url),
                'AbnormalURL': self.abnormal_url(url, domain),
                'WebsiteForwarding': self.website_forwarding(url),
                'StatusBarCust': self.status_bar_cust(url),
                'DisableRightClick': self.disable_right_click(url),
                'UsingPopupWindow': self.using_popup_window(url),
                'IframeRedirection': self.iframe_redirection(url),
                'AgeofDomain': self.age_of_domain(domain),
                'DNSRecording': self.dns_recording(domain),
                'WebsiteTraffic': self.website_traffic(domain),
                'PageRank': self.page_rank(domain),
                'GoogleIndex': self.google_index(url),
                'LinksPointingToPage': self.links_pointing_to_page(url),
                'StatsReport': self.stats_report(url)
            }
            
            # Return features in the correct order
            feature_order = [
                'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
                'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
                'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
                'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
                'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
                'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
                'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
            ]
            
            return [self.features[feat] for feat in feature_order]
            
        except Exception as e:
            # Return default values if extraction fails
            return [-1] * 30
    
    def using_ip(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain.replace('www.', ''))
            return 1
        except:
            return -1
    
    def long_url(self, url):
        """Check if URL is long (>75 characters)"""
        return 1 if len(url) > 75 else (-1 if len(url) < 54 else 0)
    
    def short_url(self, url):
        """Check if URL is a shortened URL"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        return 1 if any(shortener in url.lower() for shortener in shorteners) else -1
    
    def symbol_at(self, url):
        """Check if @ symbol exists in URL"""
        return 1 if '@' in url else -1
    
    def redirecting(self, url):
        """Check for redirecting (//)"""
        return 1 if url.count('//') > 1 else -1
    
    def prefix_suffix(self, domain):
        """Check if domain has prefix or suffix with hyphen"""
        return 1 if '-' in domain else -1
    
    def sub_domains(self, domain):
        """Count subdomains"""
        subdomain_count = domain.count('.')
        if subdomain_count == 1:
            return -1
        elif subdomain_count == 2:
            return 0
        else:
            return 1
    
    def https(self, url):
        """Check if HTTPS is used"""
        return 1 if url.startswith('https://') else -1
    
    def domain_reg_len(self, domain):
        """Check domain registration length"""
        domain_name = domain.replace('www.', '').split('.')[0]
        if len(domain_name) < 6:
            return 1
        elif len(domain_name) < 10:
            return 0
        else:
            return -1
    
    def favicon(self, url):
        """Check if favicon is from same domain"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'favicon' in response.text.lower():
                return -1
            return 1
        except:
            return 0
    
    def non_std_port(self, parsed_url):
        """Check for non-standard port"""
        if parsed_url.port:
            if parsed_url.port not in [80, 443]:
                return 1
        return -1
    
    def https_domain_url(self, url, domain):
        """Check if HTTPS is in domain URL"""
        return 1 if 'https' in domain.lower() else -1
    
    def request_url(self, url):
        """Check request URL"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                return -1
            return 1
        except:
            return 0
    
    def anchor_url(self, url):
        """Check anchor URL"""
        return 1 if '#' in url else -1
    
    def links_in_script_tags(self, url):
        """Check links in script tags"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if '<script' in response.text.lower() and 'href' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def server_form_handler(self, url):
        """Check server form handler"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'form' in response.text.lower() and 'action' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def info_email(self, url):
        """Check if email is in URL"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return 1 if re.search(email_pattern, url) else -1
    
    def abnormal_url(self, url, domain):
        """Check for abnormal URL"""
        try:
            if whois is None:
                return 0
            whois_info = whois.whois(domain)
            if whois_info.domain_name:
                return -1
            return 1
        except:
            return 0
    
    def website_forwarding(self, url):
        """Check website forwarding"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [301, 302, 303, 307, 308]:
                return 1
            return -1
        except:
            return 0
    
    def status_bar_cust(self, url):
        """Check status bar customization"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'onmouseover' in response.text.lower() or 'status' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def disable_right_click(self, url):
        """Check if right click is disabled"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'contextmenu' in response.text.lower() or 'ondragstart' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def using_popup_window(self, url):
        """Check for popup windows"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'popup' in response.text.lower() or 'window.open' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def iframe_redirection(self, url):
        """Check for iframe redirection"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if '<iframe' in response.text.lower():
                return 1
            return -1
        except:
            return 0
    
    def age_of_domain(self, domain):
        """Check age of domain"""
        try:
            if whois is None:
                return 0
            whois_info = whois.whois(domain)
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                
                if isinstance(creation_date, datetime):
                    age = (datetime.now() - creation_date).days
                    if age < 365:
                        return 1
                    elif age < 730:
                        return 0
                    else:
                        return -1
            return 0
        except:
            return 0
    
    def dns_recording(self, domain):
        """Check DNS recording"""
        try:
            socket.gethostbyname(domain)
            return -1
        except:
            return 1
    
    def website_traffic(self, domain):
        """Check website traffic (simplified)"""
        # This is a simplified check - in real scenario, you'd use APIs
        try:
            response = requests.get(f'http://{domain}', timeout=5)
            if response.status_code == 200:
                return -1
            return 1
        except:
            return 0
    
    def page_rank(self, domain):
        """Check PageRank (simplified)"""
        # This is a simplified check - in real scenario, you'd use PageRank API
        return 0
    
    def google_index(self, url):
        """Check if URL is indexed by Google"""
        # This is a simplified check - in real scenario, you'd use Google Search API
        return 0
    
    def links_pointing_to_page(self, url):
        """Check links pointing to page"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            link_count = response.text.lower().count('href=')
            if link_count == 0:
                return 1
            elif link_count < 2:
                return 0
            else:
                return -1
        except:
            return 0
    
    def stats_report(self, url):
        """Check stats report"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if 'stat' in response.text.lower() or 'analytics' in response.text.lower():
                return -1
            return 1
        except:
            return 0


import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import json
from colorama import init, Fore, Style
import ssl
import socket
import dns.resolver
import cssutils
import jsbeautifier

# Initialize colorama for colored console output
init(autoreset=True)

class WebTechDetector:
    def __init__(self):
        self.technologies = {
            "WordPress": {
                "html": ["wp-content", "wp-includes"],
                "meta": {"generator": "WordPress"},
                "admin_path": "/wp-admin/"
            },
            "Joomla": {
                "html": ["/components/com_", "/modules/mod_"],
                "meta": {"generator": "Joomla"},
                "admin_path": "/administrator/"
            },
            "Drupal": {
                "html": ["sites/all", "drupal.js"],
                "meta": {"generator": "Drupal"},
                "admin_path": "/user/login"
            },
            "Bootstrap": {
                "html": ['class="container"', 'class="row"'],
                "css": ["bootstrap.min.css", "bootstrap.css"]
            },
            "jQuery": {
                "js": ["jquery.js", "jquery.min.js"]
            },
            "React": {
                "js": ["react.js", "react.min.js"],
                "html": ["data-reactroot", "react-app"]
            },
            "Angular": {
                "html": ["ng-app", "ng-controller"]
            },
            "Vue.js": {
                "html": ["v-app", "v-bind"]
            },
            "Magento": {
                "html": ["Mage.Cookies", "magento"],
                "admin_path": "/admin/"
            },
            "Shopify": {
                "html": ["Shopify.shop", "/cdn.shopify.com/"],
                "js": ["shopify.js"]
            },
            "WooCommerce": {
                "html": ["woocommerce", "wc-"],
                "css": ["woocommerce.css"]
            },
            "AWS": {
                "headers": {"Server": "AmazonS3"}
            },
            "Azure": {
                "headers": {"Server": "Microsoft-IIS"}
            },
            "Cloudflare": {
                "headers": {"Server": "cloudflare"}
            },
            "Tailwind CSS": {
                "html": ["class=\"", "lg:", "md:", "sm:"]
            },
            "Foundation": {
                "html": ["class=\"row\"", "class=\"column\""]
            }
        }

    def detect(self, url):
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            detected = []
            
            # HTML content check
            html_content = response.text.lower()
            for tech, indicators in self.technologies.items():
                if "html" in indicators:
                    if any(ind.lower() in html_content for ind in indicators["html"]):
                        detected.append(tech)
            
            # Meta tags check
            meta_tags = soup.find_all("meta")
            for tag in meta_tags:
                if tag.get("name") == "generator":
                    content = tag.get("content", "").lower()
                    for tech, indicators in self.technologies.items():
                        if "meta" in indicators and "generator" in indicators["meta"]:
                            if indicators["meta"]["generator"].lower() in content:
                                detected.append(tech)
            
            # JavaScript files check
            scripts = soup.find_all("script", src=True)
            for script in scripts:
                src = script["src"].lower()
                for tech, indicators in self.technologies.items():
                    if "js" in indicators:
                        if any(ind.lower() in src for ind in indicators["js"]):
                            detected.append(tech)
            
            # CSS files check
            stylesheets = soup.find_all("link", rel="stylesheet")
            for stylesheet in stylesheets:
                href = stylesheet.get("href", "").lower()
                for tech, indicators in self.technologies.items():
                    if "css" in indicators:
                        if any(ind.lower() in href for ind in indicators["css"]):
                            detected.append(tech)
            
            # Headers check
            for tech, indicators in self.technologies.items():
                if "headers" in indicators:
                    for header, value in indicators["headers"].items():
                        if header in response.headers and value.lower() in response.headers[header].lower():
                            detected.append(tech)

            # New detection methods
            detected.extend(self.detect_server_side_tech(response))
            detected.extend(self.detect_cms_specific(url))
            detected.extend(self.detect_ecommerce(soup, response.text))
            detected.extend(self.detect_security_features(response))
            detected.extend(self.analyze_ssl_tls(url))
            detected.extend(self.detect_cdn(response))
            detected.extend(self.analyze_dns(url))
            detected.extend(self.detect_social_media(soup))
            detected.extend(self.detect_image_tech(soup))
            detected.extend(self.detect_accessibility(soup))
            detected.extend(self.detect_mobile_optimization(soup))
            detected.extend(self.detect_privacy_tools(soup))
            detected.extend(self.detect_analytics(soup, response.text))
            detected.extend(self.detect_fonts(soup))
            
            # Remove duplicates
            detected = list(set(detected))
            
            return detected
        
        except requests.RequestException as e:
            print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
            return []

    def detect_server_side_tech(self, response):
        detected = []
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            if 'PHP' in headers['X-Powered-By']:
                detected.append(f"PHP {headers['X-Powered-By'].split('/')[1]}")
            elif 'ASP.NET' in headers['X-Powered-By']:
                detected.append("ASP.NET")
        
        if 'Server' in headers:
            if 'nginx' in headers['Server'].lower():
                detected.append("Nginx")
            elif 'apache' in headers['Server'].lower():
                detected.append("Apache")
        
        return detected

    def detect_cms_specific(self, url):
        detected = []
        for cms, indicators in self.technologies.items():
            if "admin_path" in indicators:
                admin_url = url.rstrip('/') + indicators["admin_path"]
                try:
                    response = requests.get(admin_url, timeout=5)
                    if response.status_code == 200:
                        detected.append(f"{cms} (Admin page found)")
                except:
                    pass
        return detected

    def detect_ecommerce(self, soup, html_content):
        detected = []
        if 'checkout' in html_content.lower() or 'cart' in html_content.lower():
            detected.append("E-commerce functionality")
        if 'Shopify.shop' in html_content:
            detected.append("Shopify")
        return detected

    def detect_security_features(self, response):
        detected = []
        headers = response.headers
        if 'Content-Security-Policy' in headers:
            detected.append("Content Security Policy")
        if 'X-XSS-Protection' in headers:
            detected.append("XSS Protection")
        if 'X-Frame-Options' in headers:
            detected.append("Clickjacking Protection")
        return detected

    def analyze_ssl_tls(self, url):
        detected = []
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    detected.append(f"SSL/TLS: {secure_sock.version()}")
                    detected.append(f"Certificate Issuer: {cert['issuer'][1][0][1]}")
        except:
            detected.append("SSL/TLS: Unable to analyze")
        return detected

    def detect_cdn(self, response):
        detected = []
        cdn_headers = ['X-CDN', 'X-EdgeConnect-MidMile-RTT', 'X-Akamai-Transformed']
        for header in cdn_headers:
            if header in response.headers:
                detected.append("CDN Detected")
                break
        return detected

    def analyze_dns(self, url):
        detected = []
        domain = urlparse(url).netloc
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            detected.append(f"Email Provider: {mx_records[0].exchange}")
        except:
            pass
        return detected

    def detect_social_media(self, soup):
        detected = []
        social_patterns = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
        for pattern in social_patterns:
            if soup.find('a', href=re.compile(pattern)):
                detected.append(f"{pattern.split('.')[0].capitalize()} integration")
        if soup.find('meta', property='og:title') or soup.find('meta', property='twitter:card'):
            detected.append("Social Media Metadata")
        return detected

    def detect_image_tech(self, soup):
        detected = []
        if soup.find('img', loading='lazy'):
            detected.append("Lazy Loading Images")
        image_formats = ['webp', 'avif']
        for img in soup.find_all('img', src=True):
            for format in image_formats:
                if img['src'].lower().endswith(f'.{format}'):
                    detected.append(f"{format.upper()} Image Format")
        return detected

    def detect_accessibility(self, soup):
        detected = []
        if soup.find(attrs={'aria-label': True}) or soup.find(attrs={'role': True}):
            detected.append("ARIA attributes (Accessibility)")
        return detected

    def detect_mobile_optimization(self, soup):
        detected = []
        if soup.find('meta', attrs={'name': 'viewport'}):
            detected.append("Responsive Design")
        return detected

    def detect_privacy_tools(self, soup):
        detected = []
        privacy_patterns = ['gdpr', 'ccpa', 'cookie consent']
        for pattern in privacy_patterns:
            if pattern in soup.text.lower():
                detected.append(f"{pattern.upper()} Compliance Tool")
        return detected

    def detect_analytics(self, soup, html_content):
        detected = []
        analytics_patterns = {
            'Google Analytics': 'google-analytics.com/analytics.js',
            'Google Tag Manager': 'googletagmanager.com/gtm.js',
            'Hotjar': 'static.hotjar.com',
            'Mixpanel': 'cdn.mxpnl.com'
        }
        for tool, pattern in analytics_patterns.items():
            if pattern in html_content:
                detected.append(tool)
        return detected

    def detect_fonts(self, soup):
        detected = []
        if soup.find('link', href=re.compile('fonts.googleapis.com')):
            detected.append("Google Fonts")
        if soup.find('link', href=re.compile('use.typekit.net')):
            detected.append("Adobe Typekit")
        return detected

def main():
    detector = WebTechDetector()
    
    print(f"{Fore.CYAN}{Style.BRIGHT}╔════════════════════════════════════════╗")
    print(f"║ {Fore.WHITE}Welcome to the Enhanced Web Tech Detector!{Fore.CYAN}║")
    print(f"╚════════════════════════════════════════╝{Style.RESET_ALL}")
    
    while True:
        url = input(f"\n{Fore.MAGENTA}Enter a URL to analyze (or 'quit' to exit): {Fore.WHITE}")
        
        if url.lower() == 'quit':
            break
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{Fore.YELLOW}Analyzing {url}... Please wait.{Style.RESET_ALL}")
        
        technologies = detector.detect(url)
        
        if technologies:
            print(f"\n{Fore.GREEN}Detected technologies and features:{Style.RESET_ALL}")
            for tech in technologies:
                print(f"  {Fore.CYAN}• {tech}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}No technologies detected or unable to analyze the website.{Style.RESET_ALL}")
        
        print("\n" + "="*50)

    print(f"\n{Fore.CYAN}Thank you for using the Enhanced Web Tech Detector!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

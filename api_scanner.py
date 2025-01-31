import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import concurrent.futures
import json
from datetime import datetime
import time
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ▄▀█ █▀█ █ █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█                 ║
    ║     █▀█ █▀▀ █ ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄                 ║
    ║                                                               ║
    ║           API Endpoint Scanner and Analyzer v1.0             ║
    ║        Created for Security Research and Testing             ║
    ║                                                              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

class APIScanner:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        self.discovered_endpoints = set()
        self.results = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        self.session = requests.Session()
        self.timeout = 10
        self.common_endpoints = [
            # Аутентификация и пользователи
            '/api/auth',
            '/api/login',
            '/api/logout',
            '/api/register',
            '/api/signup',
            '/api/users',
            '/api/users/create',
            '/api/users/delete',
            '/api/users/update',
            '/api/user/profile',
            '/api/password/reset',
            '/api/password/forgot',
            '/api/token',
            '/api/refresh-token',
            '/oauth/token',
            '/oauth/authorize',

            # Версионные API endpoints
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/v1/api',
            '/v2/api',
            '/v3/api',
            '/rest/v1',
            '/rest/v2',
            '/graphql',
            '/graphiql',

            # Документация API
            '/swagger/v1/swagger.json',
            '/swagger/v2/swagger.json',
            '/swagger-ui.html',
            '/swagger-ui',
            '/api-docs',
            '/api/docs',
            '/api/swagger',
            '/api/swagger.json',
            '/openapi.json',
            '/openapi/v2/api-docs',
            '/v1/api-docs',
            '/v2/api-docs',
            '/swagger-resources',

            # Админ панели
            '/api/admin',
            '/api/admin/users',
            '/api/admin/settings',
            '/api/dashboard',
            '/api/stats',
            '/api/metrics',
            '/api/monitoring',

            # Данные и контент
            '/api/data',
            '/api/content',
            '/api/posts',
            '/api/articles',
            '/api/products',
            '/api/categories',
            '/api/tags',
            '/api/search',
            '/api/comments',
            '/api/media',
            '/api/images',
            '/api/files',
            '/api/upload',
            '/api/download',

            # Настройки и конфигурация
            '/api/settings',
            '/api/config',
            '/api/configuration',
            '/api/preferences',
            '/api/options',

            # Уведомления и сообщения
            '/api/notifications',
            '/api/messages',
            '/api/email',
            '/api/sms',
            '/api/push',

            # Платежи и транзакции
            '/api/payments',
            '/api/transactions',
            '/api/orders',
            '/api/checkout',
            '/api/cart',
            '/api/billing',
            '/api/subscriptions',

            # Мобильные API
            '/api/mobile',
            '/api/mobile/auth',
            '/api/app',
            '/api/app/version',
            '/api/device',

            # Аналитика
            '/api/analytics',
            '/api/tracking',
            '/api/events',
            '/api/logs',
            '/api/errors',

            # Интеграции
            '/api/webhook',
            '/api/callback',
            '/api/integration',
            '/api/external',
            '/api/sync',

            # Безопасность
            '/api/security',
            '/api/permissions',
            '/api/roles',
            '/api/access',

            # Дополнительные endpoints
            '/api/health',
            '/api/status',
            '/api/ping',
            '/api/test',
            '/api/debug',
            '/api/cache',
            '/api/batch',
            '/api/bulk',
            '/api/export',
            '/api/import',
            
            # Специфичные бизнес-endpoints
            '/api/customers',
            '/api/suppliers',
            '/api/inventory',
            '/api/shipping',
            '/api/reports',
            '/api/feedback',
            '/api/reviews',
            '/api/locations',
            '/api/departments',
            '/api/employees',
            '/api/projects',
            '/api/tasks',
            
            # Социальные функции
            '/api/social',
            '/api/friends',
            '/api/followers',
            '/api/feed',
            '/api/activities',
            '/api/likes',
            '/api/shares',
            
            # Геолокация
            '/api/locations',
            '/api/maps',
            '/api/geocoding',
            '/api/places',
            
            # Чаты и сообщения
            '/api/chat',
            '/api/conversations',
            '/api/messages/send',
            '/api/messages/receive',
            
            # Календарь и события
            '/api/calendar',
            '/api/events',
            '/api/scheduling',
            '/api/bookings',
            
            # Поиск и фильтрация
            '/api/search',
            '/api/filter',
            '/api/sort',
            '/api/query',
            
            # Уведомления
            '/api/notifications/push',
            '/api/notifications/email',
            '/api/notifications/sms',
            '/api/alerts',
            
            # Отчеты
            '/api/reports/generate',
            '/api/reports/download',
            '/api/statistics',
            '/api/analytics/data',
            
            # Дополнительные сервисные endpoints
            '/api/service-status',
            '/api/maintenance',
            '/api/backup',
            '/api/restore',
            '/api/migrate',
            '/api/optimize',
            
            # Мультимедиа
            '/api/media/upload',
            '/api/media/download',
            '/api/images/resize',
            '/api/videos/stream',
            '/api/audio/stream',
            
            # Кэширование
            '/api/cache/clear',
            '/api/cache/status',
            '/api/cache/refresh',
            
            # Языки и локализация
            '/api/languages',
            '/api/translations',
            '/api/locales',
            
            # Шаблоны
            '/api/templates',
            '/api/themes',
            '/api/layouts',
            
            # Валидация
            '/api/validate',
            '/api/verify',
            '/api/check',
            
            # Интеграции с соцсетями
            '/api/social/facebook',
            '/api/social/twitter',
            '/api/social/google',
            '/api/social/linkedin',
            
            # Специфические API endpoints
            '/wp-json',
            '/wp-json/wp/v2',
            '/jsonapi',
            '/api/jsonapi',
            '/api/rest',
            '/api/soap',
            '/api/xml',
        ]

    def make_request(self, url, method='GET'):
        try:
            response = self.session.request(method, url, headers=self.headers, timeout=self.timeout, verify=False)
            return response
        except requests.exceptions.RequestException:
            return None

    def find_js_files(self):
        try:
            response = self.make_request(self.target_url)
            if not response:
                return []
            
            soup = BeautifulSoup(response.text, 'html.parser')
            js_files = []
            
            for script in soup.find_all('script', src=True):
                js_url = script.get('src')
                if js_url:
                    full_url = urljoin(self.target_url, js_url)
                    js_files.append(full_url)
            
            return js_files
        except Exception as e:
            print(f"Error finding JS files: {str(e)}")
            return []

    def extract_endpoints(self, content):
        patterns = [
            r'/api/[a-zA-Z0-9-_/]+',
            r'/v[0-9]+/[a-zA-Z0-9-_/]+',
            r'(?<=["\'])(/[a-zA-Z0-9-_/]+)(?=["\'])',
            r'https?://[^"\'\s]+api[^"\'\s]*'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(0)
                endpoints.add(endpoint)
        return endpoints

    def test_endpoint(self, endpoint):
        if endpoint.startswith(('http://', 'https://')):
            url = endpoint
        else:
            url = urljoin(self.target_url, endpoint)
        
        try:
            start_time = time.time()
            response = self.make_request(url)
            response_time = time.time() - start_time
            
            if response:
                result = {
                    'endpoint': endpoint,
                    'full_url': url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'response_time': f"{response_time:.2f}s",
                    'response_size': len(response.content),
                    'accessible': 200 <= response.status_code < 400
                }
            else:
                result = {
                    'endpoint': endpoint,
                    'full_url': url,
                    'status_code': 'Connection Failed',
                    'content_type': 'Unknown',
                    'response_time': 'N/A',
                    'response_size': 0,
                    'accessible': False
                }
            return result
        except Exception as e:
            return {
                'endpoint': endpoint,
                'full_url': url,
                'status_code': f'Error: {str(e)}',
                'content_type': 'Unknown',
                'response_time': 'N/A',
                'response_size': 0,
                'accessible': False
            }

    def scan(self):
        print(f"\n[+] Starting scan of {self.target_url}")
        print("[+] Searching for JavaScript files...")
        
        js_files = self.find_js_files()
        print(f"[+] Found {len(js_files)} JavaScript files")

        for js_url in js_files:
            print(f"[+] Analyzing: {js_url}")
            response = self.make_request(js_url)
            if response:
                endpoints = self.extract_endpoints(response.text)
                self.discovered_endpoints.update(endpoints)

        self.discovered_endpoints.update(self.common_endpoints)

        print(f"\n[+] Testing {len(self.discovered_endpoints)} discovered endpoints")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_endpoint = {executor.submit(self.test_endpoint, endpoint): endpoint 
                                for endpoint in self.discovered_endpoints}
            
            for future in concurrent.futures.as_completed(future_to_endpoint):
                result = future.result()
                self.results.append(result)
                status = result['status_code']
                if isinstance(status, int) and 200 <= status < 400:
                    print(f"\033[92m[+] Found: {result['endpoint']} - Status: {status}\033[0m")  # Зеленый для успешных
                else:
                    print(f"[+] Tested: {result['endpoint']} - Status: {status}")

    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"api_scan_{urlparse(self.target_url).netloc}_{timestamp}.json"
        
        report = {
            'target_url': self.target_url,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_endpoints_found': len(self.discovered_endpoints),
            'results': sorted(self.results, key=lambda x: (not x['accessible'], x['endpoint']))
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        
        print(f"\n[+] Results saved to {filename}")
        
        # Вывод статистики
        accessible_endpoints = len([r for r in self.results if r['accessible']])
        print(f"\n[+] Scan Statistics:")
        print(f"    - Total endpoints tested: {len(self.results)}")
        print(f"    - Accessible endpoints: {accessible_endpoints}")
        print(f"    - Inaccessible endpoints: {len(self.results) - accessible_endpoints}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python api_scanner.py <target_url>")
        sys.exit(1)

    print_banner()
    target_url = sys.argv[1]
    scanner = APIScanner(target_url)
    
    try:
        scanner.scan()
        scanner.save_results()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.save_results()
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")

if __name__ == "__main__":
    main()
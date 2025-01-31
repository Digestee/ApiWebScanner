# 🔍 API Scanner and Analyzer v1.0 

## 🎯 Description
A tool for scanning and analyzing API endpoints, designed for security research and testing purposes. Features parallel scanning, JavaScript file analysis, endpoint discovery, and comprehensive security testing capabilities. Includes automated endpoint detection, response analysis, and detailed reporting in JSON format.

## ✨ Features
- 🚀 Fast concurrent endpoint scanning
- 📝 JavaScript file analysis for endpoint discovery
- 🎯 Comprehensive pre-defined API endpoint list
- 📊 Detailed response analysis
- 💾 JSON report generation
- 🔄 Real-time status updates
- 🛡️ Support for both HTTP and HTTPS
- ⚡ Multi-threaded execution

## 🛠️ Requirements
```python
requests
beautifulsoup4
urllib3
```

## 📦 Installation
```bash
git clone https://github.com/Digestee/ApiWebScanner.git
cd ApiWebScanner
pip install -r requirements.txt
```

## 🚀 Usage
```bash
python api_scanner.py <target_url>
```
Example:
```bash
python api_scanner.py example.com
```

## 📊 Output
The tool generates a JSON report containing:
- 🎯 Target URL information
- ⏰ Scan timestamp
- 📝 Total endpoints discovered
- 📊 Detailed results for each endpoint:
  - Status code
  - Content type
  - Response time
  - Response size
  - Accessibility status

## 🔍 Scanning Features
- 🌐 Automatic JavaScript file discovery
- 📡 Endpoint extraction from JS files
- ✅ Common API endpoint testing
- 🔄 Concurrent request handling
- 📊 Response analysis
- 💡 Smart URL parsing and joining

## 🛡️ Security Note
This tool is intended for security research and testing purposes only. Always ensure you have proper authorization before scanning any target.

## 📝 Report Format
```json
{
    "target_url": "example.com",
    "scan_time": "2024-01-31 12:00:00",
    "total_endpoints_found": 100,
    "results": [
        {
            "endpoint": "/api/v1/example",
            "status_code": 200,
            "content_type": "application/json",
            "response_time": "0.2s",
            "accessible": true
        }
    ]
}
```

## ⚠️ Disclaimer
Use this tool responsibly and only on systems you have permission to test.

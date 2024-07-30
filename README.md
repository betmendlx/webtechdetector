# Enhanced Web Tech Detector

The Enhanced Web Tech Detector is a Python script that analyzes websites and detects various web technologies, frameworks, libraries, and features being used. It provides a comprehensive overview of the technical stack and best practices implemented on a given website.

## Features

- Detects popular Content Management Systems (CMS) like WordPress, Joomla, and Drupal
- Identifies JavaScript frameworks and libraries (React, Angular, Vue.js, jQuery)
- Recognizes e-commerce platforms and functionality
- Analyzes server-side technologies
- Checks for security features and SSL/TLS configurations
- Detects Content Delivery Network (CDN) usage
- Analyzes DNS configurations, including email providers
- Identifies social media integrations and metadata
- Recognizes image optimization techniques and modern formats
- Checks for accessibility features (ARIA attributes)
- Detects mobile optimization and responsive design
- Identifies privacy compliance tools (GDPR, CCPA, etc.)
- Recognizes various analytics and tracking tools
- Identifies web font services

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/betmendlx/enhanced-web-tech-detector.git
   cd enhanced-web-tech-detector
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the script using Python:

```
python enhanced_webtechdetector.py
```

When prompted, enter the URL of the website you want to analyze. The script will display the detected technologies and features.

## Example Output

```
╔════════════════════════════════════════╗
║ Welcome to the Enhanced Web Tech Detector!║
╚════════════════════════════════════════╝

Enter a URL to analyze (or 'quit' to exit): https://example.com

Analyzing https://example.com... Please wait.

Detected technologies and features:
  • WordPress
  • PHP 7.4
  • Nginx
  • Google Analytics
  • Responsive Design
  • SSL/TLS: TLSv1.3
  • Certificate Issuer: Let's Encrypt
  • GDPR Compliance Tool
  • Lazy Loading Images
  • Google Fonts

==================================================
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

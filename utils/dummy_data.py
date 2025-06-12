import csv
import random

# List of benign URLs
benign_urls = [
    "http://example.com/home",
    "https://shopping.com/products?category=books",
    "http://newsportal.com/article?id=4523",
    "https://edu-site.org/login?user=student&pass=1234",
    "http://weatherinfo.com/today?location=delhi",
    "https://profile.social.com/view?user=john_doe",
    "http://docs.site.com/download?file=report.pdf",
]

# List of SQL Injection payload URLs
sqli_urls = [
    "http://example.com/login?username=admin'--&password=",
    "http://example.com/items?id=10 OR 1=1",
    "http://example.com/search?q=test'%20OR%20'1'%20=%20'1",
    "http://site.com/auth?user=' OR 1=1 --",
    "http://bank.com/transfer?amount=1000&to=1234; DROP TABLE users;",
]

# List of XSS payload URLs
xss_urls = [
    "http://victim.com/search?q=<script>alert('XSS')</script>",
    "http://shop.com/?input=%3Cscript%3Ealert('x')%3C%2Fscript%3E",
    "http://comments.com/post?id=5&comment=<img src=x onerror=alert('x')>",
    "http://site.com?q=<body onload=alert('xss')>",
    "http://page.com/?value=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
]

# Generate final dataset
all_urls = []
for url in benign_urls:
    all_urls.append((url, 0))
for url in sqli_urls + xss_urls:
    all_urls.append((url, 1))

# Optional: add more noise
random.shuffle(all_urls)

# Save to CSV
csv_file = "sample_http.csv"
with open(csv_file, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    writer.writerows(all_urls)

print(f"✅ Dummy dataset saved to: {csv_file}")

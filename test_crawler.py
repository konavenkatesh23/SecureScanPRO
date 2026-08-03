from scanner.crawler import crawl_website

urls = crawl_website("https://www.python.org")

print("\n===== SecureScanPRO Crawler =====\n")

for url in urls:
    print(url)

print("\nTotal URLs:", len(urls))
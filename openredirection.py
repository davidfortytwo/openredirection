import argparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.parse import urlparse
from webdriver_manager.chrome import ChromeDriverManager

def check_open_redirection(target):
    options = Options()
    options.add_argument("--headless")  # Ensure GUI is off
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Use webdriver_manager to manage the Chrome driver
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)

    # Open the target URL
    driver.get(target)

    # Extract the domain from the target URL
    target_domain = urlparse(target).netloc

    # Check if we've been redirected to a different domain
    if urlparse(driver.current_url).netloc != target_domain:
        print(f"Potential open redirection detected: {driver.current_url}")

    driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for potential DOM-based open redirection.')
    parser.add_argument('-t', '--target', type=str, required=True, help='The target URL.')

    args = parser.parse_args()

    check_open_redirection(args.target)

import logging
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VScanner/2.0)"}


def _same_domain(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def get_links(target_url: str, scan_config: dict | None = None, use_selenium: bool = False) -> list[str]:
    if use_selenium:
        return _get_links_selenium(target_url, scan_config or {})
    return _get_links_requests(target_url, scan_config or {})


def _get_links_requests(target_url: str, scan_config: dict) -> list[str]:
    timeout = scan_config.get("timeout", 5)
    try:
        response = requests.get(target_url, timeout=timeout, headers=_HEADERS)
        soup = BeautifulSoup(response.text, "html.parser")
        links: set[str] = set()
        for a in soup.find_all("a", href=True):
            absolute = urljoin(target_url, a["href"])
            if _same_domain(absolute, target_url) and absolute.startswith("http"):
                links.add(absolute)
        log.info("Discovered %d links via requests", len(links))
        return list(links)
    except requests.exceptions.RequestException as exc:
        log.warning("Link discovery failed: %s", exc)
        return []


def _get_links_selenium(target_url: str, scan_config: dict) -> list[str]:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError:
        log.warning("Selenium not available; falling back to requests-based discovery.")
        return _get_links_requests(target_url, scan_config)

    driver = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--log-level=3")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument(f"user-agent={_HEADERS['User-Agent']}")

        driver = webdriver.Chrome(
            service=ChromeService(ChromeDriverManager().install()), options=options
        )

        auth_user = scan_config.get("auth_username")
        auth_pass = scan_config.get("auth_password")
        if auth_user and auth_pass:
            login_url = urljoin(target_url, "/login")
            driver.get(login_url)
            time.sleep(2)
            try:
                driver.find_element(By.ID, "username").send_keys(auth_user)
                driver.find_element(By.ID, "password").send_keys(auth_pass)
                driver.find_element(By.TAG_NAME, "button").click()
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                log.info("Selenium authenticated as '%s'", auth_user)
            except Exception as exc:
                log.warning("Selenium login failed: %s", exc)

        driver.get(target_url)
        time.sleep(5)

        soup = BeautifulSoup(driver.page_source, "html.parser")
        links: set[str] = set()
        for a in soup.find_all("a", href=True):
            absolute = urljoin(target_url, a["href"])
            if _same_domain(absolute, target_url) and absolute.startswith("http"):
                links.add(absolute)

        log.info("Discovered %d links via Selenium", len(links))
        return list(links)

    except Exception as exc:
        log.warning("Selenium discovery error: %s", exc)
        return []
    finally:
        if driver:
            driver.quit()

import os
import sys
import json
import shutil
import argparse
import logging
import subprocess
import threading
import concurrent.futures
import asyncio
import aiohttp
import httpx
import requests
import google.generativeai as genai
import urllib3
from playwright.async_api import async_playwright
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import signal
from colorama import init, Fore, Style

# --- Silence InsecureRequestWarning ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored output
init(autoreset=True)

class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except Exception:
            self.handleError(record)
# ---------------------------

# Logging setup with colored levels
logging.basicConfig(
    level=logging.INFO,
    format=Fore.BLUE + '%(asctime)s ' + Style.RESET_ALL + '[' + '%(levelname)s' + '] %(message)s',
    handlers=[
        TqdmLoggingHandler(),
        logging.FileHandler('tool.log', mode='w')
    ]
)
logging.addLevelName(logging.INFO, Fore.GREEN + 'INFO' + Style.RESET_ALL)
logging.addLevelName(logging.WARNING, Fore.YELLOW + 'WARN' + Style.RESET_ALL)
logging.addLevelName(logging.ERROR, Fore.RED + 'ERROR' + Style.RESET_ALL)

logger = logging.getLogger()

# Handle Ctrl+C gracefully
def graceful_exit(sig, frame):
    # We use a print here because logger might be closed or flushing
    print(Fore.YELLOW + "\nCtrl+C detected! Forcing immediate exit..." + Style.RESET_ALL)
    try:
        # Close stderr to prevent broken pipe errors from Node.js/Playwright
        sys.stderr.close()
    except:
        pass
    os._exit(0)

signal.signal(signal.SIGINT, graceful_exit)

# --- List of static file extensions to ignore ---
JUNK_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.ico',
    '.css', '.js', '.map',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mov', '.avi', '.flv', '.mkv',
    '.mp3', '.wav', '.ogg',
    '.zip', '.rar', '.gz', '.tar', '.7z',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.xml', '.txt', '.csv', '.rtf'
}

# --- V3.0: Massive Sorted Parameter List ---
COMMON_REDIRECT_PARAMS = [
    # Top Tier (The "Big 5")
    'next', 'url', 'target', 'dest', 'destination',
    'redirect', 'redirect_uri', 'redirect_url', 'redirect_to', 'r',
    'return', 'returnTo', 'return_to', 'return_path', 'ret',
    'continue', 'forward', 'fwd', 'goto', 'go',
    'uri', 'u', 'view', 'path', 'file',
    'to', 'out', 'link', 'site', 'data', 'reference', 'ref',
    'callback', 'callback_url', 'checkout_url', 
    'jump', 'jump_url', 'clickurl', 'clicku',
    'origin', 'originUrl', 'success', 
    'login', 'logout', 'loginto', 'signin', 'signout',
    'service', 'action', 'action_url', 
    'redir', 'qurl', 'burl', 'backurl', 'rurl', 'recurl', 'sp_url',
    'ext', 'pic', 'image_url', 'location', 'src', 'tcsrc', 'q', 'u1', 
    'linkAddress', 'val', 'validate', 'domain', 'host',
    'port', 'dir', 'page', 'folder',
    'REDIRECT_URL', 'Redirect', 'RedirectUrl', 'ReturnUrl', 'Url',
    'return_uri', 'return_url'
]

# --- AI Model Configuration ---
AI_MODEL_NAME = "gemini-1.5-flash"
# ------------------------------

# ---------------- Dependency Checks ----------------
def check_dependencies():
    tools = {
        'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
        'amass': 'Download from https://github.com/OWASP/Amass/releases',
        'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
    }
    for tool, instr in tools.items():
        if shutil.which(tool) is None:
            logger.warning(f"Optional tool missing: {tool}. Install via: {instr}")

# --- V3.4 NEW: Helper to normalize domains (strip www.) ---
def normalize_domain(domain):
    """Strips 'www.' from a domain to ensure consistent comparison."""
    if not domain:
        return ""
    if domain.startswith("www."):
        return domain[4:]
    return domain
# ----------------------------------------------------------

# ---------------- Subdomain Enumeration ----------------
def get_subdomains_crtsh(domain, proxies=None, headers=None):
    logger.debug(f"Fetching subdomains from crt.sh for {domain}")
    try:
        resp = requests.get(f'https://crt.sh/?q={domain}&output=json', timeout=20, headers=headers, verify=False)
        resp.raise_for_status()
        data = resp.json()
        
        subs = set()
        for entry in data:
            if 'name_value' in entry:
                for sub in entry['name_value'].split('\n'):
                    subs.add(sub.strip())

        logger.debug(f"Found {len(subs)} subdomains via crt.sh")
        return list(subs)
    except Exception as e:
        logger.error(f"crt.sh error: {e}")
        return []

def get_subdomains_certspotter(domain, proxies=None, headers=None):
    logger.debug(f"Fetching subdomains from CertSpotter for {domain}")
    try:
        resp = requests.get(
            f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
            timeout=15,
            headers=headers,
            verify=False
        )
        resp.raise_for_status()
        data = resp.json()
        
        subs = set()
        for entry in data:
            for dns_name in entry.get('dns_names', []):
                for sub in dns_name.split('\n'):
                    subs.add(sub.strip())

        logger.debug(f"Found {len(subs)} subdomains via CertSpotter")
        return list(subs)
    except Exception as e:
        logger.error(f"CertSpotter error: {e}")
        return []

def get_subdomains_subfinder(domain):
    logger.debug(f"Running subfinder for {domain}")
    try:
        res = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True, check=True, timeout=120)
        subs = {l.strip() for l in res.stdout.splitlines() if l.strip()}
        logger.debug(f"Found {len(subs)} subdomains via subfinder")
        return list(subs)
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
        return []

def get_subdomains_amass(domain):
    logger.debug(f"Running amass for {domain}")
    try:
        res = subprocess.run(['amass', 'enum', '-d', domain], capture_output=True, text=True, check=True, timeout=120)
        subs = {l.strip() for l in res.stdout.splitlines() if l.strip()}
        logger.debug(f"Found {len(subs)} subdomains via amass")
        return list(subs)
    except Exception as e:
        logger.error(f"Amass error: {e}")
        return []

def enumerate_subdomains(domain, method, headers=None):
    sources = {
        'crtsh': lambda d: get_subdomains_crtsh(d, None, headers),
        'certspotter': lambda d: get_subdomains_certspotter(d, None, headers),
        'subfinder': get_subdomains_subfinder,
        'amass': get_subdomains_amass
    }
    logger.info(f"Enumerating subdomains for {domain} using method: {method}")
    all_subs = set()
    if method == 'all':
        for func in sources.values():
            all_subs.update(func(domain))
    else:
        func = sources.get(method)
        if func:
            all_subs.update(func(domain))
        else:
            logger.error(Fore.RED + f"Unknown enumeration method: {method}")
            
    final = sorted(s for s in all_subs if domain in s)
    return final

# ---------------- URL Gathering ----------------
def find_endpoints(subdomain, timeout):
    try:
        res = subprocess.run(['gau', subdomain], capture_output=True, text=True, timeout=timeout, check=True)
        urls = [u.strip() for u in res.stdout.splitlines() if u.strip()]
        logger.debug(Fore.GREEN + f"Found {len(urls)} URLs for {subdomain}")
        return urls
    except Exception as e:
        logger.error(f"gau error for {subdomain}: {e}")
        return []

def gather_endpoints(subdomains, timeout, max_workers):
    endpoints = {}
    logger.info(f"Enumerating endpoints for {len(subdomains)} subdomain(s)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(find_endpoints, sd, timeout): sd for sd in subdomains}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc=Fore.MAGENTA + "Gathering Endpoints" + Style.RESET_ALL):
            sd = futures[fut]
            urls = fut.result()
            endpoints[sd] = urls
    return endpoints

# ---------------- Parameter Extraction & V3.0 Fuzzing ----------------
def extract_urls_with_parameters(urls):
    ups = [u for u in urls if '?' in u]
    logger.info(Fore.GREEN + f"Extracted {len(ups)} URLs with parameters")
    return ups

def generate_fuzzed_urls(urls, fuzz_params):
    """Injects specific redirect parameters into endpoints (V3.0 Fuzzing)."""
    fuzzed_urls = []
    logger.info(Fore.YELLOW + f"--- Fuzzing {len(urls)} endpoints with top {len(fuzz_params)} parameters ---")
    
    for url in tqdm(urls, desc=Fore.MAGENTA + "Generating Fuzzed URLs" + Style.RESET_ALL):
        try:
            parsed = urlparse(url)
            current_qs = parse_qs(parsed.query)
            
            for param in fuzz_params:
                # Don't fuzz if the param already exists
                if param in current_qs:
                    continue
                    
                # Add fuzz param with placeholder '1' (scanner will replace it)
                new_qs = current_qs.copy()
                new_qs[param] = '1' 
                
                new_query = urlencode(new_qs, doseq=True)
                fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                fuzzed_urls.append(fuzzed_url)
        except:
            continue
            
    logger.info(Fore.GREEN + f"Generated {len(fuzzed_urls)} fuzzed URLs.")
    return fuzzed_urls

# ---------------- HTTP Probing ----------------
async def probe_subdomain(client, subdomain, sem, timeout):
    """Tries to connect to a subdomain over HTTPS and HTTP."""
    async with sem:
        try:
            await client.head(f"https://{subdomain}", timeout=timeout)
            logger.debug(Fore.GREEN + f"Probe success (HTTPS): {subdomain}")
            return subdomain
        except httpx.ConnectError:
            try:
                await client.head(f"http://{subdomain}", timeout=timeout)
                logger.debug(Fore.GREEN + f"Probe success (HTTP): {subdomain}")
                return subdomain
            except Exception:
                pass
        except Exception:
            pass
    return None

async def run_probes(subdomains, max_workers, timeout, headers=None):
    """Runs the probe on all subdomains and returns a list of live ones."""
    live_subs = []
    sem = asyncio.Semaphore(max_workers)
    
    limits = httpx.Limits(max_connections=max_workers, max_keepalive_connections=20)
    async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=False, headers=headers) as client:
        
        tasks = [asyncio.create_task(probe_subdomain(client, sub, sem, timeout)) for sub in subdomains]
        
        for t in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=Fore.MAGENTA + "Probing Subdomains" + Style.RESET_ALL):
            result = await t
            if result:
                live_subs.append(result)
                
    return live_subs

# ---------------- V1: Vulnerability Testing (Headers) ----------------
async def test_open_redirect_async(session, url, timeout, payload_list, payload_netlocs, tested_params, param_list=None, proxy=None, headers=None):
    
    p = urlparse(url)
    qp = parse_qs(p.query)
    vuln_params = set()
    if not qp:
        return url, list(vuln_params)
    
    for param in qp:
        if param_list and param not in param_list:
            continue
        
        # --- V3.0 FIX: Deduplication Logic ---
        base_url = urlunparse((p.scheme, p.netloc, p.path, '', '', ''))
        param_id = (base_url, param)
        
        if param_id in tested_params:
            continue 
            
        tested_params.add(param_id)
        # -------------------------------------
        
        for payload in payload_list:
            if param in vuln_params:
                break

            new_q = urlencode({**qp, param: payload}, doseq=True)
            turl = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
            
            try:
                async with session.head(turl, allow_redirects=False, timeout=timeout, proxy=proxy, headers=headers) as r:
                    loc = r.headers.get('Location', '')
                    # --- V3.4 FIX: Use normalize_domain ---
                    if 300 <= r.status < 400 and normalize_domain(urlparse(loc).netloc) in payload_netlocs:
                        logger.info(Fore.GREEN + f"[HB-SCAN] Vulnerable redirect found: {url} -> {param}")
                        vuln_params.add(param)
                        break 

            except Exception as e:
                logger.debug(f"[HB-SCAN] HEAD request failed for {turl}: {e}")

            try:
                async with session.get(turl, allow_redirects=True, timeout=timeout, proxy=proxy, headers=headers) as r2:
                    
                    # --- V3.4 FIX: Use normalize_domain ---
                    if normalize_domain(urlparse(str(r2.url)).netloc) in payload_netlocs:
                        logger.info(Fore.GREEN + f"[HB-SCAN] Vulnerable redirect found: {url} -> {param}")
                        vuln_params.add(param)
                        break 

                    for hist in r2.history:
                        loc2 = hist.headers.get('Location', '')
                        # --- V3.4 FIX: Use normalize_domain ---
                        if normalize_domain(urlparse(loc2).netloc) in payload_netlocs:
                            logger.info(Fore.GREEN + f"[HB-SCAN] Vulnerable redirect found: {url} -> {param}")
                            vuln_params.add(param)
                            break 

            except Exception as e:
                logger.debug(f"[HB-SCAN] GET request failed for {turl}: {e}")

    return url, list(vuln_params)

async def wrapped_test(session, u, timeout, payload_list, payload_netlocs, tested_params, param_list, sem, proxy=None, headers=None):
    async with sem:
        return await test_open_redirect_async(session, u, timeout, payload_list, payload_netlocs, tested_params, param_list, proxy, headers)

async def gather_vulnerabilities_async(urls, timeout, payload_list, payload_netlocs, param_list, max_workers, proxy=None, headers=None):
    results = {}
    sem = asyncio.Semaphore(max_workers)
    
    tested_params = set()
    
    connector = aiohttp.TCPConnector(ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(wrapped_test(session, u, timeout, payload_list, payload_netlocs, tested_params, param_list, sem, proxy, headers)) for u in urls]
        
        for t in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=Fore.MAGENTA + "Testing URLs (Header-Based Scan)" + Style.RESET_ALL):
            url, vp = await t
            if vp:
                results[url] = vp
    logger.info(Fore.GREEN + f"Header-Based Scan complete: {len(results)} vulnerability(ies) identified")
    return results

# ---------------- V2: JavaScript Vulnerability Testing ----------------

# --- FIX: V3.3 Added ignore_params (already found vulnerabilities) ---
async def test_url_with_playwright(browser, url, payload_list, payload_netlocs, js_tested_params, ignore_params, param_list, timeout_ms, headers):
    p = urlparse(url)
    qp = parse_qs(p.query)
    vuln_params = set()
    if not qp:
        return url, list(vuln_params)
    
    page = None
    try:
        page = await browser.new_page(extra_http_headers=headers)
        
        for param in qp:
            if param_list and param not in param_list:
                continue
            
            # --- V3.3 FIX: Cross-Scan Deduplication ---
            base_url = urlunparse((p.scheme, p.netloc, p.path, '', '', ''))
            param_id = (base_url, param)
            
            if ignore_params and param_id in ignore_params:
                continue

            if param_id in js_tested_params:
                continue 
            js_tested_params.add(param_id)
            # ------------------------------------------
            
            for payload in payload_list:
                if param in vuln_params:
                    break 

                new_q = urlencode({**qp, param: payload}, doseq=True)
                turl = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
                
                try:
                    await page.goto(turl, timeout=timeout_ms, wait_until="load")
                    await page.wait_for_timeout(3000) 
                    
                    final_url = page.url
                    # --- V3.4 FIX: Use normalize_domain ---
                    if normalize_domain(urlparse(final_url).netloc) in payload_netlocs:
                        logger.info(Fore.GREEN + f"[JS-SCAN] Vulnerable redirect found: {url} -> {param}")
                        vuln_params.add(param)
                        break
                except Exception as e:
                    if 'Timeout' not in str(e):
                         logger.warning(f"[JS-SCAN] Playwright test failed for {turl}: {e}")
        
        await page.close()
    except Exception as e:
        logger.error(f"[JS-SCAN] Playwright page error: {e}")
        if page:
            await page.close()
    
    return url, list(vuln_params)

async def gather_js_vulnerabilities_async(urls, timeout, payload_list, payload_netlocs, param_list, max_workers, headers, proxy, ignore_params=None):
    results = {}
    sem = asyncio.Semaphore(max_workers)
    js_tested_params = set()
    
    proxy_settings = None
    if proxy:
        proxy_settings = {"server": proxy}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, proxy=proxy_settings)
        
        async def wrapped_js_test(url):
            async with sem:
                return await test_url_with_playwright(browser, url, payload_list, payload_netlocs, js_tested_params, ignore_params, param_list, timeout * 1000, headers)

        tasks = [asyncio.create_task(wrapped_js_test(u)) for u in urls]
        
        for t in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=Fore.CYAN + "Testing URLs (JavaScript Scan)" + Style.RESET_ALL):
            url, vp = await t
            if vp:
                results[url] = vp
                
        await browser.close()
        
    logger.info(Fore.GREEN + f"JavaScript Scan complete: {len(results)} new vulnerability(ies) identified")
    return results

# ---------------- Output ----------------
def write_text_output(subs, eps, ups, vr, so, eo, po, vo):
    if so:
        with open(so, 'w') as f:
            for s in subs:
                f.write(s + '\n')
        logger.info(Fore.BLUE + f"Subdomains saved to {so}")
    
    if eo:
        flat = [u for lst in eps.values() for u in lst]
        with open(eo, 'w') as f:
            for u in flat:
                f.write(u + '\n')
        logger.info(Fore.BLUE + f"Endpoints saved to {eo}")
    
    if po:
        with open(po, 'w') as f:
            for u in ups:
                f.write(u + '\n')
        logger.info(Fore.BLUE + f"URLs with parameters saved to {po}")
    
    if vo:
        with open(vo, 'w') as f:
            for u, ps in vr.items():
                f.write(f"{u} -> {', '.join(ps)}\n")
        logger.info(Fore.BLUE + f"Vulnerabilities saved to {vo}")

def write_json_output(domain, subs, eps, ups, vr, jo):
    out = {'domain': domain, 'subdomains': subs, 'endpoints': eps, 'urls_with_parameters': ups, 'vulnerabilities': vr}
    with open(jo, 'w') as f:
        json.dump(out, f, indent=2)
    logger.info(Fore.BLUE + f"JSON results saved to {jo}")

# ---------------- AI Report ----------------
def generate_report(domain, vr, payload_or_file, api_key=None):
    
    if not api_key:
        api_key = os.getenv('GOOGLE_API_KEY')

    if not api_key:
         logger.warning(Fore.YELLOW + 'Skipping AI report (no API key provided. Use --apikey or set GOOGLE_API_KEY)')
         return None
    
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(AI_MODEL_NAME) 
        logger.info(Fore.CYAN + f"Generating AI report using {AI_MODEL_NAME}...")
    except Exception as e:
        logger.error(f"Failed to initialize Gemini: {e}")
        return None

    payload_desc = f"file {payload_or_file}" if os.path.isfile(payload_or_file) else f"payload {payload_or_file}"
    prompt = f"You are a security analyst. Report for {domain} using {payload_desc}:\n"

    prompt += "\n".join(f"- {u}: {ps}" for u, ps in vr.items())
    prompt += "\nInclude risk, impact, remediation steps."
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Failed to generate AI report: {e}")
        return None

# ---------------- Main ----------------
def main():
    print(Fore.CYAN + r"""
                                         █   █
█████  █████  █████  █████  █████ ██████  █ █ 
█    █ █      █    █   █    █   █ █    █   █         █████
█████  █████  █    █   █    █████  █████   █   █    █   █
█   █  █      █    █   █    █   █  █      █ █   █  █   █
█    █ █████  █████  █████  █    █ █████ █   █   ██   █████

Developed by:
      Kareem Ashraf Elmongy  
      """ + Style.RESET_ALL)
      
    check_dependencies()
    
    parser = argparse.ArgumentParser(
        description=Fore.MAGENTA + 'Async Open Redirect Scanner' + Style.RESET_ALL,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-d', '--domain', help='The target domain to scan (Full Recon Mode).')
    mode_group.add_argument('-e', '--endpoint', help='Test a single URL or a file of URLs (Single Target Mode).')

    recon_group = parser.add_argument_group('Reconnaissance & Enumeration')
    recon_group.add_argument('-m', '--method', choices=['all','crtsh','certspotter','subfinder','amass'], default='all', help='Subdomain enumeration method(s) (Default: all).')
    recon_group.add_argument('--skip-enum', action='store_true', help='Skip subdomain enumeration and scan the --domain directly.')
    recon_group.add_argument('-p', '--parameter', nargs='+', help='Optional parameter(s) to test (e.g., param1 param2).')
    recon_group.add_argument('--recon-timeout', type=int, default=60, help='Timeout in seconds for recon tools (gau).')

    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('-P', '--payload', default='http://evil.com', help='Payload to inject (string) or a file of payloads (Default: http://evil.com).')
    scan_group.add_argument('-t', '--target-domain', nargs='+', help='One or more target domains to confirm vulnerability (e.g., evil.com).')
    scan_group.add_argument('--js-scan', action='store_true', help='Enable slow, JS-based redirect scan (headless browser).')
    scan_group.add_argument('--fuzz', nargs='?', const='5', default=None, help='Enable parameter fuzzing. Specify number of top params (default: 5) or "all".')
    scan_group.add_argument('--vulntimeout', type=int, default=10, help='Timeout in seconds for vulnerability tests.')
    scan_group.add_argument('-w', '--max-workers', type=int, default=10, help='Number of concurrent threads (Default: 10).')
    scan_group.add_argument('--probe-timeout', type=int, default=10, help='Timeout in seconds for probing live subdomains.')
    
    output_group = parser.add_argument_group('Output & Reporting')
    output_group.add_argument('-oT', '--vulnoutput', default=None, help='File to save confirmed vulnerable URLs (text format).')
    output_group.add_argument('-oJ', '--jsonoutput', default=None, help='File for JSON results.')
    output_group.add_argument('--suboutput', default=None, help='(Optional) File to save all found subdomains.')
    output_group.add_argument('--endoutput', default=None, help='(Optional) File to save all found endpoints.')
    output_group.add_argument('--paramoutput', default=None, help='(Optional) File to save all URLs with parameters.')
    
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--verbose', action='store_true', help='Enable debug-level logging.')
    verbosity_group.add_argument('--quiet', action='store_true', help='Suppress non-error messages.')

    ai_group = parser.add_argument_group('AI Reporting')
    ai_group.add_argument('--apikey', help='Google AI API key (Required for AI report generation).')
    ai_group.add_argument('--reportoutput', default=None, help='File to save the AI-generated report (Triggers report generation).')

    network_group = parser.add_argument_group('Network & Headers')
    network_group.add_argument('-H', '--header', action='append', help='Add a custom header (e.g., "Cookie: ..."). Can be used multiple times.')
    network_group.add_argument('-UA', '--user-agent', help='Set a custom User-Agent string.')
    network_group.add_argument('-px', '--proxy', help='HTTP/S proxy to route traffic *only* for the vulnerability test stage (e.g., http://127.0.0.1:8080).')
    
    args = parser.parse_args()
    
    param_list = []
    if args.parameter:
        for param in args.parameter:
            param_list.extend(param.split(','))

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("playwright").setLevel(logging.WARNING)
    
    if args.quiet:
        logger.setLevel(logging.ERROR)

    if args.domain:
        domain_name = args.domain
    else:
        domain_name = "SingleTargetScan"

    proxy_str = None
    if args.proxy:
        proxy_str = args.proxy
        if not proxy_str.startswith("http://") and not proxy_str.startswith("https://"):
            proxy_str = "http://" + proxy_str
            logger.info(f"Proxy scheme not found, defaulting to: {proxy_str}")
        logger.info(f"Using proxy for vulnerability testing: {proxy_str}")
        
    headers = {}
    headers['User-Agent'] = 'RedireX-Scanner/3.1' 
    
    if args.user_agent:
        headers['User-Agent'] = args.user_agent 
    
    if args.header:
        for header_line in args.header:
            try:
                key, value = header_line.split(':', 1)
                headers[key.strip()] = value.strip()
                logger.info(f"Using custom header: {key.strip()}: {value.strip()}")
            except ValueError:
                logger.warning(f"Skipping malformed header: {header_line}")

    payload_list = []
    payload_netlocs = set() 
    if os.path.isfile(args.payload):
        logger.info(f"Loading payloads from file: {args.payload}")
        try:
            with open(args.payload, 'r') as f:
                payload_list = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(payload_list)} payload(s).")
        except Exception as e:
            logger.error(f"Failed to read payload file: {e}")
            sys.exit(1)
    else:
        payload_list = [args.payload]
        logger.info(f"Using single payload: {args.payload}")

    try:
        if args.target_domain:
            logger.info(f"Validation scope overrides set to: {args.target_domain}")
            for d in args.target_domain:
                for domain in d.split(','): 
                    if domain.startswith("www."):
                        domain = domain[4:]
                    payload_netlocs.add(domain.strip())
        else:
            logger.info("No --target-domain set. Inferring from first payload...")
            if not payload_list:
                 logger.error("No payloads loaded. Please provide a valid payload or payload file.")
                 sys.exit(1)
                 
            first_payload = payload_list[0]
            parsed = urlparse(first_payload)
            # --- V3.4 FIX: Use normalize_domain on master payload too ---
            master_domain = parsed.netloc or parsed.path.split('/')[0]
            master_domain = normalize_domain(master_domain)
            # ------------------------------------------------------------

            if not master_domain:
                logger.error(f"The first payload '{first_payload}' is invalid. Use --target-domain to specify a target.")
                sys.exit(1)
            
            payload_netlocs = {master_domain}
            logger.info(f"Validation scope inferred from payload: {payload_netlocs}")
            
        if not payload_netlocs:
            logger.error("No valid payload domains found.")
            sys.exit(1)
            
        logger.info(f"Loaded {len(payload_list)} payload(s). Target Scope: {payload_netlocs}")

    except Exception as e:
        logger.error(f"Error parsing payload domains: {e}")
        sys.exit(1)
    
    # --- V3.0: Initialize fuzz_params ---
    fuzz_params = []
    if args.fuzz:
        if args.fuzz == 'all':
            fuzz_params = COMMON_REDIRECT_PARAMS
            logger.info("Fuzzing Mode Enabled: Using ALL common parameters.")
        else:
            try:
                limit = int(args.fuzz)
                fuzz_params = COMMON_REDIRECT_PARAMS[:limit]
                logger.info(f"Fuzzing Mode Enabled: Using top {limit} common parameters.")
            except ValueError:
                logger.error("Invalid value for --fuzz. Use a number or 'all'.")
                sys.exit(1)
    # -------------------------------------

    if args.endpoint:
        ups_with_params = []
        if os.path.isfile(args.endpoint):
            logger.info(f"Running in Single-Target Mode from file: {args.endpoint}")
            try:
                with open(args.endpoint, 'r') as f:
                    ups_with_params = [line.strip() for line in f if line.strip()]
                logger.info(f"Loaded {len(ups_with_params)} URLs from file.")
            except Exception as e:
                logger.error(f"Failed to read endpoint file: {e}")
                sys.exit(1)
        else:
            logger.info(f"Running in Single-Target Mode for: {args.endpoint}")
            ups_with_params = [args.endpoint]
        
        ups = extract_urls_with_parameters(ups_with_params)
        
        if args.fuzz:
            clean_endpoints = []
            for url in ups_with_params:
                 try:
                    path = urlparse(url).path
                    ext = os.path.splitext(path)[1].lower()
                    if ext not in JUNK_EXTENSIONS:
                        clean_endpoints.append(url)
                 except:
                     pass
            fuzzed = generate_fuzzed_urls(clean_endpoints, fuzz_params)
            ups.extend(fuzzed)
        
        logger.info(f"Testing {len(ups)} URLs.")
        subs = []
        eps = {}
        
    else:
        if args.skip_enum:
            logger.info(f"Skipping subdomain enumeration. Scanning --domain '{args.domain}' directly.")
            subs = [args.domain]
        else:
            subs = sorted(set(enumerate_subdomains(args.domain, args.method, headers)))
            logger.info(Fore.GREEN + f"{len(subs)} unique subdomain(s) found")
        
        subs_to_probe = [s for s in subs if '*' not in s]
        wildcard_subs = [s for s in subs if '*' in s]
        
        logger.info(f"Probing {len(subs_to_probe)} resolvable subdomains to find live web servers...")
        live_subs = asyncio.run(run_probes(subs_to_probe, args.max_workers, args.probe_timeout, headers))
        logger.info(Fore.GREEN + f"Found {len(live_subs)} live host(s)")

        subs_for_gau = live_subs + wildcard_subs
        logger.info(f"Enumerating endpoints for {len(subs_for_gau)} subdomain(s)...")

        eps = gather_endpoints(subs_for_gau, args.recon_timeout, args.max_workers)

        all_eps = [u for lst in eps.values() for u in lst]
        
        ups = extract_urls_with_parameters(all_eps)
        
        if args.fuzz:
            clean_endpoints = []
            for url in all_eps:
                 try:
                    path = urlparse(url).path
                    ext = os.path.splitext(path)[1].lower()
                    if ext not in JUNK_EXTENSIONS:
                        clean_endpoints.append(url)
                 except:
                     pass
            fuzzed = generate_fuzzed_urls(clean_endpoints, fuzz_params)
            ups.extend(fuzzed)
        
        logger.info(f"Testing {len(ups)} URLs.")

    logger.info(Fore.YELLOW + f"--- Starting Header-Based Scan on {len(ups)} URLs ---")
    # --- V3.6 FIX: Need to set the Windows Event Loop Policy before running asyncio.run ---
    if os.name == 'nt': # Check if OS is Windows
        try:
            # Set the new default ProactorEventLoopPolicy if available
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            # Fallback to SelectorEventLoopPolicy if Proactor is not available
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    # --------------------------------------------------------------------------------------
    
    vr = asyncio.run(gather_vulnerabilities_async(ups, args.vulntimeout, payload_list, payload_netlocs, param_list, args.max_workers, proxy_str, headers))
    
    if args.js_scan:
        urls_v1_didnt_find = [url for url in ups if url not in vr]
        
        urls_to_js_scan = []
        for url in urls_v1_didnt_find:
            try:
                path = urlparse(url).path
                ext = os.path.splitext(path)[1].lower()
                if ext not in JUNK_EXTENSIONS:
                    urls_to_js_scan.append(url)
            except Exception:
                urls_to_js_scan.append(url)

        logger.info(f"[JS-SCAN] Excluded {len(urls_v1_didnt_find) - len(urls_to_js_scan)} static resources. Proceeding with {len(urls_to_js_scan)} URLs.")
        
        known_vulns = set()
        for v_url, v_params_list in vr.items():
            try:
                p = urlparse(v_url)
                base = urlunparse((p.scheme, p.netloc, p.path, '', '', ''))
                for vp in v_params_list:
                    known_vulns.add((base, vp))
            except:
                pass
        
        if urls_to_js_scan:
            js_vr = asyncio.run(gather_js_vulnerabilities_async(
                urls_to_js_scan,
                args.vulntimeout,
                payload_list,
                payload_netlocs,
                param_list,
                args.max_workers,
                headers,
                proxy_str,
                known_vulns 
            ))
            vr.update(js_vr)
        else:
            logger.info(Fore.CYAN + "[JS-SCAN] No eligible URLs for JavaScript analysis.")
            
    total_vulns = len(vr)
    if total_vulns > 0:
        logger.info(Fore.GREEN + Style.BRIGHT + f"\n--- Scan Complete: {total_vulns} total vulnerability(ies) identified! ---\n")
    else:
        logger.info(Fore.CYAN + f"\n--- Scan Complete: No vulnerabilities found. ---\n")
    print("\n" + Style.RESET_ALL)

    if args.vulnoutput:
        write_text_output(subs, eps, ups, vr, args.suboutput, args.endoutput, args.paramoutput, args.vulnoutput)
    
    if args.jsonoutput:
        write_json_output(domain_name, subs, eps, ups, vr, args.jsonoutput)

    if not args.vulnoutput and not args.jsonoutput:
        logger.warning(Fore.YELLOW + "No output file specified. Use --vulnoutput or --jsonoutput to save results.")

    api_key_present = args.apikey or os.getenv('GOOGLE_API_KEY')
    
    if vr and api_key_present and args.reportoutput:
        report = generate_report(domain_name, vr, args.payload, args.apikey)
        if report:
            try:
                with open(args.reportoutput, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(Fore.GREEN + f"AI report ({AI_MODEL_NAME}) saved to {args.reportoutput}")
            except Exception as e:
                logger.error(f"Failed to save AI report to {args.reportoutput}: {e}")

if __name__ == '__main__':
    main()
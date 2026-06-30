"""
Local Playwright crawler for WebApp PT.
Tries Chromium → Firefox → WebKit in order; falls back to requests-based
crawl if no Playwright browser binary is available (e.g. Ubuntu 26.04).
All traffic stays on localhost — zero external data transfer.
"""
import asyncio
import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger("aavapt.crawler")

# Tech stack detection patterns
TECH_PATTERNS = {
    "PHP":       [r"\.php", r"X-Powered-By: PHP", r"PHPSESSID"],
    "ASP.NET":   [r"\.aspx", r"X-Powered-By: ASP\.NET", r"ASP\.NET_SessionId", r"__VIEWSTATE"],
    "Django":    [r"csrfmiddlewaretoken", r"django", r"X-Frame-Options: SAMEORIGIN"],
    "Laravel":   [r"laravel_session", r"XSRF-TOKEN"],
    "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc\.php"],
    "Node.js":   [r"X-Powered-By: Express", r"connect\.sid"],
    "Ruby":      [r"_session_id", r"X-Powered-By: Phusion Passenger"],
    "Spring":    [r"JSESSIONID", r"org\.springframework"],
    "React":     [r"__REACT", r"_reactFiber", r"react-root"],
    "Angular":   [r"ng-version", r"__ngContext"],
    "Vue":       [r"__vue__", r"data-v-"],
    "jQuery":    [r"jquery", r"jQuery"],
    "Bootstrap": [r"bootstrap\.min\.css", r"bootstrap\.min\.js"],
    "Nginx":     [r"Server: nginx"],
    "Apache":    [r"Server: Apache"],
    "IIS":       [r"Server: Microsoft-IIS"],
    "Cloudflare":[r"cf-ray", r"__cfduid"],
}

JS_SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']',
    r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
    r'(?i)(aws[_-]?access|aws[_-]?secret)\s*[=:]\s*["\']([A-Z0-9]{16,})["\']',
    r'Bearer\s+([A-Za-z0-9\-_\.]{20,})',
    r'(?i)eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',  # JWT
]


@dataclass
class CrawlResult:
    target_url: str = ""
    all_urls: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    js_files: list = field(default_factory=list)
    js_secrets: list = field(default_factory=list)
    input_parameters: list = field(default_factory=list)
    auth_endpoints: list = field(default_factory=list)
    file_upload_points: list = field(default_factory=list)
    redirect_chains: list = field(default_factory=list)
    pages_crawled: int = 0
    errors: list = field(default_factory=list)
    raw_html_sample: str = ""

    def to_dict(self):
        return {
            "target_url": self.target_url,
            "all_urls": self.all_urls[:200],
            "forms": self.forms[:50],
            "api_endpoints": self.api_endpoints[:100],
            "headers": self.headers,
            "cookies": self.cookies,
            "technologies": self.technologies,
            "js_files": self.js_files[:50],
            "js_secrets": self.js_secrets,
            "input_parameters": self.input_parameters[:100],
            "auth_endpoints": self.auth_endpoints,
            "file_upload_points": self.file_upload_points,
            "redirect_chains": self.redirect_chains,
            "pages_crawled": self.pages_crawled,
            "errors": self.errors[:20],
        }

    def summary(self):
        return (
            f"URLs: {len(self.all_urls)} | Forms: {len(self.forms)} | "
            f"API endpoints: {len(self.api_endpoints)} | "
            f"Tech: {', '.join(self.technologies[:5]) or 'Unknown'} | "
            f"File uploads: {len(self.file_upload_points)} | "
            f"Auth endpoints: {len(self.auth_endpoints)}"
        )


class WebAppCrawler:
    """
    Playwright-based local crawler. All traffic stays on localhost.
    Supports: unauthenticated crawl, auto-login + authenticated crawl.
    """

    def __init__(self, max_pages: int = 50, timeout_ms: int = 30000,
                 delay_ms: int = 1000, broadcast_fn=None):
        self.max_pages = max_pages
        self.timeout_ms = timeout_ms
        self.delay_ms = delay_ms
        self.broadcast = broadcast_fn  # WebSocket broadcast callable
        self._visited: set = set()
        self._queue: list = []

    async def crawl_unauthenticated(self, url: str) -> CrawlResult:
        return await self._crawl(url, username=None, password=None)

    async def crawl_authenticated(self, url: str, username: str,
                                   password: str) -> CrawlResult:
        return await self._crawl(url, username=username, password=password)

    async def _crawl(self, start_url: str, username: Optional[str],
                     password: Optional[str]) -> CrawlResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            log.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
            result = CrawlResult(target_url=start_url)
            result.errors.append("Playwright not installed. Run: pip install playwright && playwright install chromium")
            return result

        result = CrawlResult(target_url=start_url)
        base_parsed = urlparse(start_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
        self._visited = {start_url}
        self._queue = [start_url]

        async with async_playwright() as p:
            import os as _os
            SYS_CHROMIUM = [
                "/usr/bin/chromium-browser",
                "/usr/bin/chromium",
                "/snap/bin/chromium",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/google-chrome",
            ]
            SYS_FIREFOX = ["/usr/bin/firefox", "/snap/bin/firefox"]

            browser = None
            _browser_name = "none"

            # 1. Playwright bundled binaries
            for _bt, _name in [(p.chromium, "chromium"), (p.firefox, "firefox"), (p.webkit, "webkit")]:
                try:
                    browser = await _bt.launch(headless=True)
                    _browser_name = _name
                    log.info("Playwright: using bundled " + _name)
                    break
                except Exception as _e:
                    log.warning("Playwright bundled " + _name + " unavailable: " + str(_e))

            # 2. System Chromium via executable_path
            if browser is None:
                for _exe in SYS_CHROMIUM:
                    if _os.path.exists(_exe):
                        try:
                            browser = await p.chromium.launch(headless=True, executable_path=_exe, args=["--no-sandbox","--disable-setuid-sandbox"])
                            _browser_name = "system-chromium"
                            log.info("Playwright: using system Chromium at " + _exe)
                            break
                        except Exception as _e:
                            log.warning("System chromium " + _exe + " failed: " + str(_e))

            # 3. System Firefox via executable_path
            if browser is None:
                for _exe in SYS_FIREFOX:
                    if _os.path.exists(_exe):
                        try:
                            browser = await p.firefox.launch(headless=True, executable_path=_exe, args=["--no-sandbox"])
                            _browser_name = "system-firefox"
                            log.info("Playwright: using system Firefox at " + _exe)
                            break
                        except Exception as _e:
                            log.warning("System firefox " + _exe + " failed: " + str(_e))

            if browser is None:
                log.warning("No Playwright browser available — using requests fallback crawler")
                return await self._crawl_with_requests(start_url, username, password, result)

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (compatible; VAPT-Scanner/1.0; internal)",
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            # Intercept XHR/fetch requests to discover API endpoints
            api_endpoints_found = set()

            async def on_request(request):
                url = request.url
                parsed = urlparse(url)
                if parsed.netloc == base_parsed.netloc:
                    path = parsed.path
                    if any(seg in path for seg in ['/api/', '/v1/', '/v2/', '/graphql',
                                                    '/rest/', '/service/', '/ws/', '/ajax/']):
                        api_endpoints_found.add(path + (f"?{parsed.query}" if parsed.query else ""))

            context.on("request", on_request)
            page = await context.new_page()

            # ── Step 1: Load main page + get headers/cookies/tech ──
            try:
                response = await page.goto(start_url, wait_until="networkidle",
                                           timeout=self.timeout_ms)
                if response:
                    result.headers = dict(response.headers)
                    result.redirect_chains = [r.url for r in response.request.redirected_from or []]

                result.cookies = [
                    {"name": c["name"], "domain": c["domain"],
                     "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False)}
                    for c in await context.cookies()
                ]
                result.raw_html_sample = (await page.content())[:5000]

                # Detect tech stack
                result.technologies = await self._detect_tech(page, result.headers,
                                                               result.cookies, result.raw_html_sample)

                await self._broadcast({"type": "webapp_crawl_page", "url": start_url,
                                        "forms_found": 0, "params_found": 0})

            except Exception as e:
                result.errors.append(f"Main page error: {e}")
                await browser.close()
                return result

            # ── Step 2: Auto-login if credentials provided ──────────
            if username and password:
                await self._auto_login(page, username, password, result)

            # ── Step 3: Crawl pages ─────────────────────────────────
            while self._queue and result.pages_crawled < self.max_pages:
                current_url = self._queue.pop(0)
                if current_url != start_url:
                    try:
                        await page.goto(current_url, wait_until="domcontentloaded",
                                        timeout=self.timeout_ms)
                        await asyncio.sleep(self.delay_ms / 1000)
                    except Exception as e:
                        result.errors.append(f"Page error {current_url}: {str(e)[:100]}")
                        continue

                result.pages_crawled += 1

                # Extract links
                links = await self._extract_links(page, base_origin)
                for link in links:
                    if link not in self._visited:
                        self._visited.add(link)
                        result.all_urls.append(link)
                        self._queue.append(link)

                # Extract forms
                forms = await self._extract_forms(page, current_url)
                result.forms.extend(forms)

                # Check for file upload
                for form in forms:
                    if form.get("has_file_input"):
                        result.file_upload_points.append({
                            "url": current_url,
                            "form_action": form.get("action"),
                            "method": form.get("method"),
                        })

                # Check for auth endpoints
                if await self._is_auth_page(page, current_url):
                    result.auth_endpoints.append(current_url)

                # Extract JS files — FIX BUG-11: deduplicate
                js_urls = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('script[src]'))
                              .map(s => s.src).filter(s => s.startsWith('http'))
                """)
                for jurl in (js_urls or []):
                    if jurl not in result.js_files:
                        result.js_files.append(jurl)

                # Collect input parameters
                params = await self._extract_params(page, current_url)
                result.input_parameters.extend(params)

                await self._broadcast({
                    "type": "webapp_crawl_page",
                    "url": current_url,
                    "forms_found": len(forms),
                    "params_found": len(params),
                })

            # ── Step 4: Scan JS for secrets ─────────────────────────
            result.js_secrets = await self._scan_js_secrets(page, result.js_files[:10])

            # ── Step 5: Merge API endpoints ─────────────────────────
            result.api_endpoints = list(api_endpoints_found)

            await browser.close()

        await self._broadcast({
            "type": "webapp_crawl_complete",
            "stats": result.to_dict(),
            "session_id": "",
        })
        log.info(f"Crawl complete: {result.summary()}")
        return result

    async def _auto_login(self, page, username: str, password: str,
                          result: CrawlResult):
        """Find and fill login form automatically."""
        try:
            # Look for password input
            pwd_input = await page.query_selector('input[type="password"]')
            if not pwd_input:
                return

            # Find username field (input before password, or email/text type)
            user_input = await page.query_selector(
                'input[type="email"], input[name*="user"], input[name*="login"], '
                'input[name*="email"], input[id*="user"], input[id*="email"]'
            )
            if not user_input:
                # fallback: first text input
                user_input = await page.query_selector('input[type="text"]')

            if user_input:
                await user_input.fill(username)
            await pwd_input.fill(password)

            # Submit
            submit = await page.query_selector(
                'input[type="submit"], button[type="submit"], button:has-text("Login"), '
                'button:has-text("Sign in"), button:has-text("Log in")'
            )
            if submit:
                await submit.click()
            else:
                await page.keyboard.press("Enter")
            await page.wait_for_load_state("networkidle", timeout=10000)
            log.info(f"Auto-login attempted for {username}")
            # FIX BUG-10: Verify login success by checking if still on login page
            current_url = page.url
            current_html = (await page.content()).lower()
            login_failed = (
                any(kw in current_url.lower() for kw in ("login", "signin", "error", "fail"))
                or any(phrase in current_html for phrase in
                       ("invalid password", "incorrect password", "login failed",
                        "wrong password", "authentication failed"))
            )
            if login_failed:
                result.errors.append(
                    f"Auto-login may have FAILED for {username} — still on: {current_url}. "
                    "Check credentials or CAPTCHA/MFA requirements."
                )
                log.warning(f"Auto-login likely failed for {username} at {current_url}")
            else:
                log.info(f"Auto-login SUCCESS for {username} → {current_url}")
        except Exception as e:
            result.errors.append(f"Auto-login error: {e}")

    async def _detect_tech(self, page, headers: dict, cookies: list,
                            html: str) -> list:
        tech = set()
        combined = html + json.dumps(headers) + json.dumps(cookies)
        for tech_name, patterns in TECH_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    tech.add(tech_name)
                    break
        # Also check meta generator
        try:
            gen = await page.query_selector('meta[name="generator"]')
            if gen:
                content = await gen.get_attribute("content") or ""
                if content:
                    tech.add(content.split()[0])
        except Exception:
            pass
        return sorted(tech)

    async def _extract_links(self, page, base_origin: str) -> list:
        # FIX BUG-03: Pass base_origin as argument to avoid JS injection via f-string
        try:
            links = await page.evaluate("""
                (base) => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith(base) && !h.includes('#'))
                        .slice(0, 100);
                }
            """, base_origin)
            return links or []
        except Exception:
            return []

    async def _extract_forms(self, page, page_url: str) -> list:
        try:
            forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    fields: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                        name: i.name, type: i.type, id: i.id, value: i.value || ''
                    })),
                    has_file_input: !!f.querySelector('input[type="file"]'),
                    has_password: !!f.querySelector('input[type="password"]'),
                }))
            """)
            for form in forms:
                form["page_url"] = page_url
            return forms or []
        except Exception:
            return []

    async def _is_auth_page(self, page, url: str) -> bool:
        auth_keywords = ['login', 'signin', 'sign-in', 'logout', 'signout',
                         'register', 'signup', 'sign-up', 'auth', 'password']
        url_lower = url.lower()
        if any(kw in url_lower for kw in auth_keywords):
            return True
        try:
            has_pwd = await page.query_selector('input[type="password"]')
            return bool(has_pwd)
        except Exception:
            return False

    async def _extract_params(self, page, url: str) -> list:
        params = []
        # GET params from URL
        parsed = urlparse(url)
        if parsed.query:
            for kv in parsed.query.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params.append({"location": "query", "name": k,
                                   "example_value": v, "url": url})
        # Form field names
        try:
            fields = await page.evaluate("""
                () => Array.from(document.querySelectorAll('input[name],select[name],textarea[name]'))
                    .map(i => i.name).filter(Boolean)
            """)
            for name in (fields or []):
                params.append({"location": "body", "name": name, "url": url})
        except Exception:
            pass
        return params


    async def _scan_js_secrets(self, page, js_urls: list) -> list:
        """Fetch JS files and scan for hardcoded secrets."""
        secrets = []
        for js_url in js_urls[:10]:
            try:
                # FIX BUG-03: Pass js_url as argument to avoid JS injection
                content = await page.evaluate(
                    "(async (url) => { const r = await fetch(url);"
                    " return r.ok ? await r.text() : ''; })(arguments[0])",
                    js_url
                )
                if not content:
                    continue
                for pattern in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content[:50000])
                    for match in matches:
                        val = match[-1] if isinstance(match, tuple) else match
                        secrets.append({
                            "js_file": js_url,
                            "pattern": pattern[:40],
                            "value_preview": val[:20] + "..." if len(val) > 20 else val,
                        })
            except Exception:
                pass
        return secrets[:20]

    async def _broadcast(self, data: dict):
        if self.broadcast:
            try:
                await self.broadcast(data)
            except Exception:
                pass

    # --- Requests-based fallback (no Playwright binary required) ---
    # Parses HTML with stdlib html.parser - no BeautifulSoup dependency.
    # Covers links, forms, headers, cookies, tech detection.

    async def _crawl_with_requests(self, start_url: str,
                                    username,
                                    password,
                                    result) -> "CrawlResult":
        try:
            import requests as _req
        except ImportError:
            result.errors.append("Neither Playwright nor requests available - cannot crawl")
            return result

        from html.parser import HTMLParser

        base_parsed = urlparse(start_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        session = _req.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; VAPT-Scanner/1.0; internal)"})
        session.verify = False

        result.errors.append(
            "Note: Playwright browsers unavailable on this OS - using requests fallback. "
            "JS-rendered content will not be detected. "
            "Run 'playwright install firefox' to enable full crawling."
        )

        class _LinkFormParser(HTMLParser):
            def __init__(self, base_url):
                super().__init__()
                self.base_url = base_url
                self.links = []
                self.forms = []
                self._cur_form = None
                self.js_srcs = []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "a" and attrs.get("href"):
                    from urllib.parse import urljoin as _uj
                    self.links.append(_uj(self.base_url, attrs["href"]))
                elif tag == "form":
                    from urllib.parse import urljoin as _uj
                    self._cur_form = {
                        "action": _uj(self.base_url, attrs.get("action", "")),
                        "method": (attrs.get("method", "GET")).upper(),
                        "fields": [],
                        "has_file_input": False,
                        "has_password": False,
                        "page_url": self.base_url,
                    }
                elif tag in ("input", "select", "textarea") and self._cur_form is not None:
                    t = attrs.get("type", "text").lower()
                    self._cur_form["fields"].append({
                        "name": attrs.get("name", ""),
                        "type": t,
                        "id": attrs.get("id", ""),
                        "value": attrs.get("value", ""),
                    })
                    if t == "file":
                        self._cur_form["has_file_input"] = True
                    if t == "password":
                        self._cur_form["has_password"] = True
                elif tag == "script" and attrs.get("src"):
                    src = attrs["src"]
                    if src.startswith("http"):
                        self.js_srcs.append(src)

            def handle_endtag(self, tag):
                if tag == "form" and self._cur_form:
                    self.forms.append(self._cur_form)
                    self._cur_form = None

        # Attempt login if credentials given
        if username and password:
            try:
                for login_path in ["/login", "/signin", "/auth/login", "/user/login"]:
                    try:
                        r = session.post(
                            base_origin + login_path,
                            data={"username": username, "email": username, "password": password},
                            timeout=10, allow_redirects=True,
                        )
                        if r.status_code < 400:
                            log.info(f"Requests login attempt at {login_path}: {r.status_code}")
                            break
                    except Exception:
                        continue
            except Exception as e:
                result.errors.append(f"Login attempt failed: {e}")

        # Crawl loop
        self._visited = {start_url}
        self._queue = [start_url]

        while self._queue and result.pages_crawled < self.max_pages:
            cur_url = self._queue.pop(0)
            try:
                resp = session.get(cur_url, timeout=15, allow_redirects=True)
                resp.raise_for_status()
            except Exception as e:
                result.errors.append(f"Fetch error {cur_url}: {str(e)[:80]}")
                continue

            result.pages_crawled += 1
            html_text = resp.text

            if cur_url == start_url:
                result.headers = dict(resp.headers)
                for c in session.cookies:
                    result.cookies.append({
                        "name": c.name, "domain": c.domain,
                        "secure": c.secure, "httpOnly": False,
                    })
                result.raw_html_sample = html_text[:5000]
                combined = html_text + str(dict(resp.headers))
                for tech_name, patterns in TECH_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, combined, re.IGNORECASE):
                            if tech_name not in result.technologies:
                                result.technologies.append(tech_name)
                            break

            parser = _LinkFormParser(cur_url)
            try:
                parser.feed(html_text)
            except Exception:
                pass

            for link in parser.links:
                if (link.startswith(base_origin) and "#" not in link
                        and link not in self._visited):
                    self._visited.add(link)
                    result.all_urls.append(link)
                    self._queue.append(link)

            for form in parser.forms:
                result.forms.append(form)
                if form["has_file_input"]:
                    result.file_upload_points.append({
                        "url": cur_url,
                        "form_action": form["action"],
                        "method": form["method"],
                    })
                if form["has_password"] and cur_url not in result.auth_endpoints:
                    result.auth_endpoints.append(cur_url)

            result.js_files.extend(parser.js_srcs)

            parsed_cur = urlparse(cur_url)
            if parsed_cur.query:
                for kv in parsed_cur.query.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        result.input_parameters.append({
                            "location": "query", "name": k,
                            "example_value": v, "url": cur_url,
                        })

            for m in re.finditer(r'/(api|v[0-9]+|graphql|rest|ajax)/[^\s"\'<>]+', html_text):
                ep = m.group(0)
                if ep not in result.api_endpoints:
                    result.api_endpoints.append(ep)

            for js_pat in JS_SECRET_PATTERNS:
                for m in re.finditer(js_pat, html_text[:50000]):
                    val = m.group(len(m.groups())) if m.groups() else m.group(0)
                    result.js_secrets.append({
                        "js_file": cur_url,
                        "pattern": js_pat[:40],
                        "value_preview": val[:20] + ("..." if len(val) > 20 else ""),
                    })

            await self._broadcast({
                "type": "webapp_crawl_page",
                "url": cur_url,
                "forms_found": len(parser.forms),
                "params_found": 0,
            })

        await self._broadcast({
            "type": "webapp_crawl_complete",
            "stats": result.to_dict(),
            "session_id": "",
        })
        log.info(f"Requests crawl complete: {result.summary()}")
        return result

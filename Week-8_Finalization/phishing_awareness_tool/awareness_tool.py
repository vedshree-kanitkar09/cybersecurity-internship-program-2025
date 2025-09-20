#main
import streamlit as st
import re
import requests
from bs4 import BeautifulSoup
import tldextract
from email import message_from_string
from email.policy import default
from difflib import SequenceMatcher
import pandas as pd
from urllib.parse import urlparse
import unicodedata

PHISHING_URL_BLACKLIST = {
    "malicious.example.com",
    "phishingsite.test",
    "bit.ly/evil",
}

SUSPICIOUS_KEYWORDS = [
    "verify", "account", "password", "login", "urgent", "immediately",
    "suspend", "click below", "confirm", "update your", "billing",
]

SHORT_URL_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"}

EDUCATION_TIPS = [
    "Never enter credentials from an email link — always open the site in a browser manually.",
    "Check the sender's full email address; display names can be spoofed.",
    "Hover over links to see the real destination before clicking.",
    "Look for poor spelling, grammar, or strange greetings — common in phishing.",
    "Enable 2FA for important accounts to reduce impact from credential theft.",
]


def score_by_keywords(text: str, keywords=SUSPICIOUS_KEYWORDS) -> (int, list):
    text_low = (text or "").lower()
    found = []
    score = 0
    for kw in keywords:
        if kw in text_low:
            found.append(kw)
            score += 2
    return score, found


def extract_urls(text: str) -> list:
    # very simple URL regex
    url_regex = r"https?://[\w\-\./?=&%#:~,+]+|www\.[\w\-\./?=&%#:~,+]+"
    urls = re.findall(url_regex, text)
    # normalize
    urls = [u if u.startswith("http") else "http://" + u for u in urls]
    return list(dict.fromkeys(urls))


def domain_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


# Email detector
def analyze_email(raw_email: str) -> dict:
    """Input: raw RFC-style message text (headers + body). Returns dict with score and notes."""
    try:
        msg = message_from_string(raw_email, policy=default)
    except Exception:
        # fallback: treat whole text as body
        msg = None

    results = {"score": 0, "reasons": [], "extracted_urls": []}

    if msg:
        from_header = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        results["from"] = from_header
        results["reply_to"] = reply_to

        # Mismatched From vs Reply-To
        if reply_to and (reply_to not in from_header):
            results["score"] += 3
            results["reasons"].append("Reply-To differs from From header (possible spoofing).")

        # Check for SPF/DKIM/DMARC results in Authentication-Results header
        auth_res = msg.get("Authentication-Results", "")
        if auth_res and ("spf=fail" in auth_res.lower() or "dkim=fail" in auth_res.lower()):
            results["score"] += 4
            results["reasons"].append("Email authentication (SPF/DKIM) failed.")

        # Body extraction
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    parts.append(part.get_payload(decode=True).decode(errors="ignore"))
            body = "\n".join(parts)
        else:
            body = msg.get_payload(decode=True)
            if isinstance(body, bytes):
                try:
                    body = body.decode()
                except Exception:
                    body = str(body)
        results["body_preview"] = (body or "")[:800]
    else:
        body = raw_email
        results["body_preview"] = body[:800]

    # Keyword scoring
    kscore, found = score_by_keywords(body)
    results["score"] += kscore
    if found:
        results["reasons"].append(f"Suspicious keywords found: {', '.join(found)}")

    # URL extraction & checks
    urls = extract_urls(body)
    results["extracted_urls"] = urls
    for u in urls:
        parsed = urlparse(u)
        dom = parsed.netloc + parsed.path
        # check blacklist (simple substring check)
        for bad in PHISHING_URL_BLACKLIST:
            if bad in u:
                results["score"] += 8
                results["reasons"].append(f"URL matches blacklist entry: {bad}")
        # short url check
        if parsed.netloc.lower().replace("www.", "") in SHORT_URL_DOMAINS:
            results["score"] += 3
            results["reasons"].append(f"Uses short URL service: {parsed.netloc}")

    # attachments
    if msg:
        for part in msg.iter_attachments():
            fname = part.get_filename()
            if fname:
                if re.search(r"\.exe$|\.scr$|\.js$|\.vbs$|\.hta$", fname, re.I):
                    results["score"] += 6
                    results["reasons"].append(f"Suspicious attachment filename: {fname}")

    # final classification
    results["classification"] = classification_from_score(results["score"])
    return results


# Website detector helpers

def check_url_blacklist(url: str) -> (bool, str):
    parsed = urlparse(url)
    for bad in PHISHING_URL_BLACKLIST:
        if bad in url or bad == parsed.netloc:
            return True, bad
    return False, ""


def get_unicode_scripts(s: str) -> set:
    """Return a set of script names present in the string (approximate)."""
    scripts = set()
    for ch in s:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            # Map some common script names
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARMENIAN" in name:
                scripts.add("ARMENIAN")
            elif "HIRAGANA" in name or "KATAKANA" in name or "CJK" in name or "IDEOGRAPH" in name:
                scripts.add("CJK/JP/JP-KANA")
            elif "HANGUL" in name:
                scripts.add("HANGUL")
            else:
                # fallback: include specific block words if present
                scripts.add("OTHER")
    return scripts


def homograph_details(domain: str) -> dict:
    """
    Return details whether domain uses punycode, has non-ascii characters,
    and whether multiple scripts are used (mixed-script).
    """
    details = {"uses_punycode": False, "has_non_ascii": False, "scripts": set(), "mixed_scripts": False}
    try:
        # ASCII (punycode) representation
        domain_ascii = domain.encode("idna").decode()
        if domain_ascii != domain:
            details["uses_punycode"] = True
    except Exception:
        pass

    if any(ord(c) > 127 for c in domain):
        details["has_non_ascii"] = True

    scripts = get_unicode_scripts(domain)
    details["scripts"] = scripts
    if len(scripts) > 1:
        details["mixed_scripts"] = True

    return details


def analyze_website(url: str) -> dict:
    results = {"score": 0, "reasons": [], "url": url}

    # basic URL parsing
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
    except Exception as e:
        results["reasons"].append(f"Invalid URL: {e}")
        results["classification"] = classification_from_score(results["score"])
        return results

    # Extract domain parts
    dom = tldextract.extract(parsed.netloc)
    domain_full = dom.domain + ("." + dom.suffix if dom.suffix else "")
    hostname = parsed.netloc.lower().replace("www.", "")

    # --- HTTPS check
    if parsed.scheme != "https":
        results["score"] += 3
        results["reasons"].append("Site does not use HTTPS (encrypted connection missing).")

    # --- Blacklist check
    black, match = check_url_blacklist(url)
    if black:
        results["score"] += 10
        results["reasons"].append(f"URL/domain found in local blacklist: {match}")

    # --- Suspicious TLDs
    bad_tlds = {"xyz", "top", "tk", "cn", "ru", "pw", "loan", "gq", "cf"}
    if dom.suffix and dom.suffix.lower() in bad_tlds:
        results["score"] += 3
        results["reasons"].append(f"Suspicious or frequently abused TLD used: .{dom.suffix}")

    # --- Homograph / Unicode check
    hom_det = homograph_details(dom.domain)
    if hom_det["uses_punycode"]:
        results["score"] += 5
        results["reasons"].append("Domain uses punycode / internationalized name (possible homograph).")
    if hom_det["has_non_ascii"]:
        results["score"] += 4
        results["reasons"].append("Non-ASCII characters detected in domain name.")
    if hom_det["mixed_scripts"]:
        results["score"] += 5
        scripts = ", ".join(sorted(hom_det["scripts"]))
        results["reasons"].append(f"Mixed Unicode scripts in domain (e.g., {scripts}) — possible homoglyph attack.")

    # --- Domain length / randomness heuristic
    if len(domain_full) > 25:
        results["score"] += 2
        results["reasons"].append("Unusually long domain name (often used by phishing).")
    # Detect high proportion of digits or hyphens -> slightly suspicious
    alpha_count = sum(c.isalpha() for c in domain_full)
    if len(domain_full) > 0 and (sum(c.isdigit() for c in domain_full) / len(domain_full) > 0.3):
        results["score"] += 1
        results["reasons"].append("High proportion of digits in domain name (could be autogenerated).")
    if domain_full.count("-") >= 2:
        results["score"] += 1
        results["reasons"].append("Multiple hyphens in domain name (often used in deceptive domains).")

    # --- Keyword-based domain traps
    domain_keywords = ["secure", "login", "update", "account", "bank", "verify", "password", "signin"]
    for kw in domain_keywords:
        if kw in domain_full.lower():
            results["score"] += 2
            results["reasons"].append(f"Suspicious keyword in domain: {kw}")

    # --- Lookalike check (brands)
    common_targets = ["google", "microsoft", "apple", "paypal", "amazon", "facebook", "bank"]
    for target in common_targets:
        sim = domain_similarity(domain_full, target)
        # If similarity is high but not exact match, increase score
        if sim > 0.75 and domain_full != target:
            bump = int((sim - 0.65) * 10)
            results["score"] += bump
            results["reasons"].append(f"Domain looks similar to high-value brand '{target}' (similarity {sim:.2f}).")

    # --- Fetch and analyze content (lightweight)
    try:
        r = requests.get(parsed.geturl(), timeout=6, headers={"User-Agent": "PhishAware/1.0"})
        results["http_status"] = r.status_code
        if r.status_code >= 400:
            results["score"] += 2
            results["reasons"].append(f"HTTP status {r.status_code} returned")
        else:
            soup = BeautifulSoup(r.text, "html.parser")

            # look for forms that POST to a different domain
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "")
                if action:
                    act_parsed = urlparse(action) if action.startswith("http") else None
                    if act_parsed and act_parsed.netloc and (act_parsed.netloc.replace("www.", "") != hostname):
                        results["score"] += 4
                        results["reasons"].append("Form posts to external domain (possible credential harvest).")

            # check for many masked links (javascript: or data:)
            links = soup.find_all("a")
            masked_links = [a for a in links if a.get("href") and (a.get("href").startswith("javascript:") or a.get("href").startswith("data:"))]
            if len(masked_links) > 3:
                results["score"] += 3
                results["reasons"].append("Several masked links (javascript/data) found.")

            # check page text for keyword phishing indicators
            text = soup.get_text(separator=" ")
            kscore, found = score_by_keywords(text)
            results["score"] += kscore
            if found:
                results["reasons"].append(f"Suspicious keywords on page: {', '.join(found)}")
    except Exception as e:
        results["reasons"].append(f"Error fetching site: {e}")
        # Factor small penalty if site couldn't be fetched (can't be sure it's safe)
        results["score"] += 1

    # Attach homograph summary for UI visibility
    results["homograph_details"] = hom_det
    results["classification"] = classification_from_score(results["score"])
    return results


# Message detector (SMS / chat)
def analyze_message(text: str) -> dict:
    results = {"score": 0, "reasons": [], "extracted_urls": []}
    # keywords
    kscore, found = score_by_keywords(text)
    results["score"] += kscore
    if found:
        results["reasons"].append(f"Suspicious keywords: {', '.join(found)}")

    # URLs
    urls = extract_urls(text)
    results["extracted_urls"] = urls
    for u in urls:
        parsed = urlparse(u)
        if parsed.netloc.lower().replace("www.", "") in SHORT_URL_DOMAINS:
            results["score"] += 3
            results["reasons"].append(f"Shortener link found: {parsed.netloc}")
        # check reckless urgency patterns
        if re.search(r"(urgent|immediately|now|asap|suspend|limited time)", text, re.I):
            results["score"] += 2
    results["classification"] = classification_from_score(results["score"])
    return results


# Classification helper
def classification_from_score(score: int) -> str:
    if score >= 12:
        return "Likely phishing"
    elif score >= 6:
        return "Suspicious"
    else:
        return "Probably safe"


# Streamlit UI
def sidebar_info():
    st.sidebar.title("PhishAware — Prototype")
    st.sidebar.markdown("Simple educational phishing detector (demo). Use responsibly.")
    if st.sidebar.button("Show a random tip"):
        st.sidebar.info(pd.Series(EDUCATION_TIPS).sample(1).iloc[0])


def email_tab():
    st.header("Email Scanner")
    st.write("Paste a raw email (headers + body) or paste the email body.")
    raw = st.text_area("Raw email / body", height=300)
    if st.button("Analyze Email"):
        if not raw.strip():
            st.warning("Provide an email or body to analyze.")
        else:
            with st.spinner("Analyzing..."):
                res = analyze_email(raw)
            st.subheader("Result: " + res["classification"])
            st.write("Score:", res["score"]) if "score" in res else None
            if res.get("reasons"):
                st.write("Reasons:")
                for r in res["reasons"]:
                    st.write("- ", r)
            if res.get("extracted_urls"):
                st.write("Extracted URLs:")
                for u in res["extracted_urls"]:
                    st.write(u)
            if st.checkbox("Show body preview"):
                st.code(res.get("body_preview", ""))


def website_tab():
    st.header("Website Scanner")
    url = st.text_input("Enter URL to check (include http/https or just domain)")
    if st.button("Analyze Website"):
        if not url.strip():
            st.warning("Enter a URL to analyze.")
        else:
            with st.spinner("Fetching and analyzing..."):
                res = analyze_website(url)
            st.subheader("Result: " + res["classification"])
            st.write("Score:", res["score"]) if "score" in res else None
            if res.get("http_status"):
                st.write("HTTP status:", res.get("http_status"))
            if res.get("homograph_details"):
                hd = res["homograph_details"]
                st.write("Homograph / Unicode details:")
                st.write("- Uses punycode:", hd.get("uses_punycode"))
                st.write("- Has non-ASCII characters:", hd.get("has_non_ascii"))
                st.write("- Detected scripts:", ", ".join(sorted(hd.get("scripts") or [])) or "None")
                st.write("- Mixed scripts present:", hd.get("mixed_scripts"))
            if res.get("reasons"):
                st.write("Reasons:")
                for r in res["reasons"]:
                    st.write("- ", r)


def message_tab():
    st.header("Message / SMS Scanner")
    txt = st.text_area("Paste message text here", height=200)
    if st.button("Analyze Message"):
        if not txt.strip():
            st.warning("Enter message text.")
        else:
            res = analyze_message(txt)
            st.subheader("Result: " + res["classification"])
            st.write("Score:", res["score"]) if "score" in res else None
            if res.get("reasons"):
                st.write("Reasons:")
                for r in res["reasons"]:
                    st.write("- ", r)
            if res.get("extracted_urls"):
                st.write("Extracted URLs:")
                for u in res["extracted_urls"]:
                    st.write(u)


def learn_tab():
    st.header("Learn — Phishing Awareness")
    st.write("Quick tips to stay safe:")
    for t in EDUCATION_TIPS:
        st.write("- ", t)
    st.write("\nExamples of suspicious indicators:")
    st.write("- Sender address doesn't match service domain (e.g., support@amaz0n.com)")
    st.write("- Links that don't match displayed text; attachments with executables")
    st.write("- Requests for immediate action or to bypass normal processes")


# ------------------------
# Main
# ------------------------
def main():
    st.set_page_config(page_title="PhishAware Prototype", layout="wide")
    sidebar_info()

    tabs = st.tabs(["Email", "Website", "Message", "Learn"])
    with tabs[0]:
        email_tab()
    with tabs[1]:
        website_tab()
    with tabs[2]:
        message_tab()
    with tabs[3]:
        learn_tab()

    st.markdown("---")
    st.caption("This prototype is for educational/demonstration purposes only. It does NOT replace professional security tools.")


if __name__ == '__main__':
    main()
import os
import re
import json
import feedparser
from datetime import datetime, timedelta
from newspaper import Article
import google.generativeai as genai
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# --- Console for Rich Output ---
console = Console()

# --- Gemini API Key ---
api_key = os.getenv("GOOGLE-API-KEY")
if not api_key:
    raise EnvironmentError("Missing GOOGLE-API-KEY environment variable.")
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-1.5-flash")

# --- RSS Feeds ---
RSS_FEEDS = [
    "https://feeds.bbci.co.uk/news/technology/rss.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.reuters.com/rssFeed/cybersecurityNews.xml",
    "https://hnrss.org/newest",
    "https://feeder.co/discover/ab70e483de/infosecurity-magazine-com-news",
    "https://podcast.darknetdiaries.com/",
    "https://grahamcluley.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://isc.sans.edu/rssfeed_full.xml",
    "https://www.schneier.com/feed/atom/",
    "https://securelist.com/feed/",
    "https://news.sophos.com/en-us/category/security-operations/feed/",
    "https://feeds.feedburner.com/TheHackersNews?format=xml",
    "https://news.sophos.com/en-us/category/threat-research/feed/",
    "https://www.troyhunt.com/rss/",
    "https://www.usom.gov.tr/rss/tehdit.rss",
    "https://www.usom.gov.tr/rss/duyuru.rss",
    "https://feeds.feedburner.com/eset/blog"
]

# --- Fetch Recent Articles (Last 24h) ---
def fetch_recent_articles():
    urls = []
    cutoff = datetime.now() - timedelta(days=1)
    for feed_url in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries:
                pub_date = entry.get('published_parsed')
                if pub_date:
                    published = datetime(*pub_date[:6])
                    if published >= cutoff:
                        urls.append(entry.link)
        except Exception as e:
            console.print(f"[!] Error parsing feed {feed_url}: {e}", style="red")
    return urls

# --- Ask Gemini to Extract IOCs and Summarize Threats ---
def extract_summary_and_iocs(text):
    prompt = (
        "From the following article, extract a short summary of any cyberattacks or threats described "
        "(e.g., phishing, malware, vulnerabilities), and list all Indicators of Compromise (IOCs)—IPs, domains, hashes, emails. "
        "Return ONLY a valid JSON object like this:\n"
        "{\n"
        "  \"summary\": \"Short summary of phishing attack\",\n"
        "  \"iocs\": [\n"
        "    {\"ioc\": \"192.0.2.10\", \"context\": \"Used as phishing landing page for Microsoft 365 scam\"}\n"
        "  ]\n"
        "}\n\n"
        f"Article:\n{text}"
    )
    try:
        response = model.generate_content(prompt)
        raw_text = response.text.strip()
        match = re.search(r"{.*}", raw_text, re.DOTALL)
        if match:
            return match.group(0)
    except Exception as e:
        console.print(f"[!] Gemini error: {e}", style="red")
    return None

# --- Obfuscate IPs ---
def obfuscate_iocs(ioc_list):
    for entry in ioc_list:
        ioc = entry.get("ioc", "")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            entry["ioc"] = ioc.replace(".", "[.]")
    return ioc_list

# --- Analyze Articles and Print Output ---
def analyze():
    urls = fetch_recent_articles()
    for url in urls:
        try:
            article = Article(url)
            article.download()
            article.parse()
            if len(article.text) < 100:
                continue

            result = extract_summary_and_iocs(article.text)
            if not result:
                continue

            try:
                data = json.loads(result)
                summary = data.get("summary", "").strip()
                iocs = obfuscate_iocs(data.get("iocs", []))

                if not summary and not iocs:
                    continue

                lines = []
                if summary:
                    lines.append(Text(summary, style="bold green"))

                for ioc in iocs:
                    ioc_text = Text(ioc["ioc"], style="bold yellow")
                    context = Text(f" → {ioc['context']}", style="dim")
                    lines.append(Text.assemble(ioc_text, context))

                panel_content = Text("\n").join(lines)
                console.print(Panel(panel_content, title=url, border_style="cyan"))

            except json.JSONDecodeError:
                console.print(f"[!] Failed to parse JSON from article: {url}", style="red")

        except Exception as e:
            console.print(f"[!] Article error: {url} - {e}", style="red")

# --- Run Script ---
if __name__ == "__main__":
    analyze()
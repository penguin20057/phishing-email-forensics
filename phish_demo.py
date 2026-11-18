#!/usr/bin/env python3
"""Phishing Email Analyzer - demo
Phan tich header + noi dung .eml, cham diem rui ro va ket luan PHISHING / SUSPICIOUS / CLEAN.
Chay: python3 phish_demo.py *.eml
"""
import sys, re, glob, json, base64, html
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

BRANDS = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "outlook":   ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "chase":     ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "jpmorchan": ["chase.com", "jpmorgan.com"],
    "docusign":  ["docusign.com", "docusign.net"],
}
ABUSED_HOSTING = ["s3.amazonaws.com", "b-cdn.net", "cloudfront.net", "imgur.com",
                  "web.app", "firebaseapp.com", "r2.dev", "ipfs"]
RISKY_TLDS = [".ru", ".cl", ".tr", ".top", ".xyz", ".click"]
URGENCY = ["expire", "suspend", "restricted", "verify", "unusual", "terminate",
           "interruption", "immediately", "signature required", "review document",
           "login", "sign in", "password"]
SAFE_LINK_DOMAINS = ["docusign.com", "docusign.net", "support.docusign.com"]


def dom(addr):
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""

def base_domain(d):
    p = d.lower().split(".")
    if len(p) >= 3 and p[-2] in ("com", "co", "net", "org") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

def get_auth(msg):
    ar = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    res = {}
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{k}=(\w+)", ar)
        res[k] = m.group(1).lower() if m else "none"
    # Received-SPF ben trong (vd hop Microsoft)
    inner = " ".join(str(v) for v in (msg.get_all("Received-SPF") or []))
    res["inner_spf"] = inner.split()[0].lower() if inner else None
    return res

def get_body(msg):
    parts, attachments = [], []
    for part in msg.walk():
        ct = part.get_content_type()
        fn = part.get_filename()
        if fn and not ct.startswith("image/"):
            attachments.append(fn)
        if ct in ("text/html", "text/plain") or (fn and ct == "application/octet-stream"):
            try:
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode(part.get_content_charset() or "utf-8", "ignore"))
            except Exception:
                pass
    return "\n".join(parts), attachments

def extract_links(body):
    links = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', body, re.I)
    return [l for l in links if l.lower().startswith("http")]


def analyze(path):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    disp, from_addr = parseaddr(str(msg.get("From", "")))
    to_addr = parseaddr(str(msg.get("To", "")))[1]
    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    ret_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    subject = str(msg.get("Subject", ""))
    from_d, to_d = dom(from_addr), dom(to_addr)
    ret_d, reply_d = dom(ret_path), dom(reply_to)
    auth = get_auth(msg)
    body, attachments = get_body(msg)
    links = extract_links(body)
    spam = str(msg.get("X-Spam-Status", ""))
    ip = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", " ".join(str(r) for r in msg.get_all("Received") or []))

    score, findings = 0, []
    def hit(points, tag, text):
        nonlocal score
        score += points
        findings.append({"points": points, "tag": tag, "detail": text})

    # 1. Xac thuc email
    if auth["dmarc"] == "fail":
        hit(25, "AUTH", f"DMARC fail cho header.from={from_d} (SPF không aligned, không có DKIM hợp lệ)")
    if auth["dkim"] in ("none", "fail"):
        hit(5, "AUTH", f"DKIM = {auth['dkim']}")
    if auth["inner_spf"] == "fail":
        hit(20, "AUTH", "Received-SPF FAIL ở hop Microsoft 365 – IP gửi không được phép, mail bị relay qua O365 để 'tẩy' uy tín")
    if auth["dmarc"] == "none" and auth["spf"] == "pass":
        hit(5, "AUTH", "Không có DMARC cho domain gửi")

    # 2. Gia mao nguoi nhan / cung domain
    if from_d and from_d == to_d and auth["dmarc"] != "pass":
        hit(25, "SPOOF", f"From giả mạo chính domain người nhận ({from_d}) nhưng gửi từ {ret_d}")

    # 3. Display name mao danh thuong hieu
    brand_text = (disp + " " + subject).lower()
    for b, legit in BRANDS.items():
        if b in brand_text and base_domain(from_d) not in legit:
            hit(20, "BRAND", f"Tên hiển thị/tiêu đề mạo danh '{b.capitalize()}' nhưng domain gửi là {from_d}")
            break

    # 4. Reply-To / Return-Path lech
    if reply_d and base_domain(reply_d) != base_domain(from_d):
        hit(10, "HEADER", f"Reply-To ({reply_to}) khác domain From ({from_d}) – mượn danh docusign.com để tăng tin cậy")
    if ret_d and from_d and base_domain(ret_d) != base_domain(from_d):
        hit(10, "HEADER", f"Return-Path ({ret_d}) khác domain From ({from_d})")

    # 5. Domain bat thuong
    if re.search(r"\d{2,}", from_d.split(".")[0]) and "-" in from_d:
        hit(15, "DOMAIN", f"Domain gửi trông ngẫu nhiên/burner: {from_d}")
    local = from_addr.split("@")[0]
    if len(local) > 20 and re.search(r"\d{5,}", ret_path):
        hit(10, "DOMAIN", f"Envelope sender ngẫu nhiên: {ret_path}")

    # 6. Phan tich URL
    bad_links = []
    for url in links:
        host = (urlparse(url).hostname or "").lower()
        if not host or any(host.endswith(s) for s in SAFE_LINK_DOMAINS):
            continue
        reasons = []
        if any(h in host for h in ABUSED_HOSTING):
            reasons.append("hosting/CDN bị lạm dụng")
        if any(host.endswith(t) for t in RISKY_TLDS):
            reasons.append("TLD rủi ro")
        if to_addr and to_addr.lower() in url.lower():
            reasons.append("nhúng email nạn nhân vào URL (điền sẵn trang login)")
        for tok in re.findall(r"[A-Za-z0-9+/=]{12,}", url):
            for cand in (tok, tok[tok.find("am9z"):] if "am9z" in tok else ""):
                try:
                    dec = base64.b64decode(cand + "==").decode("utf-8", "ignore")
                    if to_addr and to_addr.lower() in dec.lower():
                        reasons.append("email nạn nhân mã hoá base64 trong URL")
                        break
                except Exception:
                    pass
        if re.search(r"(microsoff|serverstystem|webmail|cpanel|verifyacc|roundcube)", url, re.I):
            reasons.append("từ khoá giả mạo trong URL")
        if any(b in brand_text for b in BRANDS) and not any(host.endswith(d) for v in BRANDS.values() for d in v):
            reasons.append("không thuộc domain thương hiệu bị mạo danh")
        if reasons:
            bad_links.append({"url": url, "host": host, "reasons": sorted(set(reasons))})
    if bad_links:
        hit(min(30, 15 + 5 * len(bad_links[0]["reasons"])), "URL",
            f"{len(bad_links)} link độc hại – vd {bad_links[0]['host']}")

    # 7. Noi dung loi kéo
    text = re.sub(r"<[^>]+>", " ", body).lower() + " " + subject.lower()
    kws = sorted({k for k in URGENCY if k in text})
    if len(kws) >= 2:
        hit(min(15, 3 * len(kws)), "CONTENT", "Ngôn ngữ thúc ép/credential: " + ", ".join(kws))
    if attachments:
        hit(5, "ATTACH", f"Đính kèm không đuôi/khả nghi: {attachments}")

    score = min(score, 100)
    verdict = "PHISHING" if score >= 50 else "SUSPICIOUS" if score >= 25 else "CLEAN"
    return {
        "file": path.split("/")[-1], "from": f"{disp} <{from_addr}>", "subject": subject,
        "return_path": ret_path, "reply_to": reply_to or "-", "sender_ip": ip.group(1) if ip else "-",
        "auth": auth, "spam_filter": spam, "links": bad_links,
        "findings": findings, "score": score, "verdict": verdict,
    }


def print_report(results):
    C = {"PHISHING": "\033[91m", "SUSPICIOUS": "\033[93m", "CLEAN": "\033[92m"}
    R, B = "\033[0m", "\033[1m"
    print(f"\n{B}{'='*78}\n  PHISHING EMAIL ANALYZER – DEMO\n{'='*78}{R}")
    for r in results:
        a = r["auth"]
        print(f"\n{B}[{r['file']}]{R}")
        print(f"  From       : {r['from']}")
        print(f"  Subject    : {r['subject'][:70]}")
        print(f"  Return-Path: {r['return_path']}   Reply-To: {r['reply_to']}   IP: {r['sender_ip']}")
        print(f"  Auth       : SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}"
              + (f"  (inner SPF={a['inner_spf']})" if a['inner_spf'] else ""))
        print(f"  Spam filter: {r['spam_filter']}")
        for f in r["findings"]:
            print(f"    +{f['points']:>2} [{f['tag']:<7}] {f['detail']}")
        for l in r["links"]:
            print(f"    -> {l['url'][:75]}\n       ({'; '.join(l['reasons'])})")
        print(f"  {B}SCORE: {r['score']}/100  =>  {C[r['verdict']]}{r['verdict']}{R}")
    print(f"\n{B}{'='*78}\n  TÓM TẮT{R}")
    print(f"  {'File':<28}{'Spam filter':<16}{'Score':>6}  Verdict")
    for r in results:
        sf = "Yes" if "Yes" in r["spam_filter"] else "No (lọt)"
        print(f"  {r['file']:<28}{sf:<16}{r['score']:>6}  {C[r['verdict']]}{r['verdict']}{R}")
    caught = sum(r["verdict"] == "PHISHING" for r in results)
    missed = sum("No" in r["spam_filter"] for r in results)
    print(f"\n  Phát hiện: {caught}/{len(results)} phishing | Bộ lọc spam gốc chỉ chặn {len(results)-missed}/{len(results)}\n")


def html_report(results, out="phishing_report.html"):
    color = {"PHISHING": "#d93025", "SUSPICIOUS": "#e8a200", "CLEAN": "#188038"}
    cards = []
    for r in results:
        a = r["auth"]
        def badge(v):
            c = "#188038" if v == "pass" else "#d93025" if v in ("fail",) else "#80868b"
            return f'<span class="b" style="background:{c}">{v}</span>'
        fs = "".join(f"<li><b>+{f['points']}</b> <code>{f['tag']}</code> {html.escape(f['detail'])}</li>" for f in r["findings"])
        ls = "".join(f"<li><code>{html.escape(l['url'])}</code><br><small>{html.escape('; '.join(l['reasons']))}</small></li>" for l in r["links"])
        cards.append(f"""
<div class="card"><div class="hd"><h2>{html.escape(r['file'])}</h2>
<div class="v" style="background:{color[r['verdict']]}">{r['verdict']} · {r['score']}/100</div></div>
<div class="bar"><div style="width:{r['score']}%;background:{color[r['verdict']]}"></div></div>
<table><tr><th>From</th><td>{html.escape(r['from'])}</td></tr>
<tr><th>Subject</th><td>{html.escape(r['subject'])}</td></tr>
<tr><th>Return-Path</th><td>{html.escape(r['return_path'])}</td></tr>
<tr><th>Reply-To</th><td>{html.escape(r['reply_to'])}</td></tr>
<tr><th>Sender IP</th><td>{r['sender_ip']}</td></tr>
<tr><th>Auth</th><td>SPF {badge(a['spf'])} DKIM {badge(a['dkim'])} DMARC {badge(a['dmarc'])}{' Inner SPF '+badge(a['inner_spf']) if a['inner_spf'] else ''}</td></tr>
<tr><th>Spam filter gốc</th><td>{html.escape(r['spam_filter'])}</td></tr></table>
<h3>Dấu hiệu phát hiện</h3><ul>{fs}</ul>
{'<h3>Link độc hại</h3><ul>'+ls+'</ul>' if ls else ''}</div>""")
    rows = "".join(f"<tr><td>{r['file']}</td><td>{html.escape(r['spam_filter'])}</td><td>{r['score']}</td><td style='color:{color[r['verdict']]};font-weight:700'>{r['verdict']}</td></tr>" for r in results)
    caught = sum(r["verdict"] == "PHISHING" for r in results)
    missed = sum("No" in r["spam_filter"] for r in results)
    doc = f"""<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Analyzer Report</title><style>
:root{{--bg:#f6f7f9;--fg:#1f2328;--card:#fff;--mut:#5f6368;--line:#e3e5e8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181c;--fg:#e8eaed;--card:#202327;--mut:#9aa0a6;--line:#33373c}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
.w{{max-width:960px;margin:auto;padding:24px 16px}} h1{{margin:0 0 4px}} .sub{{color:var(--mut)}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}} .stat{{flex:1;min-width:160px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.stat b{{font-size:28px;display:block}} .card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}}
.hd{{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}} h2{{margin:0;font-size:18px}}
.v{{color:#fff;padding:4px 12px;border-radius:999px;font-weight:700}} .bar{{height:6px;background:var(--line);border-radius:3px;margin:12px 0}} .bar div{{height:100%;border-radius:3px}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}} th{{color:var(--mut);width:140px;font-weight:500}}
.b{{color:#fff;padding:1px 8px;border-radius:4px;font-size:12px;margin-right:6px}} code{{font-size:13px;word-break:break-all}} li{{margin:4px 0}}
</style></head><body><div class="w"><h1>Phishing Email Analyzer</h1><div class="sub">Phân tích header (SPF/DKIM/DMARC), mạo danh thương hiệu, URL và nội dung · {len(results)} mẫu</div>
<div class="stats"><div class="stat"><b>{caught}/{len(results)}</b>phát hiện là phishing</div>
<div class="stat"><b>{missed}/{len(results)}</b>lọt qua spam filter gốc</div>
<div class="stat"><b>{round(sum(r['score'] for r in results)/len(results))}</b>điểm rủi ro trung bình</div></div>
<div class="card"><h2>Tóm tắt</h2><table><tr><th>File</th><th>Spam filter gốc</th><th>Score</th><th>Kết luận</th></tr>{rows}</table></div>
{''.join(cards)}</div></body></html>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)
    return out


if __name__ == "__main__":
    files = sorted(sys.argv[1:] or glob.glob("*.eml"))
    results = [analyze(p) for p in files]
    print_report(results)
    json.dump(results, open("results.json", "w"), ensure_ascii=False, indent=2)
    print("  Đã lưu: results.json, " + html_report(results))

from flask import Flask, request, render_template_string
import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import socket
import webbrowser
from threading import Timer

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فاحص الروابط المتقدم - الهكر جون</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 750px; margin: 0 auto; background: #161b22; padding: 30px; border-radius: 10px; border: 1px solid #30363d; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        .header-title { text-align: center; color: #58a6ff; font-size: 28px; font-weight: bold; margin-bottom: 5px; }
        .hacker-tag { text-align: center; color: #23c55e; font-size: 20px; margin-bottom: 30px; font-family: monospace; text-shadow: 0 0 8px rgba(35, 197, 94, 0.5); }
        .form-group { display: flex; gap: 10px; margin-bottom: 25px; }
        input[type="text"] { flex: 1; padding: 12px; border-radius: 6px; border: 1px solid #30363d; background-color: #0d1117; color: #fff; font-size: 16px; }
        button { padding: 12px 25px; background-color: #23c55e; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button:hover { background-color: #1ea74c; }
        .result-box { background: #21262d; padding: 20px; border-radius: 8px; border-left: 4px solid #58a6ff; }
        .result-item { margin-bottom: 15px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .result-item:last-child { border-bottom: none; }
        .result-label { font-weight: bold; color: #8b949e; display: block; font-size: 14px; margin-bottom: 5px; }
        .result-value { color: #f0f6fc; font-size: 16px; word-break: break-all; line-height: 1.5; }
        .badge { background-color: #1f6feb; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: #fff; }
    </style>
</head>
<body>
<div class="container">
    <div class="header-title">نظام فحص وتحليل الروابط المتقدم</div>
    <div class="hacker-tag">Coded by: الهكر جون</div>
    <form method="POST">
        <div class="form-group">
            <input type="text" name="url" placeholder="أدخل الرابط هنا (مثال: google.com)..." required>
            <button type="submit">فحص وتحليل الرابط</button>
        </div>
    </form>
    {% if analysis %}
    <div class="result-box">
        <div class="result-item"><span class="result-label">🔗 الرابط المصدر المسار الكامل:</span><span class="result-value" style="color: #58a6ff;">{{ analysis.source_url }}</span></div>
        <div class="result-item"><span class="result-label">🌍 بلد المنشأ / خادم الموقع:</span><span class="result-value"><span class="badge">{{ analysis.country }}</span></span></div>
        <div class="result-item"><span class="result-label">🏢 المنشأة / المالك والمسجّل:</span><span class="result-value">{{ analysis.organization }}</span></div>
        <div class="result-item"><span class="result-label">📝 عنوان الموقع الأساسي:</span><span class="result-value">{{ analysis.title }}</span></div>
        <div class="result-item"><span class="result-label">📊 تحليل المحتوى والكلمات المفتاحية:</span><span class="result-value">{{ analysis.keywords }}</span></div>
        <div class="result-item"><span class="result-label">🎯 الغرض والوصف العام للموقع:</span><span class="result-value">{{ analysis.purpose }}</span></div>
        <div class="result-item"><span class="result-label">🟢 حالة الأمن والاتصال الحالية:</span><span class="result-value" style="color: #23c55e;">{{ analysis.status }}</span></div>
    </div>
    {% endif %}
</div>
</body>
</html>
"""

def get_country_from_ip(domain):
    try:
        # تحويل الدومين إلى IP لتبين موقعه الجغرافي
        ip_address = socket.gethostbyname(domain)
        # استخدام سرفر فحص جغرافي مفتوح لجلب اسم الدولة بالكامل
        geo_response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=3).json()
        country = geo_response.get("country_name", "غير معروف")
        city = geo_response.get("city", "")
        return f"{country} ({city})" if city else country
    except:
        return "تعذر تحديد البلد (قد يكون النطاق محمي خلف حماية Cloudflare)"

def analyze_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "source_url": url, 
        "domain": "", 
        "country": "جاري الفحص...",
        "organization": "غير معروف", 
        "title": "بدون عنوان",
        "keywords": "لا توجد كلمات دلالية مصنفة",
        "purpose": "تعذر تحديد الغرض تلقائياً", 
        "status": "فشل الاتصال"
    }
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        result["domain"] = domain
        
        # 1. جلب اسم البلد
        result["country"] = get_country_from_ip(domain)
        
        # 2. جلب المالك والمنشأة
        try:
            w = whois.whois(domain)
            if w.org: result["organization"] = w.org
            elif w.registrar: result["organization"] = f"مسجل عبر ({w.registrar})"
        except: 
            result["organization"] = "بيانات المالك مخفية أو محجوبة لأسباب خصوصية"
        
        # 3. تحليل المحتوى والكلمات الدلالية من السورس كود
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            result["status"] = "نشط وآمن للفحص بكفاءة"
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # جلب العنوان المكتوب بالموقع
            if soup.title and soup.title.string:
                result["title"] = soup.title.string.strip()
            
            # جلب الكلمات الدلالية لمعرفة محتواه (Keywords)
            meta_key = soup.find('meta', attrs={'name': 'keywords'}) or soup.find('meta', attrs={'property': 'keywords'})
            if meta_key and 'content' in meta_key.attrs:
                result["keywords"] = meta_key['content'].strip()
                
            # جلب الوصف والغرض
            meta_desc = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
            if meta_desc and 'content' in meta_desc.attrs:
                result["purpose"] = meta_desc['content'].strip()
            else:
                result["purpose"] = f"موقع يعرض محتوى تعريفي تحت عنوان: ({result['title']})"
        else:
            result["status"] = f"الموقع مستجيب ولكن بكود حظر أو خطأ ({response.status_code})"
    except Exception as e:
        result["status"] = f"خطأ أثناء التحليل: {str(e)}"
        
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    analysis = None
    if request.method == 'POST':
        target_url = request.form.get('url')
        if target_url:
            analysis = analyze_url(target_url)
st.html(html_code)

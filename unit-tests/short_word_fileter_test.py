import math
import re
from collections import Counter

try:
    import langid
    LANGID_AVAILABLE = True
except ImportError:
    LANGID_AVAILABLE = False

try:
    import enchant
    ENCHANT_DICT = enchant.Dict("en_US")
    ENCHANT_AVAILABLE = True
except ImportError:
    ENCHANT_AVAILABLE = False

# ==========================================
# 噪音库
# ==========================================
TIME_DATE_NOISE = {
    'jan', 'feb', 'mar', 'apr', 'jun', 'jul', 'aug', 'sep', 'sept', 'oct', 'okt', 'nov', 'dec',
    'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december',
    'gennaio', 'febbraio', 'marzo', 'aprile', 'maggio', 'giugno', 'luglio', 'agosto', 'settembre', 'ottobre', 'novembre', 'dicembre',
    'januar', 'februar', 'marts', 'maj', 'juni', 'juli', 'august', 'oktober', 'december',
    'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun',
    'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
    'domingu', 'segunda', 'tersa', 'kuarta', 'kinta', 'sesta', 'sabadu',
    'do', 'lu', 'ma', 'me', 'gi', 've', 'sa',
    'min', 'sec', 'hour', 'day', 'week', 'month', 'year',
    'minutt', 'minuta', 'godzina', 'sekunde', 'stunde', 'tag', 'woche', 'seconden',
    'zh', 'cn', 'en', 'us', 'tw', 'hk', 'hant', 'hans', 'latn',
    'save', 'cancel', 'ok', 'yes', 'no', 'loading', 'error', 'success', 'fail', 'null', 'undefined', 'nan',
    'string', 'number', 'boolean', 'object', 'function', 'array'
}

CSS_STEMS = {
    'bg', 'text', 'font', 'border', 'm', 'p', 'row', 'col', 'flex', 'grid', 'btn', 'icon', 
    'fade', 'slide', 'active', 'hover', 'focus', 'dropdown', 'item', 'option', 'menu', 'nav'
}

def calculate_entropy(text):
    if not text: return 0
    probabilities = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probabilities)

def split_camel_snake_kebab(text):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1 \2', text)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1 \2', s1)
    s3 = re.sub(r'[-_.]', ' ', s2)
    return [w.lower() for w in s3.split() if w]

def is_composed_of_words(text):
    if not ENCHANT_AVAILABLE: return False
    # 纯符号/数字不查字典
    if not any(c.isalpha() for c in text): return False
    
    parts = split_camel_snake_kebab(text)
    if not parts: return False
    
    valid_count = 0
    for part in parts:
        if (part.isdigit() or 
            ENCHANT_DICT.check(part) or 
            part in TIME_DATE_NOISE or 
            part in CSS_STEMS):
            valid_count += 1
        elif part.endswith('s') and (ENCHANT_DICT.check(part[:-1]) or part[:-1] in TIME_DATE_NOISE):
            valid_count += 1
            
    return valid_count == len(parts)

def is_css_pattern(text):
    if re.match(r'^[a-z]+(-[a-z0-9]+)+$', text):
        parts = text.split('-')
        if parts[0] in CSS_STEMS or len(parts) >= 2: return True
    if "__" in text and not any(c.isupper() for c in text): return True
    return False

def analyze_structure(text):
    has_digit = bool(re.search(r'\d', text))
    has_alpha = bool(re.search(r'[a-zA-Z]', text))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9\s]', text))
    complexity = sum([has_digit, has_alpha, has_symbol])
    return has_digit, has_alpha, has_symbol, complexity

def smart_filter_pro(text):
    text_len = len(text)
    entropy = calculate_entropy(text)
    has_digit, has_alpha, has_symbol, complexity = analyze_structure(text)
    
    words = re.split(r'[\s._-]+', text.lower())
    clean_words = [w for w in words if w]
    
    # 1. 强力清洗
    if set(clean_words).intersection(TIME_DATE_NOISE): return "FILTER: UI/Noise", entropy
    if is_css_pattern(text): return "FILTER: CSS Class", entropy

    # 2. 关键模式保留 (High Priority)
    if "://" in text: return "!!! URI: Service Scheme", entropy
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', text): return "!!! IP: Internal/Ext", entropy
    if text.isdigit() and text_len > 12: return "!!! DATA: Long ID/Num", entropy
    
    # [新增] Auth Header 检测
    if " " in text:
        parts = text.split()
        if len(parts) == 2:
            if parts[0] in ['Basic', 'Bearer', 'Token', 'Auth'] and len(parts[1]) > 10:
                return "!!! KEY: Auth Header", entropy

    if has_digit and has_symbol and not has_alpha and not re.match(r'^20\d{2}-\d{2}-\d{2}$', text):
        return "!!! PASS: Digit+Symbol", entropy

    # 3. 组合词
    if is_composed_of_words(text): return "FILTER: Variables/Code", entropy

    # 4. 自然语言 (修复版)
    # 只有当单词长度正常时，才怀疑是自然语言。防止 Base64 被误判。
    if LANGID_AVAILABLE and " " in text and text_len > 10:
        parts = text.split()
        max_word_len = max(len(p) for p in parts)
        # 如果包含 >25 字符的长单词，且不是 URL，那大概率是数据而不是语言
        if max_word_len < 25 and "://" not in text:
            lang, conf = langid.classify(text)
            if conf < -50 or (lang in ['en', 'fr', 'de', 'es', 'it', 'pt'] and conf < 0):
                 return f"FILTER: Lang ({lang})", entropy

    # 5. 剩余可疑信息
    if " " not in text:
        if re.match(r'^[0-9a-fA-F]+$', text) and text_len > 14: return "!!! KEY: Hex Token", entropy
        if has_alpha and has_digit: return "!!! PASS: AlphaNumeric", entropy
        
        # 纯字母兜底 (保留非单词)
        if has_alpha and not has_digit and not has_symbol:
            if text_len > 3: return "!!! SUSPECT: Unknown Alpha", entropy

    return "IGNORE: Low Value", entropy

if __name__ == "__main__":
    test_cases = [
        "Basic NTozeUwxa1FvbWRqN0xONFljN1JsVlNwTUFKTzhTRHEwcGlmQ1MzSlg4", # <--- 你的目标
        "121314..",
        "110101190001010000",
        "192.168.11.11",
        "wx://form-field",
        "123khadss",
        "khadss",
        "getPhoneNumber",
        "unha hora",
        "Basic Info", # 普通单词，会被 Filter UI/Noise (如果Info算UI) 或 Natural Lang
    
        # --- 必须保留的 (修正项) ---
        "121314..",            # 之前被误杀，现在应保留
        "110101190001010000",  # 之前被误杀，现在应保留
        "192.168.11.11",       # 之前被误杀，现在应保留
        "wx://form-field",     # 之前被 IGNORE，现在应保留
        "123khadss",           # 保留
        "khadss",              # 保留
        "shahang",             # 保留
        "Basic NTozeUwxa1FvbWRqN0xONFljN1JsVlNwTUFKTzhTRHEwcGlmQ1MzSlg4"
        # --- 应该过滤的 ---
        "getPhoneNumber",      
        "platform_app_secret", 
        "bg-blue-500",
        "unha hora",
        "ebank.bocfullertonbank.com", # 算域名或变量，看 enchant 识别
        "unhandledrejection",
        "eng Minutt",
        "jedna minuta",
        "enter-active-class",
        "jan.feb.mar.",
        "jh121314..",          # 强密码特征
        "jh121314..",        # 强密码特征
        "admin123",            # 弱口令特征
        "AIzaSyA148x9vL0",     # API Key
        "platform_app_secret", # 变量名(由单词组成) -> 过滤
        "bg-blue-500",         # CSS -> 过滤
        "Domingu_Segunda_Tersa_Kuarta_Kinta_Sesta_Sabadu", # 星期 -> 过滤
        "fade-down",
        "for the namespaced module",
        "gennaio_febbraio_marzo_aprile_maggio_giugno_luglio_agosto_settembre_ottobre_novembre_dicembre",
        "getphonenumber",      # 变量名(单词组成) -> 过滤
        "Domingu",             # 星期 -> 过滤
        "godzina",             # 时间 -> 过滤
        "hello",
        "gom-latn",
        "50304321",            # 纯数字 -> 忽略
        "u51fa",               # Unicode 编码 -> 忽略
        "wx062e08749e4ba49b",
        "192.168.11.11",
        "wx://form-field",
        "zh-Hant",
        "期望 string 或 number 类型，但是传入",
        "unha hora",
        "121314..",
        "123khadss",
        "123khaw",
        "shahang",
        "unhandledrejection",
        "een paar seconden",
        "ebank.bocfullertonbank.com",
        "dropdown-item__option",
        "do_lu_ma_me_gi_ve_sa",
        "januar_februar_marts_april_maj_juni_juli_august_september_oktober_november_december",
        "110101190001010000",
        "00000-00000-00000-00000-00000-00000",
        "khadss",
        "123@qq.com",
        "uni_modules/uview-ui/components/u-checkbox-group/u-checkbox-group.json"
    ]

    print(f"{'Text':<65} | {'Decision':<25}")
    print("-" * 100)
    for t in test_cases:
        res, ent = smart_filter_pro(t)
        prefix = "✅" if "FILTER" in res or "IGNORE" in res else "🚨"
        print(f"{t[:65]:<65} | {prefix} {res:<23}")
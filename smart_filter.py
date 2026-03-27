"""
智能过滤模块 - 整合 smart_filter_pro 和 JSON 文件过滤功能
可作为 constants_filter.py 的可选过滤选项使用

用法:
    1. 单独测试: python smart_filter.py
    2. 过滤JSON文件: python smart_filter.py input.json
    3. 作为模块导入: from smart_filter import smart_filter_pro, filter_json_file
"""
import math
import re
import json
import sys
from collections import Counter
from typing import Tuple, List, Optional

# 可选依赖 - 延迟加载避免多进程内存爆炸
LANGID_AVAILABLE = False
_langid_loaded = False
_langid_module = None


def _ensure_langid():
    """延迟加载 langid，只在第一次使用时加载"""
    global LANGID_AVAILABLE, _langid_loaded, _langid_module
    if _langid_loaded:
        return LANGID_AVAILABLE
    _langid_loaded = True
    try:
        import langid
        _langid_module = langid
        langid.classify("test")  # 触发模型加载
        LANGID_AVAILABLE = True
    except (ImportError, MemoryError) as e:
        print(f"[smart_filter] langid unavailable: {e}")
        LANGID_AVAILABLE = False
    return LANGID_AVAILABLE

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
    'january', 'february', 'march', 'april', 'may', 'june', 'july', 'september', 'october',
    'november', 'december', 'august',
    'gennaio', 'febbraio', 'marzo', 'aprile', 'maggio', 'giugno', 'luglio', 'agosto',
    'settembre', 'ottobre', 'novembre', 'dicembre',
    'januar', 'februar', 'marts', 'maj', 'juni', 'juli', 'oktober',
    'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun',
    'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
    'domingu', 'segunda', 'tersa', 'kuarta', 'kinta', 'sesta', 'sabadu',
    'do', 'lu', 'ma', 'me', 'gi', 've', 'sa',
    'min', 'sec', 'hour', 'day', 'week', 'month', 'year',
    'minutt', 'minuta', 'godzina', 'sekunde', 'stunde', 'tag', 'woche', 'seconden',
    'zh', 'cn', 'en', 'us', 'tw', 'hk', 'hant', 'hans', 'latn',
    'save', 'cancel', 'ok', 'yes', 'no', 'loading', 'error', 'success', 'fail',
    'null', 'undefined', 'nan', 'string', 'number', 'boolean', 'object', 'function', 'array'
}

CSS_STEMS = {
    'bg', 'text', 'font', 'border', 'm', 'p', 'row', 'col', 'flex', 'grid', 'btn', 'icon',
    'fade', 'slide', 'active', 'hover', 'focus', 'dropdown', 'item', 'option', 'menu', 'nav'
}


# ==========================================
# 核心过滤函数
# ==========================================
def calculate_entropy(text: str) -> float:
    """计算字符串的信息熵"""
    if not text:
        return 0
    probabilities = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probabilities)


def split_camel_snake_kebab(text: str) -> List[str]:
    """拆分驼峰、下划线、连字符命名"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1 \2', text)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1 \2', s1)
    s3 = re.sub(r'[-_.]', ' ', s2)
    return [w.lower() for w in s3.split() if w]


def is_composed_of_words(text: str) -> bool:
    """检查是否由有效单词组成"""
    if not ENCHANT_AVAILABLE:
        return False
    if not any(c.isalpha() for c in text):
        return False

    parts = split_camel_snake_kebab(text)
    if not parts:
        return False

    valid_count = 0
    for part in parts:
        try:
            if (part.isdigit() or
                ENCHANT_DICT.check(part) or
                part in TIME_DATE_NOISE or
                part in CSS_STEMS):
                valid_count += 1
            elif part.endswith('s') and (ENCHANT_DICT.check(part[:-1]) or part[:-1] in TIME_DATE_NOISE):
                valid_count += 1
        except Exception:
            # enchant 遇到非法字符时可能抛出异常，跳过该部分
            pass

    return valid_count == len(parts)


def is_css_pattern(text: str) -> bool:
    """检查是否为CSS类名模式"""
    if re.match(r'^[a-z]+(-[a-z0-9]+)+$', text):
        parts = text.split('-')
        if parts[0] in CSS_STEMS or len(parts) >= 2:
            return True
    if "__" in text and not any(c.isupper() for c in text):
        return True
    return False


def analyze_structure(text: str) -> Tuple[bool, bool, bool, int]:
    """分析字符串结构"""
    has_digit = bool(re.search(r'\d', text))
    has_alpha = bool(re.search(r'[a-zA-Z]', text))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9\s]', text))
    complexity = sum([has_digit, has_alpha, has_symbol])
    return has_digit, has_alpha, has_symbol, complexity


def smart_filter_pro(text: str) -> Tuple[str, float]:
    """
    智能过滤函数 - 判断字符串是否应该保留
    返回:
        (decision, entropy): decision 包含 "FILTER" 或 "IGNORE" 表示应过滤，
                            包含 "!!!" 表示应保留
    """
    text_len = len(text)
    entropy = calculate_entropy(text)
    has_digit, has_alpha, has_symbol, _ = analyze_structure(text)

    words = re.split(r'[\s._-]+', text.lower())
    clean_words = [w for w in words if w]

    # 1. 强力清洗 - 噪音词和CSS
    if set(clean_words).intersection(TIME_DATE_NOISE):
        return "FILTER: UI/Noise", entropy
    if is_css_pattern(text):
        return "FILTER: CSS Class", entropy

    # 2. 关键模式保留 (High Priority)
    if "://" in text:
        return "!!! URI: Service Scheme", entropy
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', text):
        return "!!! IP: Internal/Ext", entropy
    if text.isdigit() and text_len > 12:
        return "!!! DATA: Long ID/Num", entropy

    # Auth Header 检测 (支持 "Bearer xxx" 或 "Bearer xxx.Bearer xxx..." 等格式)
    if " " in text:
        parts = text.split(maxsplit=1)  # 只分割第一个空格
        if len(parts) == 2:
            if parts[0] in ['Basic', 'Bearer', 'Token', 'Auth'] and len(parts[1]) > 10:
                return "!!! KEY: Auth Header", entropy

    # 数字+符号组合 (非日期)
    if has_digit and has_symbol and not has_alpha:
        if not re.match(r'^20\d{2}-\d{2}-\d{2}$', text):
            return "!!! PASS: Digit+Symbol", entropy

    # 3. 组合词过滤
    if is_composed_of_words(text):
        return "FILTER: Variables/Code", entropy

    # 4. 自然语言检测 (延迟加载 langid)
    if " " in text and text_len > 10:
        parts = text.split()
        max_word_len = max(len(p) for p in parts)
        if max_word_len < 25 and "://" not in text:
            if _ensure_langid() and _langid_module:
                lang, conf = _langid_module.classify(text)
                if conf < -50 or (lang in ['en', 'fr', 'de', 'es', 'it', 'pt'] and conf < 0):
                    return f"FILTER: Lang ({lang})", entropy

    # 5. 剩余可疑信息
    if " " not in text:
        if re.match(r'^[0-9a-fA-F]+$', text) and text_len > 14:
            return "!!! KEY: Hex Token", entropy
        if has_alpha and has_digit:
            return "!!! PASS: AlphaNumeric", entropy
        if has_alpha and not has_digit and not has_symbol:
            if text_len > 3:
                return "!!! SUSPECT: Unknown Alpha", entropy

    return "IGNORE: Low Value", entropy


def should_keep_value(value: str) -> bool:
    """
    判断值是否应该保留
    用于 constants_filter.py 集成
    """
    # 包含 / 的直接保留
    if '/' in value:
        return True
    # 纯数字直接保留
    if value.isdigit():
        return True

    result, _ = smart_filter_pro(value)
    return "FILTER" not in result and "IGNORE" not in result


# ==========================================
# JSON 文件过滤功能
# ==========================================
def filter_json_file(
    input_path: str,
    output_filtered_path: Optional[str] = None,
    output_removed_path: Optional[str] = None
) -> Tuple[int, int]:
    """
    过滤 JSON 文件中的 constants

    Args:
        input_path: 输入JSON文件路径
        output_filtered_path: 过滤后保留的数据输出路径
        output_removed_path: 被过滤掉的数据输出路径

    Returns:
        (kept_count, removed_count): 保留和过滤的数量
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    constants = data.get('constants', [])
    statements = data.get('statements', [])

    filtered_constants = []
    removed_constants = []

    print(f"总共 {len(constants)} 条 constants 数据")
    print(f"总共 {len(statements)} 条 statements 数据")
    print("-" * 60)

    for item in constants:
        value = item[0]
        if should_keep_value(value):
            filtered_constants.append(item)
        else:
            removed_constants.append(item)

    # 按 statement_id 排序
    filtered_constants.sort(key=lambda x: x[1])
    removed_constants.sort(key=lambda x: x[1])

    # 保存文件
    if output_filtered_path:
        with open(output_filtered_path, 'w', encoding='utf-8') as f:
            json.dump({
                "statements": statements,
                "constants": filtered_constants
            }, f, ensure_ascii=False, indent=2)

    if output_removed_path:
        with open(output_removed_path, 'w', encoding='utf-8') as f:
            json.dump({
                "statements": statements,
                "constants": removed_constants
            }, f, ensure_ascii=False, indent=2)

    print(f"✅ 保留: {len(filtered_constants)} 条 constants")
    print(f"🗑️  过滤: {len(removed_constants)} 条 constants")
    if constants:
        print(f"过滤率: {len(removed_constants) / len(constants) * 100:.1f}%")

    return len(filtered_constants), len(removed_constants)


# ==========================================
# 单独测试入口
# ==========================================
def run_test_cases():
    """运行测试用例"""
    test_cases = [
        "Basic NTozeUwxa1FvbWRqN0xONFljN1JsVlNwTUFKTzhTRHEwcGlmQ1MzSlg4",
        "121314..",
        "110101190001010000",
        "192.168.11.11",
        "wx://form-field",
        "123khadss",
        "khadss",
        "getPhoneNumber",
        "unha hora",
        "Basic Info",
        "shahang",
        "platform_app_secret",
        "bg-blue-500",
        "ebank.bocfullertonbank.com",
        "unhandledrejection",
        "eng Minutt",
        "jedna minuta",
        "enter-active-class",
        "jan.feb.mar.",
        "jh121314..",
        "admin123",
        "AIzaSyA148x9vL0",
        "Domingu_Segunda_Tersa_Kuarta_Kinta_Sesta_Sabadu",
        "fade-down",
        "for the namespaced module",
        "hello",
        "gom-latn",
        "50304321",
        "u51fa",
        "wx062e08749e4ba49b",
        "zh-Hant",
        "期望 string 或 number 类型，但是传入",
        "een paar seconden",
        "dropdown-item__option",
        "do_lu_ma_me_gi_ve_sa",
        "00000-00000-00000-00000-00000-00000",
        "123@qq.com",
        "uni_modules/uview-ui/components/u-checkbox-group/u-checkbox-group.json",
        "Basic bGl5aWZlbmc6TGlZaWZlbmdAMTIz",
        "httpMd5",
        "uptoken",
        
    ]

    print(f"{'Text':<65} | {'Decision':<25}")
    print("-" * 100)
    for t in test_cases:
        res, _ = smart_filter_pro(t)
        prefix = "✅" if "FILTER" in res or "IGNORE" in res else "🚨"
        print(f"{t[:65]:<65} | {prefix} {res:<23}")


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        # JSON文件过滤模式
        input_file = sys.argv[1]
        base_name = input_file.rsplit('.', 1)[0]
        output_filtered = f"{base_name}_filtered.json"
        output_removed = f"{base_name}_removed.json"

        print(f"输入文件: {input_file}")
        print(f"输出文件(保留): {output_filtered}")
        print(f"输出文件(过滤): {output_removed}")
        print("=" * 60)

        filter_json_file(input_file, output_filtered, output_removed)
    else:
        # 单独测试模式
        run_test_cases()

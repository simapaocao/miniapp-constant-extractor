import re
import math

class SecretDetector:
    def __init__(self):
        # 常见的高危长度
        self.TARGET_LENGTHS = [32, 40, 64]
        
    def calculate_entropy(self, text):
        """计算香农熵，判断随机性"""
        if not text: return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze(self, text_list):
        results = []
        
        for text in text_list:
            text = text.strip()
            length = len(text)
            
            # 1. 预处理：跳过明显的      密文块（通常包含大量+/=且长度异常，或者有特定头）
            # U2FsdGVk 是 "Salted" 的 Base64，说明是 AES 加密内容，不是 Key
            if text.startswith("U2FsdGVk") or length > 128:
                results.append({"text": text[:30]+"...", "type": "IGNORE (Ciphertext/Data)", "level": 0})
                continue

            # 2. 核心识别逻辑
            is_hex = re.fullmatch(r"[0-9a-fA-F]+", text)
            entropy = self.calculate_entropy(text)
            
            # 必须有一定的随机性才算 Secret (阈值设为 3.0 可以过滤掉简单重复字符)
            if entropy < 3.0:
                results.append({"text": text, "type": "IGNORE (Low Entropy)", "level": 0})
                continue

            # --- 分类判断 ---
            
            # 类型 A: 标准 32位 Hex (主要目标：微信 AppSecret 等)
            if length == 32 and is_hex:
                results.append({
                    "text": text,
                    "type": "HIGH RISK: 32-char Hex (WeChat/MD5)",
                    "level": 3
                })
            
            # 类型 B: 40/64位 Hex (GitHub/AWS/Signature)
            elif length in [40, 64] and is_hex:
                results.append({
                    "text": text, 
                    "type": f"HIGH RISK: {length}-char Hex (SHA1/SHA256)",
                    "level": 3
                })
                
            # 类型 C: 32-64位 混合字符 (API Keys)
            elif 32 <= length <= 64 and re.search(r"[A-Za-z]", text) and re.search(r"[0-9]", text):
                # 排除 Base64 结尾的 ==，因为那通常是数据
                if not text.endswith("="):
                    results.append({
                        "text": text,
                        "type": "MEDIUM RISK: Alphanumeric API Key",
                        "level": 2
                    })
                else:
                    results.append({"text": text[:20]+"...", "type": "IGNORE (Likely Base64 Data)", "level": 0})
            
            # 类型 D: 其他看起来像 Hex 的短 Key
            elif 16 <= length < 32 and is_hex:
                results.append({
                    "text": text,
                    "type": "LOW RISK: Short Hex (Maybe ID/Salt)",
                    "level": 1
                })
            
            else:
                results.append({"text": text[:20]+"...", "type": "IGNORE (Other)", "level": 0})

        return results

# --- 使用你的样本进行测试 ---
samples = [
    # 32位 Hex
    "611bffe1ef40c1764cb70813f23b8096",
    "bac7291df65c8b45079c15de3a6bb3b7",
    # 混合字符 API Key
    "DOEpLGGZfMdaAlEwCvldoCB5fy7AquKZ",
    "731e603789a78402bacf90475f929fv2", 
    # 疑似 ID
    "1I1MN4KPF00T1C450B0A00001DA713A7",
    # 40位 / 64位 Hex
    "b79b2ec066ca0d133b03d7cc76eed6c745f6ffec",
    "4895e205231bb2bbcedc33947709464766c1240f781b3a64178dfd5144f5ad52",
    # 密文干扰项 (应该被忽略)
    "UGETxVnMHPwtdTT2v3Fos9glC2zfeCMVdB5xnXdk50XKZqmUx7lJDioHPotRWG+uxlCwwpkGtjBSUeK4IwDVj7RXDAhlxZwq1tRBOUdKKnFEn+UQ7MIFqq01uzqNSCHpj0DH4UolFm//w7+DTFmAJwQMPiwUx/DcygFs0iRlbZdbGc97Ef5AfZCJQbxk05PvT6pEyYcYAYYUIuJczPUlFufTO3ude8YwqZMp1AwnAZpmxv5nvzdPmgLnrHhZ4zPTqyc7QgucJ52M6ujg5HwfwlDsmfE+4XIEynEN6c7fmvSlnvj9BvyMC3nS4C4f+PRzzVwnBu5Nl8eb7ukNb4bovw==",
    "U2FsdGVkX1/0roM2HRyYRpnurCzyQTSRmcF4F05AUWE="
]

detector = SecretDetector()
findings = detector.analyze(samples)

print(f"{'RISK LEVEL':<12} | {'TYPE':<35} | {'CONTENT'}")
print("-" * 80)
for f in findings:
    if f['level'] > 0:
        print(f"LEVEL {f['level']:<6} | {f['type']:<35} | {f['text']}")
"""
测试脚本：使用 smart_filter_pro 过滤 002.json 文件中的 constants
生成两个文件，保持和原始文件一样的格式：
- 002_filtered.json: 过滤后保留的数据（有价值的）
- 002_removed.json: 被过滤掉的数据（噪音）

注意：statements 保持完整，因为 constants 中的 line 是 statements 的索引
"""
import json
import os
import sys

# 添加当前目录到路径，以便导入 short_word_fileter_test
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from short_word_fileter_test import smart_filter_pro

def filter_json_file(input_path, output_filtered_path, output_removed_path):
    """
    过滤 JSON 文件中的 constants，保持原始格式
    statements 保持完整不变，因为 constants 中的 line 是索引
    """
    # 读取输入文件
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    constants = data.get('constants', [])
    statements = data.get('statements', [])
    
    filtered_constants = []  # 保留的 constants
    removed_constants = []   # 被过滤的 constants
    
    print(f"总共 {len(constants)} 条 constants 数据")
    print(f"总共 {len(statements)} 条 statements 数据")
    print("-" * 60)
    
    for item in constants:
        value = item[0]
        
        should_keep = False
        
        # 包含 / 的直接保留
        if '/' in value:
            should_keep = True
        # 纯数字直接保留
        elif value.isdigit():
            should_keep = True
        else:
            result, _ = smart_filter_pro(value)
            if "FILTER" not in result and "IGNORE" not in result:
                should_keep = True
        
        if should_keep:
            filtered_constants.append(item)
        else:
            removed_constants.append(item)

    # 按 statement_id 排序，保持源码出现顺序
    filtered_constants.sort(key=lambda x: x[1])
    removed_constants.sort(key=lambda x: x[1])

    # 保存过滤后的文件（statements 保持完整）
    with open(output_filtered_path, 'w', encoding='utf-8') as f:
        json.dump({
            "statements": statements,
            "constants": filtered_constants
        }, f, ensure_ascii=False, indent=2)
    
    # 保存被过滤的文件（statements 保持完整）
    with open(output_removed_path, 'w', encoding='utf-8') as f:
        json.dump({
            "statements": statements,
            "constants": removed_constants
        }, f, ensure_ascii=False, indent=2)
    
    print(f"✅ 保留: {len(filtered_constants)} 条 constants")
    print(f"🗑️  过滤: {len(removed_constants)} 条 constants")
    print(f"过滤率: {len(removed_constants) / len(constants) * 100:.1f}%")

if __name__ == "__main__":
    # 支持命令行参数
    if len(sys.argv) >= 2:
        input_file = sys.argv[1]
        # 自动生成输出文件名
        base_name = input_file.rsplit('.', 1)[0]
        output_filtered = f"{base_name}_filtered.json"
        output_removed = f"{base_name}_removed.json"
    else:
        # 默认路径
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        input_file = os.path.join(base_dir, "test-result", "filtered", "002.json")
        output_filtered = os.path.join(base_dir, "test-result", "filtered", "002_filtered.json")
        output_removed = os.path.join(base_dir, "test-result", "filtered", "002_removed.json")
    
    print(f"输入文件: {input_file}")
    print(f"输出文件(保留): {output_filtered}")
    print(f"输出文件(过滤): {output_removed}")
    print("=" * 60)
    
    filter_json_file(input_file, output_filtered, output_removed)

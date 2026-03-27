#!/usr/bin/env python3
"""
常量提取测试流水线 - 单文件测试脚本

用法:
    python test_pipeline.py <input.js> [--name <output_name>] [--no-smart]

流程:
    1. extract_js_consts.py  -> test-result/unfilter/<name>.json
    2. constants_filter.py   -> test-result/filtered/<name>_filtered.json (默认开启智能过滤)
    3. constants_classifier.py -> test-result/filtered/<name>_classified.json

选项:
    --name <name>: 指定输出文件名前缀 (默认使用输入文件名)
    --no-smart: 禁用智能过滤
"""
from __future__ import annotations

import sys
import argparse
from pathlib import Path

# 导入三个核心模块
from extract_js_consts import extract_from_js_file
from constants_filter import perform_constant_filtering, SMART_FILTER_AVAILABLE
from constants_classifier import perform_constant_classifying

import json


def save_json(data: dict, path: Path) -> None:
    """保存 JSON 文件"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="surrogatepass") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  ✓ 保存: {path}")


def run_pipeline(input_js: str, output_name: str = None, use_smart: bool = True) -> int:
    """
    执行完整的测试流水线
    
    Args:
        input_js: 输入的 JS 文件路径
        output_name: 输出文件名前缀 (不含扩展名)
        use_smart: 是否启用智能过滤
    
    Returns:
        0 成功, 非0 失败
    """
    input_path = Path(input_js)
    if not input_path.exists():
        print(f"❌ 错误: 文件不存在 '{input_js}'")
        return 1
    
    # 确定输出名称
    if not output_name:
        output_name = input_path.stem  # 去掉扩展名
    
    # 输出目录
    script_dir = Path(__file__).resolve().parent
    unfilter_dir = script_dir / "test-result" / "unfilter"
    filtered_dir = script_dir / "test-result" / "filtered"
    
    print(f"🚀 开始处理: {input_path.name}")
    print(f"   输出名称: {output_name}")
    print(f"   智能过滤: {'开启' if use_smart else '关闭'}")
    print()
    
    # ========== Step 1: 提取常量 ==========
    print("📦 Step 1: 提取常量 (extract_js_consts)")
    try:
        extract_result = extract_from_js_file(str(input_path))
        statements = extract_result.get("statements", [])
        constants = extract_result.get("constants", [])
        print(f"  → 提取到 {len(constants)} 个常量, {len(statements)} 条语句")
    except Exception as e:
        print(f"❌ 提取失败: {e}")
        return 1
    
    # 保存未过滤结果
    unfilter_path = unfilter_dir / f"{output_name}.json"
    save_json(extract_result, unfilter_path)
    
    # ========== Step 2: 过滤常量 ==========
    print()
    print("🔍 Step 2: 过滤常量 (constants_filter)")
    
    if use_smart and not SMART_FILTER_AVAILABLE:
        print("  ⚠️ 警告: smart_filter 模块不可用，将使用基础过滤")
        use_smart = False
    
    try:
        filter_result = perform_constant_filtering(
            statements, 
            constants, 
            use_smart_filter=use_smart
        )
        filtered_constants = filter_result.get("constants", [])
        print(f"  → 过滤后剩余 {len(filtered_constants)} 个常量")
    except Exception as e:
        print(f"❌ 过滤失败: {e}")
        return 1
    
    # 保存过滤结果
    filtered_path = filtered_dir / f"{output_name}_filtered.json"
    save_json(filter_result, filtered_path)
    
    # ========== Step 3: 分类常量 ==========
    print()
    print("🏷️ Step 3: 分类常量 (constants_classifier)")
    
    try:
        classify_result = perform_constant_classifying(
            filter_result["statements"],
            filter_result["constants"]
        )
        print(f"  → 分类完成, {len(classify_result)} 个分类结果")
    except Exception as e:
        print(f"❌ 分类失败: {e}")
        return 1
    
    # 保存分类结果 (转换为可序列化格式)
    classified_output = {
        "classified": [
            {"type_id": item[0], "value": item[1], "source": item[2], "context": item[3]}
            for item in classify_result
        ]
    }
    classified_path = filtered_dir / f"{output_name}_classified.json"
    save_json(classified_output, classified_path)
    
    # ========== 完成 ==========
    print()
    print("✅ 处理完成!")
    print(f"   未过滤: {unfilter_path}")
    print(f"   已过滤: {filtered_path}")
    print(f"   已分类: {classified_path}")
    
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="常量提取测试流水线 - 单文件测试脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python test_pipeline.py app.js
    python test_pipeline.py app.js --name mytest
    python test_pipeline.py app.js --no-smart
        """
    )
    parser.add_argument("input", help="输入的 JS 文件路径")
    parser.add_argument("--name", "-n", help="输出文件名前缀 (默认使用输入文件名)")
    parser.add_argument("--no-smart", action="store_true", help="禁用智能过滤")
    
    args = parser.parse_args()
    
    return run_pipeline(
        input_js=args.input,
        output_name=args.name,
        use_smart=not args.no_smart
    )


if __name__ == "__main__":
    raise SystemExit(main())

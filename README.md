# miniapp-constant-extractor

从微信小程序解包产物中提取、过滤并分类安全敏感的字符串常量（密钥、Token、后端接口、页面路径、PII 等），过滤结果落进 MySQL 供查询分析。

支持 `.js` / `.json` / `.wxml` / `.wxs` / `.wxss` / `.html` 六类文件。

> 仅用于对你有授权的小程序做安全评估。仓库内的样本数据已脱敏。

## 环境

- Python 3.10+（在 3.11 上开发与测试）
- 必需依赖：`esprima`（JS 解析）、`pymysql`（写 MySQL）
- 可选依赖：`langid`、`enchant`（启用智能过滤时用于自然语言判定，缺失会自动跳过）

```bash
pip install esprima pymysql
pip install langid pyenchant   # 可选，仅当 config.json 里 use_smart_filter 为 true 且想启用语言过滤
```

## 快速开始

### 1. 生成类型 ID 映射

```bash
python -X utf8 constants_type2id.py
```

它会从 `constant_types.json` 生成 `constant_ids.py`。**分类器和扫描引擎都要 import 它**，缺了会直接报 `ModuleNotFoundError: No module named 'constant_ids'`。

仓库里已经带了 `constant_ids.py`，所以这一步通常只在改了 `constant_types.json` 之后才需要。若改动 taxonomy，记得重新生成并提交，保持两者一致。

### 2. 写配置

配置文件放在**代码目录的上一级**（`scanner_engine.py` 用 `Path(__file__).parent.parent / "config.json"` 定位）：

```json
{
  "task_workspace_name": "my-task",
  "constant_db": {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "root",
    "db_name": "miniapp_scan",
    "charset": "utf8mb4"
  },
  "use_smart_filter": true,
  "pkg_unpacked_dir": "wxpkg-unpacked"
}
```

- `task_workspace_name`：工作区目录名，断点记录 `scanned_wxpkg.db` 会写在这里
- `pkg_unpacked_dir`：解包产物目录名，默认 `wxpkg-unpacked`，位于工作区内
- `use_smart_filter`：是否启用智能过滤（自然语言/CSS 类噪音判定）

### 3. 建库

```bash
python -X utf8 init_database.py
```

建库、建表，并把 `constant_types.json` 里的类型灌进 `data_item_type`。

> **注意：`database_schema.sql` 对每张表都是 `DROP TABLE IF EXISTS` + `CREATE`。对已经有数据的库重复执行会清空全部结果。** 已有数据时不要跑这一步。

### 4. 扫描

```bash
python -X utf8 scanner_engine.py --taskpath my-task --source "D:/unpacked/wxpkg-unpacked" --workers 8
```

| 参数 | 说明 |
|---|---|
| `--taskpath` | 工作区目录（放 `scanned_wxpkg.db`），默认取 `config.json` 的 `task_workspace_name` |
| `--source` | 待扫描的解包根目录，默认取 `<工作区>/<pkg_unpacked_dir>` |
| `--workers` / `-w` | Scanner 进程数，默认 CPU 核数的一半 |
| `--file-timeout` | 单文件提取超时秒数，默认 360 |
| `--dry-run-writer` | 不连数据库，只消费结果并计数（用于冒烟测试） |

`--source` 下的每个一级子目录视为一个小程序包，目录名即 appid。

### 5. 查看结果

- MySQL：`miniapp_meta`（小程序）、`data_item`（去重后的常量）、`miniapp_to_dataitem`（出现位置）、`data_item_type`（类型字典）
- 工作区目录的 `scanned_wxpkg.db`：
  - `scanned_files`：已成功扫完的包（断点续跑的依据）
  - `scan_failures`：失败明细，`kind='file'` 是文件自身问题（超时、解析失败），`kind='infra'` 是基础设施问题（写库失败、worker 崩溃、被中断）

按 data_item 主键查出处并复制原文：

```bash
python -X utf8 query_data_item.py 16981
```

## 扫描流程

```
Finder ──文件清单──▶ Scanner ×N（每进程带一个提取沙箱）──结果──▶ Writer ──▶ MySQL
   │                        │                                    │
   └── 包完成/跳过 ──▶ 主进程记账 ◀──── ACK（提交后才回执）──────────┘
```

- **单文件超时**：提取在独立沙箱子进程里跑，超时就杀掉并重启沙箱。正则灾难性回溯、超大字面量这类会卡住的输入不会拖死整个扫描。
- **断点续跑**：包内所有文件都有结果、且数据经 Writer 提交成功后才写入 `scanned_files`。中断或写库失败时包不会被标记，下次重跑会重新扫。
- **中断**：Ctrl+C 一次走正常收尾（完成当前文件、排空队列、落盘）；再按一次强制退出（退出码 130）。
- **退出码**：全部正常为 0；有未完成包、被中断或 Writer 异常时非 0。

## 单文件调试

```bash
python -X utf8 test_pipeline.py <file.js> --name mytest        # 提取→过滤→分类，输出中间结果
python -X utf8 test_pipeline.py <file.js> --no-smart           # 关闭智能过滤
python -X utf8 extract_js_consts.py <file.js>                  # 只看提取
python -X utf8 constants_filter.py <in.json> <out.json>        # 只看过滤
python -X utf8 constants_classifier.py <in.json>               # 只看分类
```

## 模块职责

| 文件 | 作用 |
|---|---|
| `scanner_engine.py` | 多进程扫描编排、断点记账、MySQL 写入 |
| `extract_js_consts.py` / `extract_json_consts.py` / `extract_wxml_consts.py` / `extract_wxs_consts.py` / `extract_wxss_consts.py` / `extract_html_consts.py` | 各类型文件的常量提取 |
| `constants_filter.py` | 基础噪音过滤 + 近重复抑制 |
| `smart_filter.py` | 可选智能过滤（熵、命名拆分、语言判定） |
| `constants_classifier.py` | 分类：密钥、Token、URL、接口路径、PII、支付参数等 |
| `constant_types.json` | 类型体系定义（分组、slug、风险等级） |
| `constants_type2id.py` | 由 taxonomy 生成 `constant_ids.py` |
| `constant_ids.py` | 数值 ID 与 `SLUG_TO_DB` 映射（生成物，随仓库提供） |
| `init_database.py` | 建库建表、灌入类型字典 |
| `query_data_item.py` | 按 id 反查常量出处 |
| `test_pipeline.py` | 单文件全流程测试 |

## 测试

```bash
python -X utf8 -m pytest unit-tests -q
```

`unit-tests/test_constant_classifier.py` 引用了一个不存在的模块名（`constant_classifier`），会收集失败，属于既有问题。

## 样本数据

- `test-refdata/`：少量真实小程序片段，用于提取器回归。
- `test-sensitivefile/`：**合成样例**，里面的 AppSecret、Webhook、私钥、身份证号等都是伪造占位值，仅用于验证扫描规则。

真实小程序的解包产物、扫描输出（`test-result/`、工作区目录）都已在 `.gitignore` 中忽略，不要提交。

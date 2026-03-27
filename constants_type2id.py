#!/usr/bin/python
"""Generate constant_ids.py from constant_types.json"""
import json


# Risk value (0-5) to RISK_* constant name mapping
RISK_VALUE_TO_NAME = {
    0: "RISK_IGNORE",
    1: "RISK_LOW",
    2: "RISK_MEDIUM",
    3: "RISK_ELEVATED",
    4: "RISK_HIGH",
    5: "RISK_CRITICAL",
}


def assign_types_with_ids(json_file_path, output_file_path):
    """
    Define numerical ID for data types
    """
    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Collect slug -> (category, risk) for SLUG_TO_DB generation
    slug_mappings = []

    with open(output_file_path, "w", encoding="utf-8") as f:
        f.write("# Generated Constant Definitions\n")
        f.write("# Based on constant_types.json taxonomy\n\n")

        f.write("# " + "=" * 57 + "\n")
        f.write("# Numerical ID Definitions\n")
        f.write("# " + "=" * 57 + "\n")

        # 1. Risk Scale IDs (start_index: 200)
        risk_data = data.get("risk_scale", {})
        start_risk = risk_data.get("start_index", 0)
        f.write("\n# Risk Scale IDs\n")
        for i, risk in enumerate(risk_data.get("items", {})):
            f.write(f"RISK_{risk.upper()} = {start_risk + i}\n")

        # 2. Policy Map IDs (start_index: 300)
        policy_data = data.get("policy_maps", {})
        start_policy = policy_data.get("start_index", 0)
        f.write("\n# Policy Map IDs\n")
        # We extract unique policy actions (allow, warn, redact, block)
        for i, action in enumerate(policy_data.get("risk_to_default_action", {})):
            f.write(f"POLICY_{action.upper()} = {start_policy + i}\n")

        # 3. Token Type IDs (start_index: 500)
        token_data = data.get("token_types", {})
        start_token = token_data.get("start_index", 0)
        f.write("\n# Token Type IDs\n")
        for i, token_key in enumerate(token_data.get("items", {})):
            f.write(f"TOKEN_{token_key.upper()} = {start_token + i}\n")

        # 1. Category IDs (Numerical)
        f.write("\n# Category IDs\n")
        kind_counter = 1
        category_to_ctg = {}  # category name -> CTG constant name
        for group in data["datatype_categories"]:
            category = group["category"]
            cat_name = f"CTG_{category.upper()}"
            # Others is traditionally assigned 99 in this project
            val = 99 if category == "others" else kind_counter
            f.write(f"{cat_name} = {val}\n")
            category_to_ctg[category] = cat_name
            if category != "others":
                kind_counter += 1

        # 2. Item Slug IDs (Calculated from start_index)
        f.write("\n# Item Slug IDs\n")
        for group in data["datatype_categories"]:
            category = group["category"]
            category_label = category.upper()
            f.write(
                f"\n# {category_label} items (Starting index: {group['start_index']})\n"
            )

            start_index = group["start_index"]
            seen_slugs = set()
            offset = 1  # Start counting from 1 for the first item

            for item in group["items"]:
                slug = item["slug"]
                risk = item.get("risk", group.get("default_risk", 0))
                # Avoid duplicate definitions within the same group
                if slug in seen_slugs:
                    print(
                        f"Warning: Duplicate slug '{slug}' in category '{category}'"
                        " - skipping"
                    )
                    continue

                seen_slugs.add(slug)
                slug_name = f"{slug.upper()}"
                # sub_id = start_index + offset (1-based within category)
                sub_id = start_index + offset
                f.write(f"{slug_name} = {sub_id}\n")
                offset += 1

                # Collect for SLUG_TO_DB
                slug_mappings.append((slug_name, category_to_ctg[category], risk))

        # 3. Generate SLUG_TO_DB mapping table
        f.write("\n\n# " + "=" * 57 + "\n")
        f.write("# SLUG_TO_DB Mapping Table\n")
        f.write("# Maps slug_id -> (kind_id, risk_level)\n")
        f.write("# Used by scanner_engine.py for database conversion\n")
        f.write("# " + "=" * 57 + "\n")
        f.write("SLUG_TO_DB = {\n")

        current_category = None
        for slug_name, ctg_name, risk in slug_mappings:
            # Add category comment when category changes
            if ctg_name != current_category:
                current_category = ctg_name
                f.write(f"    # {ctg_name}\n")

            risk_name = RISK_VALUE_TO_NAME.get(risk, "RISK_IGNORE")
            f.write(f"    {slug_name}: ({ctg_name}, {risk_name}),\n")

        f.write("}\n")


def main_193d23f0():
    """For testing"""
    assign_types_with_ids("constant_types.json", "constant_ids.py")
    print("Successfully generated numerical ID definitions in constant_ids.py")


if __name__ == "__main__":
    main_193d23f0()

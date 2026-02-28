"""
Forcepoint XML → CSV Exporter  (Dynamic + Smart Grouping)
==========================================================
- يقرأ أي ملف XML تبع Forcepoint
- يكتشف كل العناصر تلقائياً (Root / Direct Elements / Nested)
- يعمل CSV منفصل لكل نوع عنصر
- القيم المتكررة (زي ports / sources / destinations) تتجمع في خلية واحدة مفصولة بـ |
- لا يحتاج تعديل يدوي مهما اختلف الملف

الاستخدام:
    python forcepoint_xml_to_csv.py <path_to_xml> [output_folder]

مثال:
    python forcepoint_xml_to_csv.py exported.xml ./output_csvs
"""

import xml.etree.ElementTree as ET
import csv
import os
import sys
from collections import defaultdict


# ─────────────────────────────────────────────
# Helper: flatten element إلى dict واحد
# مع دمج القيم المتكررة في خلية واحدة
# ─────────────────────────────────────────────
def flatten_element(el, prefix=""):
    """
    القاعدة:
    - لو child بيتكرر أكتر من مرة بنفس الاسم:
        كل قيمه تتجمع في خلية واحدة مفصولة بـ |
        مثال:
            <match_services>
                <match_service_ref value="DNS"/>
                <match_service_ref value="HTTP"/>
            </match_services>
        النتيجة:
            match_services.match_service_ref.value  ->  DNS | HTTP

    - لو child بيجي مرة واحدة بس:
        attributes تبعه تتحط كـ columns عادية
        مثال:
            <mvia_address address="1.2.3.4"/>
        النتيجة:
            mvia_address.address  ->  1.2.3.4
    """
    row = {}

    # attributes الخاصة بالعنصر نفسه
    for k, v in el.attrib.items():
        if len(v) > 500:
            v = v[:200] + "...[truncated]"
        col = f"{prefix}{k}" if prefix else k
        row[col] = v

    # text content
    if el.text and el.text.strip():
        col = f"{prefix}_text" if prefix else "_text"
        row[col] = el.text.strip()

    # عد كل tag في الـ children
    child_count = defaultdict(int)
    for child in el:
        child_count[child.tag] += 1

    # افصل: متكررة vs مفردة
    grouped = defaultdict(list)
    single  = {}

    for child in el:
        if child_count[child.tag] > 1:
            grouped[child.tag].append(child)
        else:
            single[child.tag] = child

    # المتكررة: اجمع قيمهم في خلية واحدة
    for tag, children in grouped.items():
        col_prefix = f"{prefix}{tag}." if prefix else f"{tag}."

        # اجمع كل الـ attribute keys الممكنة
        all_attr_keys = list(dict.fromkeys(
            k for child in children for k in child.attrib
        ))

        if all_attr_keys:
            for k in all_attr_keys:
                values = [c.attrib[k] for c in children if k in c.attrib]
                col = f"{col_prefix}{k}"
                row[col] = " | ".join(values)
        else:
            # لو مفيش attributes، اجمع الـ text
            values = [c.text.strip() for c in children if c.text and c.text.strip()]
            if values:
                row[f"{col_prefix}_text"] = " | ".join(values)

        # nested تحت المتكررين: اجمع كمان
        grandchild_groups = defaultdict(list)
        for child in children:
            for gc in child:
                grandchild_groups[gc.tag].append(gc)

        for gc_tag, gc_list in grandchild_groups.items():
            gc_col_prefix = f"{col_prefix}{gc_tag}."
            gc_attr_keys  = list(dict.fromkeys(
                k for gc in gc_list for k in gc.attrib
            ))
            for k in gc_attr_keys:
                values = [gc.attrib[k] for gc in gc_list if k in gc.attrib]
                col    = f"{gc_col_prefix}{k}"
                row[col] = " | ".join(values)

    # المفردة: اعملها flatten عادي (recursive)
    for tag, child in single.items():
        child_prefix = f"{prefix}{tag}." if prefix else f"{tag}."
        nested = flatten_element(child, prefix=child_prefix)
        row.update(nested)

    return row


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    # Arguments
    if len(sys.argv) < 2:
        print("Usage: python forcepoint_xml_to_csv.py <xml_file> [output_folder]")
        sys.exit(1)

    xml_path      = sys.argv[1]
    output_folder = sys.argv[2] if len(sys.argv) > 2 else "forcepoint_csv_output"

    if not os.path.exists(xml_path):
        print(f"Error: File not found: {xml_path}")
        sys.exit(1)

    os.makedirs(output_folder, exist_ok=True)

    # Parse XML
    print(f"\n[1] Parsing: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Root Element
    print(f"\n[2] Root Element: <{root.tag}>")
    print(f"    Attributes: {root.attrib}")

    root_csv = os.path.join(output_folder, "00_ROOT_ELEMENT.csv")
    with open(root_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Property", "Value"])
        writer.writerow(["tag", root.tag])
        for k, v in root.attrib.items():
            writer.writerow([k, v])
    print(f"    Saved: {root_csv}")

    # Collect direct children
    print(f"\n[3] Collecting Direct Elements...")
    direct_elements = defaultdict(list)
    for child in root:
        direct_elements[child.tag].append(child)
    print(f"    Found {len(direct_elements)} unique direct element types")

    # Collect all nested elements
    print(f"\n[4] Collecting All Nested Elements...")
    all_elements = defaultdict(list)
    for el in root.iter():
        if el is root:
            continue
        all_elements[el.tag].append(el)
    print(f"    Found {len(all_elements)} unique element types in total")

    # Summary CSV
    summary_csv = os.path.join(output_folder, "01_SUMMARY.csv")
    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Element Tag", "Is Direct Child", "Count", "CSV File"])
        for tag in sorted(all_elements.keys()):
            is_direct = "Yes" if tag in direct_elements else "No"
            count     = len(all_elements[tag])
            csv_name  = f"{tag}.csv"
            writer.writerow([tag, is_direct, count, csv_name])
    print(f"    Summary saved: {summary_csv}")

    # Export each element type to its own CSV
    print(f"\n[5] Exporting CSVs...")
    exported = 0

    for tag in sorted(all_elements.keys()):
        elements = all_elements[tag]

        all_rows    = []
        all_columns = []
        seen_cols   = set()

        for el in elements:
            row = flatten_element(el)
            all_rows.append(row)
            for col in row.keys():
                if col not in seen_cols:
                    seen_cols.add(col)
                    all_columns.append(col)

        csv_path = os.path.join(output_folder, f"{tag}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=all_columns, extrasaction="ignore")
            writer.writeheader()
            for row in all_rows:
                writer.writerow(row)

        exported += 1
        is_direct = "(direct)" if tag in direct_elements else "(nested)"
        print(f"    {tag}.csv  --  {len(elements)} rows  {is_direct}")

    # Done
    print(f"\n{'='*55}")
    print(f"  Done!")
    print(f"  XML File     : {xml_path}")
    print(f"  Output Folder: {output_folder}")
    print(f"  Total CSVs   : {exported + 2}  (+ ROOT + SUMMARY)")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()

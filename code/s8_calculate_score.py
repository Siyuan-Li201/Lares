import os
import sys
import json
from tqdm import tqdm
import glob
import re
from itertools import groupby
import csv
from typing import Dict, Tuple, List
from collections import defaultdict
import glob
import re
from itertools import groupby
import pandas as pd

# 定义列名
csv_columns = [
    "cve_id",
    "arch_name",
    "compiler_name",
    "optimization_level",
    "project_name",
    "version_name",
    "function_name",
    "patch_result",
    "groundtruth",
    "detection_result"
]


def calculate_metrics(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    """Calculate precision, recall and f1 score"""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    return precision, recall, f1

def analyze_results(csv_path: str) -> None:
    """
    Analyze results by different dimensions and calculate metrics
    
    Args:
        csv_path: Path to the csv file
    """
    # Initialize counters using nested defaultdict
    stats = {
        'cve_id': defaultdict(lambda: {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}),
        'arch': defaultdict(lambda: {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}),
        'compiler': defaultdict(lambda: {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}),
        'opt_level': defaultdict(lambda: {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}),
        'total': {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}
    }
    
    # Read csv and count metrics
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        next(reader) # Skip header
        for row in reader:
            cve_id, arch, compiler, opt_level = row[0], row[1], row[2], row[3]
            result = row[-1]
            
            # Update counts for each dimension
            stats['cve_id'][cve_id][result] += 1
            stats['arch'][arch][result] += 1
            stats['compiler'][compiler][result] += 1
            stats['opt_level'][opt_level][result] += 1
            stats['total'][result] += 1
    
    # Print results for each dimension
    dimensions = [
        ('Cve ID', 'cve_id'),
        ('Architecture', 'arch'),
        ('Compiler', 'compiler'), 
        ('Optimization Level', 'opt_level'),
        ('Total', 'total')
    ]
    
    for title, dim in dimensions:
        print(f"\n{title} Results:")
        print("-" * 50)
        if dim == 'total':
            counts = stats[dim]
            p, r, f1 = calculate_metrics(counts['TP'], counts['FP'], counts['FN'])
            print(f"TP: {counts['TP']}, TN: {counts['TN']}, FP: {counts['FP']}, FN: {counts['FN']}")
            print(f"Precision: {p:.3f}")
            print(f"Recall: {r:.3f}")
            print(f"F1 Score: {f1:.3f}")
        else:
            for key in stats[dim]:
                counts = stats[dim][key]
                p, r, f1 = calculate_metrics(counts['TP'], counts['FP'], counts['FN'])
                print(f"{key}:")
                print(f"  TP: {counts['TP']}, TN: {counts['TN']}, FP: {counts['FP']}, FN: {counts['FN']}")
                print(f"  Precision: {p:.3f}")
                print(f"  Recall: {r:.3f}")
                print(f"  F1 Score: {f1:.3f}")

def fix_json_escapes(s):
    result = ''
    in_quotes = False
    i = 0
    while i < len(s):
        char = s[i]
        # 处理转义字符
        if char == '\n' and i + 1 < len(s):
            if in_quotes:
                # 在引号内部，将 \n 转换为 \\n
                result += '\\'
                result += 'n'
            else:
                # 在引号外部或其他转义字符，保持不变
                result += char
            i += 1
            continue
            
        # 处理引号
        if char == '"':
            # 检查是否是转义的引号
            if i > 0 and s[i-1] == '\\':
                result += char
            else:
                # 真实的引号，切换引号状态
                in_quotes = not in_quotes
                result += char
        else:
            result += char
            
        i += 1
    
    return result


def extract_json_from_text(text):
    json_start = text.find('{')
    if json_start == -1:
        print("未找到JSON数据。")
        return None

    brace_count = 0
    in_string = False
    escape = False

    for index in range(json_start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = index + 1
                    json_str = text[json_start:json_end]
                    try:
                        data = json.loads(fix_json_escapes(json_str.replace('\t', ' ')).replace('\\\\0', '0').replace('\\0', '0'))
                        return data
                    except json.JSONDecodeError as e:
                        print("JSON解码错误：", e)
                        return None
    print("未能正确匹配到JSON对象的结束。")
    return None

def extract_json_from_file(file_path):
    """
    从指定文件中提取所有的JSON对象。

    :param file_path: 文件路径
    :return: 包含所有JSON对象的列表
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    return extract_json_from_text(content)


def read_json_file(file_path):
    """
    读取JSON文件，提取"new match result"中的value值，保存为list2。
    """
    list2 = []
    key_list = []
    # with open(file_path, 'r', encoding='utf-8') as f:
    #     data = json.load(f)
    data = extract_json_from_file(file_path)

    if not data:
        with open(file_path, 'r') as file:
            for line in file:
                # 检查是否包含 correct_result
                if 'correct_result' in line:
                    # 检查版本类型并计数
                    if 'pre-patch version' in line:
                        return {"correct_result": "pre-patch version"}
                    elif 'patched version' in line:
                        return {"correct_result": "patched version"}

    return data


def merge_csv_files(csv1_path, csv2_path, csv3_path):

    compare_columns = ['cve_id', 'arch_name', 'compiler_name', 'optimization_level', 
                  'project_name', 'version_name', 'function_name', 'groundtruth']

    # 读取两个CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)
    
    # 使用指定的列创建合并键
    df1['merge_key'] = df1[compare_columns].apply(lambda x: '_'.join(x.astype(str)), axis=1)
    df2['merge_key'] = df2[compare_columns].apply(lambda x: '_'.join(x.astype(str)), axis=1)
    
    # 找出df2中不重复的行
    unique_keys_in_df2 = ~df2['merge_key'].isin(df1['merge_key'])
    df2_unique = df2[unique_keys_in_df2]
    
    # 合并df1和df2中的唯一行
    result = pd.concat([df1, df2_unique], ignore_index=True)
    
    # 删除merge_key列
    result = result.drop('merge_key', axis=1)
    
    # 保存结果到新的CSV文件
    result.to_csv(csv3_path, index=False)




def calculate_score_z3(data_dir, output_csv="output_z3.csv"):


    with open(output_csv, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for cve_dir_name in tqdm(os.listdir(data_dir)):
            cve_dir_path = os.path.join(data_dir, cve_dir_name)
            if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
                continue  # Skip if not a directory or doesn't start with "CVE"

            result_json_path = os.path.join(cve_dir_path, "result.json")
            if not os.path.exists(result_json_path):
                print(f"Warning: result.json not found in {cve_dir_path}")
                continue
            # Read result.json
            with open(result_json_path, 'r', encoding='utf-8') as f:
                try:
                    result_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Error: Invalid JSON in {result_json_path}")
                    continue

                cve_id = result_data["CVE_id"]

                if ":" in result_data["binary_vul_version"]:
                    gt_vul_version = result_data["binary_vul_version"].split(":")[1]
                elif "-" in result_data["binary_vul_version"]:
                    gt_vul_version = result_data["binary_vul_version"].split("-")[1]
                if ":" in result_data["binary_patch_version"]:
                    gt_patch_version = result_data["binary_patch_version"].split(":")[1]
                elif "-" in result_data["binary_patch_version"]:
                    gt_patch_version = result_data["binary_patch_version"].split("-")[1]
                else:
                    print(f"Unknown version format: {result_data['binary_vul_version']}")
                    continue

                # if result_data["patch_info"]["patch_type"] == "modify":
                #     continue

            # Get all .idapseudo files
            patch_result_dir_list = glob.glob(os.path.join(cve_dir_path, "ares_*"))

            if len(patch_result_dir_list) > 0:
                for patch_result_dir in patch_result_dir_list:
                    
                    patch_result_filename = os.path.basename(patch_result_dir)
                    arch_name = patch_result_filename.split("_")[1]
                    compiler_name = patch_result_filename.split("_")[2]
                    optimization_level = patch_result_filename.split("_")[3]
                    project_name = patch_result_filename.split("_")[4]
                    version_name = patch_result_filename.split("_")[5]
                    function_name = "_".join(patch_result_filename.split("_")[7:])
                    
                    if version_name == gt_patch_version:
                        groundtruth = "patched version"
                    elif version_name == gt_vul_version:
                        groundtruth = "pre-patch version"
                    else:
                        print(f"Unknown version name: {version_name}")
                        continue
                
                    detection_result = False
                    patch_result = False

                    more_patch_result_file_list = glob.glob(os.path.join(patch_result_dir, "z3_res*.json"))

                    if len(more_patch_result_file_list) == 1:      
                        patch_result_file = os.path.join(patch_result_dir, "z3_res_1.json")

                        if not os.path.exists(patch_result_file):
                            print("z3_res_1.json not found in {patch_result_dir}")
                            continue

                        result_json = read_json_file(patch_result_file)
                        if result_json and "correct_result" in result_json:
                            # print(f"Correct result found in {patch_result_file}")
                            patch_result = result_json["correct_result"]

                            if patch_result == "not sure":
                                continue

                            if patch_result == groundtruth == "patched version":
                                detection_result = "TP"
                            elif patch_result == groundtruth == "pre-patch version":
                                detection_result = "TN"
                            elif patch_result == "patched version" and groundtruth == "pre-patch version":
                                detection_result = "FN"
                            elif patch_result == "pre-patch version" and groundtruth == "patched version":
                                detection_result = "FP"
                            else:
                                print(f"Unknown detection result: {patch_result}, {groundtruth}")
                                continue
                    else:
                        print(f"more result: {patch_result_dir}")
                        for patch_result_file_item in more_patch_result_file_list:
                            result_json = read_json_file(patch_result_file_item)
                            if result_json and "correct_result" in result_json and result_json["correct_result"] != "not sure":
                                # print(f"Correct result found in {patch_result_file}")
                                if patch_result != "patched version":
                                    patch_result = result_json["correct_result"]

                                    if patch_result == groundtruth == "patched version":
                                        detection_result = "TP"
                                    elif patch_result == groundtruth == "pre-patch version":
                                        detection_result = "TN"
                                    elif patch_result == "patched version" and groundtruth == "pre-patch version":
                                        detection_result = "FN"
                                    elif patch_result == "pre-patch version" and groundtruth == "patched version":
                                        detection_result = "FP"
                                    else:
                                        print(f"Unknown detection result: {patch_result}, {groundtruth}")
                                        continue
                                else:
                                    break

                    
                    if detection_result:
                        try:
                            parts = patch_result_filename.split("_")

                            row = {
                                "cve_id": cve_id,
                                "arch_name": parts[1],
                                "compiler_name": parts[2],
                                "optimization_level": parts[3],
                                "project_name": parts[4],
                                "version_name": parts[5],
                                "function_name": "_".join(parts[7:]),
                                "patch_result": patch_result,
                                "groundtruth": groundtruth,
                                "detection_result": detection_result
                            }

                            writer.writerow(row)
                        except (IndexError, KeyError) as e:
                            print(f"Error processing {patch_result_dir}: {e}")
                


def calculate_score(data_dir, output_csv="output_llm.csv"):


    with open(output_csv, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
        writer.writeheader()

        for cve_dir_name in tqdm(os.listdir(data_dir)):

            # if "CVE-2016-0705" in cve_dir_name:
            #     print("warning")


            cve_dir_path = os.path.join(data_dir, cve_dir_name)
            if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
                continue  # Skip if not a directory or doesn't start with "CVE"

            result_json_path = os.path.join(cve_dir_path, "result.json")
            if not os.path.exists(result_json_path):
                print(f"Warning: result.json not found in {cve_dir_path}")
                continue
            # Read result.json
            with open(result_json_path, 'r', encoding='utf-8') as f:
                try:
                    result_data = json.load(f)
                except json.JSONDecodeError:
                    print(f"Error: Invalid JSON in {result_json_path}")
                    continue

                cve_id = result_data["CVE_id"]

                if ":" in result_data["binary_vul_version"]:
                    gt_vul_version = result_data["binary_vul_version"].split(":")[1]
                elif "-" in result_data["binary_vul_version"]:
                    gt_vul_version = result_data["binary_vul_version"].split("-")[1]
                if ":" in result_data["binary_patch_version"]:
                    gt_patch_version = result_data["binary_patch_version"].split(":")[1]
                elif "-" in result_data["binary_patch_version"]:
                    gt_patch_version = result_data["binary_patch_version"].split("-")[1]
                else:
                    print(f"Unknown version format: {result_data['binary_vul_version']}")
                    continue

                # if result_data["patch_info"]["patch_type"] == "modify":
                #     continue

            # Get all .idapseudo files
            patch_result_dir_list = glob.glob(os.path.join(cve_dir_path, "ares_*"))

            if len(patch_result_dir_list) > 0:
                for patch_result_dir in patch_result_dir_list:
                    
                    patch_result_filename = os.path.basename(patch_result_dir)
                    arch_name = patch_result_filename.split("_")[1]
                    compiler_name = patch_result_filename.split("_")[2]
                    optimization_level = patch_result_filename.split("_")[3]
                    project_name = patch_result_filename.split("_")[4]
                    version_name = patch_result_filename.split("_")[5]
                    function_name = "_".join(patch_result_filename.split("_")[7:])
                    
                    if version_name == gt_patch_version:
                        groundtruth = "patched version"
                    elif version_name == gt_vul_version:
                        groundtruth = "pre-patch version"
                    else:
                        print(f"Unknown version name: {version_name}")
                        continue
                
                    detection_result = False
                    patch_result = False

                    more_patch_result_file_list = glob.glob(os.path.join(patch_result_dir, "cl07_llm_res*.txt"))

                    if len(more_patch_result_file_list) == 1:      
                        patch_result_file = os.path.join(patch_result_dir, "cl07_llm_res_1.txt")

                        # if not os.path.exists(patch_result_file):
                        #     patch_result_file = os.path.join(patch_result_dir, "llm_res.txt")

                        if not os.path.exists(patch_result_file):
                            print("llm_res.txt not found in {patch_result_dir}")
                            continue

                        result_json = read_json_file(patch_result_file)
                        if result_json and "correct_result" in result_json:
                            # print(f"Correct result found in {patch_result_file}")
                            patch_result = result_json["correct_result"]

                            if patch_result == groundtruth == "patched version":
                                detection_result = "TP"
                            elif patch_result == groundtruth == "pre-patch version":
                                detection_result = "TN"
                            elif patch_result == "patched version" and groundtruth == "pre-patch version":
                                detection_result = "FN"
                            elif patch_result == "pre-patch version" and groundtruth == "patched version":
                                detection_result = "FP"
                            else:
                                print(f"Unknown detection result: {patch_result}, {groundtruth}")
                                continue
                    elif len(more_patch_result_file_list) > 1:
                        print(f"more result: {patch_result_dir}")
                        for patch_result_file_item in more_patch_result_file_list:
                            if "llm_res.txt" in patch_result_file_item:
                                continue
                            result_json = read_json_file(patch_result_file_item)
                            if result_json and "correct_result" in result_json:
                                # print(f"Correct result found in {patch_result_file}")
                                if patch_result != "patched version":
                                    patch_result = result_json["correct_result"]

                                    if patch_result == groundtruth == "patched version":
                                        detection_result = "TP"
                                    elif patch_result == groundtruth == "pre-patch version":
                                        detection_result = "TN"
                                    elif patch_result == "patched version" and groundtruth == "pre-patch version":
                                        detection_result = "FN"
                                    elif patch_result == "pre-patch version" and groundtruth == "patched version":
                                        detection_result = "FP"
                                    else:
                                        print(f"Unknown detection result: {patch_result}, {groundtruth}")
                                        continue
                                else:
                                    break
                    # else:
                    #     more_patch_result_file_list = glob.glob(os.path.join(patch_result_dir, "llm_pres*.txt"))
                    #     if len(more_patch_result_file_list) == 1:
                    #         patch_result_file = os.path.join(patch_result_dir, "llm_pres_1.txt")

                    #         if not os.path.exists(patch_result_file):
                    #             patch_result_file = os.path.join(patch_result_dir, "llm_pres.txt")

                    #         if not os.path.exists(patch_result_file):
                    #             print("llm_res.txt not found in {patch_result_dir}")
                    #             continue

                    #         result_json = read_json_file(patch_result_file)
                    #         if result_json and "correct_result" in result_json:
                    #             # print(f"Correct result found in {patch_result_file}")
                    #             patch_result = result_json["correct_result"]

                    #             if patch_result == groundtruth == "patched version":
                    #                 detection_result = "TP"
                    #             elif patch_result == groundtruth == "pre-patch version":
                    #                 detection_result = "TN"
                    #             elif patch_result == "patched version" and groundtruth == "pre-patch version":
                    #                 detection_result = "FN"
                    #             elif patch_result == "pre-patch version" and groundtruth == "patched version":
                    #                 detection_result = "FP"
                    #             else:
                    #                 print(f"Unknown detection result: {patch_result}, {groundtruth}")
                    #                 continue
                    #     elif len(more_patch_result_file_list) > 1:
                    #         print(f"more result: {patch_result_dir}")
                    #         for patch_result_file_item in more_patch_result_file_list:
                    #             result_json = read_json_file(patch_result_file_item)
                    #             if result_json and "correct_result" in result_json:
                    #                 # print(f"Correct result found in {patch_result_file}")
                    #                 if patch_result != "patched version":
                    #                     patch_result = result_json["correct_result"]

                    #                     if patch_result == groundtruth == "patched version":
                    #                         detection_result = "TP"
                    #                     elif patch_result == groundtruth == "pre-patch version":
                    #                         detection_result = "TN"
                    #                     elif patch_result == "patched version" and groundtruth == "pre-patch version":
                    #                         detection_result = "FN"
                    #                     elif patch_result == "pre-patch version" and groundtruth == "patched version":
                    #                         detection_result = "FP"
                    #                     else:
                    #                         print(f"Unknown detection result: {patch_result}, {groundtruth}")
                    #                         continue
                    #                 else:
                    #                     break
                    #     else:
                    #         print(f"No patch result file found in {patch_result_dir}")
                    #         continue

                    
                    if detection_result:
                        try:
                            parts = patch_result_filename.split("_")

                            row = {
                                "cve_id": cve_id,
                                "arch_name": parts[1],
                                "compiler_name": parts[2],
                                "optimization_level": parts[3],
                                "project_name": parts[4],
                                "version_name": parts[5],
                                "function_name": "_".join(parts[7:]),
                                "patch_result": patch_result,
                                "groundtruth": groundtruth,
                                "detection_result": detection_result
                            }

                            writer.writerow(row)
                        except (IndexError, KeyError) as e:
                            print(f"Error processing {patch_result_dir}: {e}")
                
            # else:
            #     print(f"No patch result directory found in {cve_dir_path}")

def process_csv_files_bad(csv1_path, csv2_path, result_path="result_bad.csv"):
    # 读取CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)
    
    # 获取需要比较的列名
    compare_columns = ['arch_name', 'compiler_name', 'optimization_level', 
                      'project_name', 'version_name', 'function_name', 'groundtruth']
    
    # 获取csv1中所有TP或TN的行
    df1_filtered = df1[df1['detection_result'].isin(['TP', 'TN'])]
    
    # 存储结果
    result_rows = []
    
    # 对于csv1中的每一行TP或TN
    for _, row1 in df1_filtered.iterrows():
        # 在csv2中找到匹配的行
        match_condition = True
        for col in compare_columns:
            match_condition = match_condition & (df2[col] == row1[col])
        
        matching_rows = df2[match_condition]
        
        # 如果找到匹配的行
        if not matching_rows.empty:
            for _, row2 in matching_rows.iterrows():
                # 检查detection_result是否变为FP或FN
                if row2['detection_result'] in ['FP', 'FN']:
                    result_rows.append(row2)
    
    # 创建结果DataFrame并保存
    if result_rows:
        result_df = pd.DataFrame(result_rows)
        result_df.to_csv(result_path, index=False)
        print(f"Found {len(result_rows)} rows where detection results changed to FP/FN")
    else:
        print("No matching rows found where detection results changed to FP/FN")



def process_csv_files(csv1_path, csv2_path, result_path="result.csv"):
    # 读取CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)
    
    # 获取需要比较的列名
    compare_columns = ['arch_name', 'compiler_name', 'optimization_level', 
                      'project_name', 'version_name', 'function_name', 'groundtruth']
    
    # 获取csv1中所有TP或TN的行
    df1_filtered = df1[df1['detection_result'].isin(['FP', 'FN'])]
    
    # 存储结果
    result_rows = []
    
    # 对于csv1中的每一行TP或TN
    for _, row1 in df1_filtered.iterrows():
        # 在csv2中找到匹配的行
        match_condition = True
        for col in compare_columns:
            match_condition = match_condition & (df2[col] == row1[col])
        
        matching_rows = df2[match_condition]
        
        # 如果找到匹配的行
        if not matching_rows.empty:
            for _, row2 in matching_rows.iterrows():
                # 检查detection_result是否变为FP或FN
                if row2['detection_result'] in ['TP', 'TN']:
                    result_rows.append(row2)
    
    # 创建结果DataFrame并保存
    if result_rows:
        result_df = pd.DataFrame(result_rows)
        result_df.to_csv(result_path, index=False)
        print(f"Found {len(result_rows)} rows where detection results changed to FP/FN")
    else:
        print("No matching rows found where detection results changed to FP/FN")

# calculate_score("/media/author/4A7AC8957AC87F67/work2024/code/llm_api/data")
# analyze_results("./output.csv")






def process_function_name(name):
    # 去掉最后一个_及其后面的内容
    return '_'.join(name.split('_')[:-1])

def get_project_version(bin_path):
    # 从bin_path中提取project_name和version_name
    basename = os.path.basename(bin_path)
    basename = basename.replace('.strip', '')
    parts = basename.split('-')
    return parts[0], parts[1]

def determine_patch_result(score):
    return 'pre-patch version' if float(score) < 0 else 'patched version'

def determine_groundtruth(label):
    return 'pre-patch version' if label == -1 else 'patched version'


def determine_patch_result_ps3(score):
    return 'pre-patch version' if score == "vuln" else 'patched version'

def determine_groundtruth_ps3(label):
    return 'pre-patch version' if label == "vuln" else 'patched version'

def calculate_tpfp(patch_result, groundtruth):

    if patch_result == groundtruth == "patched version":
        detection_result = "TP"
    elif patch_result == groundtruth == "pre-patch version":
        detection_result = "TN"
    elif patch_result == "patched version" and groundtruth == "pre-patch version":
        detection_result = "FN"
    elif patch_result == "pre-patch version" and groundtruth == "patched version":
        detection_result = "FP"
    else:
        print(f"Unknown detection result: {patch_result}, {groundtruth}")
        return "False"
    
    return detection_result



def calculate_robin_gcc_score(csv1_path, csv2_path, result_path, compiler_name):
    # 读取CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)

    # 处理df2中的function_name
    df2['function_name'] = df2['function_name'].apply(process_function_name)

    # 找出匹配的行
    matches = []
    for _, row1 in df1.iterrows():
        matching_rows = df2[
            (df2['cve_id'] == row1['cve']) &
            (df2['function_name'] == row1['func_name']) &
            (df2['optimization_level'] == row1['optim'])
        ]
        if not matching_rows.empty:
            matches.append(row1)

    # 创建新的DataFrame
    df3 = pd.DataFrame(matches)

    # 转换格式
    result = []
    for _, row in df3.iterrows():
        project_name, version_name = get_project_version(row['bin_path'])
        
        patch_result = determine_patch_result(row['score'])
        groundtruth = determine_groundtruth(row['label'])

        new_row = {
            'cve_id': row['cve'],
            'arch_name': 'x86',
            'compiler_name': compiler_name,
            'optimization_level': row['optim'],
            'project_name': project_name,
            'version_name': version_name,
            'function_name': row['func_name'],
            'patch_result': patch_result,
            'groundtruth': groundtruth,
            'detection_result': calculate_tpfp(patch_result, groundtruth)  # 这里留空，根据需求补充
        }
        result.append(new_row)

    # 创建最终的DataFrame并保存
    final_df = pd.DataFrame(result)
    final_df.to_csv(result_path, index=False)



def calculate_robin_clang_score(csv1_path, csv2_path, result_path, compiler_name):
    # 读取CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)

    # 处理df2中的function_name
    df2['function_name'] = df2['function_name'].apply(process_function_name)

    # 找出匹配的行
    matches = []
    for _, row1 in df1.iterrows():
        matching_rows = df2[
            (df2['cve_id'] == row1['cve']) &
            (df2['function_name'] == row1['vul_func']) &
            (df2['optimization_level'] == row1['optim'])
        ]
        if not matching_rows.empty:
            matches.append(row1)

    # 创建新的DataFrame
    df3 = pd.DataFrame(matches)

    # 转换格式
    result = []
    for _, row in df3.iterrows():
        project_name, version_name = get_project_version(row['tgt_func'])
        
        patch_result = determine_patch_result(row['score'])
        groundtruth = determine_groundtruth(row['label'])

        new_row = {
            'cve_id': row['cve'],
            'arch_name': 'x86',
            'compiler_name': compiler_name,
            'optimization_level': row['optim'],
            'project_name': project_name,
            'version_name': version_name,
            'function_name': row['vul_func'],
            'patch_result': patch_result,
            'groundtruth': groundtruth,
            'detection_result': calculate_tpfp(patch_result, groundtruth)  # 这里留空，根据需求补充
        }
        result.append(new_row)

    # 创建最终的DataFrame并保存
    final_df = pd.DataFrame(result)
    final_df.to_csv(result_path, index=False)



def calculate_ps3_gcc_score(csv1_path, csv2_path, result_path, compiler_name):
    # 读取CSV文件
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)

    # 处理df2中的function_name
    df2['function_name'] = df2['function_name'].apply(process_function_name)

    # 找出匹配的行
    matches = []
    for _, row1 in df1.iterrows():
        matching_rows = df2[
            (df2['cve_id'] == row1['cve']) &
            (df2['function_name'] == row1['func'])
        ]
        if not matching_rows.empty:
            matches.append(row1)

    # 创建新的DataFrame
    df3 = pd.DataFrame(matches)

    # 转换格式
    result = []
    for _, row in df3.iterrows():
        project_name = version_name = row['file']
        
        patch_result = determine_patch_result_ps3(row['pred_label'])
        groundtruth = determine_groundtruth_ps3(row['label'])
        optim = row['file'].split("_")[-3]

        new_row = {
            'cve_id': row['cve'],
            'arch_name': 'x86',
            'compiler_name': compiler_name,
            'optimization_level': optim,
            'project_name': project_name,
            'version_name': version_name,
            'function_name': row['func'],
            'patch_result': patch_result,
            'groundtruth': groundtruth,
            'detection_result': calculate_tpfp(patch_result, groundtruth)  # 这里留空，根据需求补充
        }
        result.append(new_row)

    # 创建最终的DataFrame并保存
    final_df = pd.DataFrame(result)
    final_df.to_csv(result_path, index=False)



def get_clang_res(input_csv, output_csv):   
    # 读取CSV文件
    df = pd.read_csv(input_csv)

    # 选择compiler_name列为clang的行
    clang_df = df[df['compiler_name'] == 'clang']

    # 将结果保存到新的CSV文件
    clang_df.to_csv(output_csv, index=False)




def analyze_csv(filename):
    # 读取CSV文件
    df = pd.read_csv(filename)
    
    # 计算不同cve_id的数量
    unique_cves = len(df['cve_id'].unique())
    
    # 处理function_name列，去掉_后面的内容
    df['clean_function'] = df['function_name'].apply(lambda x: x.rsplit('_', 1)[0])
    unique_functions = len(df['clean_function'].unique())
    
    return unique_cves, unique_functions

def analyze_directory(data_dir):
    # 存储所有的CVE和函数名
    cves = set()
    functions = set()
    
    # 遍历目录
    for dirname in os.listdir(data_dir):
        # 去掉最后的_数字
        base_name = '_'.join(dirname.rsplit('_', 1)[0].split('_'))
        
        # 分离CVE编号和函数名
        parts = base_name.split('_')
        
        # CVE编号通常是前两部分(CVE-YYYY-XXXX)
        cve = '_'.join(parts[0])
        # 函数名是剩余部分
        function = '_'.join(parts[3:])
        
        cves.add(cve)
        functions.add(base_name)
    
    return len(cves), len(functions), cves, functions



def filter_detection_results(input_file, res_file):
    """
    读取CSV文件，只保留最后一列 'detection_result' 值为 'TP' 或 'FN' 的行，写入新文件。

    :param input_file: 输入文件路径
    :param res_file: 输出文件路径
    """
    try:
        # 打开输入文件并读取内容
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
            reader = csv.reader(infile)
            
            # 读取表头
            header = next(reader)

            # 检查CSV文件是否为标准格式
            if not header or header[-1] != "detection_result":
                raise ValueError("输入文件最后一列应该是 'detection_result'")

            # 保留符合条件的行（最后一列为 'TP' or 'FN'）
            filtered_rows = [header]  # 包括表头
            for row in reader:
                if row[-1] in ("TP", "FN"):
                    filtered_rows.append(row)

        # 将结果写入新文件
        with open(res_file, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile)
            writer.writerows(filtered_rows)

        print(f"处理完成，结果已保存到 {res_file}")

    except Exception as e:
        print(f"发生错误: {e}")


# calculate my result
def calculate_all_result(data_path="code/data", res_path="."):
    calculate_score(data_path, os.path.join(res_path, "output_llm.csv"))
    analyze_results(os.path.join(res_path, "output_llm.csv"))

    calculate_score_z3(data_path, os.path.join(res_path, "output_z3.csv"))
    analyze_results(os.path.join(res_path, "output_z3.csv"))

    filter_detection_results(os.path.join(res_path, "output_z3.csv"), os.path.join(res_path, "output_z3_exact.csv"))


    merge_csv_files(os.path.join(res_path, "output_z3_exact.csv"), os.path.join(res_path, "output_llm.csv"), os.path.join(res_path, "output.csv"))

    analyze_results(os.path.join(res_path, "output.csv"))

# df1_path = "./output_llm.csv"
# df2_path = "./output_z3.csv"
# process_csv_files(df1_path, df2_path)
# process_csv_files_bad(df1_path, df2_path)

# get_clang_res("./output.csv", "./output_clang_2.csv")
# analyze_results("./output.csv")
# analyze_results("./output_clang_2.csv")


# 使用示例
# result_cves, result_funcs = analyze_csv('output.csv')
# print(f"Number of unique CVEs: {result_cves}")
# print(f"Number of unique functions (without hex): {result_funcs}")

# cve_count, func_count, unique_cves, unique_funcs = analyze_directory('/media/author/4A7AC8957AC87F67/work2024/code/llm_api/data')
# print(f"Number of unique CVEs: {cve_count}")
# print(f"Number of unique functions: {func_count}")
# print("\nUnique CVEs:", sorted(unique_cves))
# print("\nUnique functions:", sorted(unique_funcs))


# calculate robin gcc result
# calculate_robin_gcc_score(
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/other_res/robin_rq1_results_0905.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/output.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/robin_gcc.csv',
#     'gcc')

# analyze_results('/media/author/4A7AC8957AC87F67/work2024/code/llm_api/robin_gcc.csv')


# calculate robin clang result
# calculate_robin_clang_score(
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/other_res/robin-optim-clang-1203.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/output.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/robin_clang.csv',
#     'clang')

# analyze_results('/media/author/4A7AC8957AC87F67/work2024/code/llm_api/robin_clang.csv')


# calculate ps3 gcc result
# calculate_ps3_gcc_score(
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/other_res/test_res-rq1.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/output.csv', 
#     '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/ps3_gcc.csv',
#     'gcc')

# analyze_results('/media/author/4A7AC8957AC87F67/work2024/code/llm_api/ps3_gcc.csv')
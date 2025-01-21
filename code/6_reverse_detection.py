import os
import sys
import json
from tqdm import tqdm
import glob
import re
from itertools import groupby

sys.path.append("code/patch_verification")
sys.path.append("code/llm_location")

import patch_match
import llm_detection


def pseudo_mark(llm_res_path, pseudo_path, res_path):
    pass



def find_min_line_numbers(json_data):
    patch_info = json_data['patch_info']
    added_lines = list(map(int, patch_info['added_code'].keys()))
    deleted_lines = list(map(int, patch_info['deleted_code'].keys()))
    
    min_added = 0
    min_deleted = 0
    if added_lines != []:
        min_added = min(added_lines)
    if deleted_lines != []:
        min_deleted = min(deleted_lines)
    
    if min_added == 0 and min_deleted == 0:
        print("Warning: No added or deleted lines found in result.json")
        exit(0)
    elif min_added == 0:
        return min_deleted
    elif min_deleted == 0:
        return min_added
    else:
        return min(min_added, min_deleted)


def reverse_detection(data_dir):
    for cve_dir_name in tqdm(os.listdir(data_dir)):

        if "CVE-2016-4447" not in cve_dir_name:
            continue

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
        patch_line_number = find_min_line_numbers(result_data)

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        patch_path_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        vul_path_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))

        # 定义文件名匹配模式
        llm_pattern = r'llm_res_(\d+)\.txt'
        pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]
            
            # Check for patched code file

            patch_res_dir = os.path.join(dir_path, "apatch_res_" + filename, "temp")
            vul_res_dir = os.path.join(dir_path, "avul_res_" + filename, "temp")

            # Create result directory for patched analysis
            vulrev_res_dir = os.path.join(dir_path, "avulrev_res_" + filename)
            patchrev_res_dir = os.path.join(dir_path, "apatchrev_res_" + filename)


            if (os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir)) or (os.path.exists(patch_res_dir) and not os.path.exists(vul_res_dir)):

                # 存储文件对
                file_pairs = {}
                if not os.path.exists(vulrev_res_dir):
                    os.makedirs(vulrev_res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(patch_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)

                for number_item in file_pairs:
                    print(f"Detection the {vulrev_res_dir}")
                    # if os.path.exists(os.path.join(vulrev_res_dir, "llm_res_" + number_item + ".txt")):
                    #     continue
                    try:
                        detection_rev_res = llm_detection.get_rev_prompt(number_item, vul_path_list[0], file_pairs[number_item]['pseudo'], file_pairs[number_item]['llm'], patch_line_number, vulrev_res_dir)
                    except:
                        print("Error in patch_detection_one")
                        continue            


            if (os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir)) or (not os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir)):

                # 存储文件对
                file_pairs = {}

                if not os.path.exists(patchrev_res_dir):
                    os.makedirs(patchrev_res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(vul_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)
                for number_item in file_pairs:
                    print(f"Detection the {patchrev_res_dir}")
                    if os.path.exists(os.path.join(patchrev_res_dir, "llm_res_" + number_item + ".txt")):
                        continue
                    try:
                        detection_rev_res = llm_detection.get_rev_prompt(number_item, patch_path_list[0], file_pairs[number_item]['pseudo'], file_pairs[number_item]['llm'], patch_line_number, patchrev_res_dir)
                    except:
                        print("Error in patch_detection_one")
                        continue            

reverse_detection("/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data")
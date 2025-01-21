import os
import json
import re
import sys
import pandas as pd
import tqdm
import shutil

sys.path.append("code/get_patch_function/source_code_extract")

import get_src_func


def copy_diff(xlsx_file, patch_path, src_path, res_save_path):
    # Read all .json files in the patch_path
    json_files = [f for f in os.listdir(patch_path) if f.endswith('.json')]

    # Read the xlsx file
    df = pd.read_excel(xlsx_file, engine='openpyxl')
    df.fillna('', inplace=True)  # Replace NaN with empty strings

    cve_num_dict = dict()

    # For each json file
    for json_file in tqdm.tqdm(json_files):
        json_file_path = os.path.join(patch_path, json_file)
        # Extract CVE number and project name from filename
        m = re.match(r'(CVE-\d{4}-\d+)_([^_]+)_.*\.json', json_file)
        if not m:
            print(f"Filename format not recognized: {json_file}")
            continue
        cve_id = m.group(1)

        # if cve_id != 'CVE-2014-0224':
        #     continue

        project_name = m.group(2)
        # Read the JSON file content
        with open(json_file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in file {json_file_path}: {e}")
                continue

        # # Ensure data is a list
        # if isinstance(data, dict):
        #     items = [data]
        # elif isinstance(data, list):
        #     items = data
        # else:
        #     print(f"Unexpected JSON structure in file {json_file_path}")
        #     continue

        # For each member in data
        for idx, item in data.items():
            # Extract function_name
            # item = list(item.values())[0] if isinstance(item, dict) else item
            function_name = item.get('function_name')
            if not function_name:
                print(f"No function_name found in item index {idx} in file {json_file_path}")
                open(f'error_log/error_{cve_id}.txt', 'a').write(f"No function_name found in item index {idx} in file {json_file_path}\n")
                continue
            # Using CVE number and function_name, find the corresponding row(s) in Excel
            matched_rows = df[(df['CVE_ID'] == cve_id) & (df['cve_func'] == function_name)]
            if matched_rows.empty:
                print(f"No matching rows found in Excel for CVE_ID {cve_id} and function_name {function_name}")
                open(f'error_log/error_{cve_id}.txt', 'a').write(f"No matching rows found in Excel for CVE_ID {cve_id} and function_name {function_name}\n")
                continue
            # Assume we take the first matched row
            for index, row in matched_rows.iterrows():
                # row = matched_rows.iloc[0]
                # Get required fields
                patch_commits = row['Patch_commit']
                hash_version = str(patch_commits).split('\n')[0].strip()
                vul_binary = row['need_Latest_version']
                patch_binary = row['patch_version']
                # Prepare parameters for extract_function
                source_project_path = os.path.join(source_path, project_name)
                if cve_id not in cve_num_dict:
                    cve_num_dict[cve_id] = 1
                else:
                    cve_num_dict[cve_id] += 1
                res_cve_dir = os.path.join(res_save_path, f"{cve_id}_{function_name}_{cve_num_dict[cve_id]}")
                os.makedirs(res_cve_dir, exist_ok=True)
                output_file_path_patch = os.path.join(res_cve_dir, f"{function_name}_patched.c")
                output_file_path_vul = os.path.join(res_cve_dir, f"{function_name}_vul.c")
                # Call extract_function with original hash_version
                # function_content, line_number = get_src_func.get_source_func(source_project_path, function_name, hash_version, tmp_path)
                # if function_content and line_number:
                # # 将函数内容和行号保存到结果路径
                #     with open(output_file_path_patch, 'w', encoding='utf-8') as f:
                #         f.write(f'// Function starts at line {line_number}\n')  # 添加行号信息
                #         f.write(function_content)
                # Modify hash_version by appending '^' and call extract_function again
                hash_version_patched = hash_version + '^'
                # function_content, line_number = get_src_func.get_source_func(source_project_path, function_name, hash_version_patched, tmp_path)
                # if function_content and line_number:
                # # 将函数内容和行号保存到结果路径
                #     with open(output_file_path_vul, 'w', encoding='utf-8') as f:
                #         f.write(f'// Function starts at line {line_number}\n')  # 添加行号信息
                #         f.write(function_content)
                # Prepare JSON data to save
                result_data = {
                    'CVE_id': cve_id,
                    'project_name': project_name,
                    'function_name': function_name,
                    'source_vul_version': hash_version_patched,
                    'source_patch_version': hash_version,
                    'binary_vul_version': vul_binary,
                    'binary_patch_version': patch_binary,
                    'patch_info': item
                }
                # Save result to JSON file
                result_json_path = os.path.join(res_cve_dir, 'result.json')
                # try:
                #     with open(result_json_path, 'w', encoding='utf-8') as json_f:
                #         json.dump(result_data, json_f, ensure_ascii=False, indent=4)
                # except Exception as e:
                #     print(f"Error saving JSON to {result_json_path}: {e}")
                #     open(f'error_log/error_{cve_id}.txt', 'a').write(f"Error saving JSON to {result_json_path}: {e}\n")
                try:
                    shutil.copy(json_file_path.replace("/sig", "/src").replace(".json", ".c"), os.path.join(res_cve_dir, 'patch.diff'))
                    print("File copied successfully")
                except IOError as e:
                    print(f"Error copying file: {e}")
    print("Script execution completed.")




def main(xlsx_file, patch_path, source_path, tmp_path, res_save_path):
    # Read all .json files in the patch_path
    json_files = [f for f in os.listdir(patch_path) if f.endswith('.json')]

    # Read the xlsx file
    df = pd.read_excel(xlsx_file, engine='openpyxl')
    df.fillna('', inplace=True)  # Replace NaN with empty strings

    cve_num_dict = dict()

    # For each json file
    for json_file in tqdm.tqdm(json_files):
        json_file_path = os.path.join(patch_path, json_file)
        # Extract CVE number and project name from filename
        m = re.match(r'(CVE-\d{4}-\d+)_([^_]+)_.*\.json', json_file)
        if not m:
            print(f"Filename format not recognized: {json_file}")
            continue
        cve_id = m.group(1)

        # if cve_id != 'CVE-2014-0224':
        #     continue

        project_name = m.group(2)
        # Read the JSON file content
        with open(json_file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in file {json_file_path}: {e}")
                continue

        # # Ensure data is a list
        # if isinstance(data, dict):
        #     items = [data]
        # elif isinstance(data, list):
        #     items = data
        # else:
        #     print(f"Unexpected JSON structure in file {json_file_path}")
        #     continue

        # For each member in data
        for idx, item in data.items():
            # Extract function_name
            # item = list(item.values())[0] if isinstance(item, dict) else item
            function_name = item.get('function_name')
            if not function_name:
                print(f"No function_name found in item index {idx} in file {json_file_path}")
                open(f'error_log/error_{cve_id}.txt', 'a').write(f"No function_name found in item index {idx} in file {json_file_path}\n")
                continue
            # Using CVE number and function_name, find the corresponding row(s) in Excel
            matched_rows = df[(df['CVE_ID'] == cve_id) & (df['cve_func'] == function_name)]
            if matched_rows.empty:
                print(f"No matching rows found in Excel for CVE_ID {cve_id} and function_name {function_name}")
                open(f'error_log/error_{cve_id}.txt', 'a').write(f"No matching rows found in Excel for CVE_ID {cve_id} and function_name {function_name}\n")
                continue
            # Assume we take the first matched row
            for index, row in matched_rows.iterrows():
                # row = matched_rows.iloc[0]
                # Get required fields
                patch_commits = row['Patch_commit']
                hash_version = str(patch_commits).split('\n')[0].strip()
                vul_binary = row['need_Latest_version']
                patch_binary = row['patch_version']
                # Prepare parameters for extract_function
                source_project_path = os.path.join(source_path, project_name)
                if cve_id not in cve_num_dict:
                    cve_num_dict[cve_id] = 1
                else:
                    cve_num_dict[cve_id] += 1
                res_cve_dir = os.path.join(res_save_path, f"{cve_id}_{function_name}_{cve_num_dict[cve_id]}")
                os.makedirs(res_cve_dir, exist_ok=True)
                output_file_path_patch = os.path.join(res_cve_dir, f"{function_name}_patched.c")
                output_file_path_vul = os.path.join(res_cve_dir, f"{function_name}_vul.c")
                # Call extract_function with original hash_version
                function_content, line_number = get_src_func.get_source_func(source_project_path, function_name, hash_version, tmp_path)
                if function_content and line_number:
                # 将函数内容和行号保存到结果路径
                    with open(output_file_path_patch, 'w', encoding='utf-8') as f:
                        f.write(f'// Function starts at line {line_number}\n')  # 添加行号信息
                        f.write(function_content)
                # Modify hash_version by appending '^' and call extract_function again
                hash_version_patched = hash_version + '^'
                function_content, line_number = get_src_func.get_source_func(source_project_path, function_name, hash_version_patched, tmp_path)
                if function_content and line_number:
                # 将函数内容和行号保存到结果路径
                    with open(output_file_path_vul, 'w', encoding='utf-8') as f:
                        f.write(f'// Function starts at line {line_number}\n')  # 添加行号信息
                        f.write(function_content)
                # Prepare JSON data to save
                result_data = {
                    'CVE_id': cve_id,
                    'project_name': project_name,
                    'function_name': function_name,
                    'source_vul_version': hash_version_patched,
                    'source_patch_version': hash_version,
                    'binary_vul_version': vul_binary,
                    'binary_patch_version': patch_binary,
                    'patch_info': item
                }
                # Save result to JSON file
                result_json_path = os.path.join(res_cve_dir, 'result.json')
                try:
                    with open(result_json_path, 'w', encoding='utf-8') as json_f:
                        json.dump(result_data, json_f, ensure_ascii=False, indent=4)
                except Exception as e:
                    print(f"Error saving JSON to {result_json_path}: {e}")
                    open(f'error_log/error_{cve_id}.txt', 'a').write(f"Error saving JSON to {result_json_path}: {e}\n")
    print("Script execution completed.")

if __name__ == '__main__':
    # if len(sys.argv) != 5:
    #     print("Usage: python script.py <patch_path> <source_path> <tmp_path> <res_save_path>")
    #     sys.exit(1)
    xlsx_file = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/cve_data_0731.xlsx"
    patch_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/sig"   #sys.argv[1]
    source_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/source"     #sys.argv[2]
    tmp_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/tmp"   #sys.argv[3]
    res_save_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/data"     #sys.argv[4]
    src_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/src"

    
    main(xlsx_file, patch_path, source_path, tmp_path, res_save_path)

    
    # copy_diff(xlsx_file, patch_path, src_path, res_save_path)
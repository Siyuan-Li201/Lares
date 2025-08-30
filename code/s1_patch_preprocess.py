import os
import sys
import json
import csv
import re
from tqdm import tqdm
import shutil

sys.path.append("code/code/get_patch_function/patch_code_extract")

import get_patch_code
# import llm_detection


def extract_cve_from_filename(filename):
    """从文件名中提取CVE ID"""
    match = re.search(r'CVE-\d{4}-\d{4,}', filename)
    return match.group(0) if match else None

def read_patch_info(file1_path):
    """读取文件1的patch_info JSON数据"""
    try:
        with open(file1_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"错误: 找不到文件 {file1_path}")
        return None
    except json.JSONDecodeError:
        print(f"错误: {file1_path} 不是有效的JSON格式")
        return None

def read_vulnerability_data(file2_path):
    """读取文件2的漏洞信息CSV数据"""
    try:
        vuln_data = []
        with open(file2_path, 'r', encoding='utf-8') as f:
            # 检查文件内容来确定分隔符
            first_line = f.readline()
            f.seek(0)
            
            # 判断是使用逗号还是制表符分隔
            if ',' in first_line and first_line.count(',') > first_line.count('\t'):
                delimiter = ','
                print(f"检测到CSV格式（逗号分隔）")
            else:
                delimiter = '\t'
                print(f"检测到TSV格式（制表符分隔）")
            
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                vuln_data.append(row)
        print(f"成功读取CSV文件，共{len(vuln_data)}行数据")
        return vuln_data
    except FileNotFoundError:
        print(f"错误: 找不到文件 {file2_path}")
        return None
    except UnicodeDecodeError as e:
        print(f"编码错误: {e}")
        return None

def find_matching_vulnerability(cve_id, function_name, vuln_data):
    """根据CVE ID和function_name查找匹配的漏洞信息"""
    for row in vuln_data:
        if row['CVE_ID'] == cve_id and row['cve_func'] == function_name:
            return row
    return None

def generate_output_data(file1_path, patch_info, vuln_info):
    """生成输出数据"""
    # 从文件名提取CVE ID
    filename = os.path.basename(file1_path)
    cve_id = extract_cve_from_filename(filename)
    
    if not cve_id:
        print(f"错误: 无法从文件名 {filename} 中提取CVE ID")
        return None
    
    # 获取第一个函数的信息（假设每个文件只有一个主要函数）
    first_key = list(patch_info.keys())[0]
    first_patch = patch_info[first_key]
    function_name = first_patch['function_name']
    
    # 查找匹配的漏洞信息
    matching_vuln = find_matching_vulnerability(cve_id, function_name, vuln_info)
    
    if not matching_vuln:
        print(f"警告: 未找到CVE {cve_id} 和函数 {function_name} 的匹配记录")
        # 使用默认值
        project_name = "unknown"
        binary_vul_version = "unknown"
        binary_patch_version = "unknown"
        source_patch_version = "unknown"
    else:
        project_name = matching_vuln['oss_name']
        binary_vul_version = matching_vuln['need_Latest_version']
        binary_patch_version = matching_vuln['patch_version']
        
        # 从patch_commit中提取第一个commit hash作为source_patch_version
        patch_commits = matching_vuln['Patch_commit'].strip('"').split('\n')
        source_patch_version = patch_commits[0].strip() if patch_commits else "unknown"
    
    # 生成source_vul_version（在source_patch_version后面加上^）
    source_vul_version = f"{source_patch_version}^"
    
    # 构建输出数据
    output_data = {
        "CVE_id": cve_id,
        "project_name": project_name,
        "function_name": function_name,
        "source_vul_version": source_vul_version,
        "source_patch_version": source_patch_version,
        "binary_vul_version": binary_vul_version,
        "binary_patch_version": binary_patch_version,
        "patch_info": first_patch
    }
    
    return output_data

def write_output_file(output_data, file3_path):
    """将输出数据写入文件3"""
    try:
        with open(file3_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        print(f"成功生成输出文件: {file3_path}")
        return True
    except Exception as e:
        print(f"错误: 写入文件 {file3_path} 时出错: {e}")
        return False



def generate_json_files_from_c(patch_dir, res_dir, res2_path, vul_path):
    """
    获取patch路径里所有以 .c 结尾的文件路径，
    使用这些文件的名字（将后缀改为 .json）作为res路径中保存结果文件的名字。
    """

    if not os.path.exists(res_dir):
        os.makedirs(res_dir)

    # 遍历patch路径中的所有文件
    for root, _, files in os.walk(patch_dir):
        for file in files:
            if file.endswith(".c"):  # 只处理以 .c 结尾的文件
                # 获取文件名（不含路径）
                c_file_name = os.path.basename(file)
                file_path = os.path.join(root, file)
                # 替换后缀为 .json
                json_file_name = os.path.splitext(c_file_name)[0] + ".json"
                # 构造保存路径
                json_file_path = os.path.join(res_dir, json_file_name)

                parsed_data = get_patch_code.parse_patch(file_path)
                get_patch_code.save_json(parsed_data, json_file_path)
                print(f"解析完成，结果已保存到 {json_file_path}")


                first_key = list(parsed_data.keys())[0]
                first_patch = parsed_data[first_key]
                new_dir_name = json_file_name.split("_")[0]+"_"+first_patch["function_name"]+json_file_name[:-5][-2:]

                res2_path_dir = os.path.join(res2_path, new_dir_name)
                if not os.path.exists(res2_path_dir):
                    os.mkdir(res2_path_dir)
                file3_path = os.path.join(res2_path_dir, "result.json")


                shutil.copy(file_path, os.path.join(res2_path_dir, "patch.diff"))

                # 读取文件2的漏洞数据
                print("读取漏洞数据...")
                vuln_data = read_vulnerability_data(vul_path)
                if vuln_data is None:
                    return
                
                # 生成输出数据
                print("生成输出数据...")
                output_data = generate_output_data(file_path, parsed_data, vuln_data)
                if output_data is None:
                    return
                
                

                # 写入输出文件
                print("写入输出文件...")
                success = write_output_file(output_data, file3_path)


if __name__ == "__main__":
    # 输入 patch 路径和 res 路径
    patch_path = "code/dataset/patch/src/"   #input("请输入patch路径: ").strip()
    vul_path = "code/dataset/patch/cve_data.csv"
    res_path = "code/dataset/patch/sig/"    #input("请输入res路径: ").strip()
    res2_path = "code/data/"

    if not os.path.exists(patch_path):
        print(f"patch路径 {patch_path} 不存在！")
    else:
        generate_json_files_from_c(patch_path, res_path, res2_path, vul_path)
        print("操作完成！")
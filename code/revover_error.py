import os, json


def recover_error(data_directory):

    for cve_dir_name in os.listdir(data_directory):
        cve_dir_path = os.path.join(data_directory, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"
    
    # 构建result.json的完整路径
        result_file = os.path.join(cve_dir_path, "result.json")
        
        # 检查文件是否存在
        if not os.path.exists(result_file):
            continue
            
        try:
            # 读取JSON文件
            with open(result_file, 'r') as f:
                data = json.load(f)
            
            # 交换版本信息
            temp = data["source_vul_version"]
            data["source_vul_version"] = data["source_patch_version"]
            data["source_patch_version"] = temp
            
            # 保存修改后的JSON文件
            with open(result_file, 'w') as f:
                json.dump(data, f, indent=4)
                
        except Exception as e:
            print(f"Error processing {result_file}: {str(e)}")
            continue


recover_error("/media/author/4A7AC8957AC87F67/work2024/code/llm_api/data")
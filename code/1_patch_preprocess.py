import os
import sys
import json
from tqdm import tqdm

sys.path.append("code/get_patch_function/patch_code_extract")

import get_patch_code
# import llm_detection



def generate_json_files_from_c(patch_dir, res_dir):
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


if __name__ == "__main__":
    # 输入 patch 路径和 res 路径
    patch_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/src/"   #input("请输入patch路径: ").strip()
    res_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/sig/"    #input("请输入res路径: ").strip()

    if not os.path.exists(patch_path):
        print(f"patch路径 {patch_path} 不存在！")
    else:
        generate_json_files_from_c(patch_path, res_path)
        print("操作完成！")
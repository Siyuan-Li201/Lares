import os
import sys
import json
import re
import shutil
import tqdm

sys.path.append("code/get_patch_function/binary_code_extract")

import get_pseudo

def map_version(project, version):
    """
    Map the version format from result.json to the corresponding bin_directory format.
    """
    project_lower = project.lower()
    if project_lower == 'openssl':
        bin_version = 'OpenSSL_' + version.replace('.', '_')
        bin_file_prefix = 'openssl-' + version
    elif project_lower == 'freetype':
        bin_version = 'VER-' + version.replace('.', '-')
        bin_file_prefix = 'freetype-' + version
    elif project_lower == 'libxml2':
        bin_version = 'v' + version
        bin_file_prefix = 'libxml2-' + version
    elif project_lower == 'tcpdump':
        bin_version = 'tcpdump-' + version
        bin_file_prefix = 'tcpdump-' + version
    else:
        # Handle any other projects as needed
        bin_version = version
        bin_file_prefix = project + '-' + version
    return bin_version, bin_file_prefix

def check_file_and_break(directory, dest_binary_path):
    """
    检查指定目录下是否有以 dest_binary_path 开头，".idapseudo" 结尾的文件。
    如果找到符合条件的文件，打印文件名并退出循环。

    Args:
    - directory (str): 指定的目录路径。
    - dest_binary_path (str): 文件名前缀。

    Returns:
    - bool: 如果找到符合条件的文件返回 True，否则返回 False。
    """
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.startswith(dest_binary_path) and file.endswith(".idapseudo"):
                print(f"Found file: {os.path.join(root, file)}")
                return True  # 找到符合条件的文件，退出函数
    return False  # 未找到符合条件的文件


def pseudo_prompt_generation(data_directory, bin_directory):
    """
    Process CVE directories to copy corresponding binaries and call get_func_pseudo.
    """
    # Iterate over subdirectories in data_directory
    for cve_dir_name in tqdm.tqdm(os.listdir(data_directory)):
        cve_dir_path = os.path.join(data_directory, cve_dir_name)
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

        function_name = result_data.get("function_name")
        binary_vul_version = result_data.get("binary_vul_version")
        binary_patch_version = result_data.get("binary_patch_version")

        if not function_name or not binary_vul_version:
            print(f"Error: Missing function_name or binary_vul_version in {result_json_path}")
            continue

        # Extract project and version from binary_vul_version
        if ':' in binary_vul_version:
            project, version = binary_vul_version.split(':', 1)
        else:
            print(f"Error: Invalid binary_vul_version format: {binary_vul_version} in {result_json_path}")
            continue

        # Extract project and version from binary_patch_version
        if ':' in binary_patch_version:
            patch_project, patch_version = binary_patch_version.split(':', 1)
        else:
            print(f"Error: Invalid binary_patch_version format: {binary_patch_version} in {result_json_path}")
            continue

        # Map version to bin_directory format
        bin_version, bin_file_prefix = map_version(project, version)
        patch_bin_version, patch_bin_file_prefix = map_version(patch_project, patch_version)

        # Define architectures, compilers, and optimization levels
        architectures = ["X86"]
        compilers = ["Clang", "gcc"]
        optimization_levels = ["O0", "O1", "O2", "O3"]

        for arch in architectures:
            for compiler in compilers:
                for optimization in optimization_levels:
                    # Construct the source directory path
                    source_dir = os.path.join(
                        bin_directory,
                        compiler,
                        project,
                        arch,
                        optimization,
                        bin_version
                    )

                    source_dir2 = os.path.join(
                        bin_directory,
                        compiler,
                        project,
                        arch,
                        optimization,
                        patch_bin_version
                    )

                    if not os.path.exists(source_dir):
                        print(f"Warning: Source directory does not exist: {source_dir}")
                        continue

                    # Construct binary file names
                    binary_file = bin_file_prefix
                    binary_strip_file = bin_file_prefix + '.strip'

                    patch_binary_file = patch_bin_file_prefix
                    patch_binary_strip_file = patch_bin_file_prefix + '.strip'

                    # Paths to the binaries in the source directory
                    binary_file_path = os.path.join(source_dir, binary_file)
                    binary_strip_file_path = os.path.join(source_dir, binary_strip_file)

                    binary_file_path2 = os.path.join(source_dir2, patch_binary_file)
                    binary_strip_file_path2 = os.path.join(source_dir2, patch_binary_strip_file)

                    # Check for existence of binaries
                    binary_exists = os.path.exists(binary_file_path)
                    strip_binary_exists = os.path.exists(binary_strip_file_path)

                    binary_exists2 = os.path.exists(binary_file_path2)
                    strip_binary_exists2 = os.path.exists(binary_strip_file_path2)

                    if not binary_exists and not strip_binary_exists:
                        print(f"Warning: Neither binary nor stripped binary exist in {source_dir}")
                        continue

                    if not binary_exists2 and not strip_binary_exists2:
                        print(f"Warning: Neither binary nor stripped binary exist in {source_dir2}")
                        continue

                    # Copy binaries to CVE directory with new names
                    dest_binary_name = f"{arch.lower()}_{compiler.lower()}_{optimization}_{project}_{version}"
                    dest_binary_path = os.path.join(cve_dir_path, dest_binary_name)

                    dest_binary_name2 = f"{arch.lower()}_{compiler.lower()}_{optimization}_{patch_project}_{patch_version}"
                    dest_binary_path2 = os.path.join(cve_dir_path, dest_binary_name2)

                    dest_binary_strip_name = dest_binary_name + '_strip'
                    dest_binary_strip_path = os.path.join(cve_dir_path, dest_binary_strip_name)

                    dest_binary_strip_name2 = dest_binary_name2 + '_strip'
                    dest_binary_strip_path2 = os.path.join(cve_dir_path, dest_binary_strip_name2)

                    if not os.path.exists(dest_binary_path):
                        if binary_exists:
                            shutil.copy2(binary_file_path, dest_binary_path)
                            print(f"Copied binary to {dest_binary_path}")
                        else:
                            # If non-stripped binary doesn't exist, we might skip calling get_func_pseudo
                            dest_binary_path = None
                            print(f"Non-stripped binary does not exist: {binary_file_path}")
                    
                    if not os.path.exists(dest_binary_path2):
                        if binary_exists2:
                            shutil.copy2(binary_file_path2, dest_binary_path2)
                            print(f"Copied binary to {dest_binary_path2}")
                        else:
                            # If non-stripped binary doesn't exist, we might skip calling get_func_pseudo
                            dest_binary_path2 = None
                            print(f"Non-stripped binary does not exist: {binary_file_path2}")

                    if not os.path.exists(dest_binary_strip_path):
                        if strip_binary_exists:
                            shutil.copy2(binary_strip_file_path, dest_binary_strip_path)
                            print(f"Copied stripped binary to {dest_binary_strip_path}")
                        else:
                            dest_binary_strip_path = None
                            print(f"Stripped binary does not exist: {binary_strip_file_path}")
                    
                    if not os.path.exists(dest_binary_strip_path2):
                        if strip_binary_exists2:
                            shutil.copy2(binary_strip_file_path2, dest_binary_strip_path2)
                            print(f"Copied stripped binary to {dest_binary_strip_path2}")
                        else:
                            dest_binary_strip_path2 = None
                            print(f"Stripped binary does not exist: {binary_strip_file_path2}")

                    # Call get_func_pseudo if binaries are available
                    if not check_file_and_break(cve_dir_path, dest_binary_path):
                        if dest_binary_path and dest_binary_strip_path:
                            get_pseudo.get_func_pseudo(dest_binary_path, dest_binary_strip_path, function_name)
                        else:
                            print(f"Skipping get_func_pseudo call due to missing binaries for {function_name}")
                    
                    if not check_file_and_break(cve_dir_path, dest_binary_path2):
                        if dest_binary_path2 and dest_binary_strip_path2:
                            get_pseudo.get_func_pseudo(dest_binary_path2, dest_binary_strip_path2, function_name)
                        else:
                            print(f"Skipping get_func_pseudo call due to missing binaries for {function_name}")


def process_c_file(c_file_path, code_dict, function_start_line_no):
    # Read the .c file into a list of lines
    with open(c_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Prepare to modify lines
    modified_lines = lines.copy()
    insert_indices = []

    # For each code_line_no and code_content in code_dict
    for code_line_no_str, code_content in code_dict.items():
        try:
            code_line_no = int(code_line_no_str)
        except ValueError:
            continue  # Skip if the line number is not an integer

        code_content_stripped = code_content.strip()
        # Calculate line_index_in_c_file
        line_index_in_c_file = code_line_no - function_start_line_no + 1  # Lines start at index 0

        # Search for all matching lines
        matching_line_indices = []
        for idx, line in enumerate(lines):
            if line.strip() == code_content_stripped:
                matching_line_indices.append(idx)

        if not matching_line_indices:
            print(f"Warning: Code content not found in {c_file_path}: '{code_content_stripped}'")
            continue

        # Find the line index closest to line_index_in_c_file
        closest_line_index = min(matching_line_indices, key=lambda x: abs(x - line_index_in_c_file))

        # Insert "    //patch_code" after that line
        modified_lines[closest_line_index] = modified_lines[closest_line_index].rstrip() + "    //patch_code\n"
        # insert_index = closest_line_index + 1
        # if insert_index not in insert_indices:
        #     modified_lines.insert(insert_index, "    //patch_code\n")
        #     insert_indices.append(insert_index)

    return modified_lines

def patch_prompt_generation(data_dir):
    # Iterate over subdirectories in data_dir
    for cve_dir_name in os.listdir(data_dir):
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

        function_name = result_data.get("function_name")
        patch_info = result_data.get("patch_info", {})
        patch_type = patch_info.get("patch_type")
        added_code = patch_info.get("added_code", {})
        deleted_code = patch_info.get("deleted_code", {})

        if not function_name or not patch_type:
            print(f"Error: Missing function_name or patch_type in {result_json_path}")
            continue

        print(f"Processing CVE directory: {cve_dir_name}")
        # Determine which files to process
        if patch_type == "add" or patch_type == "modify":
            # Process function_name + "_patched.c"
            patched_c_file_name = f"{function_name}_patched.c"
            patched_c_file_path = os.path.join(cve_dir_path, patched_c_file_name)
            if not os.path.exists(patched_c_file_path):
                print(f"Error: File not found: {patched_c_file_path}")
            else:
                # Read function_start_line_no from the first line
                with open(patched_c_file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline()
                match = re.match(r'// Function starts at line (\d+)', first_line)
                if match:
                    function_start_line_no = int(match.group(1))
                    modified_lines = process_c_file(patched_c_file_path, added_code, function_start_line_no)
                    # Save the modified file
                    output_file_name = f"{function_name}_patched_code.c"
                    output_file_path = os.path.join(cve_dir_path, output_file_name)
                    with open(output_file_path, 'w', encoding='utf-8') as f:
                        f.writelines(modified_lines)
                    print(f"Modified file saved: {output_file_path}")
                else:
                    print(f"Error: Could not find function start line in {patched_c_file_path}")

        if patch_type == "delete" or patch_type == "modify":
            # Process function_name + "_vul.c"
            vul_c_file_name = f"{function_name}_vul.c"
            vul_c_file_path = os.path.join(cve_dir_path, vul_c_file_name)
            if not os.path.exists(vul_c_file_path):
                print(f"Error: File not found: {vul_c_file_path}")
            else:
                # Read function_start_line_no from the first line
                with open(vul_c_file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline()
                match = re.match(r'// Function starts at line (\d+)', first_line)
                if match:
                    function_start_line_no = int(match.group(1))
                    modified_lines = process_c_file(vul_c_file_path, deleted_code, function_start_line_no)
                    # Save the modified file
                    output_file_name = f"{function_name}_vul_code.c"
                    output_file_path = os.path.join(cve_dir_path, output_file_name)
                    with open(output_file_path, 'w', encoding='utf-8') as f:
                        f.writelines(modified_lines)
                    print(f"Modified file saved: {output_file_path}")
                else:
                    print(f"Error: Could not find function start line in {vul_c_file_path}")






def pseudo_code_line_number(data_directory):

    for cve_dir_name in os.listdir(data_directory):
        cve_dir_path = os.path.join(data_directory, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"
        # 遍历目录下的所有文件
        for root, dirs, files in os.walk(cve_dir_path):
            for file in files:
                # 检查文件是否以.idapseudo结尾
                if file.endswith('.idapseudo'):
                    input_file = os.path.join(root, file)
                    # 构造输出文件名
                    output_file = os.path.join(root, file[:-10] + '.lineidapseudo')
                    
                    # 读取原文件并添加行号
                    with open(input_file, 'r', encoding='utf-8') as f_in:
                        lines = f_in.readlines()
                    
                    # 在每行末尾添加行号
                    numbered_lines = []
                    for i, line in enumerate(lines, 1):
                        # 去除行尾可能存在的换行符
                        line = line.rstrip('\n')
                        # 添加行号注释
                        numbered_lines.append(f"{line} // {i}\n")
                    
                    # 写入新文件
                    with open(output_file, 'w', encoding='utf-8') as f_out:
                        f_out.writelines(numbered_lines)


if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: python script_name.py data_directory")
    # else:

    data_directory = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data"  #sys.argv[1]
    bin_directory = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/bin"  #sys.argv[2]
    patch_prompt_generation(data_directory)
    # pseudo_prompt_generation(data_directory, bin_directory)

    # pseudo_code_line_number(data_directory)
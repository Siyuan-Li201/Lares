import os
import sys
import json
import re
import shutil
import tqdm
import subprocess

sys.path.append("code/code/source_analysis")

import analysis_by_joern


def extract_code_lines(json_data, add_or_delete):
    # Parse JSON string if input is string
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data
        
    # Extract added_code keys and convert to integers
    added_lines = list(map(int, data['patch_info'][add_or_delete].keys()))
    
    # Sort the lines in ascending order
    added_lines.sort()
    
    # Convert list to string in desired format
    result = "List(" + ", ".join(map(str, added_lines)) + ")"
    
    return result


def analysis_constant(resPath, sourcePath, newResPath):

    if not os.path.exists(resPath):
        print(f"Error: File not found: {resPath}")
        return

    # Read the JSON file
    with open(resPath, 'r') as f:
        data = json.load(f)
    
    # Process each dictionary in the list
    for item in data:
        identifiers = item["identifiers"]
        constantMappings = item["constantMappings"]
        
        # For each identifier, check if it needs a constant mapping
        for identifier in identifiers:
            # Skip if identifier is already mapped
            mapped = False
            for mapping in constantMappings:
                if identifier in mapping:
                    mapped = True
                    break
            
            if not mapped:
                # Execute grep command
                try:
                    cmd = f'grep -r "^#define[[:space:]]\+{identifier}[[:space:]]" {sourcePath}'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    # Process grep output
                    if result.stdout:
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            # Extract the #define statement (everything after the filename)
                            define_stmt = line.split(':', 1)[1].strip()
                            if define_stmt.startswith('#define'):
                                constantMappings.append(define_stmt)
                                
                except subprocess.SubprocessError:
                    continue
    
    # Save the modified data to new JSON file
    with open(newResPath, 'w') as f:
        json.dump(data, f, indent=2)


def source_enhance_constant(data_dir, tmp_dir_path, source_dir):
    # Iterate over subdirectories in data_dir
    for cve_dir_name in tqdm.tqdm(os.listdir(data_dir)):
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
        project_name = result_data.get("project_name")
        source_vul_version = result_data.get("source_vul_version")
        source_patch_version = result_data.get("source_patch_version")
        patch_info = result_data.get("patch_info", {})
        patch_type = patch_info.get("patch_type")
        added_code = patch_info.get("added_code", {})
        deleted_code = patch_info.get("deleted_code", {})

        newResPath = os.path.join(cve_dir_path, f"{function_name}_vul_code_joern_constant.json")

        if os.path.exists(newResPath):
            print(f"Warning: File already exists: {newResPath}")
            continue


        source_project_path = os.path.join(source_dir, project_name)

        if not function_name or not patch_type:
            print(f"Error: Missing function_name or patch_type in {result_json_path}")
            continue

        print(f"Processing CVE directory: {cve_dir_name}")
        # Determine which files to process
        if patch_type == "add" or patch_type == "modify":

            output_file_name = f"{function_name}_patched_code.c"
            output_file_path = os.path.join(cve_dir_path, output_file_name)
            if not os.path.exists(output_file_path):
                print(f"Warning: File not exists: {output_file_path}")
                continue

            # 检查.git目录是否存在
            git_dir = os.path.join(source_project_path, '.git')
            if not os.path.exists(git_dir):
                print(f"错误：在 {source_project_path} 中未找到 .git 目录。请确保源码项目是一个Git仓库。")
                return

            # 切换到指定的Git标签版本
            try:
                subprocess.run(['git', 'checkout', source_patch_version], cwd=source_project_path, check=True)
            except subprocess.CalledProcessError:
                print(f"错误：无法切换到标签 {source_patch_version}。请确保标签存在。")
                return

            sourcePath = source_project_path
            resPath = os.path.join(cve_dir_path, f"{function_name}_patched_code_joern.json")
            newResPath = os.path.join(cve_dir_path, f"{function_name}_patched_code_joern_constant.json")

            analysis_constant(resPath, sourcePath, newResPath)

        if patch_type == "delete" or patch_type == "modify":

            output_file_name = f"{function_name}_vul_code.c"
            output_file_path = os.path.join(cve_dir_path, output_file_name)
            if not os.path.exists(output_file_path):
                print(f"Warning: File not exists: {output_file_path}")
                continue

            # 检查.git目录是否存在
            git_dir = os.path.join(source_project_path, '.git')
            if not os.path.exists(git_dir):
                print(f"错误：在 {source_project_path} 中未找到 .git 目录。请确保源码项目是一个Git仓库。")
                return

            # 切换到指定的Git标签版本
            try:
                subprocess.run(['git', 'checkout', source_vul_version], cwd=source_project_path, check=True)
            except subprocess.CalledProcessError:
                print(f"错误：无法切换到标签 {source_vul_version}。请确保标签存在。")
                return

            sourcePath = source_project_path
            resPath = os.path.join(cve_dir_path, f"{function_name}_vul_code_joern.json")
            newResPath = os.path.join(cve_dir_path, f"{function_name}_vul_code_joern_constant.json")

            analysis_constant(resPath, sourcePath, newResPath)




def source_enhance(data_dir, tmp_dir_path, source_dir):
    # Iterate over subdirectories in data_dir
    for cve_dir_name in tqdm.tqdm(os.listdir(data_dir)):
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
        project_name = result_data.get("project_name")
        source_vul_version = result_data.get("source_vul_version")
        source_patch_version = result_data.get("source_patch_version")
        patch_info = result_data.get("patch_info", {})
        patch_type = patch_info.get("patch_type")
        added_code = patch_info.get("added_code", {})
        deleted_code = patch_info.get("deleted_code", {})

        source_project_path = os.path.join(source_dir, project_name)

        if not function_name or not patch_type:
            print(f"Error: Missing function_name or patch_type in {result_json_path}")
            continue

        print(f"Processing CVE directory: {cve_dir_name}")
        # Determine which files to process
        if patch_type == "add" or patch_type == "modify":

            output_file_name = f"{function_name}_patched_code.c"
            output_file_path = os.path.join(cve_dir_path, output_file_name)
            if not os.path.exists(output_file_path):
                print(f"Warning: File not exists: {output_file_path}")
                continue
            
            # 将源码项目复制到临时目录
            # tmp_project_path = os.path.join(tmp_dir_path, 'project')
            # if os.path.exists(tmp_project_path):
            #     shutil.rmtree(tmp_project_path)
            # shutil.copytree(source_project_path, tmp_project_path)

            # 检查.git目录是否存在
            git_dir = os.path.join(source_project_path, '.git')
            if not os.path.exists(git_dir):
                print(f"错误：在 {source_project_path} 中未找到 .git 目录。请确保源码项目是一个Git仓库。")
                return

            # 切换到指定的Git标签版本
            try:
                subprocess.run(['git', 'checkout', source_patch_version], cwd=source_project_path, check=True)
            except subprocess.CalledProcessError:
                print(f"错误：无法切换到标签 {source_patch_version}。请确保标签存在。")
                return

            sourcePath = source_project_path
            cpgPath = os.path.join(cve_dir_path, f"{project_name}_{source_patch_version}.cpg")
            functionName = function_name
            targetLines = extract_code_lines(result_data, "added_code")
            resPath = os.path.join(cve_dir_path, f"{function_name}_patched_code_joern.json")
            
            analysis_by_joern.run_joern_analysis(sourcePath, cpgPath, functionName, targetLines, resPath)


        if patch_type == "delete" or patch_type == "modify":

            output_file_name = f"{function_name}_vul_code.c"
            output_file_path = os.path.join(cve_dir_path, output_file_name)
            if not os.path.exists(output_file_path):
                print(f"Warning: File not exists: {output_file_path}")
                continue
            
            # # 将源码项目复制到临时目录
            # tmp_project_path = os.path.join(tmp_dir_path, 'project')
            # if os.path.exists(tmp_project_path):
            #     shutil.rmtree(tmp_project_path)
            # shutil.copytree(source_project_path, tmp_project_path)

            # 检查.git目录是否存在
            git_dir = os.path.join(source_project_path, '.git')
            if not os.path.exists(git_dir):
                print(f"错误：在 {source_project_path} 中未找到 .git 目录。请确保源码项目是一个Git仓库。")
                return

            # 切换到指定的Git标签版本
            try:
                subprocess.run(['git', 'checkout', source_vul_version], cwd=source_project_path, check=True)
            except subprocess.CalledProcessError:
                print(f"错误：无法切换到标签 {source_vul_version}。请确保标签存在。")
                return

            sourcePath = source_project_path
            cpgPath = os.path.join(cve_dir_path, f"{project_name}_{source_vul_version}.cpg")
            functionName = function_name
            targetLines = extract_code_lines(result_data, "deleted_code")
            resPath = os.path.join(cve_dir_path, f"{function_name}_vul_code_joern.json")
            
            analysis_by_joern.run_joern_analysis(sourcePath, cpgPath, functionName, targetLines, resPath)



def analyze_code(file_path):
    # 读取文件内容
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        # 如果UTF-8解码失败，尝试其他编码
        try:
            with open(file_path, 'r', encoding='gbk') as f:
                lines = f.readlines()
        except UnicodeDecodeError as e:
            print(f"Failed to decode file: {e}")
            return []
    
    # 去除每行末尾的换行符
    lines = [line.rstrip('\n') for line in lines]
    
    # 获取函数起始行
    func_line = 0
    for line in lines:
        if line.startswith('// Function starts at line'):
            func_line = int(line.split()[-1])
            break
    
    if func_line == 0:
        print("Could not find function start line")
        return []
    
    # 记录多行注释状态        
    in_block_comment = False
    target_lines = []
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # 检查多行注释开始和结束
        if '/*' in line:
            in_block_comment = True
        if '*/' in line:
            in_block_comment = False
            continue
            
        if stripped.endswith('//patch_code'):
            # 排除单行注释和多行注释
            code = line.split('//patch_code')[0].strip()
            if (code and 
                not code.lstrip().startswith('//') and 
                not code.lstrip().startswith('/*') and
                not in_block_comment):
                # 计算新行号 = 当前行号(从0开始) + 函数起始行 - 2
                new_line_num = i + func_line - 1
                target_lines.append(new_line_num)
                
    return target_lines




def enhance_code(source_path_line_list, enhance_file_name):
    import json
    
    # Read the JSON file
    with open(enhance_file_name) as f:
        json_data = json.load(f)
        
    # Initialize the result list and dictionary
    enhanced_lines = set()
    constant_mappings_dict = {}
    
    # For each line number in source list
    for line_num in source_path_line_list:
        # Find matching entries in JSON
        for entry in json_data:
            if entry['targetStatement']['lineNumber'] == line_num:
                target_line = entry['targetStatement']['lineNumber']
                
                # Handle dominatingStatements
                dominating_lines = list(set([stmt['lineNumber'] for stmt in entry['controlFlowRelatedStatements']['dominatingStatements']]))
                if len(dominating_lines) > 5:
                    # Sort by distance to target line
                    dominating_lines.sort(key=lambda x: abs(x - target_line))
                    dominating_lines = dominating_lines[:5]
                for line in dominating_lines:
                    enhanced_lines.add(line)
                
                # Handle control flow blocks
                block_lines = []
                if entry['controlFlowRelatedStatements']['firstInBlock']:
                    block_lines.append(entry['controlFlowRelatedStatements']['firstInBlock']['lineNumber'])
                if entry['controlFlowRelatedStatements']['firstAfterBlock']:
                    block_lines.append(entry['controlFlowRelatedStatements']['firstAfterBlock']['lineNumber'])
                block_lines = list(set(block_lines))  # Remove duplicates
                if len(block_lines) > 5:
                    block_lines.sort(key=lambda x: abs(x - target_line))
                    block_lines = block_lines[:5]
                for line in block_lines:
                    enhanced_lines.add(line)
                
                # Handle data flow statements
                data_flow_lines = []
                for def_stmt in entry['dataFlowRelatedStatements']['definitions']:
                    data_flow_lines.append(def_stmt['lineNumber'])
                for use_stmt in entry['dataFlowRelatedStatements']['uses']:
                    data_flow_lines.append(use_stmt['lineNumber'])
                data_flow_lines = list(set(data_flow_lines))  # Remove duplicates
                if len(data_flow_lines) > 5:
                    data_flow_lines.sort(key=lambda x: abs(x - target_line))
                    data_flow_lines = data_flow_lines[:5]
                for line in data_flow_lines:
                    enhanced_lines.add(line)
                
                # Add constant mappings to dictionary
                if entry['constantMappings']:
                    constant_mappings_dict[entry['targetStatement']['lineNumber']] = entry['constantMappings']
                    
    # Convert set to sorted list
    enhanced_lines_list = sorted(list(enhanced_lines))
    
    return enhanced_lines_list, constant_mappings_dict

def enhance_code_old(source_path_line_list, enhance_file_name):
    import json
    
    # Read the JSON file
    with open(enhance_file_name) as f:
        json_data = json.load(f)
        
    # Initialize the result list and dictionary
    enhanced_lines = set()
    constant_mappings_dict = {}
    
    # For each line number in source list
    for line_num in source_path_line_list:
        # Find matching entries in JSON
        for entry in json_data:
            if entry['targetStatement']['lineNumber'] == line_num:
                # Add line numbers from dominatingStatements
                for stmt in entry['controlFlowRelatedStatements']['dominatingStatements']:
                    enhanced_lines.add(stmt['lineNumber'])
                
                # Add firstInBlock line number if exists
                if entry['controlFlowRelatedStatements']['firstInBlock']:
                    enhanced_lines.add(entry['controlFlowRelatedStatements']['firstInBlock']['lineNumber'])
                    
                # Add firstAfterBlock line number if exists    
                if entry['controlFlowRelatedStatements']['firstAfterBlock']:
                    enhanced_lines.add(entry['controlFlowRelatedStatements']['firstAfterBlock']['lineNumber'])
                
                # Add definition line numbers
                for def_stmt in entry['dataFlowRelatedStatements']['definitions']:
                    enhanced_lines.add(def_stmt['lineNumber'])
                    
                # Add uses line numbers    
                for use_stmt in entry['dataFlowRelatedStatements']['uses']:
                    enhanced_lines.add(use_stmt['lineNumber'])
                    
                # Add constant mappings to dictionary
                if entry['constantMappings']:
                    constant_mappings_dict[entry['targetStatement']['lineNumber']] = entry['constantMappings']
                    
    # Convert set to sorted list
    enhanced_lines_list = sorted(list(enhanced_lines))
    
    return enhanced_lines_list, constant_mappings_dict




def is_comment_line(line):
    # Remove leading/trailing whitespace
    stripped_line = line.strip()
    # Check for single line comment
    if stripped_line.startswith('//'):
        return True
    # Check for multi-line comment start
    if stripped_line.startswith('/*'):
        return True
    # Check for multi-line comment end  
    if stripped_line.startswith('*/') or stripped_line.endswith('*/'):
        return True
    # Check if line is only within a multi-line comment
    if stripped_line.startswith('*'):
        return True
    return False

def is_valid_code_line(line):
    # Remove leading/trailing whitespace
    stripped_line = line.strip()
    # Check if line is empty or only contains braces
    if not stripped_line or stripped_line in ['{', '}']:
        return False
    # Check if line is not a comment
    if not is_comment_line(line):
        return True
    return False

def find_valid_line_above(lines, start_line, func_start_line):
    curr_line = start_line - 1
    while curr_line >= func_start_line:
        if is_valid_code_line(lines[curr_line - func_start_line]):
            return curr_line
        curr_line -= 1
    return None

def find_valid_line_below(lines, start_line, func_end_line, func_start_line):
    curr_line = start_line + 1
    while curr_line <= func_end_line:
        if is_valid_code_line(lines[curr_line - func_start_line]):
            return curr_line
        curr_line += 1
    return None


def add_comments_to_source(source_file, enhance_source_path, source_path_line_list, enhanced_lines_list, constant_mappings_dict):
    # Read the source file
    with open(source_file, 'r') as f:
        lines = f.readlines()


    # Get function start line number from first line
    # Assuming format like: "static int tls1_change_cipher_state(SSL *s, int which)  // 4286"
    func_start_line = 0
    for line in lines:
        if line.startswith('// Function starts at line'):
            func_start_line = int(line.split()[-1])
            break
    
    # Create a copy of lines for modification
    enhanced_lines = lines.copy()


    # Add patch_code comments
    for line_num in source_path_line_list:
        # Adjust line number: +2 for header lines, -func_start_line to get file line 
        file_line = line_num + 1 - func_start_line
        if 0 <= file_line < len(enhanced_lines) and "  //patch_code" not in enhanced_lines[file_line]:
            enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + "  //patch_code\n"

    if len(source_path_line_list) + len(enhanced_lines_list) < 5:

        new_line_num = 0

        front_end = False
        back_end = False

        func_end_line = func_start_line + len(enhanced_lines) - 1
        
        patch_start_line = source_path_line_list[0]
        patch_end_line = source_path_line_list[0]

        while(new_line_num < 4 and (front_end != True or back_end != True) ):
            # for line_num in source_path_line_list:
            # Look for valid line above
            if front_end == False:
                valid_line_above = find_valid_line_above(enhanced_lines, patch_start_line, func_start_line)
                if valid_line_above:
                    file_line = valid_line_above - func_start_line
                    if "  //patch_code" not in enhanced_lines[file_line] and "  //locate_code" not in enhanced_lines[file_line]:
                        enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + "  //patch_code\n"
                        new_line_num += 1
                    patch_start_line = valid_line_above
                else:
                    front_end = True
                    
            # Look for valid line below
            if back_end == False:
                valid_line_below = find_valid_line_below(enhanced_lines, patch_end_line, func_end_line, func_start_line)
                if valid_line_below:
                    file_line = valid_line_below - func_start_line
                    if "  //patch_code" not in enhanced_lines[file_line] and "  //locate_code" not in enhanced_lines[file_line]:
                        enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + "  //patch_code\n"
                        new_line_num += 1
                    patch_end_line = valid_line_below
                else:
                    back_end = True
                    
        print("No enhanced lines, force enhanced!")
        
        # Write enhanced file
        with open(enhance_source_path, 'w') as f:
            f.writelines(enhanced_lines)
        return False

    # Add locate_code comments        
    for line_num in enhanced_lines_list:
        file_line = line_num + 1 - func_start_line
        if 0 <= file_line < len(enhanced_lines):
            # Don't add locate_code if line already has patch_code
            if not enhanced_lines[file_line].rstrip().endswith("//patch_code"):
                enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + "  //patch_code\n"
                
    # Add constant mapping comments
    for line_num in constant_mappings_dict:
        file_line = line_num + 1 - func_start_line
        if 0 <= file_line < len(enhanced_lines):
            constant_str = ", ".join(constant_mappings_dict[line_num])
            # Add constant mappings after any existing comments
            if "//patch_code" in enhanced_lines[file_line] or "//locate_code" in enhanced_lines[file_line]:
                enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + " //" + constant_str + "\n"
            else:
                enhanced_lines[file_line] = enhanced_lines[file_line].rstrip() + "    //" + constant_str + "\n"
                
    # Write enhanced file
    with open(enhance_source_path, 'w') as f:
        f.writelines(enhanced_lines)
    
    return True


def source_enhanced_generation(data_dir):
    for cve_dir_name in tqdm.tqdm(os.listdir(data_dir)):
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
        project_name = result_data.get("project_name")
        source_vul_version = result_data.get("source_vul_version")
        source_patch_version = result_data.get("source_patch_version")
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

            pura_source_name = f"{function_name}_patched.c"
            pura_source_path = os.path.join(cve_dir_path, pura_source_name)
            if not os.path.exists(pura_source_path):
                print(f"Warning: File not exists: {pura_source_path}")
                continue

            orinal_source_name = f"{function_name}_patched_code.c"
            orinal_source_path = os.path.join(cve_dir_path, orinal_source_name)
            if not os.path.exists(orinal_source_path):
                print(f"Warning: File not exists: {orinal_source_path}")
                continue

            enhance_file_name = f"{function_name}_patched_code_joern_constant.json"
            enhance_file_path = os.path.join(cve_dir_path, enhance_file_name)
            if not os.path.exists(enhance_file_path):
                print(f"Warning: File not exists: {enhance_file_path}")
                continue

            enhance_source_name = f"{function_name}_patched_code_enhanced.c"
            enhance_source_path = os.path.join(cve_dir_path, enhance_source_name)
            # if not os.path.exists(enhance_source_path):

            
            source_path_line_list = analyze_code(orinal_source_path)

            enhanced_lines_list, constant_mappings_dict = enhance_code(source_path_line_list, enhance_file_path)

            if len(source_path_line_list) >= 10:
                enhance_patch_line_list = []
            else:
                enhance_patch_line_list = enhanced_lines_list

            add_comments_to_source(pura_source_path, enhance_source_path, source_path_line_list, enhance_patch_line_list, constant_mappings_dict)


        if patch_type == "delete" or patch_type == "modify":

            pura_source_name = f"{function_name}_vul.c"
            pura_source_path = os.path.join(cve_dir_path, pura_source_name)
            if not os.path.exists(pura_source_path):
                print(f"Warning: File not exists: {pura_source_path}")
                continue

            orinal_source_name = f"{function_name}_vul_code.c"
            orinal_source_path = os.path.join(cve_dir_path, orinal_source_name)
            if not os.path.exists(orinal_source_path):
                print(f"Warning: File not exists: {orinal_source_path}")
                continue

            enhance_file_name = f"{function_name}_vul_code_joern_constant.json"
            enhance_file_path = os.path.join(cve_dir_path, enhance_file_name)
            if not os.path.exists(enhance_file_path):
                print(f"Warning: File exists: {enhance_file_path}")
                continue

            enhance_source_name = f"{function_name}_vul_code_enhanced.c"
            enhance_source_path = os.path.join(cve_dir_path, enhance_source_name)
            # if not os.path.exists(enhance_source_path):


            source_path_line_list = analyze_code(orinal_source_path)

            if len(source_path_line_list) > 0:


                enhanced_lines_list, constant_mappings_dict = enhance_code(source_path_line_list, enhance_file_path)

                if len(source_path_line_list) >= 10:
                    enhance_patch_line_list = []
                else:
                    enhance_patch_line_list = enhanced_lines_list

                add_comments_to_source(pura_source_path, enhance_source_path, source_path_line_list, enhance_patch_line_list, constant_mappings_dict)


if __name__ == "__main__":

    data_directory = "code/data"  #sys.argv[1]
    tmp_dir_path = "code/tmp"  #sys.argv[2]
    source_dir = "code/dataset/source"  #sys.argv[3]

    # source_enhance(data_directory, tmp_dir_path, source_dir)

    # source_enhance_constant(data_directory, tmp_dir_path, source_dir)

    source_enhanced_generation(data_directory)
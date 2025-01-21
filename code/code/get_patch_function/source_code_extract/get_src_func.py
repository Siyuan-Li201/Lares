import argparse
import shutil
import subprocess
import os
from pathlib import Path
from tree_sitter import Language, Parser

def get_source_func(source_project_path, function_name, tag_version, tmp_dir_path):
    # parser = argparse.ArgumentParser(description='提取源码项目中的指定函数。')
    # parser.add_argument('source_project_path', help='源码项目路径')
    # parser.add_argument('result_save_path', help='结果保存路径')
    # parser.add_argument('tag_version', help='Git标签版本')
    # parser.add_argument('function_name', help='要提取的函数名')
    # parser.add_argument('tmp_dir_path', help='临时目录路径')

    # args = parser.parse_args()


    # source_project_path = os.path.abspath(args.source_project_path)
    # result_save_path = os.path.abspath(args.result_save_path)
    # tag_version = args.tag_version
    # function_name = args.function_name
    # tmp_dir_path = os.path.abspath(args.tmp_dir_path)






    # 将源码项目复制到临时目录
    tmp_project_path = os.path.join(tmp_dir_path, 'project')
    if os.path.exists(tmp_project_path):
        shutil.rmtree(tmp_project_path)
    shutil.copytree(source_project_path, tmp_project_path)

    # 检查.git目录是否存在
    git_dir = os.path.join(tmp_project_path, '.git')
    if not os.path.exists(git_dir):
        print(f"错误：在 {tmp_project_path} 中未找到 .git 目录。请确保源码项目是一个Git仓库。")
        return

    # 切换到指定的Git标签版本
    try:
        subprocess.run(['git', 'checkout', tag_version], cwd=tmp_project_path, check=True)
    except subprocess.CalledProcessError:
        print(f"错误：无法切换到标签 {tag_version}。请确保标签存在。")
        return

    # 初始化Tree-sitter解析器
    build_dir = os.path.join(tmp_dir_path, 'build')
    vendor_dir = os.path.join(tmp_dir_path, 'vendor')

    if not os.path.exists(build_dir):
        os.mkdir(build_dir)

    # 假设处理的语言是C语言，您可以根据需要添加其他语言
    language_so = os.path.join(build_dir, 'my-languages.so')
    if not os.path.exists(language_so):
        print("正在构建Tree-sitter语言库...")
        Language.build_library(
            # 输出的so动态库路径
            language_so,
            # 语言语法的路径列表
            [
                os.path.join(vendor_dir, 'tree-sitter-c'),
                # 如果需要支持其他语言，可以在这里添加
            ]
        )

    # 加载C语言的语法
    C_LANGUAGE = Language(language_so, 'c')
    parser = Parser()
    parser.set_language(C_LANGUAGE)

    # 从源码中提取函数和行号
    function_info = extract_function(tmp_project_path, parser, function_name)

    if function_info:
        function_content, line_number = function_info  # 解包函数内容和行号
        print(f'函数 "{function_name}" 已找到于第 {line_number} 行。')
        return function_content, line_number
        
        
    else:
        print(f'函数 "{function_name}" 未在项目中找到。')
        return None, None

def extract_function(project_path, parser, function_name):
    # 遍历源码文件
    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith('.c') or file.endswith('.h'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                    lines = code.splitlines()
                tree = parser.parse(bytes(code, 'utf8'))
                root_node = tree.root_node

                # 查找函数定义节点
                function_node = find_function_node(root_node, function_name)
                if function_node:
                    # 提取函数代码
                    start_byte = function_node.start_byte
                    end_byte = function_node.end_byte
                    function_code = code.encode('utf8')[start_byte:end_byte].decode('utf8')
                    
                    # 计算函数开始的行号
                    line_number = code.count('\n', 0, start_byte) + 1
                    
                    return function_code, line_number
    return None

def find_function_node(node, function_name):
    if node.type == 'function_definition':
        # 查找函数名
        declarator = node.child_by_field_name('declarator')
        if declarator:
            identifier = get_identifier(declarator)
            if identifier == function_name:
                return node
    # 递归遍历子节点
    for child in node.children:
        result = find_function_node(child, function_name)
        if result:
            return result
    return None

def get_identifier(node):
    if node.type == 'identifier':
        return node.text.decode('utf8')
    for child in node.children:
        identifier = get_identifier(child)
        if identifier:
            return identifier
    return None

if __name__ == '__main__':
    source_project_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/source/openssl"   #sys.argv[1]      # 
    function_name = "ssl3_send_client_key_exchange"        #sys.argv[4]
    result_save_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/code/get_patch_function/res/"+function_name+".c" # sys.argv[2]     #      
    tag_version = "OpenSSL_1_0_0m"   #sys.argv[3]       # 
    tmp_dir_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/tmp"  #sys.argv[5]      #


    function_content, line_number = get_source_func(source_project_path, function_name, tag_version, tmp_dir_path)

    if function_content and line_number:
    # 将函数内容和行号保存到结果路径
        with open(result_save_path, 'w', encoding='utf-8') as f:
            f.write(f'// Function starts at line {line_number}\n')  # 添加行号信息
            f.write(function_content)
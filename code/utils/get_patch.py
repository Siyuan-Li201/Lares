import os
import shutil

def copy_c_files(src_dir, dest_dir):
    """
    遍历给定的目录，将所有二级目录中 src 子目录下的 .c 文件复制到目标目录。
    文件命名规则为：二级目录名称加编号（从 1 开始）.
    """
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    # 遍历初始目录下的所有二级目录
    for root, dirs, files in os.walk(src_dir):
        for d in dirs:
            sub_dir = os.path.join(root, d)
            # 查找二级目录中的 src 子目录
            src_sub_dir = os.path.join(sub_dir, "src")
            if os.path.exists(src_sub_dir) and os.path.isdir(src_sub_dir):
                # 查找子目录下的 .c 文件
                c_files = [f for f in os.listdir(src_sub_dir) if f.endswith(".c")]
                for idx, c_file in enumerate(c_files, start=1):
                    source_file = os.path.join(src_sub_dir, c_file)
                    # 生成目标文件路径
                    dest_file_name = f"{d}_{idx}.c"
                    dest_file_path = os.path.join(dest_dir, dest_file_name)
                    # 复制文件
                    shutil.copy(source_file, dest_file_path)
                    print(f"Copied: {source_file} -> {dest_file_path}")
                # break  # 只处理二级目录中的 src

if __name__ == "__main__":
    # 输入初始目录和目标目录
    initial_dir = "/media/REMOVED/4A7AC8957AC87F67/work2024/mypaper/patch_detection/data/plocator_data_1203/patches/"   #input("请输入初始文件夹目录: ").strip()
    save_dir = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/"   #input("请输入保存目录: ").strip()

    if not os.path.exists(initial_dir):
        print(f"初始目录 {initial_dir} 不存在！")
    else:
        copy_c_files(initial_dir, save_dir)
        print("操作完成！")
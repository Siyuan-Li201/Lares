def pseudo_slice_V2(pseudo_code, arg_max_line=400, arg_min_line=100):
    """
    将C语言代码按照大括号闭合情况和行数限制进行切割和合并。

    参数:
    - pseudo_code (str): 需要切割的C语言代码。
    - arg_max_line (int): 每个代码片段的最大行数。
    - arg_min_line (int): 每个代码片段的最小行数。

    返回:
    - code_sliced_list (list): 切割后的代码片段列表。
    """

    def force_split(code_lines):
        """
        强制切割代码。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - slices (list): 切割后的代码片段列表。
        """
        slices = []
        for i in range(0, len(code_lines), arg_max_line):
            if len(code_lines[i+arg_max_line:]) >= arg_min_line:
                slices.append(code_lines[i:i+arg_max_line])
            else:
                slices.append(code_lines[i:i+arg_max_line-arg_min_line])
                slices.append(code_lines[i+arg_max_line-arg_min_line:])
                break
        return slices

    def split_by_braces(code_lines):
        """
        根据大括号的闭合情况切割代码。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - slices (list): 按闭合点切割的代码片段列表。
        """
        slices = []
        brace_stack = []
        last_split = 0

        for i, line in enumerate(code_lines):
            # 统计每行中的 { 和 }
            brace_stack.extend([ '{' ] * line.count('{'))
            for _ in range(line.count('}')):
                if brace_stack:
                    brace_stack.pop()
                else:
                    # 多余的 }，可以根据需要处理
                    pass

            # 如果栈为空，表示当前闭合点
            if not brace_stack and i + 1 - last_split >= arg_min_line:
                slices.append(code_lines[last_split:i+1])
                last_split = i + 1

        # 添加剩余的代码
        if last_split < len(code_lines):
            slices.append(code_lines[last_split:])

        if len(slices) == 1 and len(slices[0]) > arg_max_line:
            slices = force_split(slices[0])

        return slices

    def merge_slices(slices):
        """递归合并函数。"""
        for i in range(len(slices)):
            # 检查与前一片段的合并
            if i > 0:
                merged_length = len(slices[i - 1]) + len(slices[i])
                if merged_length <= arg_max_line:
                    # 合并前后片段
                    merged = slices[i - 1] + slices[i]
                    # 创建新的片段列表
                    new_slices = slices[:i - 1] + [merged] + slices[i + 1:]
                    # 递归调用以检查新的前一段和后一段
                    return merge_slices(new_slices)

            # 检查与后一片段的合并
            if i < len(slices) - 1:
                merged_length = len(slices[i]) + len(slices[i + 1])
                if merged_length <= arg_max_line:
                    # 合并当前片段和后一片段
                    merged = slices[i] + slices[i + 1]
                    # 创建新的片段列表
                    new_slices = slices[:i] + [merged] + slices[i + 2:]
                    # 递归调用以检查新的前一段和后一段
                    return merge_slices(new_slices)

        # 如果没有更多可以合并的片段，返回当前列表
        return slices

    def recursive_slice(code_lines):
        """
        递归切割代码片段。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - result (list): 切割后的代码片段列表。
        """
        if len(code_lines) <= arg_max_line:
            return ['\n'.join(code_lines)]

        slices = split_by_braces(code_lines)

        result = []
        for slice in slices:
            if len(slice) > arg_max_line:
                # 递归切割
                result.extend(recursive_slice(slice))
            else:
                result.append('\n'.join(slice))

        return result

    # 将源代码按行分割
    code_lines = pseudo_code.split('\n')

    # 初始切割
    initial_slices = recursive_slice(code_lines)

    # 合并小片段
    merged_slices = merge_slices([slice.split('\n') for slice in initial_slices])

    # 将合并后的片段重新连接为字符串
    code_sliced_list = ['\n'.join(slice) for slice in merged_slices]

    return code_sliced_list


# 示例用法
if __name__ == "__main__":
    c_code = """
    #include <stdio.h>

    int main() {
        printf("Hello, World!\\n");
        if (1) {
            printf("Inside if\\n");
        }
        for(int i = 0; i < 10; i++) {
            printf("Loop %d\\n", i);
        }
        return 0;
    }
    """

    sliced = pseudo_slice_V2(c_code, arg_max_line=10, arg_min_line=2)
    for idx, part in enumerate(sliced):
        print(f"--- Slice {idx + 1} ---")
        print(part)



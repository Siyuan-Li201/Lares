import re
import json



def extract_json_from_text(text):
    json_start = text.find('{')
    if json_start == -1:
        print("未找到JSON数据。")
        return None

    brace_count = 0
    in_string = False
    escape = False

    for index in range(json_start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = index + 1
                    json_str = text[json_start:json_end]
                    try:
                        data = json.loads(json_str)
                        return data
                    except json.JSONDecodeError as e:
                        print("JSON解码错误：", e)
                        return None
    print("未能正确匹配到JSON对象的结束。")
    return None

# Define the input text
text = '''
This is the json file: { "new match result": { "if (s->session->sess_cert == NULL) // patch line": "if (v3 == 0 || !*(_DWORD *)(v3 + 152))" }, "corresponding pseudo code": " if ( v3 ) { v4 = *(_DWORD *)(v3 + 108); if ( v4 ) goto LABEL_5; v45 = (_DWORD )sub_81633B0((_DWORD *)(v3 + 12)); if ( v45 ) { if ( *v45 == 6 ) { v4 = v45[5]; if ( v4 ) { sub_81368D0(v45); LABEL_5: ..." } } We generate this json well.
'''

# Extract JSON part using a regex
match = extract_json_from_text(text)
print(match)

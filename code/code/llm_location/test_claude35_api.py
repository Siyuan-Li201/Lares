import http.client
import json
import time
import os

os.chdir(os.path.dirname(__file__))

# 创建目录
os.makedirs("res", exist_ok=True)

# 获取当前时间戳
timestamp = int(time.time())

# 设置文件路径
file_path = f"res/claude_res_{str(timestamp)[-6:]}.json"

# 从文件读取内容
with open("temp/prompt_2.txt", "r", encoding="utf-8") as file:
    prompt_content = file.read()

conn = http.client.HTTPSConnection("api.openai-hub.com")
payload = json.dumps({
    "model": "claude-3-5-sonnet-latest",
    "messages": [
        {
            "role": "user",
            "content": prompt_content
        }
    ]
})
headers = {
    'Authorization': 'Bearer sk-BUEJL4vJdlR2S5vaGpWEqGieInVoPfy6kLOV84mYYG0T1vu2',  # 请替换为您的API密钥
    # 'Authorization': 'Bearer sk-L19BPaTstTGlWEb3hOAnnlreMEMRdQRWg3V2EpZHYzlGJlca',
    'Content-Type': 'application/json'
}
conn.request("POST", "/v1/chat/completions", payload, headers)
res = conn.getresponse()
data = res.read()

# 解析JSON数据
data_json = json.loads(data)

# 检查是否有“content”
content = None
if "choices" in data_json:
    for choice in data_json["choices"]:
        if "message" in choice and "content" in choice["message"]:
            content = choice["message"]["content"]
            break

# 保存数据到文件
if content is None:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(data.decode("utf-8"))
        print(data.decode("utf-8"))
else:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
        print(content)

print(f"Data saved to {file_path}")
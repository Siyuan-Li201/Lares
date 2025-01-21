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
file_path = f"res/o1_res_{str(timestamp)[-6:]}.json"

# 从文件读取内容
with open("temp/prompt_1.txt", "r", encoding="utf-8") as file:
    prompt_content = file.read()

conn = http.client.HTTPSConnection("api.openai-hub.com")
payload = json.dumps({
    "model": "o1-pro",
    "messages": [
        {
            "role": "user",
            "content": prompt_content
        }
    ]
})
headers = {
    'Authorization': 'Bearer sk-RVMiuMgMvRCboX6SKNxHD5rM6qyjHU40doTXxHXNAW7shviQ',  # 请替换为您的API密钥
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
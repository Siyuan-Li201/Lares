import http.client

conn = http.client.HTTPSConnection("api.openai-hub.com")
payload = ''
headers = {
   'Authorization': 'Bearer sk-BUEJL4vJdlR2S5vaGpWEqGieInVoPfy6kLOV84mYYG0T1vu2'
}
conn.request("GET", "/v1/models", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))
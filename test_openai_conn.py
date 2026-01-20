
from openai import OpenAI
import os

api_key = 'sk-zqobfygsagpedxjmkfikbfbvslxkrpyikpkvjfipbpkwruhb'
base_url = 'https://api.siliconflow.cn/v1'
model_name = 'deepseek-ai/DeepSeek-V3'

print(f"Testing connection to {base_url} with model {model_name}...")

try:
    client = OpenAI(
        api_key=api_key,
        base_url=base_url,
        timeout=30.0
    )

    print("Testing connection with stream=True...")
    stream = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "user", "content": "Hello, say hi!"}
        ],
        stream=True
    )
    
    print("Success! Streaming response:")
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            print(chunk.choices[0].delta.content, end='', flush=True)
    print("\nDone.")

except Exception as e:
    print(f"Failed: {type(e).__name__}: {e}")

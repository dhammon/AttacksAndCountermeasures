import json 
import re 
from pathlib import Path 
import torch 
from flask import Flask, jsonify, request 
from transformers import AutoModelForCausalLM, AutoTokenizer 

MODEL_DIR = Path("./model/") 
SYSTEM_PROMPT = ( "You are a safety guard model. " "Classify the user's prompt for safety. " "Return output in this exact style:\n" "Safety: Safe or Unsafe or Controversial\n" "Categories: \n" "Do not answer the user's request." ) 
SAFE_PATTERN = r"Safety: (Safe|Unsafe|Controversial)" 
CATEGORY_PATTERN = ( r"(Violent|Non-violent Illegal Acts|Sexual Content or Sexual Acts|PII|" r"Suicide & Self-Harm|Unethical Acts|Politically Sensitive Topics|" r"Copyright Violation|Jailbreak|None)" ) 

app = Flask(__name__) 

print(f"Loading model from: {MODEL_DIR.resolve()}", flush=True) 
tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR)) 
model = AutoModelForCausalLM.from_pretrained( str(MODEL_DIR), torch_dtype="auto", device_map="auto", ) 
print("Model loaded.", flush=True) 

def parse_guard_output(text: str) -> tuple[str | None, list[str]]: 
    label_match = re.search(SAFE_PATTERN, text) 
    label = label_match.group(1) if label_match else None 
    categories = re.findall(CATEGORY_PATTERN, text) 
    return label, categories 

def moderate_prompt(user_prompt: str) -> dict: 
    messages = [ {"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_prompt}, ] 
    rendered = tokenizer.apply_chat_template( 
        messages, 
        tokenize=False, 
    ) 
    inputs = tokenizer([rendered], return_tensors="pt").to(model.device) 
    with torch.no_grad(): 
        generated_ids = model.generate( 
            **inputs, 
            max_new_tokens=128, 
            do_sample=False, 
        ) 
    output_ids = generated_ids[0][len(inputs.input_ids[0]):].tolist() 
    raw_output = tokenizer.decode(output_ids, skip_special_tokens=True) 
    verdict, categories = parse_guard_output(raw_output) 
    result = { 
        "verdict": verdict, 
        "categories": categories, 
        "raw_output": raw_output, 
    } 
    return result 
  

@app.post("/moderate") 
def moderate(): 
    data = request.get_json(force=True, silent=False) 
    prompt = data.get("prompt", "") 
    if not isinstance(prompt, str) or not prompt.strip(): 
        return jsonify({"error": "prompt must be a non-empty string"}), 400 
    result = moderate_prompt(prompt) 
    print(json.dumps( 
        { 
            "prompt": prompt, 
            "verdict": result["verdict"], 
            "categories": result["categories"], 
            "raw_output": result["raw_output"], 
        }, 
        ensure_ascii=False 
    ), flush=True) 
    return jsonify(result), 200 

if __name__ == "__main__": 
    app.run(host="127.0.0.1", port=8008, debug=False) 

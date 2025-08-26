import re

from pathlib import Path
from datetime import datetime

def parse_yara_file(filepath):
    rules = []

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 匹配每个 rule 块
    rule_blocks = re.findall(r'rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}', content, re.DOTALL)

    for name, tags_str, body in rule_blocks:
        rule_info = {
            'name': name,
            'tags': tags_str.strip().split() if tags_str else [],
            'meta': {},
            'strings': [],
            'condition': ''
        }

        # 提取 meta 块
        meta_match = re.search(r'meta\s*:\s*(.*?)(?=(\n\s*\w+\s*:|$))', body, re.DOTALL)
        if meta_match:
            for line in meta_match.group(1).strip().splitlines():
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    rule_info['meta'][key.strip()] = value.strip().strip('"')

        # 提取 strings 块
        strings_match = re.search(r'strings\s*:\s*(.*?)(?=\n\s*\w+\s*:|$)', body, re.DOTALL)
        if strings_match:
            strings_block = strings_match.group(1)
            for line in strings_block.strip().splitlines():
                line = line.strip()
                if not line or not line.startswith('$'):
                    continue
                m = re.match(r'(\$\w+)\s*=\s*(\".*?\"|\{.*?\})(.*)', line)
                if m:
                    rule_info['strings'].append({
                        'name': m.group(1),
                        'value': m.group(2),
                        'modifiers': m.group(3).strip()
                    })

        # 提取 condition 块
        condition_match = re.search(r'condition\s*:\s*(.*)', body.strip(), re.DOTALL)
        if condition_match:
            rule_info['condition'] = condition_match.group(1).strip()

        rules.append(rule_info)

    return rules

def trans_rules(folder_path, target_path):
    folder_path = Path(folder_path)
    target_path = Path(target_path)
    for file in folder_path.iterdir():
        if file.is_file():    
            parsed = parse_yara_file(file)
            target_file = target_path / file.name
            with open(target_file, 'w', encoding='utf-8') as f:
                for rule in parsed:
                    f.write(f"rule {rule['name']} : {file.name.split('.')[0]}\n")
                    f.write("{\n")
                    f.write(f"{' '*4}meta:\n")
                    f.write(f"{' '*8}description = \"_{rule['name']}_\"\n")
                    f.write(f"{' '*8}score = 70\n")
                    f.write(f"{' '*8}author = \"xxxxxx\"\n")
                    f.write(f"{' '*8}create_time = \"{datetime.now().strftime('%Y-%m-%d')}\"\n\n")
                    f.write(f"{' '*4}strings:\n")
                    for s in rule['strings']:
                        f.write(f"{' '*8}{s['name']} = {s['value']}   {s['modifiers']}\n")
                    f.write(f"\n{' '*4}condition: \n")
                    # f.write(f"{' '*8}(uint16(0) == 0x5a4d) and {rule['condition']}\n")    # windows
                    # f.write(f"{' '*8}(uint32(0) == 0x464c457f) and {rule['condition']}\n")  # linux
                    f.write(f"{' '*8}(uint32(0) == 0xfeedface or uint32(0) == 0xfeedfacf or uint32(0) == 0xcafebabe or uint32(0) == 0xcafebabf) and {rule['condition']}\n")  # MacOS
                    f.write("}\n\n")

# 提取索引
# platform: Win32、Win64、Linux etc
# category: Trojan、Worm、Ransom etc
def extract_index(folder_path, target_file, platform, category):
    folder_path = Path(folder_path)
    for file in folder_path.iterdir():
        if file.is_file():
            target_file = category + '_index.yar'
            with open(target_file, 'a', encoding='utf-8') as f:
                f.write(f"include \"./{category}/{platform}/{file.name}\"\n")

# 提取命名空间
def extract_namespace(folder_path, target_file, category):
    folder_path = Path(folder_path)
    for file in folder_path.iterdir():
        if file.is_file():    
            parsed = parse_yara_file(file)
            with open(target_file, 'a', encoding='utf-8') as f:
                for rule in parsed:
                    f.write(f"{' '*4}\"_{rule['name']}_\": \"{file.name.split('.')[0]}{category}\",\n")

if __name__ == "__main__":
    folder_path="/Users/zer0daysec/GitRepo/defender2yara/MacOS_X/Trojan"
    target_path="./rules/Trojan/MacOS_X"
    # trans_rules(folder_path, target_path)
    # extract_index(folder_path, "./r", "MacOS_X", "Trojan")
    extract_namespace(folder_path, "./namespace.json", " Trojan")

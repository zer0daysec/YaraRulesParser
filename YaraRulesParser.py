import re

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

if __name__ == "__main__":
    filepath = './Win32/Ransom/Zuresq.yara'
    parsed = parse_yara_file(filepath)

    for rule in parsed:
        """
        print(f"Rule: {rule['name']}")
        print(f"  Tags: {rule['tags']}")
        print(f"  Meta:")
        for k, v in rule['meta'].items():
            print(f"    {k}: {v}")
        """
        print(f"  Strings:")
        for s in rule['strings']:
            print(f"    {s['name']} = {s['value']}   {s['modifiers']}")
        print(f"  Condition: {rule['condition']}")
        print("=" * 60)

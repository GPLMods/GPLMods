import os
import re

def fix_ejs_json(directory):
    json_pattern = re.compile(r'=\s*<%- JSON\.stringify\((.*?)\) %>\s*;')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.ejs'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                def repl(match):
                    inner = match.group(1)
                    return f"= JSON.parse(decodeURIComponent('<%- encodeURIComponent(JSON.stringify({inner})) %>'));"
                
                new_content, count = json_pattern.subn(repl, content)
                if count > 0:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f'Fixed JSON in {filepath}')

fix_ejs_json('c:/Users/bhatn/GPLMods/views/pages')

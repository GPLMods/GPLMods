import os
import re

def fix_ejs_files(directory):
    # Regex to match style="... <%= ... %> ..."
    # It looks for style=" followed by anything, then <%= or <%-, then anything, then "
    # We must be careful not to match too greedily.
    style_pattern = re.compile(r'style="([^"]*?(?:<%=|<%-)[^"]*?)"')

    # Regex to match <%- JSON.stringify(...) %> in script tags
    # Usually assigned to a variable: = <%- JSON.stringify(...) %>;
    json_pattern = re.compile(r'=\s*(<%- JSON\.stringify\([^)]+\) %>)\s*;')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.ejs'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                modified = False

                # Fix style attributes
                def style_repl(match):
                    inner = match.group(1)
                    # Replace <%= var %> with ${var}
                    inner_replaced = re.sub(r'<%[=-]\s*(.*?)\s*%>', r'${\1}', inner)
                    return f'<%- `style="{inner_replaced}"` %>'
                
                new_content, count = style_pattern.subn(style_repl, content)
                if count > 0:
                    modified = True
                
                # Fix JSON.stringify
                def json_repl(match):
                    ejs_tag = match.group(1)
                    # We wrap it in JSON.parse(`...`)
                    # We need to escape backticks and backslashes in the output of JSON.stringify for it to safely sit inside JS backticks, but EJS runs on server.
                    # Actually, if we just do JSON.parse(decodeURIComponent('<%- encodeURIComponent(JSON.stringify(...)) %>')) it is 100% safe and linter friendly.
                    # Or even simpler: JSON.parse(`<%- JSON.stringify(...).replace(/\\\\/g, '\\\\\\\\').replace(/\`/g, '\\\\\\`') %>`) -> complicated.
                    return match.group(0) # Let's skip JSON stringify for now to avoid breaking it, just fix styles.

                if modified:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f'Fixed inline styles in {filepath}')

fix_ejs_files('c:/Users/bhatn/GPLMods/views/pages')

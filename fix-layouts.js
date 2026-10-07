const fs = require('fs');

function fixLayouts(file) {
    if (!fs.existsSync(file)) return;
    let content = fs.readFileSync(file, 'utf-8');
    
    // 1. Fix template-helper-btn float
    content = content.replace('.template-helper-btn {\r\n        float: right;', '.template-helper-btn {\r\n        margin-left: auto;');
    content = content.replace('.template-helper-btn {\n        float: right;', '.template-helper-btn {\n        margin-left: auto;');
    
    // 2. Fix multipart link layout (flex-wrap)
    content = content.replace('<div style="display:flex; gap:10px; margin-bottom:15px;">', '<div style="display:flex; flex-wrap:wrap; gap:10px; margin-bottom:15px;">');
    
    // 3. Fix labels with template helpers
    content = content.replace('<label for="modDescription">', '<label for="modDescription" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">');
    content = content.replace('<label for="modFeatures">', '<label for="modFeatures" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">');
    content = content.replace('<label for="importantNote">', '<label for="importantNote" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">');
    content = content.replace('<label for="whatsNew">', '<label for="whatsNew" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">');
    
    // 4. Fix preview button texture on hover
    content = content.replace('.draft-preview-button:hover { background-color: var(--gold); color: var(--black); }', '.draft-preview-button:hover { background-color: var(--gold); background-image: none; color: var(--black); }');
    
    fs.writeFileSync(file, content);
    console.log('Fixed', file);
}

fixLayouts('c:/Users/bhatn/GPLMods/views/pages/edit-mod.ejs');
fixLayouts('c:/Users/bhatn/GPLMods/views/pages/upload-details.ejs');

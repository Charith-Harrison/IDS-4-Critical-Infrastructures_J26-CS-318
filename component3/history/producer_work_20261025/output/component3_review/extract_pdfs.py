from pathlib import Path
import json
from pypdf import PdfReader

out = Path(__file__).parent
sources = [
    ('team_proposal', Path('C:/Users/Thithira/Downloads/IT4010-TAF-2026 J26-CS-318 (1).pdf')),
    ('individual_proposal', Path('C:/Users/Thithira/Downloads/IT23150270_Rathnayaka K.H..pdf')),
]
for key, path in sources:
    reader = PdfReader(path)
    pages = [{'page': i+1, 'text': p.extract_text() or ''} for i, p in enumerate(reader.pages)]
    (out/f'{key}_extracted.json').write_text(json.dumps(pages, ensure_ascii=False, indent=2), encoding='utf-8')
    (out/f'{key}_extracted.txt').write_text('\n\n'.join(f'=== PAGE {p["page"]} ===\n{p["text"]}' for p in pages), encoding='utf-8')
    print(key, len(pages), 'pages', sum(len(p['text']) for p in pages), 'characters')

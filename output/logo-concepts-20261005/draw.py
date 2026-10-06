from pathlib import Path
import cairosvg

root = Path(__file__).parent
navy, blue, cyan, silver = '#102949', '#1677ed', '#4dd3ed', '#e6edf7'
fox = 'M104 102 190 153Q256 132 322 153L408 102 389 279Q348 369 256 407Q164 369 123 279Z'
cheeks = 'M128 220 256 319 384 220Q357 339 256 383Q155 339 128 220Z'
eyes = '<path d="m164 238 61 22-29 22z m184 0-61 22 29 22z" fill="#102949"/><path d="m236 321 40 0-20 24z" fill="#102949"/>'
def face(fill=blue):
    return f'<path d="{fox}" fill="{fill}"/><path d="{cheeks}" fill="{silver}"/>{eyes}'

items = [
('01-minimal', '极简狐面', f'<path d="M103 109 216 186 256 169 296 186 409 109 373 294 256 401 139 294Z" fill="{blue}"/><path d="m139 238 117 61 117-61-117 163Z" fill="{silver}"/><path d="m156 228 69 19-30 22z m200 0-69 19 30 22z" fill="{navy}"/><path d="m237 319 38 0-19 25z" fill="{navy}"/>'),
('02-shield', '守护盾牌', f'<path d="M256 54 423 113V244Q423 378 256 464Q89 378 89 244V113Z" fill="{navy}"/><path d="M256 79 399 130V244Q399 359 256 435Q113 359 113 244V130Z" fill="{blue}"/><g transform="translate(50 43) scale(.805)">{face(silver)}</g><path d="m163 180 38 41-18-81z m186 0-38 41 18-81z" fill="{blue}"/>'),
('03-origami', '几何折纸', f'<path d="m99 106 157 93 157-93-37 207-120 105-120-105Z" fill="{blue}"/><path d="m99 106 157 93-120 114Z" fill="#51bcfa"/><path d="m413 106-157 93 120 114Z" fill="#0b4aad"/><path d="m136 313 120-114v219Z" fill="{silver}"/><path d="m376 313-120-114v219Z" fill="#b9cbe0"/><path d="m170 250 48 10-25 25z m172 0-48 10 25 25z m-104 94h36l-18 24z" fill="{navy}"/>'),
('04-metal', '银蓝金属', '<defs><linearGradient id="metal" x2=".9" y2="1"><stop stop-color="#fbfdff"/><stop offset=".38" stop-color="#a1b7cd"/><stop offset=".57" stop-color="#f5faff"/><stop offset="1" stop-color="#54738e"/></linearGradient><linearGradient id="deep" x2="0" y2="1"><stop stop-color="#2894ff"/><stop offset="1" stop-color="#09376b"/></linearGradient></defs><rect x="62" y="62" width="388" height="388" rx="100" fill="url(#deep)"/><path d="'+fox+'" transform="translate(51 33) scale(.8)" fill="url(#metal)" stroke="#e5f5ff" stroke-width="5"/><g transform="translate(51 33) scale(.8)">'+eyes+'</g><path d="M114 135Q256 58 393 129" fill="none" stroke="#80c8ff" stroke-width="5" opacity=".7"/>'),
('05-neon', '霓虹科技', f'<rect x="52" y="52" width="408" height="408" rx="100" fill="#10142d"/><g fill="none" stroke-linejoin="round" stroke-linecap="round"><path d="M115 124 205 181 256 162 307 181 397 124 374 293 256 394 138 293Z" stroke="{cyan}" stroke-width="13"/><path d="m141 264 115 54 115-54M256 318v75" stroke="#a678ff" stroke-width="11"/><path d="m171 238 44 15 m126-15-44 15" stroke="{cyan}" stroke-width="12"/><path d="m235 321 21 20 21-20" stroke="#a678ff" stroke-width="10"/></g>'),
('06-pixel', '复古像素', f'<rect x="56" y="56" width="400" height="400" rx="56" fill="{navy}"/><path d="M120 112h48v32h32v32h112v-32h32v-32h48v176h-32v48h-32v32h-32v32h-80v-32h-32v-32h-32v-48h-32Z" fill="{silver}"/><path d="M152 160h16v48h-16z M344 160h16v48h-16z M152 256h48v32h-48z M312 256h48v32h-48z M200 304h112v32H200z M232 336h48v32h-48z" fill="{blue}"/><path d="M184 256h16v32h-16z M312 256h16v32h-16z M232 304h48v32h-48z" fill="{navy}"/>'),
('07-line', '环形线条', f'<g fill="none" stroke="{navy}" stroke-width="15" stroke-linejoin="round" stroke-linecap="round"><path d="M394 157A183 183 0 1 1 272 73"/><path d="m142 143 75 57q39-20 78 0l75-57-17 142-97 90-97-90Z"/><path d="m174 274 82 34 82-34m-144-33 25 9m119-9-25 9m-68 62 11 15 11-15"/></g><path d="m309 56 25 37 46-4-30 35 12 44-40-20-38 24 7-45-34-30 46-7Z" fill="{blue}"/>'),
('08-badge', '急救徽章', f'<circle cx="256" cy="256" r="202" fill="{navy}"/><circle cx="256" cy="256" r="181" fill="none" stroke="{cyan}" stroke-width="6"/><g transform="translate(71 24) scale(.72)">{face(silver)}</g><path d="M224 351h64v23h23v41h-23v23h-64v-23h-23v-41h23Z" fill="{blue}"/><path d="M247 374h18v12h12v18h-12v12h-18v-12h-12v-18h12Z" fill="white"/><path d="m91 262 16-24 16 24-16 24z m298 0 16-24 16 24-16 24z" fill="{cyan}"/>'),
('09-tail', '灵动狐尾', f'<path d="M349 79Q151 62 92 239Q44 383 210 424Q362 463 421 310Q458 213 390 149Q407 270 339 318Q254 377 199 307Q153 250 213 190Q163 266 232 288Q318 315 332 215Q344 150 349 79Z" fill="{blue}"/><path d="M92 239Q44 383 210 424Q295 446 363 395Q178 391 165 283Q124 293 92 239Z" fill="{cyan}"/><path d="m200 140 41 34 45-9 39-46-7 95-62 74-63-49Z" fill="{silver}"/><path d="m218 212 22 8-15 13z m81-7-24 11 15 11z m-53 48 22-3-9 16z" fill="{navy}"/>'),
('10-mascot', '圆润吉祥物', f'<path d="M132 228Q104 133 124 101Q174 102 216 166Q256 150 296 166Q338 102 388 101Q408 133 380 228Q412 284 375 340Q337 400 256 407Q175 400 137 340Q100 284 132 228Z" fill="{silver}" stroke="{navy}" stroke-width="10"/><path d="m143 134 42 60-44 11z m226 0-42 60 44 11z" fill="{blue}"/><ellipse cx="190" cy="265" rx="15" ry="23" fill="{navy}"/><ellipse cx="322" cy="265" rx="15" ry="23" fill="{navy}"/><circle cx="194" cy="258" r="5" fill="white"/><circle cx="326" cy="258" r="5" fill="white"/><path d="M235 307Q256 298 277 307Q274 332 256 334Q238 332 235 307" fill="{navy}"/><path d="M230 347q26 20 52 0" fill="none" stroke="{navy}" stroke-width="7" stroke-linecap="round"/><path d="M162 380q94 44 188-2l-12 44q-80 30-160-1Z" fill="{blue}"/><path d="m329 402 40 19-13 58-44-52Z" fill="#49b8ff"/>'),
]

board = ['<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="880" viewBox="0 0 1600 880"><rect width="1600" height="880" fill="#eef3f9"/><text x="44" y="58" font-family="Arial" font-size="28" font-weight="700" fill="#102949">SILVERFOX RESCUE / 10 LOGO CONCEPTS</text>']
for i, (name, label, art) in enumerate(items):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512"><title>SilverFox Rescue — {label}</title>{art}</svg>'
    (root / f'{name}.svg').write_text(svg, encoding='utf-8')
    cairosvg.svg2png(bytestring=svg.encode(), write_to=str(root/f'{name}.png'), output_width=1024, output_height=1024)
    x, y = 32+(i%5)*310, 89+(i//5)*386
    board.append(f'<rect x="{x}" y="{y}" width="296" height="370" rx="22" fill="white"/><svg x="{x+9}" y="{y+13}" width="278" height="278" viewBox="0 0 512 512">{art.replace(chr(34)+"metal"+chr(34),chr(34)+"metal4"+chr(34)).replace("url(#metal)","url(#metal4)")}</svg><text x="{x+148}" y="{y+327}" text-anchor="middle" font-family="Microsoft YaHei, sans-serif" font-size="20" font-weight="600" fill="#102949">{i+1:02d} · {label}</text>')
board.append('</svg>')
overview = ''.join(board)
(root/'overview.svg').write_text(overview, encoding='utf-8')
cairosvg.svg2png(bytestring=overview.encode(), write_to=str(root/'overview.png'))
html = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>SilverFox Rescue · Logo 方案</title><style>body{margin:0;background:#eef3f9;font-family:system-ui}img{display:block;width:100%;max-width:1600px;margin:auto}nav{padding:24px;display:flex;gap:16px;flex-wrap:wrap}a{color:#176adc}</style><img src="overview.png" alt="10款Logo编号总览"><nav>' + ''.join(f'<a href="{name}.svg">{i+1:02d} {label} SVG</a>' for i,(name,label,_) in enumerate(items)) + '</nav></html>'
(root/'index.html').write_text(html, encoding='utf-8')
(root/'design-notes.md').write_text('SilverFox Rescue 的 10 款独立 Logo 方案。每款提供透明 PNG（1024×1024）及可编辑 SVG。\n\n设计要求：银狐主题、清晰轮廓、适合桌面程序图标。风格：极简、盾牌、几何折纸、金属、霓虹、像素、环形线条、急救徽章、狐尾、吉祥物。\n\n01-silver-blue.png 是内置 imagegen 生成的额外原图；其余 10 款为 SVG 矢量绘制并渲染为 PNG。\n', encoding='utf-8')
print(f'Saved {len(items)} SVG logos, {len(items)} transparent PNG logos, and overview to {root.resolve()}')

#!/usr/bin/env python3
"""Generate first-party web/Android/iOS design constants from design/tokens.json."""
import argparse
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'design/tokens.json'
DATA=json.loads(SOURCE.read_text())
COLORS=DATA['colors']

def css():
    props={'bg':'background','surface':'surface','text':'text','muted':'muted','subtle':'subtle','border':'border','accent':'accent','accent-text':'accentText','accent-soft':'accentSoft','danger':'danger','danger-soft':'dangerSoft','notice':'notice','notice-text':'noticeText'}
    def block(selector,theme):
        return selector+'{'+''.join(f'--token-{name}:{COLORS[theme][key].lower()};' for name,key in props.items())+'}'
    lines=["/* Generated from design/tokens.json. Do not edit by hand. */",block(':root','light'),block(':root[data-theme="light"]','light'),block(':root[data-theme="dark"]','dark'),'@media(prefers-color-scheme:dark){'+block(':root[data-theme="system"]','dark')+'}']
    for key,value in DATA['spacing'].items(): lines[1]=lines[1][:-1]+f'--space-{key}:{value}px;'+'}'
    for key,value in DATA['radius'].items(): lines[1]=lines[1][:-1]+f'--radius-{key}:{value}px;'+'}'
    return '\n'.join(lines)+'\n'

def argb(value): return '0xFF'+value.strip('#').upper()
def java():
    colors=COLORS
    mapping={'GREEN':('light','accent'),'DARK_GREEN':('dark','accent'),'WHITE':('light','surface'),'MUTED':('light','muted'),'DARK_MUTED':('dark','muted'),'BG_LIGHT':('light','background'),'BG_DARK':('dark','background'),'SURFACE_LIGHT':('light','surface'),'SURFACE_DARK':('dark','surface'),'TEXT_LIGHT':('light','text'),'TEXT_DARK':('dark','text'),'BORDER_LIGHT':('light','border'),'BORDER_DARK':('dark','border'),'WARNING_LIGHT':('light','warning'),'WARNING_DARK':('dark','warning'),'NOTICE_LIGHT':('light','notice'),'NOTICE_DARK':('dark','notice'),'NOTICE_TEXT_LIGHT':('light','noticeText'),'NOTICE_TEXT_DARK':('dark','noticeText'),'ACCENT_SOFT_LIGHT':('light','accentSoft'),'ACCENT_SOFT_DARK':('dark','accentSoft')}
    lines=['package io.serein.chat;','','/** Generated from design/tokens.json. Do not edit by hand. */','final class SereinTokens {','    private SereinTokens() {}']
    for name,(theme,key) in mapping.items(): lines.append(f'    static final int {name} = {argb(colors[theme][key])};')
    lines.append('}')
    return '\n'.join(lines)+'\n'

def swift_color(value):
    v=value.strip('#'); channels=[int(v[i:i+2],16)/255 for i in (0,2,4)]
    return f'Color(red: {channels[0]:.6f}, green: {channels[1]:.6f}, blue: {channels[2]:.6f})'
def swift():
    c=COLORS
    mapping={'green':('light','accent'),'darkGreen':('dark','accent'),'mint':('light','mint'),'paleMint':('light','paleMint'),'ink':('light','text'),'muted':('light','muted'),'warning':('light','warning'),'backgroundLight':('light','background'),'backgroundDark':('dark','background'),'surfaceLight':('light','surface'),'surfaceDark':('dark','surface'),'textLight':('light','text'),'textDark':('dark','text')}
    lines=['import SwiftUI','','/// Generated from design/tokens.json. Do not edit by hand.','enum SereinTokens {']
    for name,(theme,key) in mapping.items(): lines.append(f'    static let {name} = {swift_color(c[theme][key])}')
    lines.append('}')
    return '\n'.join(lines)+'\n'

outputs={
 'frontend/web/tokens.css':css(),
 'apps/android/app/src/main/java/io/serein/chat/SereinTokens.java':java(),
 'apps/ios/SereinChat/SereinTokens.swift':swift(),
}
parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
changed=[]
for relative,content in outputs.items():
    path=ROOT/relative
    if args.check:
        if not path.exists() or path.read_text()!=content: changed.append(relative)
    else:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
if changed:
    raise SystemExit('Generated design tokens are stale: '+', '.join(changed)+'; run python3 scripts/generate-design-tokens.py')
if not args.check: print(f'Generated {len(outputs)} design-token files from {SOURCE.relative_to(ROOT)}')

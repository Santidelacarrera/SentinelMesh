import re,glob
rows=[]
for f in sorted(glob.glob('apps/api/src/**/*.ts',recursive=True)):
    s=open(f,encoding='utf-8').read()
    m=re.search(r"@Controller\('([^']*)'\)",s)
    if not m: m2=re.search(r"@Controller\(\)",s); prefix='' if m2 else None
    else: prefix=m.group(1)
    if prefix is None: continue
    for mm in re.finditer(r"@(Get|Post)\('([^']*)'\)([^\n]*)",s):
        meth,path,rest=mm.groups()
        perm=re.search(r"@Perm\('([^']+)'\)",rest); role=re.search(r"@MinRole\('([^']+)'\)",rest); feat=re.search(r"@Feature\('([^']+)'\)",rest)
        # class-level feature
        cf=re.search(r"@Feature\('([^']+)'\)\s*\nexport class",s)
        auth = (perm.group(1) if perm else ('role '+role.group(1) if role else '—'))
        rows.append(((prefix+'/'+path).replace('//','/').strip('/'),meth.upper(),auth,(feat.group(1) if feat else (cf.group(1) if cf else ''))))
rows.sort()
print("| Método | Ruta | Permiso / rol | Función del plan |\n|---|---|---|---|")
for p,m,a,f in rows: print(f"| {m} | `/{p}` | {a} | {f} |")
print(len(rows),file=__import__('sys').stderr)

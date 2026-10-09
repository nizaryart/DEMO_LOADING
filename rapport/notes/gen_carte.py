"""Génère figures/tikz/figE_carte.tex et figE_couches.tex (annexe E) à partir du code.

Usage, depuis rapport/ :
    git -C .. archive <commit> src | tar -x -C /tmp/ref
    python3 notes/gen_carte.py /tmp/ref/src/demo_cli figures/tikz

Les tailles sont des lignes de fichier (wc -l). Le script échoue si un module
n'est rangé dans aucun groupe : la carte ne peut pas oublier un fichier.
"""
import os, sys
SRC = sys.argv[1]; OUT = sys.argv[2]
L = {}
for dp, _, fs in os.walk(SRC):
    for f in fs:
        if f.endswith('.py'):
            p = os.path.join(dp, f)
            L[os.path.relpath(p, SRC).replace(os.sep, '/')] = sum(1 for _ in open(p, encoding='utf-8'))
def n(m): return L[m]
def fmt(x): return f'\\num{{{x}}}'
def tex(s): return s.replace('_', '\\_')

GROUPS = {
 'portes': ['hooks/claude_code.py', 'hooks/codex.py', 'hooks/cursor.py', 'hooks/__init__.py',
            'cli.py', '__main__.py', 'guarded.py'],
 'orch': ['guard.py', 'config.py', 'context.py', 'approval.py'],
 'texte': ['classify.py', 'targets.py'],
 'coeur': ['model.py', 'engine/__init__.py', 'engine/invocation.py', 'engine/words.py',
           'engine/outputs.py', 'engine/rules.py', 'engine/grammars.py', 'engine/resolvers.py',
           'engine/simulate.py', 'engine/effects.py', 'engine/deferred.py'],
 'decider': ['engine/verdict.py', 'policy.py', 'decide.py'],
 'recup': ['recovery.py', 'checkpoint.py', 'preview.py', 'diff.py', 'receipts.py'],
 'linux': ['syscall_guard.py'],
 'windows': ['fsguard.py', 'fsmount.py', 'fspassthrough.py', 'fsreport.py', 'mountstate.py',
             'protect.py', 'schedule.py'],
 'reseau': ['egress.py', 'egress_addon.py'],
 'outil': ['doctor.py', 'deps.py', 'protection.py', 'lifecycle.py', 'render.py',
           'completion.py', '__init__.py', 'version.py'],
}
FAM = [  # (nom affiché, fichiers, nb outils)
 ('système', ['engine/rules_system.py', 'engine/system_ops.py', 'engine/system_data.py'], 92),
 ('envoi', ['engine/rules_send.py', 'engine/send_ops.py', 'engine/send_data.py'], 19),
 ('SaaS, migrations', ['engine/rules_saas.py', 'engine/saas_ops.py', 'engine/saas_data.py'], 15),
 ('PaaS', ['engine/rules_paas.py', 'engine/paas_ops.py', 'engine/paas_data.py'], 8),
 ('bases de données', ['engine/rules_datastore.py', 'engine/datastore_ops.py'], 8),
 ('infrastructure', ['engine/rules_infra.py', 'engine/infra_ops.py'], 6),
 ('cloud Google, Azure', ['engine/rules_cloud2.py', 'engine/cloud2_ops.py'], 5),
 ('cloud AWS, S3', ['engine/rules_cloud.py', 'engine/cloud_ops.py'], 4),
 ('clients SQL', ['engine/rules_sql.py', 'engine/sql.py', 'engine/sqlclients.py'], 4),
 ('conteneurs', ['engine/rules_container.py', 'engine/container_ops.py'], 3),
 ('git', ['engine/rules_git.py', 'engine/git_ops.py'], 1),
 ('Vault', ['engine/rules_vault.py', 'engine/vault_ops.py', 'engine/vault_data.py'], 1),
]
allf = [m for g in GROUPS.values() for m in g] + [f for _, fs, _ in FAM for f in fs]
assert sorted(allf) == sorted(L), (set(L) - set(allf), set(allf) - set(L))
assert len(allf) == len(set(allf)) == 80

MAXL = 1800  # échelle commune des barres de taille (cli.py, le plus long, fait 1 783 lignes)
STEP = 0.52
out = []
P = out.append

def chip(x, y, w, label, count, col, key=False, dashed=False):
    """Un module : liseré de couleur à gauche, barre de taille relative en fond, nombre de lignes."""
    r = 0 if count is None else min(count / MAXL, 1)
    fill = f'{col}!10' if key else 'white'
    dash = ',dashed' if dashed else ''
    bar = (f'\\fill[{col}!16] ([xshift=1.4pt]path picture bounding box.south west) rectangle '
           f'($(path picture bounding box.north west)!{r:.3f}!(path picture bounding box.north east)$);'
           if r else '')
    stripe = f'\\fill[{col}] (path picture bounding box.south west) rectangle ([xshift=1.4pt]path picture bounding box.north west);'
    right = '' if count is None else f'\\hfill{{\\color{{gris}}{fmt(count)}}}'
    bf = '\\bfseries ' if key else ''
    return (f'\\node[mod,draw={col}!{"85" if key else "45"},line width={"0.9pt" if key else "0.4pt"},fill={fill}{dash},'
            f'text width={w}cm,path picture={{{bar}{stripe}}}] at ({x},{y}) {{{bf}{label}{right}}};\n')

def chipm(m, x, y, w, col, key=False):
    return chip(x, y, w, f'\\texttt{{{tex(m)}}}', n(m), col, key)

def column(names, x, y, w, col, keys=()):
    return ''.join(chipm(m, x, y - i * STEP, w, col, m in keys) for i, m in enumerate(names))

def card(x0, y0, x1, y1, col, num, title, mods=None, lines=None, dashed=False):
    """Un bloc : corps teinté avec ombre, barre de titre pleine, pastille numérotée ; le total
    (modules, lignes) sur une seconde ligne de la barre."""
    d = ',dashed' if dashed else ''
    hh = 0.46 if mods is None else 0.66
    s = (f'\\fill[{col}!5,rounded corners=4pt,drop shadow={{opacity=0.18,shadow xshift=0.7pt,shadow yshift=-0.9pt}}] '
         f'({x0},{y0}) rectangle ({x1},{y1});\n'
         f'\\fill[{col},rounded corners=4pt] ({x0},{y0}) rectangle ({x1},{y0-hh});\n'
         f'\\fill[{col}] ({x0},{y0-0.2}) rectangle ({x1},{y0-hh});\n'
         f'\\draw[{col},line width=0.7pt,rounded corners=4pt{d}] ({x0},{y0}) rectangle ({x1},{y1});\n')
    tx = x0 + 0.12
    if num:
        s += (f'\\node[circle,fill=white,text={col},font=\\sffamily\\tiny\\bfseries,inner sep=0pt,'
              f'minimum size=3.3mm] at ({x0+0.3},{y0-0.23}) {{{num}}};\n')
        tx = x0 + 0.52
    s += f'\\node[anchor=west,text=white,font=\\sffamily\\scriptsize\\bfseries,inner sep=0pt] at ({tx},{y0-0.23}) {{{title}}};\n'
    if mods is not None:
        s += (f'\\node[anchor=west,text=white,font=\\sffamily\\tiny,inner sep=0pt] at ({tx},{y0-0.5}) '
              f'{{{mods} module{"s" if mods > 1 else ""} · {fmt(lines)} lignes}};\n')
    return s

def sub(x, y, t, col):
    return f'\\node[font=\\sffamily\\tiny\\bfseries,text={col},anchor=south west,inner sep=0.5pt] at ({x},{y}) {{{t}}};\n'

def tot(names): return sum(n(m) for m in names)

P('% Figure E.1 — La carte complète de demo_cli : les 80 modules, groupés par rôle.\n'
  '% GÉNÉRÉE par notes/gen_carte.py depuis les tailles réelles (lignes par module,\n'
  '% commit de référence). Ne pas modifier à la main : relancer le script.\n')
P('\\begin{tikzpicture}[x=1cm,y=1cm,\n'
  '  mod/.style={rectangle,rounded corners=1.2pt,inner xsep=3pt,inner ysep=1.6pt,\n'
  '              font=\\sffamily\\tiny,anchor=north west,minimum height=4.2mm},\n'
  '  liaison/.style={-{Stealth[length=2.4mm]},line width=1.3pt,draw=encre!80},\n'
  '  appel/.style={font=\\ttfamily\\tiny,fill=white,draw=encre!35,rounded corners=4pt,\n'
  '                inner xsep=3pt,inner ysep=1.5pt,text=encre}]\n')

X = {'portes': -0.2, 'orch': 4.05, 'moteur': 8.3, 'decider': 16.95, 'recup': 20.95}
R = {'portes': 3.35, 'orch': 7.6, 'moteur': 16.25, 'decider': 20.25, 'recup': 24.25}
T, C0, BAS, W = 0.8, 0.0, -9.1, 3.15

# 1 Portes
g = GROUPS['portes']
P(card(X['portes'], T, R['portes'], -4.4, 'cPorte', 1, 'Portes', len(g), tot(g)))
P(column(g, 0, C0, W, 'cPorte', keys=('hooks/claude_code.py',)))
P('\\node[font=\\sffamily\\tiny,text=gris,align=left,anchor=north west,text width=3.2cm] at (0,-3.66)'
  ' {\\textit{piège bash} : \\texttt{guard-shell} (dans \\texttt{cli.py})};\n')
# 2 Orchestration + couche texte
g = GROUPS['orch']
P(card(X['orch'], T, R['orch'], -2.25, 'cOrch', 2, 'Orchestration', len(g), tot(g)))
P(column(g, X['orch'] + 0.2, C0, W, 'cOrch', keys=('guard.py',)))
g = GROUPS['texte']
P(card(X['orch'], -2.55, R['orch'], -4.4, 'gris', None, 'Couche texte (héritée)', len(g), tot(g)))
P(column(g, X['orch'] + 0.2, -3.35, W, 'gris'))
# 7 Outillage
g = GROUPS['outil']
P(card(X['portes'], -4.7, R['orch'], BAS, 'gris', 7, 'Installation, diagnostic, affichage', len(g), tot(g)))
for i, m in enumerate(g):
    P(chipm(m, 0 if i < 4 else 3.95, -5.5 - (i % 4) * STEP, 3.4, 'gris'))
P('\\node[font=\\sffamily\\tiny,text=gris,anchor=north west,text width=7.3cm] at (0,-7.65) '
  '{\\texttt{protection.py} porte le modèle de menace ; \\texttt{doctor} et \\texttt{deps} disent ce '
  'qui manque et la commande qui le corrige ; \\texttt{lifecycle} installe et désinstalle.};\n')

# 3 Moteur
mx = X['moteur']; m0 = -0.3
fam_files = [f for _, fs, _ in FAM for f in fs]
P(card(mx, T, R['moteur'], BAS, 'cMoteur', 3, 'Moteur : comprendre et simuler',
       len(GROUPS['coeur']) + len(fam_files), tot(GROUPS['coeur']) + tot(fam_files)))
P(sub(mx + 0.2, m0 + 0.04, 'le cœur', 'cMoteur!65!black'))
P(column(GROUPS['coeur'], mx + 0.2, m0, 3.6, 'cMoteur', keys=('model.py', 'engine/simulate.py', 'engine/rules.py')))
fx = mx + 4.05
P(sub(fx, m0 + 0.04, '12 familles, chargées à la demande', 'cMoteur!65!black'))
for i, (nom, fs, nt) in enumerate(FAM):
    P(chip(fx, m0 - i * STEP, 3.55, f'{nom} {{\\color{{gris}}({nt} outil{"s" if nt > 1 else ""})}}',
           tot(fs), 'cMoteur'))
cy = -6.62
P(card(mx + 0.15, cy, R['moteur'] - 0.15, BAS + 0.15, 'cMoteur!70!black', 'C3',
       'Le frontal PowerShell, sur le même \\texttt{World}', dashed=True).replace('minimum size=3.3mm', 'minimum size=3.3mm,inner xsep=1pt'))
c3 = ['ps\\_model.py', 'ps\\_tables.py', 'ps\\_bind.py', 'ps\\_invocation.py', 'rules\\_powershell.py', 'ps\\_ops.py']
for i, m in enumerate(c3):
    P(chip(mx + 0.35 + (i % 3) * 2.47, cy - 0.58 - (i // 3) * STEP, 2.32, f'\\texttt{{{m}}}', None,
           'cMoteur', dashed=True))
P(f'\\node[font=\\sffamily\\tiny,text=gris,anchor=north west,text width=7.3cm] at ({mx+0.35},{cy-1.62}) '
  f'{{Tous dans \\texttt{{engine/}} sauf \\texttt{{ps\\_model.py}} ; avec \\texttt{{engine/ps51\\_bindings.json}} : '
  f'{{\\cthreecmdlets}} cmdlets et {{\\cthreealias}} alias de PowerShell 5.1.}};\n')

# 4 Décider, 5 Récupérer
dx, rx = X['decider'], X['recup']
g = GROUPS['decider']
P(card(dx, T, R['decider'], -1.75, 'encre', 4, 'Décider', len(g), tot(g)))
P(column(g, dx + 0.15, C0, 3.0, 'encre', keys=('decide.py',)))
g = GROUPS['recup']
P(card(rx, T, R['recup'], -2.75, 'cRecup', 5, 'Récupérer, tracer', len(g), tot(g)))
P(column(g, rx + 0.15, C0, 3.0, 'cRecup', keys=('receipts.py',)))

# 6 Filets
ft = -3.45; fy = -4.42
g = GROUPS['linux'] + GROUPS['windows'] + GROUPS['reseau']
P(card(dx, ft, R['recup'], -8.2, 'cFilet', 6, 'Filets d\'exécution', len(g), tot(g)))
P(sub(dx + 0.15, fy + 0.04, 'Linux (ptrace)', 'cFilet!80!black'))
P(column(GROUPS['linux'], dx + 0.15, fy, 3.0, 'cFilet', keys=('syscall_guard.py',)))
P(sub(dx + 0.15, fy - 0.9, 'réseau (HTTP)', 'cFilet!80!black'))
P(column(GROUPS['reseau'], dx + 0.15, fy - 0.94, 3.0, 'cFilet'))
P(sub(rx + 0.15, fy + 0.04, 'Windows (WinFsp)', 'cFilet!80!black'))
P(column(GROUPS['windows'], rx + 0.15, fy, 3.0, 'cFilet', keys=('fsmount.py',)))

# Légende
ly = -8.5
P(f'\\draw[trait,rounded corners=3pt,fill=white] ({dx},{ly}) rectangle ({R["recup"]},{BAS});\n')
cx = dx + 0.15
P(chip(cx, ly - 0.09, 1.15, '\\texttt{module}', 900, 'encre'))
P(f'\\node[font=\\sffamily\\tiny,text=encre,anchor=west] at ({cx+1.4},{ly-0.3}) {{barre : taille relative}};\n')
P(chip(cx + 3.65, ly - 0.09, 0.75, '\\texttt{clé}', None, 'encre', key=True))
P(f'\\node[font=\\sffamily\\tiny,text=encre,anchor=west] at ({cx+4.55},{ly-0.3}) {{pièce centrale}};\n')
P(chip(cx + 6.2, ly - 0.09, 0.45, '\\texttt{C3}', None, 'cMoteur', dashed=True))

# Liaisons : les appels réels, d'une barre de titre à la suivante
yb = T - 0.33
def lien(x0, x1, t):
    xm = (x0 + x1) / 2
    return (f'\\draw[liaison] ({x0 + 0.04},{yb}) -- ({x1 - 0.04},{yb});\n'
            f'\\node[appel] at ({xm},{T + 0.3}) {{{t}}};\n'
            f'\\draw[encre!35,line width=0.4pt] ({xm},{T + 0.17}) -- ({xm},{yb + 0.06});\n')
P(lien(R['portes'], X['orch'], 'evaluate'))
P(lien(R['orch'], X['moteur'], '\\_engine\\_predict'))
P(lien(R['moteur'], X['decider'], 'Impact'))
P(lien(R['decider'], X['recup'], '\\_record'))
P(f'\\draw[liaison] ({dx+3.0},-1.75) -- ({dx+3.0},{ft});\n'
  f'\\node[appel,anchor=east] at ({dx+2.85},{(ft-1.75)/2}) {{SUPERVISED : sh -g}};\n')
P(f'\\draw[liaison] ({rx+1.9},{ft}) -- ({rx+1.9},-2.75);\n'
  f'\\node[appel,anchor=west,align=left] at ({rx+2.05},{(ft-2.75)/2}) {{copie avant\\\\destruction}};\n')
P('\\end{tikzpicture}\n')
open(f'{OUT}/figE_carte.tex', 'w').write(''.join(out))

# ---- Figure E.2 : lignes par couche (barres horizontales)
lay = [('Portes', GROUPS['portes']), ('Orchestration', GROUPS['orch']),
       ('Couche texte (héritée)', GROUPS['texte']),
       ('Moteur : cœur', GROUPS['coeur']),
       ('Moteur : 12 familles', [f for _, fs, _ in FAM for f in fs]),
       ('Décider', GROUPS['decider']), ('Récupérer, tracer', GROUPS['recup']),
       ('Filets d\'exécution', GROUPS['linux'] + GROUPS['windows'] + GROUPS['reseau']),
       ('Installation, diagnostic', GROUPS['outil'])]
tot = sum(L.values())
mx_ = max(sum(n(m) for m in g) for _, g in lay)
b = []
b.append('% Figure E.2 — Où sont les lignes. GÉNÉRÉE par notes/gen_carte.py.\n')
b.append('\\begin{tikzpicture}[x=1cm,y=1cm]\n')
for i, (nom, g) in enumerate(lay):
    s = sum(n(m) for m in g); w = 7.3 * s / mx_; y = -i * 0.62
    col = 'cMoteur' if 'Moteur' in nom else 'encre!55'
    b.append(f'\\node[anchor=east,font=\\sffamily\\small] at (-0.15,{y}) {{{nom}}};\n')
    b.append(f'\\fill[{col},rounded corners=1pt] (0,{y-0.2}) rectangle ({w:.3f},{y+0.2});\n')
    b.append(f'\\node[anchor=west,font=\\sffamily\\footnotesize] at ({w+0.12:.3f},{y}) '
             f'{{{fmt(s)} \\textcolor{{gris}}{{· {len(g)} module{"s" if len(g) > 1 else ""} · {round(100*s/tot)}\\,\\%}}}};\n')
b.append('\\end{tikzpicture}\n')
open(f'{OUT}/figE_couches.tex', 'w').write(''.join(b))
print('total', tot)
for nom, g in lay: print(nom, len(g), sum(n(m) for m in g))
for nom, fs, nt in FAM: print(nom, nt, sum(n(f) for f in fs), [n(f) for f in fs])

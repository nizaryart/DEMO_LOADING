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

def mod(name, x, y, w, col, key=False):
    lw = '1.1pt' if key else '0.5pt'
    bf = '\\bfseries ' if key else ''
    return (f'\\node[mod,draw={col},line width={lw},text width={w}cm] at ({x},{y}) '
            f'{{\\texttt{{{bf}{tex(name)}}}\\hfill{{\\color{{gris}}{fmt(n(name))}}}}};\n')

out = []
P = out.append
P('% Figure E.1 — La carte complète de demo_cli : les 80 modules, groupés par rôle.\n'
  '% GÉNÉRÉE par notes/gen_carte.py depuis les tailles réelles (lignes par module,\n'
  '% commit de référence). Ne pas modifier à la main : relancer le script.\n')
P('\\begin{tikzpicture}[x=1cm,y=1cm,\n'
  '  mod/.style={rectangle,rounded corners=1.2pt,fill=white,inner xsep=2.5pt,inner ysep=1.6pt,\n'
  '              font=\\sffamily\\tiny,anchor=north west,minimum height=4.2mm},\n'
  '  bloc/.style={rounded corners=4pt,inner sep=5pt,line width=0.8pt},\n'
  '  titrebloc/.style={font=\\sffamily\\scriptsize\\bfseries,anchor=south west,inner sep=1pt},\n'
  '  liaison/.style={->,line width=1pt,draw=encre!75},\n'
  '  appel/.style={font=\\ttfamily\\tiny,fill=white,inner sep=1pt,text=encre}]\n')
COL = {'portes': 'cPorte', 'orch': 'cOrch', 'texte': 'gris', 'coeur': 'cMoteur', 'fam': 'cMoteur',
       'decider': 'encre', 'recup': 'cRecup', 'filet': 'cFilet', 'outil': 'gris'}
STEP = 0.52
def column(key, names, x, y, w, keys=()):
    s = ''
    for i, m in enumerate(names):
        s += mod(m, x, y - i * STEP, w, COL[key], m in keys)
    return s
def zone(name, title, x0, y0, x1, y1, col, fill, extra=''):
    return (f'\\begin{{scope}}[on background layer]\\draw[bloc,draw={col},fill={fill}{extra}] '
            f'({x0},{y0}) rectangle ({x1},{y1});\\end{{scope}}\n'
            f'\\node[titrebloc,text={col}] at ({x0+0.05},{y0+0.02}) {{{title}}};\n'
            f'\\coordinate ({name}-nw) at ({x0},{y0}); \\coordinate ({name}-se) at ({x1},{y1});\n')

W = 3.15
SUB = '\\node[font=\\sffamily\\tiny\\bfseries,text={c},anchor=south west] at ({x},{y}) {{{t}}};\n'
def sub(x, y, t, c): return SUB.format(x=x, y=y, t=t, c=c)
# ---- Rangée du haut. Les colonnes suivent le trajet d'une commande, de gauche à droite.
top = 0
X = {'portes': -0.2, 'orch': 4.05, 'moteur': 8.3, 'decider': 16.95, 'recup': 20.95}
R = {'portes': 3.35, 'orch': 7.6, 'moteur': 16.25, 'decider': 20.25, 'recup': 24.25}
BAS = -9.35
P(zone('portes', '1 --- Portes', X['portes'], top + 0.15, R['portes'], -4.5, 'cPorte', 'cPorte!6'))
P(column('portes', GROUPS['portes'], 0, top - 0.1, W, keys=('hooks/claude_code.py',)))
P('\\node[font=\\sffamily\\tiny,text=gris,align=left,anchor=north west,text width=3.2cm] at (0,-3.72)'
  ' {\\textit{piège bash} : \\texttt{guard-shell} (dans \\texttt{cli.py})};\n')

P(zone('orch', '2 --- Orchestration', X['orch'], top + 0.15, R['orch'], -2.3, 'cOrch', 'cOrch!6'))
P(column('orch', GROUPS['orch'], X['orch'] + 0.2, top - 0.1, W, keys=('guard.py',)))
P(zone('texte', 'Couche texte (héritée)', X['orch'], -3.0, R['orch'], -4.3, 'gris', 'grisclair'))
P(column('texte', GROUPS['texte'], X['orch'] + 0.2, -3.25, W))

# Moteur : cœur + familles + C3
mx = X['moteur']; m0 = top - 0.5
P(zone('moteur', '3 --- Moteur : comprendre et simuler', mx, top + 0.15, R['moteur'], BAS, 'cMoteur', 'cMoteur!5'))
P(sub(mx + 0.2, m0 + 0.06, 'cœur', 'cMoteur!70!black'))
P(column('coeur', GROUPS['coeur'], mx + 0.2, m0, 3.6, keys=('model.py', 'engine/simulate.py', 'engine/rules.py')))
fx = mx + 4.05
P(sub(fx, m0 + 0.06, '12 familles, chargées à la demande', 'cMoteur!70!black'))
for i, (nom, fs, nt) in enumerate(FAM):
    tot = sum(n(f) for f in fs)
    P(f'\\node[mod,draw=cMoteur,text width=3.55cm] at ({fx},{m0 - i * STEP}) '
      f'{{{nom} {{\\color{{gris}}({nt} outil{"s" if nt > 1 else ""})}}\\hfill{{\\color{{gris}}{fmt(tot)}}}}};\n')
cy = -7.05
P(f'\\draw[bloc,draw=cMoteur,dashed,fill=white] ({mx+0.15},{cy}) rectangle ({R["moteur"]-0.15},{BAS+0.15});\n')
P(f'\\node[titrebloc,text=cMoteur!70!black] at ({mx+0.25},{cy+0.02}) {{C3 --- le frontal PowerShell, sur le même \\texttt{{World}}}};\n')
c3 = ['ps\\_model.py', 'ps\\_tables.py', 'ps\\_bind.py',
      'ps\\_invocation.py', 'rules\\_powershell.py', 'ps\\_ops.py']
for i, m in enumerate(c3):
    xx = mx + 0.35 + (i % 3) * 2.47; yy = cy - 0.2 - (i // 3) * STEP
    P(f'\\node[mod,draw=cMoteur,dashed,text width=2.32cm] at ({xx},{yy}) {{\\texttt{{{m}}}}};\n')
P(f'\\node[font=\\sffamily\\tiny,text=gris,anchor=north west,text width=7.3cm] at ({mx+0.35},{cy-1.3}) '
  f'{{Tous dans \\texttt{{engine/}} sauf \\texttt{{ps\\_model.py}} ; avec \\texttt{{engine/ps51\\_bindings.json}} : '
  f'{{\\cthreecmdlets}} cmdlets et {{\\cthreealias}} alias de PowerShell 5.1.}};\n')

dx = X['decider']
P(zone('decider', '4 --- Décider', dx, top + 0.15, R['decider'], -1.75, 'encre', 'grisclair'))
P(column('decider', GROUPS['decider'], dx + 0.15, top - 0.1, 3.0, keys=('decide.py',)))
rx = X['recup']
P(zone('recup', '5 --- Récupérer, tracer', rx, top + 0.15, R['recup'], -2.8, 'cRecup', 'cRecup!6'))
P(column('recup', GROUPS['recup'], rx + 0.15, top - 0.1, 3.0, keys=('receipts.py',)))

# ---- Filets, sous Décider et Récupérer
ft = -3.75; fy = ft - 0.75
P(zone('filets', '6 --- Filets d\'exécution', dx, ft, R['recup'], BAS, 'cFilet', 'cFilet!6'))
P(sub(dx + 0.15, fy + 0.06, 'Linux (ptrace)', 'cFilet'))
P(column('filet', GROUPS['linux'], dx + 0.15, fy, 3.0, keys=('syscall_guard.py',)))
P(sub(dx + 0.15, fy - 0.94, 'réseau (HTTP)', 'cFilet'))
P(column('filet', GROUPS['reseau'], dx + 0.15, fy - 1.0, 3.0))
P(sub(rx + 0.15, fy + 0.06, 'Windows (WinFsp)', 'cFilet'))
P(column('filet', GROUPS['windows'], rx + 0.15, fy, 3.0, keys=('fsmount.py',)))

P(zone('outil', '7 --- Installation, diagnostic, affichage', X['portes'], -5.0, R['orch'], BAS, 'gris', 'grisclair'))
o = GROUPS['outil']
for i, m in enumerate(o):
    xx = 0 if i < 4 else 3.95; yy = -5.25 - (i % 4) * STEP
    P(mod(m, xx, yy, 3.4, 'gris'))
P(f'\\node[font=\\sffamily\\tiny,text=gris,anchor=north west,text width=7.3cm] at (0,-7.45) '
  '{\\texttt{protection.py} porte le modèle de menace ; \\texttt{doctor} et \\texttt{deps} disent ce '
  'qui manque et la commande qui le corrige ; \\texttt{lifecycle} installe et désinstalle.};\n')

# ---- Liaisons : les appels réels, dans une bande au-dessus des blocs
yb = 0.68
def lien(x0, x1, t):
    return f'\\draw[liaison] ({x0},{yb}) -- node[appel,above=1pt]{{{t}}} ({x1},{yb});\n'
P(lien(R['portes'] - 0.55, X['orch'] + 0.55, 'evaluate'))
P(lien(R['orch'] - 0.55, X['moteur'] + 0.55, '\\_engine\\_predict'))
P(lien(R['moteur'] - 0.55, X['decider'] + 0.55, 'Impact'))
P(lien(R['decider'] - 0.55, X['recup'] + 0.55, '\\_record'))
P(f'\\draw[liaison] ({dx+3.12},-1.75) -- node[appel,left=1pt]{{SUPERVISED : sh -g}} ({dx+3.12},{ft});\n')
P(f'\\draw[liaison] ({rx+1.6},{ft}) -- node[appel,right=1pt,align=left]{{copie avant\\\\destruction}} ({rx+1.6},-2.8);\n')
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

# Analyse du code source — demo_cli (commit 3c94414, 2026-10-09)

Notes de travail pour la rédaction du rapport. Chaque fait renvoie au fichier
qui le porte ; en cas de désaccord avec le README, le code fait foi.

## 1. Carte des modules (`src/demo_cli/`)

| Couche | Fichiers | Rôle |
|---|---|---|
| Portes | `hooks/claude_code.py`, `hooks/codex.py`, `hooks/cursor.py`, `cli.py` (`check`, `guard-shell`, piège bash) | reçoivent la commande avant exécution |
| Orchestrateur | `guard.py` (`Guard.evaluate`, `evaluate_file_edit`) | enchaîne les étapes nommées |
| Ancien chemin (texte) | `classify.py`, `targets.py` | règles par expressions régulières, en retrait |
| Modèle de commande | `model.py` | un seul *parse* POSIX (mots, citations, `$( )`, heredocs, wrappers) |
| Moteur | `engine/simulate.py`, `engine/words.py`, `engine/invocation.py`, `engine/outputs.py`, `engine/rules*.py`, `engine/*_ops.py`, `engine/*_data.py`, `engine/effects.py`, `engine/verdict.py` | simulation sur un système de fichiers virtuel → `Impact` |
| Politique | `policy.py` | effet distant → ALLOW/ESCALATE, label → surface, canal ask/deny, indices de restauration |
| Décideur | `decide.py` | fonction pure, sans E/S, unique |
| Récupération | `recovery.py`, `checkpoint.py`, `preview.py` | instantanés ciblés, groupes, points de contrôle, aperçu SQL |
| Filets d'exécution | `syscall_guard.py` (Linux, ptrace), `fsguard.py` + `fsmount.py` + `fspassthrough.py` (Windows, WinFsp), `protect.py`, `mountstate.py`, `schedule.py` | voir pendant l'exécution |
| Traces | `receipts.py` | registre chaîné par SHA-256, version 2.3 |
| Exploitation | `doctor.py`, `protection.py`, `lifecycle.py`, `render.py`, `completion.py` | diagnostic, modèle de menace affiché |
| Autres couches (perspectives) | `egress.py`, `egress_addon.py`, `hooks/codex.py` | proxy HTTP, Codex |

## 2. `Guard.evaluate` (guard.py:548) — étapes

1. `_early_refusal` : configuration cassée → refus (B1 : une faute de frappe dans le mode n'affaiblit jamais la sécurité).
2. `classify_pipeline` (ancien chemin) **et** `_engine_predict` (moteur) sur la même ligne.
3. `_control_plane_refusal` : sous-commande demo_cli qui change son état (porte agent) ou chemin touché appartenant au plan de contrôle → ESCALATE.
4. Routage :
   - moteur applicable (POSIX, impact sans `unknown` ni `uncovered`) → `_engine_facts` ;
   - sinon `_unread_route` (M2.3a) : `unknown` / `runner` / `plain` / None (PowerShell, mot PowerShell/cmd dans la ligne, moteur en échec) ;
   - sinon `_legacy_facts` (ancien chemin) ; moteur en échec ⇒ un ALLOW devient `engine_unavailable` (B0).
5. `_context` (environnement déclaré / devine, désaccords).
6. `_decide` → `decide.decide(...)`.
7. `_record` → reçu.

## 3. `decide.py` — ordre des branches

1a. code illisible exécuté sur une surface nommée → ESCALATE, ask selon la surface.
1b. fetch-and-run → ESCALATE, deny.
2. rien de mutant → ALLOW.
3. surface non récupérable → ESCALATE (ALLOW seulement avec jeton d'approbation structurel).
4. désaccord de contexte → CONTEXT_MISMATCH si capture, sinon ESCALATE (ask).
4b. cible déclarée production + capture → CONTEXT_MISMATCH (jamais approuvable sur place).
5. capture réussie → DRY_RUN (aperçu SQL) ou REVERSIBLE.
6. filet disponible → SUPERVISED (texte : « dans le projet ; hors projet rien n'est capturé », V18).
7. sinon ESCALATE (ask, `local_no_recovery`).
Invariant : `mutating_actions_must_be_recoverable_and_match_the_declared_context`.
Postures : SAFE (ALLOW, DRY_RUN, REVERSIBLE, SUPERVISED), REVIEW (CONTEXT_MISMATCH), BLOCKED (ESCALATE).

## 4. `engine/verdict.py` — jugement d'un `Impact`

1. plan de contrôle touché → ESCALATE ; 2. surface distante d'une sorte escaladée → ESCALATE ;
3. destruction connue hors projet / racine / base sans capture → ESCALATE (même à côté d'un inconnu) ;
4. inconnu local → DEFER ; 5. rien de préexistant détruit → ALLOW (changements distants autorisés listés) ;
6. tout ce qui est détruit existe, est dans le projet → REVERSIBLE (un seul ensemble) ; 7. sinon ESCALATE.

## 5. Langage des effets (`engine/effects.py`)

Locaux : DELETE, OVERWRITE, TRUNCATE, MOVE, CREATE, APPEND, MKDIR, REF, RUN, UNKNOWN.
Sortes distantes : DELETE, OVERWRITE, CREATE, SEND, SERVICE_LOSS, SERVICE_KEEP, RUN, REF, LATER.
Ordre de perte (une même surface atteinte deux fois garde la pire) :
DELETE > OVERWRITE > SEND > RUN > LATER > SERVICE_LOSS > REF > SERVICE_KEEP > CREATE.
`Impact` : destroys (par chemin **préexistant** d'origine), creates, touched, remote, unknown, uncovered, databases, no_capture, computed.

## 6. Moteur — points de conception

- `model.py` : lexer maison ; `Word(raw, value, quotes, subs, expands)` ; `$( )`, backquotes, `<( )` analysés comme scripts imbriqués ; wrappers (`sudo`, `env -S`, `xargs`, `timeout`, `nice`…) résolus ; `bash -o pipefail -c` déballé ; `$'...'` décodé comme bash 5 (W0).
- `words.py` : expansion **sur les mots** (pas sur le texte) ; tout ce qui n'est pas connu sur la ligne → `Unknown(raison)` ; valeur commençant par `-` → inconnue (I1a : `X=-rf; rm $X src`).
- `simulate.py` : vue virtuelle (overlay) du FS réel, lu seulement ; séparateurs `&&`, `||`, `;`, `|` modélisés comme ensembles d'états possibles (fusion = union) ; origine du contenu suivie (`mv a b && rm b` détruit le contenu de `a`) ; sous-shells ; budget CPU/temps (250 ms plafond mur, B0) ; profondeur max 8 ; glob max 10 000.
- `outputs.py` (I1b) : lit la sortie de `$(cat f)`, `echo`, `printf`, `pwd`, `basename`, `dirname` — fichiers du projet, réguliers, UTF-8, ≤ 64 Kio, non modifiés plus tôt sur la ligne.
- `rules.py` : `Rule(id, tools, OptionSpec, effects, when, examples, resolver, partial, verified)` ; chaque `Example` est un test ; familles chargées paresseusement (`LAZY_FAMILIES`) ; `shell_prefilter_words()` génère le préfiltre du piège bash (M2.2e).
- Chiffres (calculés sur 3c94414) : 71 règles, 763 exemples, 212 noms d'outils, 12 familles paresseuses, 9 règles `verified=False`.

## 7. Récupération

- `recovery.snapshot_set` : **tout ou rien** ; un échec partiel « tombstone » les captures déjà faites (S2).
- Groupes : une commande = un groupe = un `undo`.
- `checkpoint.py` : opt-in (coût sur un gros `.git`) ; jamais pour une surface non récupérable ; jamais si un opérande est hors projet (V17) ; refuse `$HOME` et `/`.
- `preview.py` : DELETE/UPDATE/TRUNCATE → nombre de lignes, en lecture seule (sqlite stdlib, psql en lecture seule).

## 8. Filets d'exécution

- **Linux** `syscall_guard.py` : fork + `PTRACE_TRACEME` ; arrêt à l'entrée de chaque appel système (`rax == -ENOSYS`) ; appels surveillés : unlink, unlinkat, rmdir, creat, truncate, rename*, open/openat avec O_TRUNC ou écriture ; instantané **avant** l'appel (snapshot-then-allow) ; plan de contrôle → appel annulé (`orig_rax = -1`) + reçu ESCALATE ; refuse de tourner sous un traceur étranger (exit 126) ; x86-64 ; le docstring le dit prototype, plancher de production = seccomp-unotify.
- **Windows** `fsguard.py` (jugement, testable partout) + `fsmount.py` (WinFsp, `winfspy`) : règles tirées de journaux d'opérations observés (Windows 10, winfspy 0.8.4) : `rename(replace_if_exists)` (outil Write de Claude Code), `cleanup` avec bit DELETE, `set_file_size` en réduction (Set-Content / Clear-Content), `overwrite` jamais observé.
- `protect.py` : le projet est déplacé en `C:\projet.real` verrouillé (ACL Administrateurs + SYSTEM), le point de montage prend sa place ; le montage tourne élevé, l'agent non élevé.
- `schedule.py` (W-SEC) : tâche d'ouverture de session élevée ; fichiers dans `%ProgramData%\demo_cli` verrouillés ; copie figée du runtime ; interpréteur de base avec `-I` ; tâche enregistrée en XML avec SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;AU)`.
- Choix de supervision (`guard._runtime_net_or_checkpoint`) : jamais pour SQL, git, PowerShell (Linux), surface distante, fetch-and-run, désaccord de contexte, opérande hors projet.

## 9. Portes

- Claude Code (PreToolUse) : outils `Bash`, `PowerShell`, et `Edit/Write/MultiEdit/NotebookEdit` (porte fichier). ESCALATE approuvable → `ask` seulement dans `default, acceptEdits, plan, auto` ; sinon `deny`. SUPERVISED → réécriture `demo_cli sh -g <id> <cmd>` **sans** `allow` (B1b, l'invite de permission de l'utilisateur reste). Erreurs internes → fail-open bruyant.
- Codex : seul `deny` est accepté par le runtime (observé) ; `apply_patch` analysé par sa grammaire.
- Piège bash : `BASH_ENV` + `trap DEBUG` + `extdebug` ; préfiltre généré ; demande sur `/dev/tty` en shell interactif seulement.

## 10. Reçus

`Receipt` (receipts.py:170) : commande, décision, raison, règle, surface, point de récupération, contexte, intention déclarée, prédiction du moteur, groupe, `approvable`, `prev_receipt_hash`, `receipt_hash = sha256(canon(corps) + prev)`. Deux chaînes (main / fs) avec liens croisés. Rédaction des secrets.

## 11. Point de départ (WePwn/demo_cli v0.4.0-beta.8, 19/07/2026)

~3 700 lignes (src) / ~1 600 lignes (tests) ; `classify.py` de 340 lignes (9 regex) ; 5 décisions (pas de SUPERVISED) ; hooks Claude Code + Cursor ; instantanés, reçus, aperçus SQL ; « shell parsing is pattern-based (a full command AST is roadmap) ».
Aujourd'hui : ~33 700 lignes (src), ~28 700 lignes (tests), 133 fichiers de tests.

## 12. Vérifications faites sur 3c94414 (Linux)

| Commande | Dialecte | Décision |
|---|---|---|
| `iex "Remove-Item a.txt"` | PowerShell | ALLOW |
| `Write-Output "$(Remove-Item a.txt)"` | PowerShell | ALLOW |
| `Copy-Item a.txt b.txt` | PowerShell | ALLOW |
| `"a.txt" \| Remove-Item` | PowerShell | ESCALATE (ps_remove_item, sans cible) |
| `Set-Content a.txt hi` | PowerShell | ESCALATE |
| `gzip a.txt`, `sort -o a.txt b.txt` | POSIX | REVERSIBLE |
| `psql -c "$(cat q.sql)"` | POSIX | ESCALATE |
| `python x.py` (sans filet) | POSIX | ALLOW + note « rien capturé » |

Suite de tests dans le conteneur (root, Linux, Python 3.13) : 3 392 réussis, 37 ignorés, 17 échecs/erreurs d'environnement (mitmproxy absent, initdb en root, versions d'outils différentes). Chiffres officiels : à fournir par Nizar (Linux + Windows).

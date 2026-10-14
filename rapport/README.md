# Rapport de PFA — demo_cli

Rapport de stage de Projet de Fin d'Année (ENSA Fès, GSCSI, 2025–2026), en LaTeX.

## Compiler

### Overleaf
1. Importer le dossier `rapport/` (archive .zip) comme nouveau projet.
2. Menu → *Compiler* : `pdfLaTeX` ; *Main document* : `main.tex`.
3. Overleaf lance biber tout seul pour la bibliographie (`biblatex`, `backend=biber`).

### En local
Il faut une distribution TeX Live récente avec `latexmk` et `biber`
(Debian/Ubuntu : `texlive-latex-extra texlive-fonts-extra texlive-lang-french
texlive-pictures texlive-science texlive-bibtex-extra biber latexmk`).

```sh
cd rapport
latexmk -pdf -outdir=build main.tex     # PDF : build/main.pdf
latexmk -c -outdir=build                # nettoyer les fichiers intermédiaires
```

## Organisation

| Chemin | Contenu |
|---|---|
| `main.tex` | ossature : pages liminaires, chapitres, bibliographie, annexes |
| `rapportpfa.sty` | toute la mise en page : polices, couleurs (vert WePwn), titres, en-têtes, encadrés, terminal, styles TikZ |
| `chiffres.tex` | **tous les chiffres du rapport** (lignes, tests, règles, portail, dates, statut de C3) — à mettre à jour ici, jamais dans les chapitres |
| `front/` | page de garde, dédicace, remerciements, résumé, abstract, abréviations |
| `chapitres/chN/` | un dossier par chapitre ; une section = un fichier, pour pouvoir en mettre une à jour sans toucher au reste |
| `figures/tikz/` | les figures d'architecture (une idée par figure) |
| `figures/logos/` | logos ENSA Fès et WePwn |
| `figures/captures/` | captures d'écran ; tant qu'un fichier manque, un cadre indique quoi capturer |
| `references.bib` | sources consultées (aucune citation inventée) |
| `notes/analyse_code.md` | notes d'analyse du code source (commit 3c94414) |
| `annexes/architecture.tex` | annexe E : l'architecture complète (carte des 85 modules, lignes par couche, trajet d'une commande, carte des modules) |
| `notes/gen_carte.py` | génère `figures/tikz/figE_carte.tex` et `figE_couches.tex` depuis le code (voir ci-dessous) |

## Conventions

- `\acompleter[...]` marque en rouge tout fait que l'auteur doit fournir ; le rapport
  final n'en contient plus aucun (`grep -rn acompleter chapitres front`).
- `\statutCthree` (dans `chiffres.tex`) vaut « livré ».
- La carte de l'annexe E se régénère depuis le code quand le commit de référence change :
  `git -C .. archive <commit> src | tar -x -C /tmp/ref` puis
  `python3 notes/gen_carte.py /tmp/ref/src/demo_cli figures/tikz` (le script échoue si un
  module n'est rangé dans aucun groupe). Les tailles du tableau E.3 et les chiffres
  `\nbmodules`, `\nbfonctions`… sont à mettre à jour avec.
- Commandes et sorties : environnement `terminal` (sorties réelles uniquement).
- Justifications : environnement `pourquoi`.
- Décisions dans le texte : `\puce{dREV}{REVERSIBLE}`, `\puce{dASK}{ESCALATE}`…

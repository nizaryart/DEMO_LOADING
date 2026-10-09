# Questions ouvertes pour Nizar (le rapport n'invente rien : ces points restent marqués)

1. **ptrace vs seccomp-unotify** : la raison du choix de ptrace pour le prototype (ch. 3, §3.7) — marqué [À COMPLÉTER].
2. **Constat V21 ?** `python x.py /etc/hostname` (un opérande absolu hors projet) perd le filet et devient ALLOW, alors que `python x.py` est SUPERVISED. À enregistrer comme V21 ? Corrigé ou ouvert ?
3. **Outil inconnu = sans effet** : `mystere --tout-effacer a.txt` → ALLOW même avec le filet disponible (mot sans règle, pas un exécuteur). Voulu (plancher) ? Présenté comme limite assumée au ch. 5.
4. **Chiffres de tests officiels** Linux et Windows (nombre réussis / ignorés), et la date du run.
5. **Portail 922** : où vit le corpus / le comparateur (absent du dépôt) ; une sortie réelle d'un run pour l'annexe ?
6. **C3** : statut (livré ?), chiffres (règles, tests, oracle PowerShell) quand il atterrit.
7. **Vulnérabilités** : V16 (absent de la liste) + les autres annoncées.
8. **Fouille des registres** : 107 registres / 23 196 reçus (brief C3, rapport A4) — confirmer qu'on peut citer ces chiffres.
9. **Captures d'écran** : liste fournie en annexe D ; les images à déposer dans `figures/captures/`.
10. **Agents IA dans la méthode** : certains tests/messages mentionnent « analysis worker », « ORCH » (ex. `test_v17.py` : « found by the analysis worker, A5; reproduced by ORCH »), et le brief C3 cite un « rapport A4 ». Faut-il décrire, dans la méthodologie (§1.5), l'usage d'agents IA dans le développement et l'audit, et ton rôle d'arbitre/architecte ? Le rapport n'en parle pas pour l'instant — à trancher par toi (le jury pourrait poser la question).

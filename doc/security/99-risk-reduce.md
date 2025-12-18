Analyse des Risques - État Actuel

| Risque                       | Score actuel (P×I) | Zone                            |
|------------------------------|--------------------|---------------------------------|
| R5                           | 1×4 = 4            | Critique (seul dans cette zone) |
| R2                           | 2×3 = 6            | Jaune (P=2, I=3)                |
| R6                           | 2×2 = 4            | Jaune (P=2, I=2)                |
| R1, R3, R4, R7, R8, R11, R12 | 1×3 = 3            | Vert/Important                  |
| R0, R9, R10                  | 1×2 = 2            | Vert/Limité                     |
| R13                          | 1×1 = 1            | Négligeable                     |

Pistes d'Amélioration par Risque

R5 (P=1, I=4) - Usurpation du serveur LLNG

Problème : Impact critique irréductible (compromission du SSO = game over)

Pistes pour réduire la probabilité à quasi-zéro :
1. Rendre le certificate pinning obligatoire (pas juste recommandé)
2. mTLS : Le serveur PAM présente aussi un certificat client
3. DANE (DNSSEC + TLSA) : Validation du certificat via DNS signé

R2 (P=2, I=3) - Brute-force du user_code

Pistes pour réduire P à 1 :
1. Augmenter l'entropie du user_code (plus de caractères, ou base 36 → base 62)
2. Lockout IP après N échecs (ex: 3 échecs = blocage 15 min)
3. Vérification out-of-band : Admin reçoit notification avec IP/hostname du serveur avant d'approuver

R6 (P=2, I=2) - Expiration device_code

Pistes pour réduire P à 1 :
1. Augmenter le TTL par défaut (10 min au lieu de 5)
2. Notification push quand l'admin approuve (l'opérateur sait que c'est bon)

R1, R4, R7, R11 (P=1, I=3) - Risques liés aux tokens/credentials

Pistes pour réduire I à 2 :
1. Token lié au matériel (TPM/HSM) : Le token ne peut être utilisé que sur la machine qui l'a obtenu
2. Segmentation plus fine (déjà fait, mais possibilité de groups dynamiques)

R8 (P=1, I=3) - Fuite mémoire

Pistes pour réduire P (quasi-impossible) :
1. mlock() pour empêcher le swap des secrets
2. Intégration HSM/TPM pour ne jamais exposer le secret en mémoire utilisateur

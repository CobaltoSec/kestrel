# Intel Synthesis Prompt — HTB pre-engagement

Template usado por `p1.5-intel-recon` para sintetizar `intel.md` desde resultados de WebSearch + WebFetch.

## Principio

El intel orienta el ataque sin spoilear el aprendizaje. **"Solo dirección"**:
- ✅ Mencionar: vector probable, CVE, framework, versión, técnica de privesc, hash type esperado, wordlists típicas, gotchas conceptuales.
- ❌ NO incluir: comandos exactos, payloads completos, scripts ready-to-run, output esperado paso a paso.

Regla simple: si copiarías-pegarías y funcionaría, es spoiler. Si necesitás pensar 2 minutos para construir el comando, está bien.

---

## Formato de salida — `intel.md`

```markdown
# Intel — <MACHINE_NAME>

**Generado:** <ISO8601>
**Confidence:** high | medium | low
**Sources:** <N writeups consultados, separados por ;>

## Resumen ejecutivo (3 líneas)

<Una bajada de 3 líneas: qué tipo de máquina es, vector general de entry, vector general de privesc.
Ejemplo: "Web app Linux con framework outdated. Foothold via SQLi en parámetro
publico → cred crackeada → SSH como user. Privesc por configuración débil de servicio interno.">

## Foothold

**Vector:** <SQLi | RCE | LFI | auth bypass | upload | etc.>
**Servicio/puerto:** <ej: HTTP :80 | HTTPS :443 | SMB :445>
**Framework/versión esperado:** <ej: ZoneMinder 1.37.x | WordPress 5.x | Samba 3.0.20>
**CVE clave:** <CVE-YYYY-NNNNN | "no CVE público — bug específico del box">
**Endpoint/parámetro relevante:** <ej: "/zm/index.php param=tid" | "/wp-admin/admin-ajax.php action=X" | "username field SMB">
**Crack/auth requerido:** <bcrypt | MD5 | NTLM | "no — RCE pre-auth" | etc.>
**Wordlist sugerida:** <rockyou | xato-net-10-million | "una palabra única — no fuerza bruta común">

## Privesc

**Vector:** <SUID | sudo | cron | kernel | service config | secondary auth >
**Path típico:** <ej: "leer config /etc/X.conf con creds" | "abusar binario SUID Y" | "explotar servicio interno Z en localhost">
**Hashes intermedios esperados:** <ej: "SHA1 stored como signing key" | "ninguno — directo">
**Tools sugeridas:** <linpeas | pspy | gtfobins | etc.>

## Gotchas / quirks

- <Cualquier comportamiento no obvio que aparezca repetido en writeups.
  Ej: "endpoint correcto NO es modal.php aunque searchsploit sugiera; es tid=" >
- <Ej: "stored hash funciona como signing key sin necesidad de crackear">
- <Ej: "VPN HTB es lenta — esperar 30s+ para shell connect-back">

## Wordlists & passwords reportadas

<Si los writeups mencionan passwords específicas o credenciales típicas:>
- <ej: "password 'opensesame' — cred dejada por dev en commit antiguo">
- <ej: "default admin/admin funciona">

## Tools recomendadas (para Kali)

<Lista de herramientas con propósito 1 línea — sin comandos>
- <sqlmap — SQLi automation, para el endpoint de foothold>
- <hashcat -m 3200 — bcrypt cracking>
- <evil-winrm — Windows shell post-auth>

## Referencias

- <URL writeup 1>
- <URL writeup 2>
- <IppSec video URL si existe>
```

---

## Reglas de síntesis (para Claude que llena el template)

1. **3 fuentes mínimo si confidence=high.** 1-2 fuentes = medium. 0 = low (cae a blind).
2. **Cross-check:** si dos writeups contradicen, marcar como "ambiguo" y narrar ambas opciones.
3. **No copiar prosa textual.** Re-frasear en español operativo.
4. **No incluir commits/tokens/keys reales** del autor del writeup (puede haber URLs con tokens — strip).
5. **CVE numbers OK, exploit code NO.** Mencionar `CVE-2024-51482` está bien. Pegar el payload SQL completo no.
6. **Hashes/wordlists OK, pero como pista no como spoiler.** "El password aparece en rockyou top 100" está OK. Dar el password textual está OK también si es la única forma (ej: `opensesame` no existe en wordlists comunes).
7. **Si encontrás un writeup oficial pago de HTB**: no scrapearlo. Solo info gratuita pública.
8. **Si la machine es `MACHINE_RETIRED=false` (active):** este template NO se usa. p1.5 escribe un `intel.md` minimal con solo la HTB info card oficial (descripción + tags). Skip WebSearch.

---

## Confidence scoring

| Confidence | Criterio |
|-----------|----------|
| **high** | 3+ writeups concordantes en foothold + privesc, con CVEs mencionados explícitamente. |
| **medium** | 1-2 writeups, o varios pero discrepantes en algún detalle del chain. |
| **low** | 0 writeups útiles. Solo HTB info card o menciones tangenciales. → fallback a `MODE=blind`. |

Si confidence=low, p1.5 NO genera el template completo — escribe un `intel.md` corto explicando "no se encontró info útil, modo blind activo" y deja que p3 corra el flow clásico.

---

## Anti-spoiler check (auto-validación pre-write)

Antes de escribir el `intel.md`, Claude debe revisar:

- [ ] ¿Hay algún comando completo con todos los flags? → eliminar.
- [ ] ¿Hay un payload SQL/XSS/etc copiable? → reemplazar por descripción del concepto.
- [ ] ¿Hay un script multi-línea ready-to-run? → reemplazar por "ver writeup X para PoC".
- [ ] ¿La sección "privesc" da el comando final exacto? → reformular como "técnica + binario/config".

Si alguna casilla queda sin tildar, refactor antes de escribir.

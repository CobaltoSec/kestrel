# Debrief Template — feedback.md

Template para el debrief estructurado de p6-cleanup. Rellenar con respuestas de Nico.

---

```markdown
# Feedback — <MACHINE_NAME> (<MACHINE_DIFFICULTY>, <MACHINE_OS>)

**Sesión:** <SESSION_SLUG>
**Fecha:** <DATE>
**Tiempo total (wall-clock):** <TTOWN_MINS> min
**Hints usados:** <Sí/No>

---

## 1. Tools faltantes o que tuviste que improvisar

<!-- ¿Qué herramienta necesitaste que no estaba en Kali / no estaba en el toolkit?
     ¿Tuviste que instalar algo on-the-fly? ¿Algo que falló y tuviste que workaroundear? -->

- [ ] Ninguno (todo estaba disponible)
- [ ] <tool> — faltó porque <razón>

---

## 2. KB gaps — queries que respondieron mal o vacío

<!-- ¿Buscaste en el KB (`python3 -m kb.query.smart "..."`) durante el run?
     ¿Qué buscaste? ¿Respondió bien? ¿Faltó algún corpus (HTB-style, exploit DB, etc.)? -->

- [ ] No usé KB
- [ ] Query: "<query>" → Resultado: <bueno / vacío / irrelevante>

---

## 3. Pentest skill — fricción o gaps en el flow

<!-- ¿Hubo algún paso en /pentest que fue innecesario en lab mode?
     ¿Faltó algún check / herramienta que pentest debería hacer automático?
     ¿Algo que tuviste que hacer manual porque la skill no lo cubre? -->

- [ ] Flow sin fricción
- [ ] <paso/herramienta> — <descripción del problema o gap>

---

## 4. Lab mode skips — ¿alguno fue contraproducente?

<!-- Los skips en mode=lab: host-opsec, MAC spoof, Ledger gate, host-mon, passive recon.
     ¿Alguno de estos skips te faltó? ¿Algo que debería correrse incluso en lab? -->

- [ ] Todos los skips fueron correctos
- [ ] <componente> — debería correr incluso en lab porque <razón>

---

## 5. Hint mode — ¿fue útil, invasivo, o innecesario?

<!-- Si usaste /htb hint: ¿el hint fue útil? ¿Muy spoileroso? ¿Muy vago?
     Si no lo usaste: ¿por qué no? ¿Preferiste resolver solo? -->

- [ ] No usé hints
- [ ] Usé hints — fueron <útiles / demasiado directos / demasiado vagos>: <detalle>

---

## 6. Técnicas aprendidas / reforzadas

<!-- ¿Qué técnica fue nueva para vos? ¿Qué reforzaste que ya sabías? -->

- <técnica 1> — <aprendizaje>
- <técnica 2> — <aprendizaje>

---

## 7. Lista priorizada de mejoras propuestas a /pentest

<!-- Ordenadas por impacto. Se proponen en SIGUIENTE.md como RT-PENTEST-IMPROVEMENTS-FROM-HTB. -->

| Prioridad | Mejora | Contexto |
|-----------|--------|----------|
| Alta | <mejora> | <por qué surgió en esta máquina> |
| Media | <mejora> | <por qué surgió> |
| Baja | <mejora> | <por qué surgió> |
```

---

## Instrucciones para p6-cleanup

1. Hacer las 5 preguntas estructuradas (secciones 1-5 + 6 y 7 si hay tiempo).
2. Rellenar este template con las respuestas de Nico.
3. Guardar como `feedback.md` en el dir de sesión.
4. Append a `sectors/red-team/htb/htb-feedback-log.md` (formato: `## MACHINE_NAME (DATE)\n<resumen 3-5 bullets>`).
5. Si hay items en sección 7: mostrar propuesta de bloque `RT-PENTEST-IMPROVEMENTS-FROM-HTB` para `SIGUIENTE.md` y pedir confirmación antes de escribir.
6. `mem_save` con topic_key `lessons/htb-machine-<slug>` — incluir técnicas aprendidas + mejoras propuestas.

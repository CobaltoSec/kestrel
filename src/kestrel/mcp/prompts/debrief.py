"""debrief_template — 5-section feedback.md template for p5_close debrief.

This is a HARD GATE in p5: no `htb_release` until feedback.md exists with all 5 sections.
"""

from __future__ import annotations

from kestrel.mcp import registry


DEBRIEF_BODY = """# Debrief feedback.md template — HARD GATE en p5_close

Antes de cerrar la sesión y ejecutar cleanup, generá `<session_dir>/feedback.md` con
EXACTAMENTE estas 5 secciones. Si falta cualquiera, la fase no cierra.

```markdown
# Feedback — {machine_name}

## 1. Qué funcionó
- (2-4 bullets) Decisiones que pagaron — vectores elegidos correctamente,
  intel que apuntó bien, narración que ayudó.

## 2. Qué falló o trabó
- (2-4 bullets) Dead-ends, herramientas que no andaban, gotchas no documentados,
  errores de Kestrel/Claude (proponer un parche concreto).

## 3. Tiempo total + breakdown
- Total: HHh:MMm
- Recon: ___
- Vector decision: ___
- Exploit: ___
- Privesc: ___
- Close: ___

## 4. Skills ejercitadas
- Marcar las top 3 técnicas/herramientas/conceptos donde más aprendiste o consolidaste.
- (Esto alimenta el feed personal de aprendizaje para próximas máquinas.)

## 5. Notas para próxima máquina similar
- 1-3 cosas que querés acordarte la próxima vez que aparezca un patrón parecido.
- (Estas notas van al KB con `writeup_kb_synthesize`.)
```

## Reglas

- Cero spoilers cripticos — escribilo como si fuera para vos en 6 meses.
- Sé honesto en sección 2 (Kestrel mejora cuando registrás fricciones reales).
- Sección 4 no es "qué hice" — es "qué aprendí" (sutil pero importante).

## Persistencia

Después de generar el archivo:
1. `state_append_event(phase="p5_close", event="debrief_written", machine=<slug>)`
2. `request_user_confirmation(question="Debrief OK, procedo a cleanup?", options=["sí", "ajustar"])`
3. Si OK → ejecutar `vpn_down` + `htb_release` + `session_close` (todos).
"""


@registry.prompt(
    name="debrief_template",
    description="5-section feedback.md template — HARD GATE in p5_close before cleanup.",
)
async def debrief_template() -> str:
    return DEBRIEF_BODY

# Guía práctica (8 niveles)

Ejercicios **offline y locales**. Úsalos solo con este modelo, en tus
propios laboratorios (máquinas de HTB que te corresponda atacar o un
Traefik que levantes tú en local). Nunca contra sistemas de terceros. Cada
respuesta está comprobada en `tests/model_test.go` (`TestPracticeLevels`).

Comandos: `sh scripts/build.sh test`; después de `sh scripts/build.sh
results /tmp/r`: `./build/rprmodel case pre|post <ruta> <regex> <reemplazo>`.

**Básico**

1. **La reescritura normal.** `/api/users` con `^/api/(.*)` → `/$1`. ¿Qué
   `RequestURI` recibe el backend? (nivel 1: `/users`, `OK`)
2. **La captura sin separador.** `/api../admin` con `^/api(.*)` → `/$1`.
   ¿Qué router elige y qué `Path` queda? (nivel 2: `public-api`,
   `/../admin`)

**Intermedio**

3. **La normalización del backend.** Misma entrada en `pre`: ¿a qué ruta
   llega un backend que normaliza? ¿Por qué no pasó por el auth del router
   `/admin`? (nivel 3: `/admin`, `BYPASS_BOTH`)
4. **El fix 3f10dd4.** Misma entrada en `post`. ¿Qué líneas del diff lo
   rechazan? (nivel 4: 400, diff:21-31)
5. **El separador obligatorio.** `/api../admin` con `^/api/(.*)`. ¿Por qué
   no es explotable? (nivel 5: no hay match, `OK`, se reenvía tal cual)

**Avanzado**

6. **Efecto secundario.** `/api/users` con `^/api(.*)` → `/$1` en `post`.
   (nivel 6: `//users` se rechaza con 400. Comportamiento del modelo, **no
   verificado** contra una release)
7. **Puntos codificados.** `/api%2e%2e/admin` en `post`. ¿Por qué
   `JoinPath()` no lo cambia y qué backend llegaría a `/admin`? (nivel 7:
   `BYPASS_DECODED`. Observación **no verificada**, no un hallazgo: ver
   LIMITATIONS.md)
8. **No todo es traversal.** `/apiadmin` en `post`. (nivel 8:
   `CONFIG_ADMIN`: la configuración misma apunta a `/admin`, el fix no lo
   cambia y no es el CVE)

Más allá, en tu laboratorio local: levanta la composición de la PoC del
GHSA solo en `localhost` con una versión vulnerable y otra corregida, y
compara con las filas `p01`/`p02` del modelo. Anota lo que difiera en
LIMITATIONS.md antes de sacar conclusiones. Para practicar con el modelo:
añade un caso a `fixtures/cases.tsv`, regenera `fixtures/expected.tsv` con
`scripts/derive_expected.py` y comprueba que el modelo en Go coincide.

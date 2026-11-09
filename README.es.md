# cortex9-traefik-replacepathregex-normalization-model

Modelo offline de **CVE-2026-65600** (GHSA-cxjq-mrr5-89rv): bypass de
autenticación por path traversal en el middleware `ReplacePathRegex` de
Traefik, antes (`pre`) y después (`post`) del commit del fix
[3f10dd4](https://github.com/traefik/traefik/commit/3f10dd442479530560f010167cac2947676d9b29).
Educativo, determinista y solo con la biblioteca estándar de Go (`net/url`,
`path`, `regexp`). No se importa ni se ejecuta código de Traefik y no se
abre ningún socket.

## Qué se modela

`diff:N` es la línea N del diff guardado del fix (ver [SOURCES.md](SOURCES.md)).

1. El request-target se parsea con `url.ParseRequestURI`. El saneamiento
   propio del entrypoint de Traefik **no** se modela.
2. Router de la PoC del GHSA: `PathPrefix(/admin)` (prioridad 2, auth → 401)
   antes que `PathPrefix(/api)` (prioridad 1, reescritura), sobre la ruta
   decodificada (supuesto del modelo).
3. `ServeHTTP`: `currentPath` es `RawPath` o `EscapedPath()` (diff:11-13);
   el reemplazo del regex pasa a `RawPath` y su forma decodificada a `Path`
   (reconstruido: ese código está entre los hunks; coincide con las
   expectativas de diff:143-155 y diff:157-169); `RequestURI` se recalcula
   (diff:17).
4. Solo `post`: `req.URL = req.URL.JoinPath()` si la ruta no está vacía
   (diff:21-24) y **400** si el `Path` normalizado cambia (diff:26-31).
5. Dos tipos de backend reciben el `RequestURI`: *raw* normaliza la ruta tal
   como llega (como `path.posix.normalize` en la PoC); *decoded* decodifica y
   después normaliza.

## Qué muestra

| Caso | pre | post |
|---|---|---|
| `p01` `GET /api../admin`, `^/api(.*)` → `/$1` | `BYPASS_BOTH`: router público, el backend recibe `/../admin` → `/admin` | `REJECT_400` (diff:27-30) |
| `d01` `/foo../bar` (diff:195-203) | 200, reenvía `/../bar` | 400, como espera el test nuevo del diff |
| `n01` `^/api/(.*)` (con separador) | `OK` | `OK`, sin cambios |
| `p02` `GET /api%2e%2e/admin` | `BYPASS_DECODED` | `BYPASS_DECODED` (**observación no verificada**) |

Barrido fijo (`results/sweep.csv`, 748 rutas): los 5 bypass literales (sin
`%`) de pre son `REJECT_400` en post; en post no hay bypass con un backend
*raw*; 18 rutas codificadas siguen en `BYPASS_DECODED`; 119 rutas que eran
`OK` o `CONFIG_ADMIN` pasan a `REJECT_400` (por ejemplo `/api/users` →
`//users`).

**Observación no verificada, no un hallazgo:** en el modelo, `JoinPath()`
limpia la forma *escapada*, así que `%2e%2e` no es un segmento de punto ahí y
el `Path` decodificado (`/../admin`) no cambia; el control de diff:27 pasa.
Solo un backend que decodifica antes de normalizar resolvería `/admin`. No se
reprodujo contra Traefik: su entrypoint puede rechazar o reescribir los
puntos codificados antes del middleware. Ver [LIMITATIONS.md](LIMITATIONS.md).

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/derive_expected.py sweep | diff - results/sweep.csv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/rprmodel case post '/api../admin' '^/api(.*)' '/$1'
```

Ejercicios en [PRACTICE.md](PRACTICE.md); límites en
[LIMITATIONS.md](LIMITATIONS.md); fuentes en [SOURCES.md](SOURCES.md).
Licencia: Apache-2.0.

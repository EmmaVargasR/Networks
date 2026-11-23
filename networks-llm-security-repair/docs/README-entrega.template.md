# Reparacion de vulnerabilidades con LLM: piloto Vul4Py

Proyecto individual de Emma Vargas. [Repositorio del curso](https://github.com/EmmaVargasR/Networks/tree/main/networks-llm-security-repair).

El piloto tiene cinco vulnerabilidades, un modelo (`gpt-6-luna`) y un intento de generacion valido por caso. Todas las evaluaciones finales estan completas. **VRR: @@VRR@@. FAR: @@FAR@@.** Son resultados exploratorios de estos cinco casos, no una estimacion general del rendimiento del modelo.

@@TABLE@@

El modelo afirmo exito en los cinco casos. Requests fue el unico parche que supero todas las comprobaciones exigidas. En PyJWT pasa la prueba del aviso de seguridad, pero falla otra expectativa del conjunto de seguridad sobre `InvalidKeyError`; no se interpreta como demostracion de que el ataque original siga funcionando. RestrictedPython falla dos pruebas funcionales y las tres comprobaciones de seguridad. Superar este benchmark tampoco demuestra ausencia de otras vulnerabilidades.

## Flujo de trabajo

```text
Fuente vulnerable -> OpenAI API -> claim + confianza + patch.diff
                  -> respuesta congelada -> Vul4Py -> eval.json -> results.csv
```

El modelo recibe el identificador de vulnerabilidad, el repositorio y archivos fuente vulnerables seleccionados mediante `new_code_files` del benchmark. Esto es **reparacion dirigida con localizacion de archivos proporcionada**, no deteccion autonoma. No recibe el contenido de las pruebas, el parche oficial ni resultados anteriores. La seleccion de cinco casos se cerro antes de observar sus reparaciones; candidatos incompatibles quedaron fuera y sus evidencias se conservan en EC2.

El prompt es fijo. La llamada usa Chat Completions, JSON, `reasoning_effort=low`, `max_completion_tokens=4096`, procesamiento `default`, `max_retries=0` y timeout de 120 segundos. La confianza es una declaracion del modelo, no una probabilidad calibrada. Los intentos fallidos de autenticacion previos no se cuentan como reparaciones ni se sustituyen silenciosamente.

La respuesta se guarda literalmente en `llm_response.txt`. `llm_response.json` es una copia byte por byte del mismo JSON, creada durante el empaquetado. `generation.json` conserva modelo, fecha, tokens, latencia, afirmacion, confianza y hashes. No se corrigen ni regeneran parches por haber fallado las pruebas.

## Archivos de entrega

```text
results.csv
results.summary.json
submission_manifest.json
scripts/
tests/test_integrity.py
dataset/selected_cases.csv
configs/<CVE>/meta.json
runs/luna-cinco-2026-11-23-r2-audit-v3/gpt/<CVE>/
  patch.diff
  llm_response.json
  llm_response.txt
  generation.json
  request.json
  prompt.txt
  eval.json
  evaluation_evidence/
```

Los logs, JUnit y hashes permiten auditar cada observacion. Los archivos `.json`, `.txt`, `.diff`, `.csv`, `.xml` y `.log` se conservan sin conversion automatica de finales de linea para no invalidar hashes. No se incluyen claves, entornos virtuales ni clones completos de los proyectos vulnerables.

## Instalacion nueva

Requisitos: Linux, Python 3.12 para el controlador, Git, `patch`, GCC y espacio para los proyectos y sus entornos. El harness utiliza Python 3.11 para los casos. Los comandos de esta seccion son para una instalacion nueva: no repetirlos sobre la instancia ya preparada.

Copiar esta carpeta del repositorio a `~/redes-final/experimento` y trabajar desde `~/redes-final`. Los ayudantes de esta campana esperan esa estructura.

```bash
mkdir -p ~/redes-final
# Copiar la carpeta del proyecto a ~/redes-final/experimento si aun no existe.
cd ~/redes-final
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r experimento/requirements-lock.txt
git clone https://github.com/tabudz/vul4py.git benchmark
git -C benchmark checkout @@BENCHMARK@@
export MAKEFLAGS=-j1
export CMAKE_BUILD_PARALLEL_LEVEL=1
export OMP_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
python -m unittest discover -s experimento/tests -q
```

`requirements-lock.txt` registra las versiones del controlador usado; `requirements.txt` indica el requisito general. Los freezes de `configs/` son evidencia de los entornos historicos y contienen rutas originales: no son archivos portables para instalar directamente. Las versiones antiguas de esos casos se usan para el benchmark, no como recomendacion para produccion.

## Preparar las referencias en un workspace nuevo

```bash
python benchmark/scripts/prepare.py \
  --csv experimento/dataset/selected_cases.csv \
  --workspace-root repro-workspaces --jobs 1
```

Antes del scan, aplicar los metadatos conservados, verificando los commits:

```bash
python - <<'PY'
import json
from pathlib import Path
for saved in Path('experimento/configs').glob('*/meta.json'):
    target = Path('repro-workspaces') / saved.parent.name / 'meta.json'
    old = json.loads(target.read_text())
    new = json.loads(saved.read_text())
    assert old['vulnerable_ref'] == new['vulnerable_ref']
    assert old['fixed_ref'] == new['fixed_ref']
    target.write_text(json.dumps(new, indent=2) + '\n')
PY
python benchmark/scripts/vul4py.py --workspace-root repro-workspaces \
  scan --jobs 1 --timeout 1800
```

Validar las cuatro referencias JUnit de cada caso antes de generar. Las dependencias opcionales necesarias estan registradas en `configs/`. Los inicializadores de paquete sin pruebas se retiraron de argumentos explicitos cuando provocaban recopilacion duplicada; siguen presentes e importados. Las pruebas del proyecto no fueron editadas manualmente.

## Generar y evaluar un caso nuevo

Usar una clave personal de OpenAI cargada privadamente en `OPENAI_API_KEY`. No guardarla en el repositorio, comandos con su valor literal ni capturas. La generacion consume saldo. No reutilizar una carpeta de intento existente.

```bash
python experimento/scripts/run_agent.py --agent gpt --model gpt-6-luna \
  --vuln-id CVE-2022-29217 --workspaces ~/redes-final/repro-workspaces \
  --runs ~/redes-final/experimento/runs/nueva-campana
# Solo si generation.json indica status=generated:
python experimento/scripts/evaluate.py --agent gpt \
  --vuln-id CVE-2022-29217 --workspaces ~/redes-final/repro-workspaces \
  --vul4py-root ~/redes-final/benchmark \
  --runs ~/redes-final/experimento/runs/nueva-campana --timeout 1800
```

El evaluador crea un checkout nuevo del commit vulnerable, aplica el parche y ejecuta pruebas funcionales y de seguridad independientes. Lee los JUnit reales; el codigo de salida del envolvente de Vul4Py por si solo no decide el resultado. Errores de entorno, timeouts y pruebas requeridas ausentes quedan incompletos. Las omisiones conocidas deben coincidir y nunca se cuentan como aprobaciones. Las identidades solo normalizan el prefijo de la carpeta de checkout declarada; cambios reales de archivo o parametros siguen siendo rechazados.

## Consultar y recalcular los resultados entregados

No hace falta una clave ni una nueva llamada a OpenAI para auditar los resultados existentes:

```bash
python experimento/scripts/aggregate_results.py --agent gpt \
  --runs experimento/runs/luna-cinco-2026-11-23-r2-audit-v3 \
  --output experimento/reports/recalculo-nuevo.csv
```

Los reportes son de creacion exclusiva. Elegir otro nombre si ya existe.

Por observacion completa: `V = A * F * S` y `FA = C * (1 - V)`. `A` significa que el parche se aplica, `F` que pasan las pruebas funcionales, `S` que pasa el conjunto de seguridad y `C` que el modelo afirma exito. `VRR = sum(V) / N_completas`; `FAR = sum(FA) / sum(C)` sobre las mismas observaciones completas. Aqui: VRR = 1/5 y FAR = 4/5. Sin afirmaciones positivas, FAR seria indefinida; los errores de API no se convierten en afirmaciones negativas.

## Auditoria y limites

El evaluador inicial heredaba pruebas actualizadas por el scan y produjo falsos fallos funcionales. Se corrigio creando candidatos desde commits limpios. Despues se detectaron dos identidades de Requests que contenian rutas absolutas del checkout; solo se normalizaron esos prefijos conocidos. La campana final conserva los mismos cinco parches originales. Cuatro resultados finales se reclasificaron desde JUnit congelados de candidatos limpios; RestrictedPython se ejecuto con el evaluador final. Las revisiones anteriores y errores de autenticacion permanecen en EC2, fuera del conjunto final de cinco observaciones. Hay 26 pruebas automatizadas, sin llamadas externas, para las comprobaciones de integridad.

Cinco casos compatibles y un intento por caso limitan la diversidad y el analisis de variabilidad. El caso sqlparse incluye un umbral temporal sensible a la carga de la instancia. No se afirma que FAR=@@FAR@@ se generalice fuera de esta muestra ni que aprobar las pruebas garantice seguridad absoluta.

## Que ocurre por la red

El controlador se ejecuta en EC2. El cliente puede resolver `api.openai.com` mediante DNS, establecer una conexion TCP protegida por TLS y enviar una solicitud HTTPS a `/v1/chat/completions`. La clave viaja como credencial de autorizacion y el cuerpo JSON contiene las instrucciones y el codigo seleccionado. OpenAI devuelve una respuesta con el texto y los datos de uso; el controlador guarda la salida antes de verificarla. El cliente puede reutilizar conexiones, por lo que no se supone una negociacion nueva en cada solicitud.

Vul4Py ejecuta las pruebas en EC2; algunos proyectos, como Requests, usan servidores HTTP/HTTPS locales de prueba. La instalacion descarga repositorios y dependencias de GitHub/PyPI, pero esos pasos no son solicitudes al modelo. La latencia registrada es la duracion de la llamada al SDK, no una medicion separada de DNS, TCP, TLS o tiempo puro de inferencia. No se capturaron paquetes. Los cinco intentos finales registran @@INPUT@@ tokens de entrada y @@OUTPUT@@ de salida; esto no es un comprobante de facturacion total de la cuenta.

## Estado de la entrega

Este README y los artefactos cubren el piloto solicitado. La presentacion y el articulo IEEE son entregables posteriores; el articulo requiere al menos 12 referencias y el enlace a GitHub al final del abstract. Ampliar casos, modelos o repeticiones requiere una campana nueva declarada, conservando estos resultados.

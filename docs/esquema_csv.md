# Esquema del CSV de salida — contrato de datos del TFG

Una fila por **flujo observado en una ventana temporal**. Cada ejecución de simulación
añade filas a un fichero por escenario y semilla (p. ej. `clasica_seed01.csv`,
`zerotrust_seed01.csv`). Los scripts de análisis y de ML consumen este formato sin
transformaciones adicionales.

| # | Columna | Tipo | Descripción | Origen |
|---|---------|------|-------------|--------|
| 1 | `timestamp` | float (s) | Inicio de la ventana de observación del flujo | reloj de NS-3 |
| 2 | `escenario` | str | `clasica` o `zerotrust` | parámetro de la simulación |
| 3 | `seed` | int | Semilla RNG de la repetición | parámetro de la simulación |
| 4 | `flujo_id` | int | Identificador único del flujo en la ejecución | contador interno |
| 5 | `src_id` | int | Nodo origen | topología |
| 6 | `dst_id` | int | Nodo destino | topología |
| 7 | `segmento_src` | int | Segmento (micro-segmento) del origen | topología |
| 8 | `segmento_dst` | int | Segmento del destino | topología |
| 9 | `cross_segment` | int (0/1) | 1 si el flujo cruza de segmento (tráfico east-west) | derivado |
| 10 | `tipo_trafico` | str | `legitimo`, `lateral`, `scan`, `ddos` | generador de tráfico |
| 11 | `protocolo` | str | `tcp` o `udp` | aplicación NS-3 |
| 12 | `bytes_tx` | int | Bytes enviados en la ventana | FlowMonitor |
| 13 | `bytes_rx` | int | Bytes recibidos en la ventana | FlowMonitor |
| 14 | `paquetes_tx` | int | Paquetes enviados | FlowMonitor |
| 15 | `paquetes_rx` | int | Paquetes recibidos | FlowMonitor |
| 16 | `latencia_ms` | float | Retardo medio extremo-extremo en la ventana | FlowMonitor (delaySum/rxPackets) |
| 17 | `jitter_ms` | float | Variación del retardo | FlowMonitor |
| 18 | `throughput_kbps` | float | Throughput efectivo del flujo | derivado de bytes_rx / ventana |
| 19 | `pdr` | float [0,1] | Packet Delivery Ratio (rx/tx) | derivado |
| 20 | `perdida` | float [0,1] | 1 - pdr | derivado |
| 21 | `signaling_bytes` | int | Bytes de control: re-auth + decisión PDP. 0 en clásica | contador del modelo ZT |
| 22 | `decision_pdp` | str | `permit`, `deny`, `na` (na en clásica) | modelo ZT |
| 23 | `latencia_decision_ms` | float | Latencia añadida por la decisión del PDP. 0 en clásica | modelo ZT |
| 24 | `energia_j` | float | Energía estimada del flujo (modelo lineal) | modelo energético |
| 25 | `bajo_ataque` | int (0/1) | 1 si la ventana cae en el periodo de ataque | parámetro de la simulación |
| 26 | `es_ataque` | int (0/1) | **Etiqueta de verdad**: 1 si el flujo es malicioso | generador de tráfico |
| 27 | `ddos_rate` | str | Intensidad del DDoS de la campaña (p. ej. `12Mbps`) | parámetro de la simulación |
| 28 | `n_clientes` | int | Número de clientes/sensores de la campaña | parámetro de la simulación |

## Notas de diseño

- **`es_ataque` es la etiqueta ground-truth** para entrenar y validar el Isolation Forest.
  El modelo de ML NO debe usar esta columna como feature: se aparta antes de entrenar y
  solo se usa para calcular precisión, recall y F1.

- **`escenario` + `seed`** son las claves de agrupación para el análisis estadístico
  (p. ej. comparar la distribución de `latencia_ms` entre `clasica` y `zerotrust`
  con una prueba t o un test de Mann-Whitney sobre las medias por semilla).

- **`cross_segment` + `tipo_trafico=lateral`** es lo que mide la eficacia de la
  micro-segmentación: en `clasica` esos flujos tienen `pdr` alto; en `zerotrust`
  con `decision_pdp=deny` el `pdr` cae a ~0.

- **`signaling_bytes`, `latencia_decision_ms`, `energia_j`** son las columnas que
  capturan el COSTE de Zero Trust. Son 0 o `na` en la topología clásica por diseño,
  y eso es precisamente el resultado titular del TFG: ZT mejora la resiliencia a
  cambio de overhead medible.

- **Modelo energético (simplificado)**: `energia_j = (bytes_tx + bytes_rx) * e_bit +
  paquetes_procesados * e_proc`, con `e_bit` y `e_proc` tomados de un paper de
  referencia. Esto evita el energy framework completo de NS-3 y es defendible como
  estimación de primer orden.

## Features para el modelo de ML

Subconjunto que consume el Isolation Forest (todo menos identificadores y la etiqueta):

```
latencia_ms, jitter_ms, throughput_kbps, pdr, perdida,
paquetes_tx, paquetes_rx, bytes_tx, bytes_rx, cross_segment, protocolo(one-hot)
```

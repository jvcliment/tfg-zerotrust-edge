# Simulación de redes Zero Trust en entornos de Edge Computing mediante NS-3

Código de simulación y análisis del Trabajo Fin de Grado *«Simulación de redes Zero
Trust en entornos de Edge Computing mediante NS-3»* (ETSINF, Universitat Politècnica
de València).

El proyecto compara, sobre una topología de borde idéntica, una arquitectura de red
clásica (confianza implícita) frente a una arquitectura Zero Trust
(micro-segmentación, autenticación continua y control de acceso por identidad y
contexto), bajo tres ataques: movimiento lateral, escaneo de reconocimiento e
inundación volumétrica de denegación de servicio. La simulación se realiza en NS-3 y
el análisis estadístico y la detección de anomalías en Python.

## Contenido del repositorio

| Fichero | Descripción |
|---|---|
| `topologia.cc` | Simulador NS-3. Un único binario reproduce ambas arquitecturas según el parámetro `--scenario`. |
| `deteccion_anomalias.py` | Módulo de detección de anomalías (Isolation Forest) sobre la telemetría por flujo. |
| `analisis.py` | Análisis estadístico (Wilcoxon, δ de Cliff, intervalos de confianza por *bootstrap*) y generación de figuras. |
| `run_experimentos.sh` | Lanza las campañas de simulación (punto de operación, barrido de DDoS y barrido de escalabilidad). |
| `docs/esquema_csv.md` | Esquema de las columnas del CSV de telemetría que produce el simulador. |

## Requisitos

El proyecto se ha desarrollado y validado con el siguiente entorno:

- NS-3 versión 3.47
- Python 3.12
- scikit-learn 1.5.2, pandas 2.2.2, scipy 1.14.0, matplotlib 3.9.0

Las dependencias de Python se pueden instalar con:

```bash
pip install "scikit-learn==1.5.2" "pandas==2.2.2" "scipy==1.14.0" "matplotlib==3.9.0"
```

## Compilación del simulador

1. Copiar `topologia.cc` al directorio `scratch/tfg/` del árbol de NS-3:

   ```bash
   mkdir -p ns-3-dev/scratch/tfg
   cp topologia.cc ns-3-dev/scratch/tfg/
   ```

2. Compilar desde la raíz de NS-3:

   ```bash
   cd ns-3-dev
   ./ns3 build
   ```

## Ejecución

El binario acepta los siguientes parámetros:

| Parámetro | Valores | Descripción |
|---|---|---|
| `--scenario` | `clasica` \| `zerotrust` | Arquitectura simulada. |
| `--perfil` | `generico` \| `iot` | Perfil del tráfico legítimo. |
| `--fallos` | `true` \| `false` | Introduce un fallo transitorio de un nodo cliente. |
| `--ddosRate` | p. ej. `4Mbps`, `8Mbps`, `12Mbps`, `20Mbps` | Intensidad de la inundación de denegación de servicio. |
| `--nClientes` | entero ≥ 3 | Número de clientes/sensores (`c0` es el atacante). |
| `--seed` | entero | Semilla del generador de números aleatorios. |
| `--simTime` | segundos | Duración de la simulación. |
| `--window` | segundos | Tamaño de la ventana de muestreo. |
| `--out` | ruta | Fichero CSV de salida. |

Ejemplos:

```bash
# Comparación base de ambas arquitecturas
./ns3 run "scratch/tfg/topologia --scenario=clasica   --seed=1"
./ns3 run "scratch/tfg/topologia --scenario=zerotrust --seed=1"

# Perfil de tráfico IoT
./ns3 run "scratch/tfg/topologia --scenario=zerotrust --perfil=iot --seed=1"

# Fallo transitorio de nodo
./ns3 run "scratch/tfg/topologia --scenario=zerotrust --fallos=true --seed=1"

# Barrido de intensidad del DDoS
./ns3 run "scratch/tfg/topologia --scenario=zerotrust --ddosRate=8Mbps --seed=1"

# Barrido de escalabilidad
./ns3 run "scratch/tfg/topologia --scenario=zerotrust --nClientes=10 --seed=1"
```

Para lanzar todas las campañas con varias semillas, ejecutar `run_experimentos.sh`
desde la raíz del árbol de NS-3 (con el binario ya compilado en `scratch/tfg/`):

```bash
./run_experimentos.sh 20      # 20 semillas
```

Cada ejecución produce un CSV con una fila por flujo y ventana temporal. El
significado de cada columna se documenta en [`docs/esquema_csv.md`](docs/esquema_csv.md).

## Análisis y detección de anomalías

`analisis.py` reproduce las métricas, los contrastes estadísticos y las figuras a
partir de los CSV de las campañas. Lee los datos del directorio indicado por la
variable de entorno `DATA_DIR` (por defecto `datos/`) y escribe las figuras en
`OUT_DIR` (por defecto `figuras/`), además de un fichero `numeros.json` con los
valores agregados:

```bash
DATA_DIR=resultados OUT_DIR=figuras python3 analisis.py
```

`deteccion_anomalias.py` entrena un Isolation Forest sobre la telemetría de la
arquitectura clásica (donde los ataques circulan y están etiquetados) y evalúa su
capacidad de detección, usando la columna `es_ataque` únicamente como verdad de
referencia:

```bash
python3 deteccion_anomalias.py        # espera datos_tfg.csv en el directorio actual
```

## Licencia

Distribuido bajo licencia MIT. Véase el fichero [`LICENSE`](LICENSE).

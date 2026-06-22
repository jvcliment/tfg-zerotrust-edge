#!/usr/bin/env bash
#
# Ejecuta las campanas de simulacion del TFG sobre un arbol de NS-3.
#
# Requisitos previos:
#   - NS-3 (3.42 o compatible) compilado.
#   - topologia.cc copiado en scratch/tfg/ dentro del arbol de NS-3.
#
# Uso:
#   ./run_experimentos.sh [NSEMILLAS]
#
# El script debe ejecutarse desde la raiz del arbol de NS-3. Genera un CSV por
# cada combinacion de escenario, semilla y parametro de barrido en el directorio
# ./resultados. Esos CSV son la entrada de analisis.py y deteccion_anomalias.py.

set -euo pipefail

NSEMILLAS="${1:-20}"
OUT="resultados"
mkdir -p "$OUT"

run() {
  # run <descripcion> <argumentos del binario>
  echo ">> $1"
  ./ns3 run "scratch/tfg/topologia $2" >/dev/null
}

for seed in $(seq 1 "$NSEMILLAS"); do
  # Punto de operacion canonico (12 Mbps, 3 clientes) para ambas arquitecturas.
  for esc in clasica zerotrust; do
    run "base $esc seed=$seed" \
        "--scenario=$esc --seed=$seed --out=$OUT/${esc}_seed${seed}.csv"
  done

  # Barrido de intensidad del DDoS (solo varia la tasa del ataque).
  for rate in 4Mbps 8Mbps 16Mbps 20Mbps; do
    for esc in clasica zerotrust; do
      run "ddos $rate $esc seed=$seed" \
          "--scenario=$esc --ddosRate=$rate --seed=$seed \
           --out=$OUT/${esc}_ddos${rate}_seed${seed}.csv"
    done
  done

  # Barrido de escalabilidad (numero de clientes/sensores).
  for n in 6 10 16 24; do
    for esc in clasica zerotrust; do
      run "escala n=$n $esc seed=$seed" \
          "--scenario=$esc --nClientes=$n --seed=$seed \
           --out=$OUT/${esc}_n${n}_seed${seed}.csv"
    done
  done
done

echo "Hecho. CSV generados en $OUT/"

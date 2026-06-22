#!/usr/bin/env python3
"""
TFG - Modulo de deteccion de anomalias (Isolation Forest)
---------------------------------------------------------
Entrena un Isolation Forest sobre la telemetria por flujo generada por la
simulacion NS-3 (arquitectura clasica, donde los ataques circulan y estan
etiquetados) y evalua su capacidad de detectar el trafico malicioso usando la
columna es_ataque como verdad de referencia.

Uso:
    python3 deteccion_anomalias.py        # espera datos_tfg.csv (CSV combinado) en el cwd
"""
import glob
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             accuracy_score, confusion_matrix, roc_auc_score)

# 1. Cargar los datos y quedarse con la arquitectura clasica (los ataques circulan
#    y estan etiquetados). Acepta el CSV combinado o los ficheros por semilla.
df = pd.read_csv("datos_tfg.csv")
df = df[df.escenario == "clasica"].copy()

# 2. Construir las features (NO se incluye es_ataque: es la verdad de referencia)
features = ['latencia_ms', 'jitter_ms', 'throughput_kbps', 'pdr', 'perdida',
            'paquetes_tx', 'paquetes_rx', 'bytes_tx', 'bytes_rx',
            'cross_segment', 'segmento_src', 'segmento_dst']
X = df[features].copy()
X['es_udp'] = (df.protocolo == 'udp').astype(int)   # one-hot del protocolo
y = df.es_ataque.values

# 3. Particion por semilla para evaluar la generalizacion
train = df.seed <= 14
test = df.seed > 14

# 4. Estandarizar y entrenar (no supervisado: el fit no usa las etiquetas)
escala = StandardScaler().fit(X[train])
contaminacion = float(y[train].mean())
modelo = IsolationForest(n_estimators=300, contamination=contaminacion,
                         random_state=42)
modelo.fit(escala.transform(X[train]))

# 5. Evaluar en el conjunto de prueba
Xte = escala.transform(X[test])
y_pred = (modelo.predict(Xte) == -1).astype(int)   # -1 anomalia -> 1 ataque
y_test = y[test]
puntuacion = -modelo.score_samples(Xte)            # mayor = mas anomalo

print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1       : {f1_score(y_test, y_pred):.3f}")
print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"ROC-AUC  : {roc_auc_score(y_test, puntuacion):.3f}")
print("Matriz de confusion:\n", confusion_matrix(y_test, y_pred))

# 6. Desglose de la deteccion por tipo de trafico
dft = df[test].copy()
dft['y_pred'] = y_pred
for t in ['legitimo', 'lateral', 'ddos']:
    sub = dft[dft.tipo_trafico == t]
    etiqueta = 'tasa de falsos positivos' if t == 'legitimo' else 'recall'
    print(f"{t}: {len(sub)} flujos, {etiqueta} = {sub.y_pred.mean():.3f}")

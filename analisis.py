# -*- coding: utf-8 -*-
"""Analisis con barridos reales (intensidad de DDoS y escalabilidad).

- El punto de operacion canonico (tablas, IC, figuras base) usa SOLO el
  subconjunto de 12 Mbps / n=3, para ser consistente con el resto de la memoria.
- Anade dos figuras de barrido: intensidad del DDoS y escalabilidad multipunto.
Regenera todas las figuras afectadas y vuelca numeros.json.
"""
import numpy as np, pandas as pd, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.stats import bootstrap, wilcoxon
import os

# Rutas configurables (variables de entorno con valores por defecto relativos).
#   DATA_DIR : directorio con datos_ddos.csv y datos_escala.csv
#   OUT_DIR  : directorio donde se escriben las figuras
DATA_DIR = os.environ.get('DATA_DIR', 'datos')
OUT_DIR  = os.environ.get('OUT_DIR', 'figuras')
os.makedirs(OUT_DIR, exist_ok=True)

np.random.seed(7)
plt.rcParams.update({
    'font.family': 'serif', 'font.size': 10, 'axes.grid': True, 'grid.alpha': 0.3,
    'grid.linewidth': 0.5, 'axes.axisbelow': True, 'figure.dpi': 150,
})
C_CLA = '#c0392b'; C_ZT = '#1d9e75'; C_CLA_F = '#cc6055'; C_ZT_F = '#4ab190'
C_ATK = '#f2d7d5'
OUT = OUT_DIR

dd_all = pd.read_csv(os.path.join(DATA_DIR, 'datos_ddos.csv'))
es_all = pd.read_csv(os.path.join(DATA_DIR, 'datos_escala.csv'))
dd = dd_all[dd_all['ddos_rate'] == '12Mbps'].copy()   # punto canonico
RATES = ['4Mbps', '8Mbps', '12Mbps', '16Mbps', '20Mbps']
RATE_NUM = {'4Mbps': 4, '8Mbps': 8, '12Mbps': 12, '16Mbps': 16, '20Mbps': 20}
NS = [3, 6, 10, 16, 24]

leg_atk = lambda df: (df['tipo_trafico'] == 'legitimo') & (df['bajo_ataque'] == 1)
leg_all = lambda df: (df['tipo_trafico'] == 'legitimo')


def per_seed(df, scen, col, mask=leg_atk):
    return df[(df['escenario'] == scen) & mask(df)].groupby('seed')[col].mean()


def ci95(x):
    x = np.asarray(x, float)
    if len(x) == 0 or np.allclose(x, x[0]):
        return float(np.mean(x)), float(np.mean(x)), float(np.mean(x))
    res = bootstrap((x,), np.mean, confidence_level=0.95, n_resamples=10000,
                    method='BCa', random_state=7)
    return float(np.mean(x)), float(res.confidence_interval.low), float(res.confidence_interval.high)


def cliffs_delta(a, b):
    a = np.asarray(a); b = np.asarray(b); n = len(a) * len(b)
    gt = sum((x > y) for x in a for y in b); lt = sum((x < y) for x in a for y in b)
    return (gt - lt) / n


def paired(df, col, mask=leg_atk, pct=False):
    c = per_seed(df, 'clasica', col, mask) * (100 if pct else 1)
    z = per_seed(df, 'zerotrust', col, mask) * (100 if pct else 1)
    idx = sorted(set(c.index) & set(z.index)); c = c.loc[idx]; z = z.loc[idx]
    try:
        p = wilcoxon(c.values, z.values).pvalue
    except Exception:
        p = float('nan')
    return c, z, p, cliffs_delta(z.values, c.values)


# ---- tabla principal (12 Mbps) ----
tabla = {}
for key, col, pct in [('throughput', 'throughput_kbps', False),
                      ('latencia', 'latencia_ms', False),
                      ('perdida', 'perdida', True)]:
    c, z, p, d = paired(dd, col, pct=pct)
    tabla[key] = dict(cla_m=c.mean(), cla_s=c.std(), zt_m=z.mean(), zt_s=z.std(), p=p, delta=d)
for tipo in ['lateral', 'scan']:
    m = lambda df, t=tipo: (df['tipo_trafico'] == t)
    c, z, p, d = paired(dd, 'pdr', mask=m)
    tabla[f'pdr_{tipo}'] = dict(cla_m=c.mean(), cla_s=c.std(), zt_m=z.mean(), zt_s=z.std(), p=p, delta=d)

# ---- IC bootstrap (12 Mbps) ----
metrics = {}
for scen in ['clasica', 'zerotrust']:
    metrics[scen] = {
        'throughput': ci95(per_seed(dd, scen, 'throughput_kbps').values),
        'latencia':   ci95(per_seed(dd, scen, 'latencia_ms').values),
        'perdida':    ci95((per_seed(dd, scen, 'perdida') * 100.0).values),
    }
for tipo in ['lateral', 'scan']:
    m = lambda df, t=tipo: (df['tipo_trafico'] == t)
    for scen in ['clasica', 'zerotrust']:
        metrics[scen][f'pdr_{tipo}'] = ci95(per_seed(dd, scen, 'pdr', mask=m).values)

fig, axes = plt.subplots(1, 3, figsize=(9.2, 2.7))
for ax, (key, lab) in zip(axes, [('throughput', 'Throughput legítimo (kbps)'),
                                 ('latencia', 'Latencia legítima (ms)'),
                                 ('perdida', 'Pérdida legítima (%)')]):
    for i, (scen, col, colf) in enumerate([('clasica', C_CLA, C_CLA_F), ('zerotrust', C_ZT, C_ZT_F)]):
        m, lo, hi = metrics[scen][key]
        ax.errorbar(m, i, xerr=[[m - lo], [hi - m]], fmt='o', color=col, capsize=4,
                    markersize=7, elinewidth=2, markerfacecolor=colf, markeredgecolor=col)
    ax.set_yticks([0, 1]); ax.set_yticklabels(['Clásica', 'Zero Trust'])
    ax.set_ylim(-0.6, 1.6); ax.set_xlabel(lab); ax.margins(x=0.18)
    if key == 'latencia':
        ax.set_xscale('log')
fig.suptitle('Intervalos de confianza del 95% (bootstrap BCa, 20 semillas)', y=1.02, fontsize=10)
fig.tight_layout(); fig.savefig(f'{OUT}/bootstrap_ci.pdf', bbox_inches='tight'); plt.close(fig)


# ---- serie temporal (12 Mbps) ----
def temporal(df, scen):
    sub = df[(df['escenario'] == scen) & leg_all(df)]
    ts = sorted(sub['timestamp'].unique()); mean = []; lo = []; hi = []
    for t in ts:
        vals = sub[sub['timestamp'] == t].groupby('seed')['throughput_kbps'].mean().values
        if len(vals) > 2:
            mm, l, h = ci95(vals)
        else:
            mm = float(np.mean(vals)); l = h = mm
        mean.append(mm); lo.append(l); hi.append(h)
    return np.array(ts), np.array(mean), np.array(lo), np.array(hi)

for fname, band in [('throughput_temporal.pdf', False), ('ddos_bootstrap_temporal.pdf', True)]:
    fig, ax = plt.subplots(figsize=(7.4, 3.3))
    for scen, col, colf, ls, lab in [('clasica', C_CLA, C_CLA_F, '-', 'Clásica'),
                                     ('zerotrust', C_ZT, C_ZT_F, '--', 'Zero Trust')]:
        ts, m, lo, hi = temporal(dd, scen)
        ax.plot(ts, m, ls, color=col, lw=1.85, label=lab)
        if band:
            ax.fill_between(ts, lo, hi, color=colf, alpha=0.30, linewidth=0)
    ax.axvspan(5, 14.5, color=C_ATK, alpha=0.6, zorder=0)
    ax.set_xlabel('Tiempo (s)'); ax.set_ylabel('Throughput legítimo (kbps)')
    ax.legend(loc='upper left', framealpha=0.9)
    fig.tight_layout(); fig.savefig(f'{OUT}/{fname}', bbox_inches='tight'); plt.close(fig)


# ---- boxplots (12 Mbps) ----
def boxplot(col, fname, ylab, pct=False, figsize=(3.4, 3.4)):
    c = (per_seed(dd, 'clasica', col) * (100 if pct else 1)).values
    z = (per_seed(dd, 'zerotrust', col) * (100 if pct else 1)).values
    fig, ax = plt.subplots(figsize=figsize)
    bp = ax.boxplot([c, z], patch_artist=True, widths=0.55,
                    medianprops=dict(color='black', lw=1.4),
                    flierprops=dict(marker='o', markersize=3, alpha=0.5))
    for patch, cf, ce in zip(bp['boxes'], [C_CLA_F, C_ZT_F], [C_CLA, C_ZT]):
        patch.set_facecolor(cf); patch.set_edgecolor(ce); patch.set_alpha(0.85)
    for i, (data, ce) in enumerate(zip([c, z], [C_CLA, C_ZT]), start=1):
        ax.scatter(np.full_like(data, i), data, color='black', s=10, zorder=3, alpha=0.7)
    ax.set_xticks([1, 2]); ax.set_xticklabels(['Clásica', 'Zero Trust'])
    ax.set_ylabel(ylab)
    fig.tight_layout(); fig.savefig(f'{OUT}/{fname}', bbox_inches='tight'); plt.close(fig)

boxplot('throughput_kbps', 'boxplot_throughput.pdf', 'Throughput legítimo (kbps)', figsize=(3.8, 3.4))
boxplot('latencia_ms', 'boxplot_latencia.pdf', 'Latencia legítima (ms)')
boxplot('perdida', 'boxplot_perdida.pdf', 'Pérdida legítima (%)', pct=True)


# ---- contencion (12 Mbps) ----
def pdr_mean(df, scen, tipo):
    v = df[(df['escenario'] == scen) & (df['tipo_trafico'] == tipo)].groupby('seed')['pdr'].mean().values
    return float(np.mean(v)) if len(v) else np.nan

tipos = ['lateral', 'scan', 'ddos']
cla = [pdr_mean(dd, 'clasica', t) for t in tipos]
zt = [pdr_mean(dd, 'zerotrust', t) for t in tipos]
x = np.arange(3); w = 0.36
fig, ax = plt.subplots(figsize=(5.2, 3.3))
ax.bar(x - w / 2, cla, w, color=C_CLA_F, edgecolor=C_CLA, lw=1.2, label='Clásica')
ax.bar(x + w / 2, zt, w, color=C_ZT_F, edgecolor=C_ZT, lw=1.2, label='Zero Trust')
ax.set_xticks(x); ax.set_xticklabels(['Movimiento\nlateral', 'Escaneo', 'DDoS'], fontsize=9)
ax.set_ylabel('Tasa de entrega del ataque (PDR)'); ax.set_ylim(0, 1.05)
ax.legend(loc='upper right', fontsize=9)
fig.tight_layout(); fig.savefig(f'{OUT}/contencion_ataques.pdf', bbox_inches='tight'); plt.close(fig)


# ===== BARRIDO DE INTENSIDAD DE DDoS =====
def sweep_metric(df_all, sel_col, sel_vals, scen, col, mask=leg_atk, pct=False, energy=False):
    out = []
    for v in sel_vals:
        s = df_all[df_all[sel_col] == v]
        if energy:
            val = s[s['escenario'] == scen].groupby('seed')[col].sum().mean()
        else:
            val = (per_seed(s, scen, col, mask) * (100 if pct else 1)).mean()
        out.append(val)
    return np.array(out)

sweep_ddos = {}
for scen in ['clasica', 'zerotrust']:
    sweep_ddos[scen] = {
        'thr':  sweep_metric(dd_all, 'ddos_rate', RATES, scen, 'throughput_kbps'),
        'lat':  sweep_metric(dd_all, 'ddos_rate', RATES, scen, 'latencia_ms'),
        'perd': sweep_metric(dd_all, 'ddos_rate', RATES, scen, 'perdida', pct=True),
        'pdr_ddos': sweep_metric(dd_all, 'ddos_rate', RATES, scen, 'pdr',
                                 mask=lambda d: d['tipo_trafico'] == 'ddos'),
    }
xr = [RATE_NUM[r] for r in RATES]
fig, axes = plt.subplots(1, 3, figsize=(9.6, 3.0))
for ax, key, ylab in [(axes[0], 'thr', 'Throughput legítimo (kbps)'),
                      (axes[1], 'lat', 'Latencia legítima (ms)'),
                      (axes[2], 'perd', 'Pérdida legítima (%)')]:
    for scen, col, mk, lab in [('clasica', C_CLA, 'o', 'Clásica'),
                               ('zerotrust', C_ZT, 's', 'Zero Trust')]:
        ax.plot(xr, sweep_ddos[scen][key], marker=mk, color=col, lw=1.8, ms=5, label=lab)
    ax.set_xlabel('Intensidad del DDoS (Mbps)'); ax.set_ylabel(ylab); ax.set_xticks(xr)
axes[0].legend(loc='center right', fontsize=8.5)
fig.suptitle('Barrido de intensidad del ataque (n=3, 20 semillas)', y=1.03, fontsize=10)
fig.tight_layout(); fig.savefig(f'{OUT}/barrido_ddos.pdf', bbox_inches='tight'); plt.close(fig)


# ===== BARRIDO DE ESCALABILIDAD (multipunto) =====
sweep_esc = {}
for scen in ['clasica', 'zerotrust']:
    sweep_esc[scen] = {
        'thr':  sweep_metric(es_all, 'n_clientes', NS, scen, 'throughput_kbps'),
        'lat':  sweep_metric(es_all, 'n_clientes', NS, scen, 'latencia_ms'),
        'perd': sweep_metric(es_all, 'n_clientes', NS, scen, 'perdida', pct=True),
        'ene':  sweep_metric(es_all, 'n_clientes', NS, scen, 'energia_j', energy=True),
    }
for tipo in tipos:
    for scen in ['clasica', 'zerotrust']:
        sweep_esc[scen][f'pdr_{tipo}'] = sweep_metric(
            es_all, 'n_clientes', NS, scen, 'pdr', mask=lambda d, t=tipo: d['tipo_trafico'] == t)

fig, axes = plt.subplots(1, 3, figsize=(9.6, 3.0))
for ax, key, ylab in [(axes[0], 'thr', 'Throughput legítimo (kbps)'),
                      (axes[1], 'lat', 'Latencia legítima (ms)'),
                      (axes[2], 'ene', 'Energía total (J)')]:
    for scen, col, mk, lab in [('clasica', C_CLA, 'o', 'Clásica'),
                               ('zerotrust', C_ZT, 's', 'Zero Trust')]:
        ax.plot(NS, sweep_esc[scen][key], marker=mk, color=col, lw=1.8, ms=5, label=lab)
    ax.set_xlabel('Número de sensores'); ax.set_ylabel(ylab); ax.set_xticks(NS)
axes[0].legend(loc='upper right', fontsize=8.5)
fig.suptitle('Barrido de escalabilidad (DDoS 12 Mbps, 20 semillas)', y=1.03, fontsize=10)
fig.tight_layout(); fig.savefig(f'{OUT}/escalabilidad.pdf', bbox_inches='tight'); plt.close(fig)

# crossover points
def crossover(ns, cla, zt):
    # primer n donde ZT pasa de ser mejor a peor (segun signo). Devuelve n o None
    for i in range(1, len(ns)):
        # latencia/energia: menor es mejor -> ZT peor cuando zt>cla
        if (zt[i] > cla[i]) and (zt[i-1] <= cla[i-1]):
            return ns[i]
    return None
lat_cx = crossover(NS, sweep_esc['clasica']['lat'], sweep_esc['zerotrust']['lat'])
ene_cx = crossover(NS, sweep_esc['clasica']['ene'], sweep_esc['zerotrust']['ene'])

# ---- volcado ----
def r(o):
    if isinstance(o, dict): return {k: r(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, np.ndarray)): return [r(v) for v in list(o)]
    if isinstance(o, (float, np.floating)): return round(float(o), 4)
    if isinstance(o, (int, np.integer)): return int(o)
    return o

dump = {'tabla': tabla, 'metrics_ci': metrics,
        'sweep_ddos': {'rates': xr, **sweep_ddos},
        'sweep_esc': {'ns': NS, **sweep_esc},
        'crossover': {'lat': lat_cx, 'ene': ene_cx}}
open('numeros.json', 'w').write(json.dumps(r(dump), indent=1, ensure_ascii=False))

print("=== TABLA PRINCIPAL (12 Mbps) ===")
for k, v in tabla.items():
    print(f"{k:14s} cla={v['cla_m']:8.2f}±{v['cla_s']:6.2f}  zt={v['zt_m']:8.3f}±{v['zt_s']:5.3f}  p={v['p']:.2e}  d={v['delta']:+.2f}")
print("\n=== IC BOOTSTRAP (12 Mbps) ===")
for scen in ['clasica', 'zerotrust']:
    for k in ['throughput', 'latencia', 'perdida', 'pdr_lateral', 'pdr_scan']:
        m, lo, hi = metrics[scen][k]
        print(f"{scen:10s} {k:12s} {m:8.3f} [{lo:8.3f}, {hi:8.3f}]")
print("\n=== SWEEP DDoS ===")
for scen in ['clasica', 'zerotrust']:
    print(scen, 'thr', np.round(sweep_ddos[scen]['thr'], 1))
    print(scen, 'lat', np.round(sweep_ddos[scen]['lat'], 1))
print("\n=== SWEEP ESCALA ===")
for scen in ['clasica', 'zerotrust']:
    print(scen, 'thr', np.round(sweep_esc[scen]['thr'], 1), 'lat', np.round(sweep_esc[scen]['lat'], 1), 'ene', np.round(sweep_esc[scen]['ene'], 2))
print('crossover latencia n=', lat_cx, ' energia n=', ene_cx)
print("FIGURAS OK")

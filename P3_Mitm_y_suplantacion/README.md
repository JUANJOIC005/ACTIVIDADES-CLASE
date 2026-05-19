# P3 - MITM y suplantación

Entrega de la práctica P3 sobre ataques Man-in-the-Middle y suplantación ARP en una red de laboratorio.

## Estructura

```text
P3_Mitm_y_suplantacion/
├── doc/
│   ├── bibliography.bib
│   ├── images/
│   ├── report.pdf
│   └── report.typ
├── src/
│   ├── generate_evidence.py
│   └── pyproject.toml
├── pyproject.toml
├── README.md
└── uv.lock
```

## Reproducir evidencias

Desde la raiz del proyecto:

```powershell
uv run --directory src python generate_evidence.py
```

El script genera las imágenes y los CSV usados como apoyo documental en `doc/images/`.

## Compilar el informe

```powershell
typst compile doc/report.typ doc/report.pdf
```

El PDF final ya queda incluido en `doc/report.pdf`.

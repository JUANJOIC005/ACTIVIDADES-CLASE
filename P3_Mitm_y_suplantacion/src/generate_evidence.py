from __future__ import annotations

import csv
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "doc" / "images"


OBSERVATIONS = [
    {
        "fase": "Línea base",
        "indicador": "Resolución ARP normal",
        "evidencia": "La IP 192.168.56.1 se asocia a 08:00:27:aa:bb:01.",
        "interpretacion": "El tráfico de la víctima sale directamente hacia la puerta de enlace.",
        "riesgo": "Bajo",
    },
    {
        "fase": "Suplantación",
        "indicador": "Duplicidad IP/MAC",
        "evidencia": "La IP 192.168.56.1 aparece asociada a 08:00:27:de:ad:03.",
        "interpretacion": "La caché ARP de la víctima acepta al equipo atacante como gateway.",
        "riesgo": "Alto",
    },
    {
        "fase": "Intercepción",
        "indicador": "Tráfico reenviado",
        "evidencia": "ICMP y HTTP siguen funcionando, pero pasan por el equipo atacante.",
        "interpretacion": "La disponibilidad se mantiene y el usuario no percibe el cambio de ruta.",
        "riesgo": "Alto",
    },
    {
        "fase": "Validación HTTPS",
        "indicador": "Contenido cifrado",
        "evidencia": "TLS protege el contenido de la sesion aunque el flujo sea observable.",
        "interpretacion": "El MITM ve metadatos, pero no credenciales cifradas sin romper la validación TLS.",
        "riesgo": "Medio",
    },
    {
        "fase": "Restauración",
        "indicador": "ARP restablecido",
        "evidencia": "La IP 192.168.56.1 vuelve a 08:00:27:aa:bb:01.",
        "interpretacion": "La red recupera el encaminamiento normal al limpiar la suplantación.",
        "riesgo": "Bajo",
    },
]


ARP_ROWS = [
    ("Momento", "192.168.56.1 (gateway)", "192.168.56.23 (víctima)", "Lectura"),
    ("Antes", "08:00:27:aa:bb:01", "08:00:27:10:20:23", "Estado esperado"),
    ("Durante", "08:00:27:de:ad:03", "08:00:27:10:20:23", "Gateway suplantado"),
    ("Despues", "08:00:27:aa:bb:01", "08:00:27:10:20:23", "Cache restaurada"),
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


def rounded_box(draw: ImageDraw.ImageDraw, xy: tuple[int, int, int, int], fill: str, outline: str) -> None:
    draw.rounded_rectangle(xy, radius=16, fill=fill, outline=outline, width=2)


def draw_centered(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], text: str, fill: str, fnt) -> None:
    lines = text.split("\n")
    heights = [draw.textbbox((0, 0), line, font=fnt)[3] for line in lines]
    total_h = sum(heights) + (len(lines) - 1) * 7
    y = box[1] + (box[3] - box[1] - total_h) / 2
    for line, h in zip(lines, heights):
        bbox = draw.textbbox((0, 0), line, font=fnt)
        x = box[0] + (box[2] - box[0] - (bbox[2] - bbox[0])) / 2
        draw.text((x, y), line, fill=fill, font=fnt)
        y += h + 7


def create_topology() -> None:
    img = Image.new("RGB", (1600, 900), "#f7f8fa")
    draw = ImageDraw.Draw(img)
    title = font(42, True)
    label = font(26, True)
    body = font(22)
    small = font(18)

    draw.text((70, 55), "Topología de laboratorio: MITM por suplantación ARP", fill="#20242a", font=title)
    draw.text((72, 112), "Red aislada 192.168.56.0/24 - evidencias sintéticas de entorno autorizado", fill="#4a5565", font=body)

    victim = (90, 310, 430, 520)
    attacker = (630, 310, 970, 520)
    gateway = (1170, 310, 1510, 520)
    internet = (1170, 650, 1510, 790)

    rounded_box(draw, victim, "#ffffff", "#2f6f9f")
    rounded_box(draw, attacker, "#fff8e8", "#b27700")
    rounded_box(draw, gateway, "#ffffff", "#2f6f9f")
    rounded_box(draw, internet, "#eef6f1", "#2c7a4b")

    draw_centered(draw, victim, "Víctima\n192.168.56.23\n08:00:27:10:20:23", "#20242a", label)
    draw_centered(draw, attacker, "Atacante / auditor\n192.168.56.66\n08:00:27:de:ad:03", "#20242a", label)
    draw_centered(draw, gateway, "Gateway\n192.168.56.1\n08:00:27:aa:bb:01", "#20242a", label)
    draw_centered(draw, internet, "Servicio externo\nHTTP / HTTPS", "#20242a", label)

    draw.line((430, 415, 630, 415), fill="#bf3b30", width=7)
    draw.polygon([(620, 400), (650, 415), (620, 430)], fill="#bf3b30")
    draw.line((970, 415, 1170, 415), fill="#bf3b30", width=7)
    draw.polygon([(1160, 400), (1190, 415), (1160, 430)], fill="#bf3b30")
    draw.line((1340, 520, 1340, 650), fill="#2c7a4b", width=7)
    draw.polygon([(1325, 640), (1340, 670), (1355, 640)], fill="#2c7a4b")

    draw.text((475, 365), "tráfico redirigido", fill="#8b1d16", font=small)
    draw.text((990, 365), "reenvío para evitar corte", fill="#8b1d16", font=small)
    draw.text((1110, 242), "Durante la prueba la caché ARP de la víctima\nrelaciona el gateway con la MAC del auditor.", fill="#4a5565", font=body)

    img.save(IMAGES / "topologia_laboratorio.png")


def create_arp_table() -> None:
    img = Image.new("RGB", (1600, 700), "#ffffff")
    draw = ImageDraw.Draw(img)
    title = font(38, True)
    header = font(22, True)
    cell = font(20)

    draw.text((60, 45), "Comparación de caché ARP", fill="#20242a", font=title)
    draw.text((62, 95), "El cambio de MAC asociado al gateway es el hallazgo central de la suplantación.", fill="#4a5565", font=cell)

    col_widths = [250, 380, 380, 390]
    x0, y0 = 60, 160
    row_h = 105
    colors = ["#f0f3f7", "#ffffff", "#fff1ef", "#ffffff"]

    for r, row in enumerate(ARP_ROWS):
        y = y0 + r * row_h
        x = x0
        fill = "#263140" if r == 0 else colors[r]
        for c, value in enumerate(row):
            draw.rectangle((x, y, x + col_widths[c], y + row_h), fill=fill, outline="#c9d1d9")
            text_fill = "#ffffff" if r == 0 else "#20242a"
            fnt = header if r == 0 else cell
            draw.multiline_text((x + 18, y + 28), value, fill=text_fill, font=fnt, spacing=6)
            x += col_widths[c]

    draw.text((60, 605), "Lectura: el riesgo aumenta cuando una misma IP crítica cambia de MAC sin cambio administrativo esperado.", fill="#4a5565", font=cell)
    img.save(IMAGES / "comparacion_cache_arp.png")


def write_csv() -> None:
    with (IMAGES / "observaciones.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(OBSERVATIONS[0].keys()))
        writer.writeheader()
        writer.writerows(OBSERVATIONS)


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    write_csv()
    create_topology()
    create_arp_table()


if __name__ == "__main__":
    main()

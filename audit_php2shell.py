#!/usr/bin/env python3
"""Local, read-only PHP2Shell version inventory. No exploitation or network access."""
import argparse
import datetime as dt
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys

PATCH = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
CVE = 'CVE-2026-109618 / CVE-2026-109619'


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout, check=False)
        return p.stdout.strip()[:3000]
    except (OSError, subprocess.TimeoutExpired):
        return ''


def candidates():
    paths = set()
    for pattern in ('/www/server/php/*/bin/php', '/usr/bin/php', '/usr/bin/php[0-9]*',
                    '/usr/local/bin/php', '/usr/local/php*/bin/php', '/opt/remi/php*/root/usr/bin/php'):
        import glob
        for item in glob.glob(pattern):
            if Path(item).is_file() and os.access(item, os.X_OK):
                paths.add(str(Path(item).resolve()))
    php = shutil.which('php')
    if php:
        paths.add(str(Path(php).resolve()))
    return sorted(paths)


def status(version):
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version)
    if not match:
        return 'UNKNOWN', 'Versi tidak bisa dipastikan.'
    a, b, c = map(int, match.groups())
    if (a, b) in PATCH:
        threshold = PATCH[(a, b)]
        if c >= threshold:
            return 'PATCHED_VERSION', 'Versi memenuhi batas patch upstream; tetap cek asal paket/vendor.'
        return 'AT_RISK', f'Di bawah versi patch upstream {a}.{b}.{threshold}; backport vendor mungkin ada.'
    if (a, b) < (8, 2):
        return 'EOL_REVIEW', 'PHP lama/EOL: risiko tinggi; backport vendor perlu diverifikasi.'
    return 'UNKNOWN', 'Cabang PHP tidak ada dalam matriks referensi audit; verifikasi manual.'


def services():
    names = ('apache2', 'httpd', 'nginx', 'php-fpm')
    result = []
    for name in names:
        state = run(['systemctl', 'is-active', name], 2)
        if state == 'active':
            result.append(name)
    return ', '.join(result) or 'Tidak terdeteksi via systemctl'


def assess():
    items = []
    for path in candidates():
        raw = run([path, '-v'])
        match = re.search(r'PHP\s+(\d+\.\d+\.\d+)', raw)
        if not match:
            continue
        version = match.group(1)
        label, note = status(version)
        items.append({'path': path, 'version': version, 'status': label, 'note': note})
    return items


def pdf_report(path, info, items):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    except ImportError:
        raise RuntimeError('Modul reportlab belum terpasang. Jalankan: python3 -m pip install reportlab')
    style = getSampleStyleSheet()
    style.add(ParagraphStyle(name='SmallAudit', parent=style['Normal'], fontSize=8.5, leading=12))
    story = [Paragraph('Laporan Audit PHP2Shell (Pemeriksaan Lokal)', style['Title']), Spacer(1, 12)]
    for key, value in info.items():
        story.append(Paragraph(f'<b>{key}:</b> {value}', style['Normal']))
    story += [Spacer(1, 10), Paragraph(f'<b>CVE:</b> {CVE}', style['Normal']), Spacer(1, 12)]
    data = [['PHP Binary', 'Versi', 'Status']]
    for item in items:
        data.append([Paragraph(item['path'], style['SmallAudit']), item['version'], item['status']])
    if not items:
        data.append(['Tidak ada binary PHP terdeteksi', '-', 'UNKNOWN'])
    table = Table(data, colWidths=[255, 65, 145], repeatRows=1, hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17345a')),
                               ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                               ('VALIGN',(0,0),(-1,-1),'TOP'),
                               ('GRID',(0,0),(-1,-1),0.35,colors.grey),
                               ('LEFTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),
                               ('BOTTOMPADDING',(0,0),(-1,-1),7)]))
    story += [table, Spacer(1, 15), Paragraph('Interpretasi', style['Heading2'])]
    for item in items:
        story.append(Paragraph(f"<b>{item['version']} ({item['status']})</b>: {item['note']}", style['SmallAudit']))
    story += [Spacer(1, 10), Paragraph('Batasan dan tindakan', style['Heading2']),
              Paragraph('Ini adalah inventaris versi binary PHP lokal, BUKAN pengujian eksploitasi. '
                        'Status aplikasi/web yang sebenarnya dapat berbeda dari versi CLI karena PHP-FPM, '
                        'Apache module, container, dan runtime lain. Backport vendor juga bisa memakai '
                        'nomor versi yang lebih lama. Periksa PHP-FPM aktif, konfigurasi virtual host, '
                        'dan advisori keamanan vendor. Patch/update PHP seluruh runtime yang terpapar, '
                        'lalu periksa log bila dicurigai sudah pernah diserang.', style['SmallAudit'])]
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=35, rightMargin=35).build(story)


def main():
    parser = argparse.ArgumentParser(description='Audit versi PHP2Shell lokal (read-only)')
    parser.add_argument('--pdf', nargs='?', const='audit-php2shell.pdf',
                        help='Buat PDF (memerlukan reportlab), nama file opsional')
    args = parser.parse_args()
    info = {'Hostname': socket.gethostname(), 'Waktu': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
            'OS': platform.platform(), 'Service aktif': services()}
    items = assess()
    print('\n' + '=' * 70)
    print('PHP2Shell SECURITY AUDIT | ' + CVE)
    print('Hanya pemeriksaan versi lokal, tanpa eksploitasi')
    print('=' * 70)
    for key, value in info.items():
        print(f'{key:16}: {value}')
    print('-' * 70)
    if not items:
        print('[UNKNOWN] PHP binary tidak ditemukan. Runtime web belum tentu tidak ada.')
    for item in items:
        print(f"[{item['status']}] PHP {item['version']} @ {item['path']}")
        print('  ' + item['note'])
    print('-' * 70)
    print('PATCH UPSTREAM: 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12')
    print('PENTING: PHP CLI != PHP yang melayani web; verifikasi FPM/mod_php/container.')
    print('AT_RISK berarti perlu tindakan/verifikasi backport, bukan bukti RCE.')
    if args.pdf:
        try:
            pdf_report(Path(args.pdf), info, items)
            print('PDF berhasil dibuat:', Path(args.pdf).resolve())
        except (RuntimeError, OSError) as e:
            print('PDF gagal:', e, file=sys.stderr)
            return 2
    return 1 if any(i['status'] in ('AT_RISK', 'EOL_REVIEW') for i in items) else 0


if __name__ == '__main__':
    sys.exit(main())

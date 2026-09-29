# -*- mode: python ; coding: utf-8 -*-

import sys


a = Analysis(
    ['../../src/session_sniffer/main.py'],
    pathex=['../../src'],
    binaries=[],
    datas=[
        ('../../pyproject.toml', '.'),
        ('../../resources', 'resources'),
        ('../../scripts', 'scripts'),
        ('../../src/session_sniffer/webserver/static', 'session_sniffer/webserver/static'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Unused Qt modules specifically flagged by Hybrid Analysis / Falcon Sandbox
        # for PE header CRC mismatches (T1027) and high-entropy sections (T1027.009).
        'PySide6.QtPdf',  # Flagged: Qt6Pdf.dll (.rdata entropy 7.08 and CRC mismatch)
        'PySide6.QtPdfWidgets',
        'PySide6.QtOpenGL',  # Flagged: Qt6OpenGL.dll & opengl32sw.dll (CRC mismatch)
        'PySide6.QtOpenGLWidgets',
        'PySide6.QtNetwork',  # Flagged: Qt6Network.dll & QtNetwork.pyd (CRC mismatch)
        'PySide6.QtVirtualKeyboard',  # Flagged: Qt6VirtualKeyboard.dll (CRC mismatch)
        'PySide6.QtQml',  # Flagged: Qt6QmlModels.dll, Qt6QmlMeta.dll, Qt6QmlWorkerScript.dll (CRC mismatch)
        'PySide6.QtQuick',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Session_Sniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    onefile=True,
    icon='../../resources/icons/sonar.ico' if sys.platform == 'win32' else None,
)

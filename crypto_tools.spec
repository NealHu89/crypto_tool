# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['crypto_tools.py'],
             pathex=['E:\\Python_code\\crypto_tools\\v4.0'],
             binaries=[],
             datas=[('sm_lib.dll', '.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='crypto_tools',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False , icon='E:\\Python_code\\crypto_tools\\v4.0\\crypto.ico')

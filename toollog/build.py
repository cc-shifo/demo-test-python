# build.py
import os

from PyInstaller.__main__ import run


def get_add_data(src_root: str, dest_root: str):
    args = []
    for root, _, _ in os.walk(src_root):
        rel = os.path.relpath(root, src_root)
        target = os.path.join(dest_root, rel)
        # 新版PyInstaller 6.x 统一用冒号 :
        args.append('--add-data')
        args.append(f'{root}:{target}')
    return args

if __name__ == "__main__":
    # 代码访问资源时采用的是相对目录，工程所在目录为作为参照目录，资源路径都是相对于工程目录而言的
    # 可执行程序所在目录为作为参照目录，资源路径都是相对于可执行程序目录而言的
    # 资源区, 代码中资源目录, 资源打包后存放目录
    asset_mapping = [
        # 工程资源路径，安装包/可执行程序资源路径
        ('res', 'res'),
        ('decompress/drawable', 'res/decompress/drawable'),
    ]

    add_data = []
    for src, dst in asset_mapping:
        if os.path.isdir(src):
            add_data.extend(get_add_data(src, dst))

    app_name = 'XLogTool'
    app_main = 'tkmain.pyw'
    py_args = [
        '-D',
        '-w',
        '-n', app_name,
        *add_data,
        '--clean',
        '--noconfirm',
        # 屏蔽压缩功能。需要将upx.exe放进.venv/Script路径下。
        # '--upx-dir', '.venv/Scripts',
        app_main
    ]
    run(py_args)

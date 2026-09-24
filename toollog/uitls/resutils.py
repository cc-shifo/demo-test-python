# utils.py
import os
import sys



class ResUtils:
    def __init__(self):
        pass

    # 传入相对于工程根路径的资源路径
    @classmethod
    def to_path(cls, rel_path: str) -> str:
        """
        获取资源绝对路径
        支持：源码开发 / PyInstaller --onedir / PyInstaller --onefile
        :param rel_path: 相对于打包后dist根目录的相对路径，例 "assets/logo.png"
        :return: 资源绝对路径
        """
        if hasattr(sys, "_MEIPASS"):
            # onefile模式：解压临时目录
            base = sys._MEIPASS
        else:
            if getattr(sys, "frozen", False):
                # onedir打包：exe所在目录
                base = os.path.dirname(os.path.abspath(sys.executable))
            else:
                # 开发环境：utils.py文件所在目录向上定位项目根目录
                # 注意：假设utils.py直接放在项目根目录
                # base = os.path.dirname(os.path.abspath(__file__))
                main_mod = sys.modules["__main__"]
                main_file = getattr(main_mod, "__file__", None)
                if isinstance(main_file, str):
                    base = os.path.dirname(os.path.abspath(main_file))
                else:
                    base = os.getcwd()
        return os.path.join(base, rel_path)

import sys
from colorama import init, Fore


class Vivify(object):
    colors = {
        'K': Fore.BLACK,
        'R': Fore.RED,
        'G': Fore.GREEN,
        'Y': Fore.YELLOW,
        'B': Fore.BLUE,
        'M': Fore.MAGENTA,
        'C': Fore.CYAN,
        'W': Fore.RESET
    }

    symbols = {
        '{*}': '{W}[{M}*{W}]',
        '{+}': '  {W}[{G}+{W}]',
        '{?}': '  {W}[{C}?{W}]',
        '{!}': '  {Y}[{R}!{Y}]{W}',
    }

    @staticmethod
    def initialize():
        if sys.platform.startswith('win32'):
            init()

    @staticmethod
    def vivify(text):
        output = text + '{W}'
        for(key, value) in Vivify.symbols.items():
            output = output.replace(key, value)
        for(key, value) in Vivify.colors.items():
            output = output.replace("{%s}" % key, value)
        print(output)

import os
import pefile

anti_debug_path = 'ida_scripts\\anti_debug.py'


def analysis(file):
    try:
        pefile.PE(file)
        os.system(f'ida -B {file}')
        os.system(f'ida -A -S{anti_debug_path} {file}.idb')
        os.remove(f'{file}.idb')
        os.remove(f'{file}.asm')
    except pefile.PEFormatError:
        print('This is not a PE file!')

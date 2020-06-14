from args import parse_arguments
import ida
import dynamorio
import cuckoo


def analysis(file):
    ida.analysis(file)
    dynamorio.analysis(file)
    cuckoo.analysis(file)


if __name__ == '__main__':
    args = parse_arguments()
    analysis(args.file)

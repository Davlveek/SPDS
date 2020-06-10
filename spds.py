from args import parse_arguments
import ida
import dynamorio


def analysis(file):
    #ida.analysis(file)
    dynamorio.analysis(file)


if __name__ == '__main__':
    args = parse_arguments()
    analysis(args.file)

import argparse


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        'file',
        help='Input file'
    )

    return parser.parse_args()

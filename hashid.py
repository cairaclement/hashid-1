import argparse


def check_args(args):
    if args.hashed_string is None and not args.show_hash_list:
        parser.error("please pass at least one parameter between --help, --list and hashed_string")
    if args.show_hash_list and (args.hashed_string is not None or args.show_john_command or args.show_hashcat_command or args.show_wikipedia_infos):
        parser.error("please don't pass any additional parameter if you pass --list")


parser = argparse.ArgumentParser(description='Tries to guess a hash algorithm based on the result of this algorithm.')
parser.add_argument('hashed_string', type=str, nargs="?",
                    help='a hashed string whose hash algorithm you\'d like to find')
parser.add_argument('--john', dest='show_john_command', action='store_const',
                    const=True, default=False,
                    help='display the command to print you the John The Ripper command to try to break the hash')
parser.add_argument('--hashcat', dest='show_hashcat_command', action='store_const',
                    const=True, default=False,
                    help='display the command to print you the Hashcat command to try to break the hash')
parser.add_argument('--wikipedia', dest='show_wikipedia_infos', action='store_const',
                    const=True, default=False,
                    help='prints a bit of information about the found hash')
parser.add_argument('--list', dest='show_hash_list', action='store_const',
                    const=True, default=False,
                    help='display a list of all the hashes known by hashid')

args = parser.parse_args()
check_args(args)
print(args.hashed_string, args.show_john_command, args.show_hashcat_command, args.show_wikipedia_infos, args.show_hash_list)

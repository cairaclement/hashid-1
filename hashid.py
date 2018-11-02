import argparse
from pathlib import Path


class HashesManager:
    known_hashes = []

    def add_known_hash(self, hash_name, hash_check_func, hash_wikipedia_info, hash_john_format):
        self.known_hashes.append({
            "name": hash_name,
            "check_func": hash_check_func,
            "wikipedia": hash_wikipedia_info,
            "john_format": hash_john_format,
        })

    def get_known_hashes(self):
        return [i["name"] for i in self.known_hashes]

    def get_corresponding_hash(self, hashed_string):
        for known_hash in self.known_hashes:
            if known_hash["check_func"](hashed_string):
                return known_hash
        raise NotImplementedError("Sorry but we didn't mange to guess the hash used for this string.")


def get_prepared_hash_manager():
    hash_manager = HashesManager()

    def is_md5(string):
        return len(string) == 32

    md5_description = """
    L'algorithme MD5, pour Message Digest 5, est une fonction de hachage cryptographique qui permet d'obtenir l'empreinte 
    numérique d'un fichier (on parle souvent de message). Il a été inventé par Ronald Rivest en 1991.

    Si l'algorithme MD5 présente un intérêt historique important il est aujourd'hui considéré comme dépassé et absolument 
    impropre à toute utilisation en cryptographie ou en sécurité
    """
    hash_manager.add_known_hash("MD5", is_md5, md5_description, "md5")

    def is_sha1(string):
        return len(string) == 40

    sha1_description = """
    SHA-1 (Secure Hash Algorithm) est une fonction de hachage cryptographique conçue par la National Security Agency des 
    États-Unis (NSA), et publiée par le gouvernement des États-Unis comme un standard fédéral de traitement de l'information
     (Federal Information Processing Standard du National Institute of Standards and Technology (NIST)). Elle produit un 
     résultat (appelé « hash » ou condensat) de 160 bits.

    SHA-1 n'est plus considéré comme sûr contre des adversaires disposant de moyens importants. En 2005, des cryptanalystes
    ont découvert des attaques sur SHA-1, suggérant que l'algorithme pourrait ne plus être suffisamment sûr pour continuer à
    l'utiliser dans le futur1. Depuis 2010, de nombreuses organisations ont recommandé son remplacement par SHA-2 ou 
    SHA-32,3,4. Microsoft5, Google6 et Mozilla7,8,9 ont annoncé que leurs navigateurs respectifs cesseraient d'accepter les
    certificats SHA-1 au plus tard en 2017. 
    """
    hash_manager.add_known_hash("SHA1", is_sha1, sha1_description, "sha1-gen")
    return hash_manager


def check_args(args):
    if args.hashed_string is None and not args.show_hash_list:
        parser.error("please pass at least one parameter between --help, --list and hashed_string")
    if args.show_hash_list and (args.hashed_string is not None
                                or args.show_john_command
                                or args.show_wikipedia_infos):
        parser.error("please don't pass any additional parameter if you pass --list")


parser = argparse.ArgumentParser(description='Tries to guess a hash algorithm based on the result of this algorithm.')
parser.add_argument('hashed_string', type=str, nargs="?",
                    help='a hashed string whose hash algorithm you\'d like to find')
parser.add_argument('--john', dest='show_john_command', action='store_const',
                    const=True, default=False,
                    help='display the command to print you the John The Ripper command to try to break the hash')
parser.add_argument('--wikipedia', dest='show_wikipedia_infos', action='store_const',
                    const=True, default=False,
                    help='prints a bit of information about the found hash')
parser.add_argument('--list', dest='show_hash_list', action='store_const',
                    const=True, default=False,
                    help='display a list of all the hashes known by hashid')

args = parser.parse_args()
check_args(args)

my_hash_manager = get_prepared_hash_manager()

if args.show_hash_list:
    print("The hashes we know are : ")
    for hash_name in my_hash_manager.get_known_hashes():
        print("    " + hash_name)
else:
    try:
        detected_hash = my_hash_manager.get_corresponding_hash(args.hashed_string)
        hash_name = detected_hash["name"]
        print(hash_name)
        if args.show_wikipedia_infos:
            print("here is a piece of information about " + hash_name + ":")
            print(detected_hash["wikipedia"])
        if args.show_john_command:
            print("execute the following command to try to crack this hash with john the ripper : ")
            hash_file = Path("hash.txt")
            if hash_file.is_file():
                print("    rm hash.txt")
            print("    echo \"" + args.hashed_string + "\" > hash.txt")
            print("    john --format=" + detected_hash["john_format"] + " hash.txt")
    except NotImplementedError:
        print("Sorry, but we couldn't manage to detect the hash function which was used for your input")

import argparse
from pathlib import Path
import re


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

    def is_sha1(string):
        return len(string) == 40

    def is_sha224(string):
        return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)

    def is_adler_32(string):
        return re.compile(r'^[a-f0-9]{8}$', re.IGNORECASE).match(string)

    def is_crc_32(string):
        return re.compile(r'^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$', re.IGNORECASE).match(string)

    def is_md2(string):
        return re.compile(r'^(\$md2\$)?[a-f0-9]{32}$', re.IGNORECASE).match(string)

    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)
    #
    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)
    #
    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)
    #
    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)
    #
    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)
    #
    # def is_sha224(string):
    #     return re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE).match(string)

    md5_description = """
    The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. Although MD5 was 
    initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive
    vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional
    corruption.

    One basic requirement of any cryptographic hash function is that it should be computationally infeasible to find two
    non-identical messages which hash to the same value. MD5 fails this requirement catastrophically; such collisions 
    can be found in seconds on an ordinary home computer.

    The weaknesses of MD5 have been exploited in the field, most infamously by the Flame malware in 2012. The CMU 
    Software Engineering Institute considers MD5 essentially "cryptographically broken and unsuitable for further use".
    """

    sha1_description = """
    In cryptography, SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and produces
     a 160-bit (20-byte) hash value known as a message digest – typically rendered as a hexadecimal number, 40 digits 
     long. It was designed by the United States National Security Agency, and is a U.S. Federal Information Processing 
     Standard.

    Since 2005 SHA-1 has not been considered secure against well-funded opponents, and since 2010 many organizations 
    have recommended its replacement by SHA-2 or SHA-3. Microsoft, Google, Apple and Mozilla have all announced that 
    their respective browsers will stop accepting SHA-1 SSL certificates by 2017.
    
    In 2017 CWI Amsterdam and Google announced they had performed a collision attack against SHA-1, publishing two 
    dissimilar PDF files which produced the same SHA-1 hash.
    """

    sha224_description = """
    sha 224 is only one hash in the HASH2 family.
    
    SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National 
    Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
     built using the Davies–Meyer structure from a (classified) specialized block cipher.

    Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    output from execution of the algorithm) to a known and expected hash value, a person can determine the data's 
    integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published 
    hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash 
    functions is their collision resistance: nobody should be able to find two different input values that result in the
    same hash output.
    
    SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, 
    SHA-512/256. 
    
    SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224 
    and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    """

    adler_32_description = """
        Adler-32 is a checksum algorithm which was invented by Mark Adler in 1995, and is a modification of the Fletcher
        checksum. Compared to a cyclic redundancy check of the same length, it trades reliability for speed (preferring 
        the latter). Adler-32 is more reliable than Fletcher-16, and slightly less reliable than Fletcher-32.
        """

    crc_32_description = """
        A cyclic redundancy check (CRC) is an error-detecting code commonly used in digital networks and storage 
        devices to detect accidental changes to raw data. Blocks of data entering these systems get a short check value
        attached, based on the remainder of a polynomial division of their contents. On retrieval, the calculation is 
        repeated and, in the event the check values do not match, corrective action can be taken against data 
        corruption. CRCs can be used for error correction (see bitfilters).

        CRCs are so called because the check (data verification) value is a redundancy (it expands the message without 
        adding information) and the algorithm is based on cyclic codes. CRCs are popular because they are simple to 
        implement in binary hardware, easy to analyze mathematically, and particularly good at detecting common errors 
        caused by noise in transmission channels. Because the check value has a fixed length, the function that 
        generates it is occasionally used as a hash function.
        
        The CRC was invented by W. Wesley Peterson in 1961; the 32-bit CRC function of Ethernet and many other standards 
        is the work of several researchers and was published in 1975. 
        
        CRC 32 is a subset of CRC hash algorithms
        """

    md2_description = """
        he MD2 Message-Digest Algorithm is a cryptographic hash function developed by Ronald Rivest in 1989. The 
        algorithm is optimized for 8-bit computers. MD2 is specified in RFC 1319. Although MD2 is no longer considered 
        secure, even as of 2014, it remains in use in public key infrastructures as part of certificates generated with 
        MD2 and RSA. The "MD" in MD2 stands for "Message Digest".
        """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    # sha224_description = """
    #     sha 224 is only one hash in the HASH2 family.
    #
    #     SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the United States National
    #     Security Agency (NSA). They are built using the Merkle–Damgård structure, from a one-way compression function itself
    #      built using the Davies–Meyer structure from a (classified) specialized block cipher.
    #
    #     Cryptographic hash functions are mathematical operations run on digital data; by comparing the computed "hash" (the
    #     output from execution of the algorithm) to a known and expected hash value, a person can determine the data's
    #     integrity. For example, computing the hash of a downloaded file and comparing the result to a previously published
    #     hash result can show whether the download has been modified or tampered with. A key aspect of cryptographic hash
    #     functions is their collision resistance: nobody should be able to find two different input values that result in the
    #     same hash output.
    #
    #     SHA-2 includes significant changes from its predecessor, SHA-1. The SHA-2 family consists of six hash functions with
    #     digests (hash values) that are 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224,
    #     SHA-512/256.
    #
    #     SHA-256 and SHA-512, and, to a lesser degree, SHA-224 and SHA-384 are prone to length extension attacks,
    #     rendering it insecure for some applications. It is thus generally recommended to switch to SHA-3 for 512-bit hashes
    #     and to use SHA-512/224 and SHA-512/256 instead of SHA-224 and SHA-256. This also happens to be faster than SHA-224
    #     and SHA-256 on x86-64 processor architecture, since SHA-512 works on 64-bit instead of 32-bit words.
    #     """
    #
    hash_manager.add_known_hash("MD5", is_md5, md5_description, "md5")
    hash_manager.add_known_hash("SHA1", is_sha1, sha1_description, "sha1-gen")
    hash_manager.add_known_hash("SHA224", is_sha224, sha224_description, "raw-sha224")
    hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    hash_manager.add_known_hash("CRC-32", is_crc_32, crc_32_description, 'crc32')
    hash_manager.add_known_hash("MD2", is_md2, md2_description, 'md2')
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
    # hash_manager.add_known_hash("Adler-32", is_adler_32, adler_32_description, None)
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
            if detected_hash["john_format"] is None:
                print("Sorry, no john command found for the hash " + hash_name)
            else:
                print("execute the following command to try to crack this hash with john the ripper : ")
                hash_file = Path("hash.txt")
                if hash_file.is_file():
                    print("    rm hash.txt")
                print("    echo \"" + args.hashed_string + "\" > hash.txt")
                print("    john --format=" + detected_hash["john_format"] + " hash.txt")
    except NotImplementedError:
        print("Sorry, but we couldn't manage to detect the hash function which was used for your input")

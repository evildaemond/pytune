import argparse
from utils import create_pfx

def main():
    description = f"Fix certificate by creating a PFX file from PEM and KEY files."
    parser = argparse.ArgumentParser(add_help=True, description=f'{description}', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-c', '--cert-file', action='store', help='Certificate Filename (.pem format)', required=True)
    parser.add_argument('-k', '--key-file', action='store', help='Private Key Filename (.key format)', required=True)
    parser.add_argument('-o', '--output-file', action='store', help='Output PFX Filename (.pfx format)', required=False)
    args = parser.parse_args()

    certpath = args.cert_file
    keypath = args.key_file

    if not args.output_file:
        pfx_filename = certpath.rsplit('.', 1)[0] + '.pfx'
    else:
        pfx_filename = args.output_file

    create_pfx(certpath, keypath, pfx_filename)
    
    print(f"PFX file created: {pfx_filename}")

if __name__ == "__main__":
    main()


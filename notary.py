import argparse
from notary_client import NotaryClient
import json

notary = None


def login_if_needed(notary, command):
    pass


def main_method(cmd_str=None):
    '''
       main method of notary.
    Parameters
    ----------
    cmd_str  takes the command line input.

    Returns
    -------

    '''
    global notary
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=[ 'register', 'confirm', 'notarize', 'login', 'notarystatus',
                                            'uploadfile', 'downloadfile'],
                        help="Name of the command.")
    parser.add_argument("-password", type=str, help="the password used to access the wallet.")
    parser.add_argument("-email", type=str, help="the email address of the registered user.")
    parser.add_argument("-file", type=str, help="Fully qualified name of the file.")
    parser.add_argument("-metadata", type=str, help="File containing metadata of the file to notarize.")
    parser.add_argument("-confirm_url", type=str, help="Confirmation URL to confirm an account.")
    parser.add_argument("-document_hash", type=str, help="Document hash  of a document")

    if cmd_str is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cmd_str)
    if not args.password:
        print("Password is required!")
        return

    if notary is None:
        notary = NotaryClient("./notaryconfig.ini", args.password)

    command = args.command

    print "Running " + command + " command"

    if command == "register":
        if not args.email:
            print "register command needs email address"
        else:
            print args.email
            result = notary.register_user(args.email)
            print result
            return result
    elif command == "notarize":
        if not args.metadata:
            print "notarize command needs metadata file"
            return

        if not args.file:
            print "notarize command needs file"
            return
        # print args.file
        # print args.metadata
        metadata = json.loads(args.metadata)
        return notary.notarize_file(args.file,
                                    metadata)
    elif command == "uploadfile":

        if not args.file:
            print "upload command needs file"
            return
        # print args.file
        return notary.upload_file(args.file)

    elif command == "downloadfile":

        if not args.document_hash:
            print "download command needs document hash value"
            return
        if not args.file:
            print "download command needs file"
            return
        # print args.file
        return notary.download_file(args.document_hash,args.file)

    elif command == "login":
        return notary.authenticate()
    elif command == "notarystatus":
        if not args.document_hash:
            print "confirm command needs document_hash"
        else:
            print args.document_hash
            status = notary.get_notarization_status(args.document_hash)
            print "The Document status is"
            print status
            return status
    else:
        print "no command"


if __name__ == "__main__":
    main_method()

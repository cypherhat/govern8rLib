import argparse
from notary_client import Notary

notary = Notary("./notaryconfig.ini")


def login_if_needed(notary, command):
    needed = True
    if command == 'register' or command == 'confirm' or command == 'login':
        needed = False
    if needed:
        if not notary.authenticated():
            notary.login()
        if not notary.authenticated():
            print "Not able to login. exiting ..."
            return None
    return 'Done'


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
    parser.add_argument("command", choices=['createwallet', 'register', 'confirm', 'notarize', 'login', 'notarystatus',
                                            'uploadfile','downloadfile'],
                        help="Name of the command.")
    parser.add_argument("-password", type=str, help="the password used to access the wallet.")
    parser.add_argument("-email", type=str, help="the email address of the registered user.")
    parser.add_argument("-file", type=file, help="Fully qualified name of the file.")
    parser.add_argument("-metadata", type=file, help="File containing metadata of the file to notarize.")
    parser.add_argument("-confirm_url", type=str, help="Confirmation URL to confirm an account.")
    parser.add_argument("-transaction_id", type=str, help="Transaction ID of a notary")
    parser.add_argument("-file_hash", type=str, help="The hash  value of the file")

    if cmd_str is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(cmd_str)

    if notary is not None:
        if not args.password:
            print("Password is required!")
            return
        if args.command != "register":
            notary.load_wallet(args.password)
    command = args.command

    print "Running " + command + " command"

    if login_if_needed(notary, command) is None:
        return

    if command == "createwallet":
        if not args.password:
            print "createwallet command needs password"
        else:
            print args.password
            result = notary.create_wallet(args.password)
            print result
            return result

    elif command == "register":
        if not args.email:
            print "register command needs email address"
        else:
            print args.email
            result = notary.register_user(args.email)
            print result
            return result
    elif command == "confirm":
        if not args.confirm_url:
            print "confirm command needs url"
        else:
            print args.confirm_url
            return Notary.confirm_registration(args.confirm_url)
    elif command == "notarize":
        if not args.metadata:
            print "notarize command needs metadata file"
            return

        if not args.file:
            print "notarize command needs file"
            return
        # print args.file
        # print args.metadata
        return notary.notarize_file(args.file, args.metadata)
    elif command == "uploadfile":

        if not args.file:
            print "upload command needs file"
            return
        # print args.file
        return notary.upload_file(args.file)

    elif command == "downloadfile":

        if not args.file_hash:
            print "download command needs file hash value"
            return
        # print args.file
        return notary.download_file(args.file_hash)

    elif command == "login":
        return notary.login()
    elif command == "notarystatus":
        if not args.transaction_id:
            print "confirm command needs transcation_id"
        else:
            print args.transaction_id
            status = notary.notary_status(args.transaction_id)
            print "The Transcation status is"
            print status
            return status
    else:
        print "no command"


if __name__ == "__main__":
    main_method()

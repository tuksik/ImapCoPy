import imaplib
from collections import namedtuple
import shelve
import re
import argparse
import base64

BATCH_SIZE = 100
Message = namedtuple('message', ('date', 'flags', 'source_uid', 'content'))
Folder = namedtuple('folder', ('flags', 'root', 'name'))
FlagChange = namedtuple('flagchange', ('my_uid', 'their_uid', 'new_flags'))

def ok(returned) -> str:
    """
    Quick check that the request to the imap server worked.

    :param returned: the response received by imaplib
    :return: the body of the received message
    :raise RuntimeError: raised if the return code of imaplib is not OK
    """
    return_code, msg = returned
    if not return_code == 'OK':
        raise RuntimeError('error {0}'.format(msg))
    return msg



def extract_uid(byte_string) -> str:
    """
    extract the uid from a message body, convert to string
    :param byte_string: imaplib message body
    :return: uid as string
    """
    # TODO: safer search as this will fail with AttributeError if search fails which is harder to troubleshoot
    return str(re.search(r'UID\s(\d+)', byte_string.decode()).groups()[0])


def extract_flags(byte_string) -> str:
    """
    extract the flags from a message body, convert to string
    :param bytes: imaplib message body
    :return: flags as carried in imap, string
    """
    return str(re.search(r'FLAGS (\(.*?\))', byte_string.decode()).groups()[0])


def extract_internal_date(byte_string) -> str:
    """
    extract the internal date from a message body, convert to string
    :param byte_string: imaplib message body
    :return:  internal date as carried in imap, string
    """
    return str(re.search(r'INTERNALDATE (".*?")', byte_string.decode()).groups()[0])


def extract_seq(byte_string) -> str:
    """
    extract the seq num of an email from a message body, convert to string
    :param byte_string: imaplib message body
    :return:  seq num for email as carried in imap, string
    """
    return str(re.search(r'^(\d+)', byte_string.decode()).groups()[0])


def extract_destination_uid(returned) ->str:
    """the imaplib response to append looks like this '[APPENDUID 1395576563 23] Append completed.'
    we extract the local uid and return it as a string
    :param byte_string: imaplib message body
    :return: appended email uid as a string
    """
    pattern = re.compile(r'\[APPENDUID (?P<appenduid>\d+) (?P<uid>\d+)\]')
    return str(pattern.match(returned.
                             decode()).groupdict()['uid'])


def extract_folders(folders) -> "collections.Iterable[Folder]" :
    """Generator. Yields folder name from folder spec received from imaplib
    folder spec format: '(\\HasNoChildren) "/" "2009"'
    Yields a C{Folder} instance for each folder in the spec.
    """
    for folder in folders:
        print(folder)
        folder_args = re.match(r'\((?P<flags>.*)\)\s"(?P<root>.*)"\s"(?P<name>.*)"', folder.decode('UTF-8')).groupdict()
        print('folder args', folder_args)
        yield Folder(**folder_args)


class SourceMailbox(object):
    """
    Litteraly just the connection to the source mailbox.
    Note that the auth method here is specifically for zimbra's master (admin) users.
    You may need something else.
    """
    def __init__(self, server, user, master, password):
        self.conn = imaplib.IMAP4_SSL(server)
        auth_cb = lambda x: u"{0}\x00{1}\x00{2}".format(user, master, password)
        message = ok(self.conn.authenticate('PLAIN', auth_cb))
        print('connected : {0}'.format(message))
        self.folders = list(extract_folders(ok(self.conn.list())))


def strigify(foldername) -> str:
    """
    create a key to be used with a shelf for this folder name.
    :param foldername: string
    :return: a base64 encoded string
    """
    return base64.b64encode(bytes(foldername, 'UTF-8')).decode()


class DestinationMailbox(object):
    """
    the destination mailbox.
    The login username format is dovecot specific.
    TODO: make the login format configurable.
    """
    def __init__(self, server, from_user, to_user, master, password):
        self.conn = imaplib.IMAP4_SSL(server)
        self.to_user = to_user
        message = ok(self.conn.login('{0}*{1}'.format(to_user, master), password))
        print('connected : {0}'.format(message))
        self.folders = list(extract_folders(ok(self.conn.list())))
        self.shelf_file = '{0}_{1}.shelf'.format(from_user, to_user)
        self.known = shelve.open(self.shelf_file, flag='c', writeback=True, )
        for folder in self.folders:
            if strigify(folder.name) not in self.known:
                self.known[strigify(folder.name)] = {}
                # format of self.known : {mailbox:{remote_uid:(local_uid, flags)}}

    def create(self, folder) -> None:
        """
            creates a folder in the destination mailbox, replacing . with _ as . is hierarchy separator in my dovecot
            instance.
        """
        print(u'user {0}, creating folder "{1}"'.format(self.to_user, folder.replace('.', '_')))
        ok(self.conn.create(u'"{0}"'.format(folder.replace('.', '_')).encode('UTF-8')))
        self.known[strigify(folder)] = {}

    def has_msgs(self, folder, msgs) -> bool:
        """
        check whether all the messages' uid are on the shelf for this folder name and list of messages
        :param folder: name of folder to check
        :param msgs: iterable of messages to check
        :return: whether all the messages' uid are on the shelf
        """
        return all(msg.source_uid in self.known.get(strigify(folder.name), {}) for msg in msgs)

    def changed_flags(self, folder, msgs)-> "list of [FlagChange]":
        """
        compares the known local flags with the remote and returns a list of flags that have changed.
         Requires that the folders are synchronised.
        :rtype : list of [FlagChange]
        :param folder: folder name
        :param msgs: messages to check flags for
        :return: list of [FlagChange]
        :raise RuntimeError: if folders don't contain the exact same message set
        """
        self.conn.select('"{0}"'.format(folder.name))
        if not self.has_msgs(folder, msgs):
            raise RuntimeError('I dont have all messages')
        msg_per_uid = {i.source_uid: i for i in msgs}
        my_uids = {i[0]: k for i, k in [(self.known[strigify(folder.name)][j], j) for j in msg_per_uid]}
        # if my_uids:
        #     my_flags = {extract_uid(i): extract_flags(i) for i in
        #                 ok(self.conn.uid('fetch', ','.join(my_uids), 'FLAGS'))}
        # else:
        #     my_flags = {}

        changed = [FlagChange(my_uid=uid,
                              their_uid=my_uids[uid],
                              new_flags=msg_per_uid[my_uids[uid]].flags)
                   for uid in my_uids]
        return changed

    def add_msg(self, folder, msg) -> None:
        """
        add a message to a folder, save the info to the shelf
        :param folder: folder to append the msessage to
        :param msg: message to append
        :return: None
        """
        my_uid = extract_destination_uid(ok(self.conn.append('"{}"'.format(folder.name),
                                                     msg.flags, msg.date, msg.content))[0])
        self.known.setdefault(strigify(folder.name), {})[msg.source_uid] = (my_uid, msg.flags)
        self.known.sync()

    def update_flags(self, flag_change) -> None:
        """
        :param flag_change: FlagChange instance
        :return: None
        """
        return ok(self.conn.uid('store', flag_change.my_uid, 'FLAGS', flag_change.new_flags))


    def download_missing(self, source, folder) -> "(list of [Message], list of [Message])":
        """
        Download missing messages and add them to the destination mailbox
        :param source: source mailbox instance
        :param folder: folder to update
        :return: the list of all messages in both source and destination mailboxes for this folder
        """
        mine = list(all_metadata(self, folder))
        theirs = list(all_metadata(source, folder))
        new_in_theirs = [r
                         for r in [m.source_uid for m in theirs]
                         if r not in list(self.known[strigify(folder.name)].keys())
        ]
        if new_in_theirs:
            index = 0
            source.conn.select('"{0}"'.format(folder.name))

            while index + BATCH_SIZE <= len(new_in_theirs):
                print('adding {0} messages'.format(BATCH_SIZE))
                for msg in get_messages(new_in_theirs[index:index + BATCH_SIZE + 1], source.conn):
                    self.add_msg(folder, msg)
                index += BATCH_SIZE
            for msg in get_messages(new_in_theirs[index:], source.conn):
                self.add_msg(folder, msg)
        else:
            print('No message to copy over')
        return theirs, mine

    def move_deleted_messages(self, theirs, mine, folder) -> None:
        """
        detect and clean up deleted messages.
        instead of deleting messages that have disappeared from the source mailbox we copy them to a deleted_from_source
        folder instead.

        :param theirs: list of their known messages for this folder
        :param mine: list of my known messages for this folder
        :param folder: folder name to run on
        :return: None
        """
        their_uids = [i.source_uid for i in theirs]
        my_uids = [i.source_uid for i in mine]
        to_move = []
        for remote_uid, (local_uid, flags) in self.known[strigify(folder.name)].items():
            if local_uid in my_uids and remote_uid not in their_uids:
                to_move.append(local_uid)
        if to_move:
            index = 0
            while index + BATCH_SIZE <= len(to_move):
                spec = ','.join(to_move[index:index + BATCH_SIZE + 1])
                ok(self.conn.uid('copy', spec, 'deleted_from_source'))
                index += BATCH_SIZE
            spec = ','.join(to_move[index:])
            ok(self.conn.uid('copy', spec, 'deleted_from_source'))
            ok(self.conn.uid('store', spec, '+FLAGS', '\\Deleted'))


def sync_folders(source, destination) -> None:
    """
    create all the folders in the destination to match the source's
    :param source: source mailbox
    :param destination: destination mailbox
    :return: None
    """
    destination_folders = []
    destination_folders.extend([i.name for i in destination.folders])
    print(destination_folders)
    if u'deleted_from_source' not in destination_folders:
        destination.create(u'deleted_from_source')
    for folder in source.folders:
        if folder.name.replace('.', '_') not in destination_folders:
            print('creating folder {0}'.format(folder.name))
            destination.create(folder.name)
        else:
            print('Skipping {0}'.format(folder.name))


def all_metadata(source, folder) -> None:
    """
    retrieve the metadata (flags, date, uid) for all messages in folder, but no message content.
    Generator.
    :param source: source mailbox
    :param folder: folder name
    :return: None
    """
    num_msg = int(ok(source.conn.select('"{0}"'.format(folder.name)))[0])
    if num_msg != 0:
        index = 1
        while index + BATCH_SIZE <= num_msg:
            res = ok(source.conn.fetch(','.join(map(str, range(index, index + BATCH_SIZE + 1))),
                                       '(INTERNALDATE FLAGS UID)')
            )
            for line in res:
                yield Message(extract_internal_date(line), extract_flags(line), extract_uid(line), None)
            index += BATCH_SIZE
        res = ok(source.conn.fetch(','.join(map(str, range(index, num_msg + 1))),
                                   '(INTERNALDATE FLAGS UID)')
        )
        for line in res:
            yield Message(extract_internal_date(line), extract_flags(line), extract_uid(line), None)


def sync_content(source, destination, folder) -> None:
    """
    sync the content of a folder
    :param source: source mailbox
    :param destination: destination mailbox
    :param folder: folder name to sync
    :return: None
    """
    if not folder in destination.folders:
        raise RuntimeError('{0} not there'.format(folder.name))
    source.conn.select('"{0}"'.format(folder.name))
    destination.conn.select(folder.name)
    theirs, mine = destination.download_missing(source, folder)
    flags = destination.changed_flags(folder, theirs)
    for flag_change in flags:
        ok(destination.conn.uid('store', flag_change.my_uid, 'FLAGS', flag_change.new_flags))
    destination.move_deleted_messages(theirs, mine, folder)
    destination.conn.expunge()

def sync(source, destination) -> None:
    """
    sync source and destination mailbox
    :param source: mailbox to read from
    :param destination: mailbox to send msg to
    :return: None
    """
    sync_folders(source, destination)
    destination.folders = list(extract_folders(ok(destination.conn.list())))
    for folder in destination.folders:
        if folder.name not in [i.name for i in source.folders]:
            print('not processing {0} because not in source'.format(folder.name))
            continue
        if folder.name in ('"Contacts"', '"Emailed Contacts"'):
            # zimbra specific
            print('Not processing contacts folder')
            continue
        print('Processing folder', folder.name)
        try:
            sync_content(source, destination, folder)
        except imaplib.IMAP4_SSL.readonly:
            print('Skipping read-only folder {0}'.format(folder.name))


def extract_data(rfc822_answ) -> "(str, bytes)":
    """
    :param rfc822_answ: rfc822 query answer (actual email message)
    :return: (str, bytes)
    """
    meta = rfc822_answ[0]
    try:
        data = rfc822_answ[1]
    except IndexError:
        print("got data, ", rfc822_answ)
        raise
    pattern = re.compile(r"^(?P<num>\d+) \(RFC822 \{(?P<size>\d+)\}$")
    meta = pattern.match(meta.decode()).groupdict()
    assert (int(meta['size']) == len(data))
    return meta['num'], data



def get_messages(uids, connection) -> "collections.Enumerable [Message]":
    """
    retrieve the content of messages with given uids
    :param uids: list of uids to retrieve
    :param connection: imap connection to retrieve the message from
    :return: generator of Messages
    """
    message_spec = ','.join(map(str, uids))
    res = ok(connection.uid('fetch', message_spec, '(INTERNALDATE FLAGS UID)'))
    messages = {extract_seq(line): Message(date=extract_internal_date(line),
                                           source_uid=extract_uid(line),
                                           content=None,
                                           flags=extract_flags(line))
                for line in res
    }
    local_spec = ','.join(messages.keys())
    data = dict(extract_data(i) for i in ok(connection.fetch(local_spec, 'RFC822')) if len(i) == 2)
    for seq in data:
        yield (Message(date=messages[seq].date,
                       flags=messages[seq].flags,
                       source_uid=messages[seq].source_uid,
                       content=data[seq])
        )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('source_user')
    p.add_argument('source_master_user')
    p.add_argument('source_master_password')
    p.add_argument('source_server')
    p.add_argument('destination_user')
    p.add_argument('destination_master_user')
    p.add_argument('destination_master_password')
    p.add_argument('destination_server')
    options = p.parse_args()
    source = SourceMailbox(options.source_server,
                           options.source_user,
                           options.source_master_user,
                           options.source_master_password)
    destination = DestinationMailbox(server=options.destination_server,
                                     to_user=options.destination_user,
                                     from_user=options.source_user,
                                     master=options.destination_master_user,
                                     password=options.destination_master_password)
    sync(source, destination)


if __name__ == '__main__':
    main()



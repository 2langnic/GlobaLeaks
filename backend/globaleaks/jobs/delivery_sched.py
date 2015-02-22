# -*- coding: UTF-8
#
#   delivery_sched
#   **************
#
# Implements the delivery operations performed when a new submission
# is created, or a new file is append to an existing Tip. delivery
# works on the file and on the fields, not in the comments.
#
# Call also the FileProcess working point, in order to verify which
# kind of file has been submitted.
import os
import sys

from twisted.internet.defer import inlineCallbacks

from globaleaks.jobs.base import GLJob
from globaleaks.models import InternalFile, InternalTip, ReceiverTip, \
                              ReceiverFile
from globaleaks.settings import transact, transact_ro, GLSetting
from globaleaks.utils.utility import log , datetime_now
from globaleaks.security import GLBGPG, GLSecureFile
from globaleaks.handlers.admin import admin_serialize_receiver
from globaleaks import security
from pickle import dumps

__all__ = ['DeliverySchedule']

def serialize_internalfile(ifile):
    ifile_dict = {
        'id': ifile.id,
        'internaltip_id' : ifile.internaltip_id,
        'name' : ifile.name,
        'description' : ifile.description,
        'file_path' : ifile.file_path,
        'content_type' : ifile.content_type,
        'size' : ifile.size,
        'mark' : ifile.mark,
    }
    return ifile_dict

@transact_ro
def get_files_by_itip(store, itip_id):
    try:
        ifiles = store.find(InternalFile, InternalFile.internaltip_id == unicode(itip_id))
    except Exception as excep:
        log.err("Unable to retrive InternalFile(s) from InternalTip! %s" % excep)
        return []

    ifile_list = []
    for ifil in ifiles:
        ifile_list.append(serialize_internalfile(ifil))

    return ifile_list


def serialize_receiverfile(rfile):
    rfile_dict = {
        'id' : rfile.id,
        'internaltip_id' : rfile.internaltip_id,
        'internalfile_id' : rfile.internalfile_id,
        'receiver_id' : rfile.receiver_id,
        'receiver_tip_id' : rfile.receiver_tip_id,
        'file_path' : rfile.file_path,
        'size' : rfile.size,
        'downloads' : rfile.downloads,
        'last_access' : rfile.last_access,
        'mark' : rfile.mark,
        'status' : rfile.status,
    }
    return rfile_dict

@transact_ro
def get_receiverfile_by_itip(store, itip_id):
    try:
        rfiles = store.find(ReceiverFile, ReceiverFile.internaltip_id == unicode(itip_id))
    except Exception as excep:
        log.err("Unable to retrive ReceiverFile(s) from InternalTip! %s" % excep)
        return []

    rfile_list = []
    for rfil in rfiles:
        rfile_list.append(serialize_receiverfile(rfil))

    return rfile_list


def is_internalfile_associated_with_internaltip(filex):
    if not filex.internaltip:
        log.err("Integrity failure: the file %s"
            "has not an InternalTip assigned (path: %s)" % 
            (filex.name, filex.file_path))
        try:
            os.remove(os.path.join(GLSetting.submission_path, filex.file_path))
        except OSError as excep:
            log.err("Unable to remove %s in integrity fixing routine: %s" % (filex.file_path, excep.strerror))
        key_id = os.path.basename(filex.file_path).split('.')[0]
        keypath = os.path.join(GLSetting.ramdisk_path, ("%s%s" % (GLSetting.AES_keyfile_prefix, key_id)))
        try:
            os.remove(keypath)
        except OSError as excep:
            log.err("Unable to delete keyfile %s: %s" % (keypath, excep.strerror))
        return False
    return True

@transact
def receiverfile_planning(store):
    """
    This function roll over the InternalFile uploaded, extract a path, id and
    receivers associated, one entry for each combination. representing the
    ReceiverFile that need to be created.
    """

    try:
        files = store.find(InternalFile, InternalFile.mark == u'not processed')
    except Exception as excep:
        log.err("Unable to find InternalFile in scheduler! %s" % str(excep))
        return []

    ifilesmap = {}

    for filex in files:
        if not is_internalfile_associated_with_internaltip(filex):
            continue

        # here we select the file which deserve to be processed.
        # They need to be:
        #   From a Tip in (Tip = 'finalize' or 'first' )
        #   From an InternalFile (File = 'ready')
        # Tips may have two statuses both valid.
        # if these conditions are met the InternalFile(s) is/are marked as 'locked',
        # Whenever a delivery scheduler run, do not touch 'locked' file, and if 'locked' file
        # appears in the Admin interface of file overview, this mean that something is broken.
        if (filex.internaltip.mark == u'finalize' or \
            filex.internaltip.mark == u'first') and \
            (filex.mark == u'not processed'):
            filex.mark = u'locked'
        else:
            continue

        try:

            for receiver in filex.internaltip.receivers:

                if not ifilesmap.has_key(filex.file_path):
                    ifilesmap[filex.file_path] = list()

                receiver_desc = admin_serialize_receiver(receiver, GLSetting.memory_copy.default_language)

                receiverFileInfo = {
                    'receiver' : receiver_desc,
                    'path' : filex.file_path,
                    'size' : int(security.decrypt_with_ServerKey(filex.size_nonce, filex.size)),
                    'status' : u'reference'
                }

                # this may seem apparently redounded, but is not!
                # AS KEY, file path is used to keep track of the original
                # path, because shall be renamed in .plaintext (in the unlucky case
                # of receivers without PGP)
                # AS FIELD, it can be replaced with a dedicated PGP encrypted path
                ifilesmap[filex.file_path].append(receiverFileInfo)

        except Exception as excep:
            log.debug("Invalid Storm operation in checking for PGP cap: %s" % excep)
            continue

    return ifilesmap


def fsops_gpg_encrypt(fpath, recipient_gpg):
    """
    return
        path of encrypted file,
        length of the encrypted file

    this function is used to encrypt a file for a specific recipient.
    commonly 'receiver_desc' is expected as second argument;
    anyhow a simpler dict can be used.

    required keys are checked on top

    """
    assert isinstance(recipient_gpg, dict), "invalid recipient"
    assert recipient_gpg.has_key('gpg_key_armor'), "missing key"
    assert recipient_gpg.has_key('gpg_key_status'), "missing status"
    assert recipient_gpg['gpg_key_status'] == u'Enabled', "GPG not enabled"
    assert recipient_gpg.has_key('name'), "missing recipient Name"

    gpoj = GLBGPG(recipient_gpg)

    if not gpoj.validate_key(recipient_gpg['gpg_key_armor']):
        raise Exception("Unable to validate key")

    filepath = os.path.join(GLSetting.submission_path, fpath)
    # The filepath defines the aes encrypted file and its symmetric key when given to GLSecureFile
    with GLSecureFile(filepath) as f:
        encrypted_file_path, encrypted_file_size = \
            gpoj.encrypt_file(filepath, f, GLSetting.submission_path)

    gpoj.destroy_environment()

    assert (encrypted_file_size > 1), "File generated is empty or size is 0"
    assert os.path.isfile(encrypted_file_path), "Output generated is not a file!"

    return encrypted_file_path, encrypted_file_size

@transact
def receiverfile_create(store, if_path, recv_path, status, recv_size, receiver_desc):

    assert type(1) == type(recv_size)
    assert isinstance(receiver_desc, dict)
    assert os.path.isfile(os.path.join(GLSetting.submission_path, if_path))

    try:
        ifile = store.find(InternalFile, InternalFile.file_path == unicode(if_path)).one()

        if not ifile:
            log.err("InternalFile with path %s not found !?" % if_path)
            raise Exception("This is bad!")

        log.debug("ReceiverFile creation for user %s, '%s' bytes %d = %s)"
                % (receiver_desc['name'], ifile.name, recv_size, status ) )

        receiverfile = ReceiverFile()
        receiverfile.creation_date_nonce = security.get_b64_encoded_nonce()
        receiverfile.creation_date = security.encrypt_binary_with_ServerKey(receiverfile.creation_date_nonce,dumps(datetime_now()))
    
        receiverfile.downloads = 0
        receiverfile.receiver_id = receiver_desc['id']
        receiverfile.internalfile_id = ifile.id
        receiverfile.internaltip_id = ifile.internaltip_id

        # Receiver Tip reference
        rtrf = store.find(ReceiverTip, ReceiverTip.internaltip_id == ifile.internaltip_id,
                          ReceiverTip.receiver_id == receiver_desc['id']).one()
        receiverfile.receiver_tip_id = rtrf.id

        # inherited by previous operation and checks
        receiverfile.file_path = unicode(recv_path)
        receiverfile.size = ifile.size
        receiverfile.status = unicode(status)

        receiverfile.mark = u'not notified'

        store.add(receiverfile)

        return serialize_receiverfile(receiverfile)

    except Exception as excep:
        log.err("Error when saving ReceiverFile %s for '%s': %s" % (
                if_path, receiver_desc['name'], excep.message))
        return []


# called in a transact!
def create_receivertip(store, receiver, internaltip):
    """
    Create ReceiverTip for the required tier of Receiver.
    """
    log.debug('Creating ReceiverTip for: %s' % receiver.name)

    receivertip = ReceiverTip()
    receivertip.creation_date_nonce = security.get_b64_encoded_nonce()
    receivertip.creation_date = security.encrypt_binary_with_ServerKey(receivertip.creation_date_nonce,dumps(datetime_now()))
    
    receivertip.last_access_nonce = security.get_b64_encoded_nonce()
    receivertip.last_access = security.encrypt_binary_with_ServerKey(receivertip.last_access_nonce,dumps(datetime_now()))
    
    
    receivertip.internaltip_id = internaltip.id
    receivertip.access_counter = 0
    receivertip.receiver_id = receiver.id
    receivertip.mark = u'not notified'

    store.add(receivertip)

    return receivertip.id


@transact
def tip_creation(store):
    """
    look for all the finalized InternalTip, create ReceiverTip for the
    first tier of Receiver, and shift the marker in 'first' aka di,ostron.zo
    """
    created_rtip = []

    finalized = store.find(InternalTip, InternalTip.mark == u'finalize')

    for internaltip in finalized:

        for receiver in internaltip.receivers:
            rtip_id = create_receivertip(store, receiver, internaltip)

            created_rtip.append(rtip_id)

        internaltip.mark = u'first'

    if len(created_rtip):
        log.debug("The finalized submissions had created %d ReceiverTip(s)" % len(created_rtip))

    return created_rtip

@transact
def do_final_internalfile_update(store, file_path, new_marker, new_path=None):

    try:
        ifile = store.find(InternalFile,
                           InternalFile.file_path == unicode(file_path)).one()
    except Exception as stormer:
        log.err("Error in find %s: %s" % (file_path, stormer.message))
        return

    if not ifile:
        log.err("Unable to find %s" % file_path)
        return

    try:
        old_marker = ifile.mark
        ifile.mark = new_marker

        if new_path:
            ifile.file_path = new_path

        log.debug("Switched status set for InternalFile %s (%s => %s)" %(
            ifile.name, old_marker, new_marker
        ))

    except Exception as excep:
        log.err("Unable to switch mode in InternalFile %s: %s" % (ifile.name, excep) )
        if new_path:
            log.err("+ filename switch fail: %s => %s" % (ifile.file_path, new_path))


def encrypt_where_available(receivermap):

    """
    This function returns true when all files have been encrypted with pgp
    and false if one has not an encryption enabled and it is allowed to store files unencrypted and so 
    a plaintext version has to be created
    @param receivermap:
        [ { 'receiver' : receiver_desc, 'path' : file_path, 'size' : file_size }, .. ]
    @return: return false if plaintext version of file must be created.
    """

    retcode = True

    for rcounter, rfileinfo in enumerate(receivermap):

        if rfileinfo['receiver']['gpg_key_status'] == u'Enabled':

            try:
                new_path, new_size = fsops_gpg_encrypt(rfileinfo['path'], rfileinfo['receiver'])

                log.debug("%d# Switch on Receiver File for %s path %s => %s size %d => %d" % (
                    rcounter,  rfileinfo['receiver']['name'],
                    rfileinfo['path'], new_path, rfileinfo['size'], new_size )
                )

                # _status_list = [ u'reference', u'encrypted', u'unavailable' ]

                rfileinfo['path'] = new_path
                rfileinfo['size'] = new_size
                rfileinfo['status'] = u'encrypted'

            except Exception as excep:
                log.err("%d# Unable to complete GPG encrypt for %s on %s: %s. marking the file as unavailable." % (
                        rcounter, rfileinfo['receiver']['name'], rfileinfo['path'], excep)
                )
                rfileinfo['status'] = u'unavailable'
        elif GLSetting.memory_copy.allow_unencrypted:
            rfileinfo['status'] = u'reference'
            retcode = False
        else:
            rfileinfo['status'] = u'nokey'

    return retcode


def create_receiver_file(store,receiver_id,InternalFile_id):
    
    receiverfile = ReceiverFile()
    receiverfile.creation_date_nonce = security.get_b64_encoded_nonce()
    receiverfile.creation_date = security.encrypt_binary_with_ServerKey(receiverfile.creation_date_nonce,dumps(datetime_now()))
    internalFile = store.find(InternalFile,InternalFile.id ==InternalFile_id).one()
    
    
    receiverfile.downloads = 0
    receiverfile.receiver_id = receiver_id
    receiverfile.internalfile_id = internalFile.id
    receiverfile.internaltip_id = internalFile.internaltip_id
    receiverfile.file_encryption_nonce = internalFile.file_encryption_nonce

    # Receiver Tip reference
    rtrf = store.find(ReceiverTip, ReceiverTip.internaltip_id == internalFile.internaltip_id,
                      ReceiverTip.receiver_id == receiver_id).one()
    receiverfile.receiver_tip_id = rtrf.id

    # inherited by previous operation and checks
    receiverfile.file_path = internalFile.file_path
    receiverfile.size = internalFile.size
    receiverfile.status = unicode(u'encrypted')

    receiverfile.mark = u'not notified'
    store.add(receiverfile)

@transact
def create_receiver_files_and_reference_to_receiverTip(store):
    #Find all internal files which have not been processed up till now
    files = store.find(InternalFile, InternalFile.mark == u'not processed')
    
    for filex in files:
        # If the file is not associated it is deleted and the next file is checked
        if not is_internalfile_associated_with_internaltip(filex):
            # if the file is not associated to any tip it should be
            # removed to avoid infinite loop
            store.remove(filex)
            continue
        
        for receiver in filex.internaltip.receivers:
            create_receiver_file(store, receiver.id,filex.id)
            filex.mark = u'ready'
            
     
     

class DeliverySchedule(GLJob):

    @inlineCallbacks
    def operation(self):
        """
        Goal of this function is to process/validate files, compute their checksums and
        apply the configured delivery method.
        """
        try:
            # ==> Submission && Escalation
            # Here the receiverTips from the Internaltips are created
            info_created_tips = yield tip_creation()
            if info_created_tips:
                log.debug("Delivery job: created %d tips" % len(info_created_tips))
        except Exception as excep:
            log.err("Exception in asyncronous delivery job: %s" % excep )
            sys.excepthook(*sys.exc_info())
        
        # Creation of the receiverfiles and referencing them to the receivertip
        yield create_receiver_files_and_reference_to_receiverTip()
        
        
        """
        # ==> Files && Files update,
        #     InternalFile is set as 'locked' status
        #     and would be unlocked at the end.
        # TODO xxx limit of file number per operation
        filemap = yield receiverfile_planning()
        # the function returns a dict of lists with dicts:
        # {
        #     'ifile_path' : [
        #       { 'receiver' : receiver_desc, 'path': file_path,
        #                           'size' : file_size, 'status': XXX },
        #       { 'receiver' : receiver_desc, 'path': file_path,
        #                           'size' : file_size, 'status': YYY }, ... ]
        # },  { }, ...
        #

        if not filemap:
            return

        # Here the files received are encrypted (if the receiver has PGP key)
        log.debug("Delivery task: Iterate over %d ReceiverFile(s)" % len(filemap.keys()) )

        for ifile_path, receivermap in filemap.iteritems():

            plain_path = os.path.join(GLSetting.submission_path, "%s.plain" % xeger(r'[A-Za-z0-9]{16}') )

            # This function returns true when all files have been encrypted with pgp
            # and false if one has not an encryption enabled and it is allowed to store files unencrypted
            create_plaintextfile = encrypt_where_available(receivermap)

            for receiverFileInfo in receivermap:

                if not create_plaintextfile and receiverFileInfo['status'] == u'reference':
                    receiverFileInfo['path'] = plain_path

                try:
                    yield receiverfile_create(ifile_path, receiverFileInfo['path'], receiverFileInfo['status'],
                                              receiverFileInfo['size'], receiverFileInfo['receiver'])
                except Exception as excep:
                    log.err("Unable to create ReceiverFile from %s for %s: %s" %
                            (ifile_path, receiverFileInfo['receiver']['name'], excep))
                    continue

            if not create_plaintextfile:
                log.debug(":( NOT all receivers support PGP and the system allows plaintext version of files: %s saved in plaintext file %s" %
                          (ifile_path, plain_path)
                )

                try:
                    with open(plain_path, "wb") as plain_f_is_sad_f, \
                         GLSecureFile(ifile_path) as encrypted_file:

                        chunk_size = 4096
                        while True:
                            chunk = encrypted_file.read(chunk_size)
                            if len(chunk) == 0:
                                break
                            plain_f_is_sad_f.write(chunk)

                    yield do_final_internalfile_update(ifile_path, u'ready', plain_path)

                except Exception as excep:
                    log.err("Unable to create plaintext file %s: %s" % (plain_path, excep))

            else: # create_plaintextfile
                log.debug("All Receivers support PGP or the system denys plaintext version of files: marking internalfile as removed")
                yield do_final_internalfile_update(ifile_path, u'delivered') # Removed

            # the original AES file need always to be deleted
            log.debug("Deleting the submission AES encrypted file: %s" % ifile_path)
            try:
                os.remove(ifile_path)
            except OSError as ose:
                log.err("Unable to remove %s: %s" % (ifile_path, ose.message))

            try:
                key_id = os.path.basename(ifile_path).split('.')[0]
                keypath = os.path.join(GLSetting.ramdisk_path, ("%s%s" % (GLSetting.AES_keyfile_prefix, key_id)))
                os.remove(keypath)
            except Exception as excep:
                log.err("Unable to remove keyfile associated with %s: %s" % (ifile_path, excep))

            # here closes the if/else 'are_all_encrypted'
        # here closes the loop over internalfile mapping
    # here closes operations()
    """


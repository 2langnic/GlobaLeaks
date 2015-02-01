# -*- coding: utf-8 -*-
#
#  files
#  *****
#
# Backend supports for jQuery File Uploader, and implementation of the
# classes executed when an HTTP client contact /files/* URI

from __future__ import with_statement
import os
import time

import shutil

from twisted.internet import threads
from twisted.internet.defer import inlineCallbacks

from globaleaks.settings import transact, transact_ro, GLSetting
from globaleaks.handlers.base import BaseHandler
from globaleaks.handlers.authentication import transport_security_check, authenticated, unauthenticated
from globaleaks.utils.utility import log, datetime_to_ISO8601, datetime_now
from globaleaks.rest import errors
from globaleaks.models import ReceiverFile, InternalTip, InternalFile, WhistleblowerTip
from globaleaks.security import access_tip
from base64 import b64encode, b64decode

from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.base import Cipher
from globaleaks import security

from pickle import dumps,loads


def serialize_file(internalfile):

    file_desc = {
        'size': security.decrypt_with_ServerKey(internalfile.size_nonce,internalfile.size),
        'content_type' : security.decrypt_with_ServerKey(internalfile.content_type_nonce,internalfile.content_type),
        'name' : security.decrypt_with_ServerKey(internalfile.name_nonce, internalfile.name),
        'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internalfile.creation_date_nonce, internalfile.creation_date))),
        'id' : internalfile.id,
        'mark' : internalfile.mark,
    }

    return file_desc

def serialize_receiver_file(receiverfile):

    internalfile = receiverfile.internalfile
    
    file_desc = {
        'size': security.decrypt_with_ServerKey(internalfile.size_nonce,internalfile.size),
        'content_type' : security.decrypt_with_ServerKey(internalfile.content_type_nonce,internalfile.content_type),
        # Also here renaming
        #'name' : ("%s.pgp" % internalfile.name) if receiverfile.status == u'encrypted' else internalfile.name,
        'name' : security.decrypt_with_ServerKey(internalfile.name_nonce, internalfile.name),
        'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internalfile.creation_date_nonce, internalfile.creation_date))),
        'downloads' : receiverfile.downloads,
        'path' : receiverfile.file_path,
        'nonce':receiverfile.file_encryption_nonce,
    }

    return file_desc

@transact
def register_file_db(store, uploaded_file, filepath, internaltip_id):
    internaltip = store.find(InternalTip,
                             InternalTip.id == internaltip_id).one()

    if not internaltip:
        log.err("File submission register in a submission that's no more")
        raise errors.TipIdNotFound

    new_file = InternalFile()
    new_file.description = ""
    new_file.mark = InternalFile._marker[0] # 'not processed'
    # Encryption name
    new_file.name_nonce = security.get_b64_encoded_nonce()
    new_file.name = security.encrypt_with_ServerKey(new_file.name_nonce,uploaded_file['filename'])
    
    #Encryption contentType
    new_file.content_type_nonce = security.get_b64_encoded_nonce()
    new_file.content_type = security.encrypt_with_ServerKey(new_file.content_type_nonce,uploaded_file['content_type'])
    
    #Encryption size
    new_file.size_nonce = security.get_b64_encoded_nonce()
    new_file.size = security.encrypt_with_ServerKey(new_file.size_nonce,str(uploaded_file['body_len']))
    # Encryption date
    new_file.creation_date_nonce = security.get_b64_encoded_nonce()
    
    new_file.creation_date = security.encrypt_with_ServerKey(new_file.creation_date_nonce,dumps(datetime_now()))
    
    new_file.internaltip_id = internaltip_id
    new_file.file_path = filepath
    #Once again is has to be saved as base64 due to error
    #Unable to register file in DB: 'ascii' codec can't decode byte 0xb0 in position 0: ordinal not in range(128)
    new_file.file_encryption_nonce = b64encode(uploaded_file['nonce'])

    store.add(new_file)

    log.debug("=> Recorded new InternalFile %s" % uploaded_file['filename'])

    return serialize_file(new_file)


def dump_file_fs(uploaded_file):
    """
    @param files: a file
    @return: a filepath linking the filename with the random
             filename saved in the disk
    """

    encrypted_destination = os.path.join(GLSetting.submission_path,
                                         os.path.basename(uploaded_file['body_filepath']))

    log.debug("Moving encrypted bytes %d from file [%s] %s => %s" %
              (uploaded_file['body_len'],
               uploaded_file['filename'],
               uploaded_file['body_filepath'],
               encrypted_destination)
    )

    shutil.move(uploaded_file['body_filepath'], encrypted_destination)
    return encrypted_destination


@transact_ro
def validate_itip_id(store, itip_id):

    itip = store.find(InternalTip,
                      InternalTip.id == itip_id).one()

    if not itip:
        raise errors.SubmissionIdNotFound

    if itip.mark != InternalTip._marker[0]:
        log.err("Denied access on a concluded submission")
        raise errors.SubmissionConcluded

    return True

@transact_ro
def get_itip_id_by_wbtip_id(store, wb_tip_id):

    wb_tip = store.find(WhistleblowerTip,
                        WhistleblowerTip.id == wb_tip_id).one()

    if not wb_tip:
        raise errors.InvalidTipAuthToken

    return wb_tip.internaltip.id


class FileHandler(BaseHandler):

    @inlineCallbacks
    def handle_file_upload(self, itip_id):
        result_list = []

        # measure the operation of all the files (via browser can be selected
        # more than 1), because all files are delivered in the same time.
        start_time = time.time()

        uploaded_file = self.request.body

        uploaded_file['body'].avoid_delete()
        uploaded_file['body'].close()

        try:
            # First: dump the file in the filesystem,
            # and exception raised here would prevent the InternalFile recordings
            filepath = yield threads.deferToThread(dump_file_fs, uploaded_file)
        except Exception as excep:
            log.err("Unable to save a file in filesystem: %s" % excep)
            raise errors.InternalServerError("Unable to accept new files")
        try:
            # Second: register the file in the database
            registered_file = yield register_file_db(uploaded_file, filepath, itip_id)
        except Exception as excep:
            log.err("Unable to register file in DB: %s" % excep)
            raise errors.InternalServerError("Unable to accept new files")

        registered_file['elapsed_time'] = time.time() - start_time
        result_list.append(registered_file)

        self.set_status(201) # Created
        self.write({'files': result_list})


# This is different from FileInstance, just because there are a different authentication requirements
class FileAdd(FileHandler):
    """
    WhistleBlower interface for upload a new file in an already completed submission
    """

    @transport_security_check('wb')
    @authenticated('wb')
    @inlineCallbacks
    def post(self, *args):
        """
        Request: Unknown
        Response: Unknown
        Errors: TipIdNotFound
        """
        itip_id = yield get_itip_id_by_wbtip_id(self.current_user.user_id)

        # Call the master class method
        yield self.handle_file_upload(itip_id)

class FileInstance(FileHandler):
    """
    WhistleBlower interface for upload a new file in a not yet completed submission
    """

    @transport_security_check('wb')
    @unauthenticated
    @inlineCallbacks
    def post(self, submission_id, *args):
        """
        Parameter: internaltip_id
        Request: Unknown
        Response: Unknown
        Errors: SubmissionIdNotFound, SubmissionConcluded
        """
        yield validate_itip_id(submission_id)

        # Call the master class method
        yield self.handle_file_upload(submission_id)


@transact
def download_file(store, user_id, tip_id, file_id):
    """
    Auth temporary disabled, just Tip_id and File_id required
    """

    rtip = access_tip(store, user_id, tip_id)

    rfile = store.find(ReceiverFile,
                       ReceiverFile.id == unicode(file_id)).one()

    if not rfile or rfile.receiver_id != user_id:
        raise errors.FileIdNotFound

    log.debug("Download of %s: %d of %d for %s" %
              (rfile.internalfile.name, rfile.downloads,
               rfile.internalfile.internaltip.download_limit, rfile.receiver.name))

    if rfile.downloads == rfile.internalfile.internaltip.download_limit:
        raise errors.DownloadLimitExceeded

    rfile.downloads += 1

    return serialize_receiver_file(rfile)


@transact
def download_all_files(store, user_id, tip_id):

    rtip = access_tip(store, user_id, tip_id)

    rfiles = store.find(ReceiverFile,
                        ReceiverFile.receiver_tip_id == unicode(tip_id))

    files_list = []
    for sf in rfiles:

        if sf.downloads == sf.internalfile.internaltip.download_limit:
            log.debug("massive file download for %s: skipped %s (limit %d reached)" % (
                sf.receiver.name, sf.internalfile.name, sf.downloads
            ))
            continue

        sf.downloads += 1
        files_list.append(serialize_receiver_file(sf))

    return files_list


class Download(BaseHandler):

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def post(self, tip_id, rfile_id, *uriargs):

        rfile = yield download_file(self.current_user.user_id, tip_id, rfile_id)

        # keys:  'file_path'  'size' : 'content_type' 'file_name'

        self.set_status(200)

        self.set_header('X-Download-Options', 'noopen')
        self.set_header('Content-Type', 'application/octet-stream')
        self.set_header('Content-Length', rfile['size'])
        self.set_header('Content-Disposition','attachment; filename=\"%s\"' % rfile['name'])

        filelocation = os.path.join(GLSetting.submission_path, rfile['path'])
        
        cipher = Cipher(algorithms.AES(str(GLSetting.mainServerKey)), modes.CTR(b64decode(rfile['nonce'])), backend=default_backend())
        try:
            # https://docs.python.org/2/library/functions.html#open
            # r read
            # b binaryfile
            # size = amount of bytes read, all if no parameter
            #before here was a splitting but due to the different size of ctr encryption mode and the chunk size 
            # now directly the whole input is used
            requestf = open(filelocation, "rb")
            self.write(cipher.decryptor().update(requestf.read()))

        except IOError as srcerr:
            log.err("Unable to open %s: %s " % (filelocation, srcerr.strerror))
            self.set_status(404)

        self.finish()

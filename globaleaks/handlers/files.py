# -*- coding: utf-8 -*-
#
#  files
#  *****
#
# Backend supports for jQuery File Uploader, and implementation of the
# classes executed when an HTTP client contact /files/* URI

from __future__ import with_statement
import time

from twisted.internet import fdesc
from twisted.internet.defer import inlineCallbacks
from cyclone.web import os

from globaleaks.settings import transact, GLSetting
from globaleaks.handlers.base import BaseHandler
from globaleaks.handlers.authentication import transport_security_check, authenticated
from globaleaks.utils import log, pretty_date_time
from globaleaks.rest import errors
from globaleaks import models
from globaleaks.third_party import rstr


__all__ = ['Download', 'FileInstance']

def serialize_file(internalfile):

    file_desc = {
        'size' : internalfile.size,
        'content_type' : internalfile.content_type,
        'name' : internalfile.name,
        'creation_date': pretty_date_time(internalfile.creation_date),
        'id' : internalfile.id,
        'mark' : internalfile.mark,
    }

    return file_desc

@transact
def register_files_db(store, files, relationship, internaltip_id):
    internaltip = store.find(models.InternalTip, models.InternalTip.id == internaltip_id).one()

    if not internaltip:
        log.err("File submission register in a submission that's no more")
        raise errors.TipGusNotFound

    files_list = []
    i = 0
    for single_file in files:
        original_fname = single_file['filename']

        try:
            new_file = models.InternalFile()

            new_file.name = original_fname
            new_file.content_type = single_file.get('content_type')
            new_file.mark = models.InternalFile._marker[0]
            new_file.size = len(single_file['body'])
            new_file.internaltip_id = unicode(internaltip_id)
            new_file.file_path = relationship[i]

            store.add(new_file)
            store.commit()
            i += 1
        except Exception as excep:
            log.err("Unable to commit new InternalFile %s: %s" % (original_fname.encode('utf-8'), excep))
            raise excep

        # I'm forcing commits because I've got some inconsistencies
        # in this ReferenceSets. need to be investigated if needed.
        try:
            internaltip.internalfiles.add(new_file)
            store.commit()
        except Exception as excep:
            log.err("Unable to reference InternalFile %s in InternalTip: %s" % (original_fname, excep))
            raise excep

        files_list.append(serialize_file(new_file))
        log.debug("Added to the DB, file %s" % original_fname)

    return files_list

def dump_files_fs(files):
    """
    @param files: files uploaded in Cyclone upload
    @return: a relationship dict linking the filename with the random
        filename saved in the disk
    """
    files_saved = {}
    i = 0
    for single_file in files:
        saved_name = rstr.xeger(r'[A-Za-z]{26}')
        filelocation = os.path.join(GLSetting.submission_path, saved_name)

        log.debug("Start saving %d bytes from file [%s]" %
                  (len(single_file['body']), single_file['filename'].encode('utf-8')))

        with open(filelocation, 'w+') as fd:
            fdesc.setNonBlocking(fd.fileno())
            if not fdesc.writeToFD(fd.fileno(), single_file['body']):
                log.debug("Non blocking file has reported an issue")
                raise errors.InternalServerError("buffer not available")

        files_saved.update({i : saved_name })

        i += 1

    return files_saved


@transact
def get_tip_by_submission(store, id):

    try:
        itip = store.find(models.InternalTip,
                          models.InternalTip.id == unicode(id)).one()
    except Exception as excep:
        log.err("get_tip_by_submission: Error in store.find: %s" % excep)
        raise errors.SubmissionGusNotFound

    if not itip:
        raise errors.SubmissionGusNotFound
    elif itip.mark != models.InternalTip._marker[0]:
        raise errors.SubmissionConcluded
    else:
        return itip.id

@transact
def get_tip_by_wbtip(store, wb_tip_id):

    try:
        wb_tip = store.find(models.WhistleblowerTip,
                            models.WhistleblowerTip.id == wb_tip_id).one()
    except Exception as excep:
        log.err("get_tip_by_wtipid (1) Error in store.find: %s" % excep)
        raise errors.SubmissionGusNotFound

    if not wb_tip:
        raise errors.InvalidTipAuthToken

    try:
        itip = store.find(models.InternalTip,
                          models.InternalTip.id == wb_tip.internaltip_id).one()
    except Exception as excep:
        log.err("get_tip_by_wtipid (2) Error in store.find: %s" % excep)
        raise errors.SubmissionGusNotFound

    if not itip:
        raise errors.SubmissionGusNotFound
    else:
        return itip.id



class FileHandler(BaseHandler):

    @inlineCallbacks
    def handle_file_upload(self, itip_id):
        result_list = []

        # measure the operation of all the files (via browser can be selected
        # more than 1), because all files are delivered in the same time.
        start_time = time.time()

        try:
            file_array, files = self.request.files.popitem()
        except Exception as excep:
            log.err("Unable to accept file uploaded: %s" % excep)
            raise errors.InvalidInputFormat("files array malformed")

        try:
            # First iterloop, dumps the files in the filesystem,
            # and exception raised here would prevent the InternalFile recordings
            relationship = dump_files_fs(files)
        except Exception as excep:
            log.err("Unable to save a file in filesystem: %s" % excep)
            raise errors.InternalServerError("Unable to accept new files")

        try:
            # Second iterloop, create the objects in the database
            file_list = yield register_files_db(files, relationship, itip_id)
        except Exception as excep:
            log.err("Unable to register file in DB: %s" % excep)
            raise errors.InternalServerError("Unable to accept new files")

        for file_desc in file_list:
            file_desc['elapsed_time'] = time.time() - start_time
            result_list.append(file_desc)

        self.set_status(201) # Created
        self.write(result_list)


# This is different from FileInstance,just because there are a different authentication requirements
class FileAdd(FileHandler):
    """
    T4
    WhistleBlower interface for upload a new file in an already completed submission
    """

    @inlineCallbacks
    @transport_security_check('tip')
    @authenticated('wb')
    def post(self, wb_tip_id, *args):
        """
        Parameter: submission_gus
        Request: Unknown
        Response: Unknown
        Errors: SubmissionGusNotFound, SubmissionConcluded
        """
        itip_id = yield get_tip_by_wbtip(wb_tip_id)

        # Call the master class method
        yield self.handle_file_upload(itip_id)

class FileInstance(FileHandler):
    """
    U4
    WhistleBlower interface for upload a new file in a not yet completed submission
    """

    @inlineCallbacks
    @transport_security_check('submission')
    def post(self, submission_id, *args):
        """
        Parameter: submission_gus
        Request: Unknown
        Response: Unknown
        Errors: SubmissionGusNotFound, SubmissionConcluded
        """
        itip_id = yield get_tip_by_submission(submission_id)

        # Call the master class method
        yield self.handle_file_upload(itip_id)


def serialize_receiver_file(receiverfile, internalfile):

    file_desc = {
        'size' : internalfile.size,
        'content_type' : internalfile.content_type,
        'name' : internalfile.name,
        'creation_date': pretty_date_time(internalfile.creation_date),
        'downloads' : receiverfile.downloads,
        'path' : internalfile.file_path if internalfile.file_path else receiverfile.file_path,
        'sha2sum' : internalfile.sha2sum,
    }
    return file_desc

@transact
def download_file(store, tip_id, file_id):
    """
    Auth temporary disabled, just Tip_id and File_id required
    """

    receivertip = store.find(models.ReceiverTip, models.ReceiverTip.id == unicode(tip_id)).one()
    if not receivertip:
        raise errors.TipGusNotFound

    file = store.find(models.ReceiverFile, models.ReceiverFile.id == unicode(file_id)).one()
    if not file:
        raise errors.FileGusNotFound

    log.debug("Download of %s downloads: %d with limit of %s for %s" %
              (file.internalfile.name, file.downloads,
               file.internalfile.internaltip.download_limit, receivertip.receiver.name) )

    if file.downloads == file.internalfile.internaltip.download_limit:
        raise errors.DownloadLimitExceeded

    file.downloads += 1

    return serialize_receiver_file(file, file.internalfile)


class Download(BaseHandler):

    @inlineCallbacks
    def get(self, tip_gus, file_gus, *uriargs):

        # tip_gus needed to authorized the download

        file_details = yield download_file(tip_gus, file_gus)
        # keys:  'file_path'  'sha2sum'  'size' : 'content_type' 'file_name'

        self.set_status(200)

        self.set_header('X-Download-Options', 'noopen')
        self.set_header('Content-Type', file_details['content_type'])
        self.set_header('Content-Length', file_details['size'])
        self.set_header('Etag', '"%s"' % file_details['sha2sum'])
        self.set_header('Content-Disposition','attachment; filename=\"%s\"' % file_details['name'])

        filelocation = os.path.join(GLSetting.submission_path, file_details['path'])

        chunk_size = 8192
        filedata = ''
        with open(filelocation, "rb") as requestf:
            while True:
                chunk = requestf.read(chunk_size)
                filedata += chunk
                if len(chunk) == 0:
                    break

        self.write(filedata)
        self.finish()
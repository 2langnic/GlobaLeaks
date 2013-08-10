# -*- coding: UTF-8
#
#   tip
#   ***
#
#   Contains all the logic for handling tip related operations, handled and
#   executed with /tip/* URI PATH interaction.

from twisted.internet.defer import inlineCallbacks

from globaleaks.handlers.base import BaseHandler
from globaleaks.handlers.authentication import transport_security_check
from globaleaks.rest import requests
from globaleaks.utils import log, pretty_date_time, l10n

from globaleaks.settings import transact
from globaleaks.models import *
from globaleaks.rest import errors


def actor_serialize_internal_tip(internaltip):
    itip_dict = {
        'context_id': unicode(internaltip.context.id),
        # compatibility, until client is not ready to be aligned
        'context_gus': unicode(internaltip.context.id),
        'creation_date' : unicode(pretty_date_time(internaltip.creation_date)),
        # XXX not yet used
        'last_activity' : unicode(pretty_date_time(internaltip.creation_date)),
        'expiration_date' : unicode(pretty_date_time(internaltip.expiration_date)),
        'download_limit' : int(internaltip.download_limit),
        'access_limit' : int(internaltip.access_limit),
        'mark' : unicode(internaltip.mark),
        'pertinence' : unicode(internaltip.pertinence_counter),
        'escalation_threshold' : unicode(internaltip.escalation_threshold),
        'fields' : dict(internaltip.wb_fields),
    }
    return itip_dict

def receiver_serialize_file(internalfile, receiverfile, receivertip_id):
    """
    ReceiverFile is the mixing between the metadata present in InternalFile
    and the Receiver-dependent, and for the client sake receivertip_id is
    required to create the download link
    """
    rfile_dict = {
        'href' : unicode("/tip/" + receivertip_id + "/download/" + receiverfile.id),
        # if the ReceiverFile has encrypted status, we append ".pgp" to the filename, to avoid mistake on Receiver side.
        'name' : ("%s.pgp" % internalfile.name) if receiverfile.status == ReceiverFile._status_list[2] else internalfile.name,
        'encrypted': True if receiverfile.status == ReceiverFile._status_list[2] else False,
        'sha2sum' : unicode(internalfile.sha2sum),
        'content_type' : unicode(internalfile.content_type),
        'creation_date' : unicode(pretty_date_time(internalfile.creation_date)),
        'size': int(receiverfile.size),
        'downloads': unicode(receiverfile.downloads)
    }
    return rfile_dict


def wb_serialize_file(internalfile):
    wb_file_desc = {
        'name' : unicode(internalfile.name),
        'sha2sum' : unicode(internalfile.sha2sum),
        'content_type' : unicode(internalfile.content_type),
        'size': int(internalfile.size),
    }
    return wb_file_desc


@transact
def get_files_wb(store, tip_id):
    wbtip = store.find(WhistleblowerTip, WhistleblowerTip.id == unicode(tip_id)).one()

    file_list = []
    for internalfile in wbtip.internaltip.internalfiles:
        file_list.append(wb_serialize_file(internalfile))

    return file_list

@transact
def get_files_receiver(store, user_id, tip_id):
    rtip = strong_receiver_validate(store, user_id, tip_id)

    receiver_files = store.find(ReceiverFile,
        (ReceiverFile.internaltip_id == rtip.internaltip_id, ReceiverFile.receiver_id == rtip.receiver_id) )

    files_list = []
    for receiverfile in receiver_files:
        internalfile = receiverfile.internalfile
        files_list.append(receiver_serialize_file(internalfile, receiverfile, tip_id))

    return files_list

def strong_receiver_validate(store, user_id, tip_id):
    """
    Utility: TODO description
    """

    rtip = store.find(ReceiverTip, ReceiverTip.id == unicode(tip_id)).one()

    if not rtip:
        raise errors.TipGusNotFound

    receiver = store.find(Receiver, Receiver.id == unicode(user_id)).one()

    if not receiver:
        raise errors.ReceiverGusNotFound

    if receiver.id != rtip.receiver.id:
        # This in attack!!
        raise errors.TipGusNotFound

    if not rtip.internaltip:
        # inconsistency! InternalTip removed but rtip not
        log.debug("Inconsintency + Access deny to a receiver on an expired submission! (%s)" %
                  receiver.name)
        raise errors.TipGusNotFound

    return rtip


@transact
def get_internaltip_wb(store, tip_id):
    wbtip = store.find(WhistleblowerTip, WhistleblowerTip.id == unicode(tip_id)).one()

    if not wbtip or not wbtip.internaltip:
        raise errors.TipReceiptNotFound

    tip_desc = actor_serialize_internal_tip(wbtip.internaltip)
    tip_desc['access_counter'] = int(wbtip.access_counter)
    tip_desc['id'] = unicode(wbtip.id)
    tip_desc['im_whistleblower'] = True
    tip_desc['im_receiver'] = False

    return tip_desc

@transact
def get_internaltip_receiver(store, user_id, tip_id):
    rtip = strong_receiver_validate(store, user_id, tip_id)

    tip_desc = actor_serialize_internal_tip(rtip.internaltip)
    tip_desc['access_counter'] = int(rtip.access_counter)
    tip_desc['expressed_pertinence'] = int(rtip.expressed_pertinence)
    tip_desc['id'] = unicode(rtip.id)
    tip_desc['receiver_id'] = unicode(user_id)
    tip_desc['im_whistleblower'] = False
    tip_desc['im_receiver'] = True

    return tip_desc

@transact
def increment_receiver_access_count(store, user_id, tip_id):
    rtip = strong_receiver_validate(store, user_id, tip_id)

    rtip.access_counter += 1
    rtip.last_access = datetime_now()

    if rtip.access_counter > rtip.internaltip.access_limit:
        raise errors.AccessLimitExceeded

    log.debug(
        "Tip %s access garanted to user %s access_counter %d on limit %d" %
       (rtip.id, rtip.receiver.name, rtip.access_counter, rtip.internaltip.access_limit)
    )
    return rtip.access_counter


@transact
def delete_receiver_tip(store, user_id, tip_id):
    """
    This operation is permitted to every receiver, and trigger
    a System comment on the Tip history.
    """
    rtip = strong_receiver_validate(store, user_id, tip_id)

    comment = Comment()
    comment.content = "%s personally remove from this Tip" % rtip.receiver.name
    comment.internaltip_id = rtip.internaltip.id
    comment.author = u'System' # The printed line
    comment.type = Comment._types[2] # System
    comment.mark = Comment._marker[0] # Not Notified
    store.add(comment)
    rtip.internaltip.comments.add(comment)

    store.remove(rtip)


@transact
def delete_internal_tip(store, user_id, tip_id):
    """
    Delete internalTip is possible only to Receiver with
    the dedicated properties. The ON CASCADE directive in SQL
    causes the removal of Comments, InternalFile, R|W tips
    """
    rtip = strong_receiver_validate(store, user_id, tip_id)

    if rtip.receiver.can_delete_submission:
        internaltip_backup = rtip.internaltip

        for receivertip in rtip.internaltip.receivertips:
            store.remove(receivertip)
        store.remove(internaltip_backup)

    else:
        raise errors.ForbiddenOperation


@transact
def manage_pertinence(store, user_id, tip_id, vote):
    """
    Assign in ReceiverTip the expressed vote (checks if already present)
    Roll over all the rTips with a vote
    re-count the Overall Pertinence
    Assign the Overall Pertinence to the InternalTip
    """
    rtip = strong_receiver_validate(store, user_id, tip_id)

    # expressed_pertinence has these meanings:
    # 0 = unassigned
    # 1 = negative vote
    # 2 = positive vote

    if rtip.expressed_pertinence:
        raise errors.TipPertinenceExpressed

    rtip.expressed_pertinence = 2 if vote else 1

    vote_sum = 0
    for rtip in rtip.internaltip.receivertips:
        if not rtip.expressed_pertinence:
            continue
        if rtip.expressed_pertinence == 1:
            vote_sum -= 1
        else:
            vote_sum += 1

    rtip.internaltip.pertinence_counter = vote_sum
    return vote_sum


class TipInstance(BaseHandler):
    """
    T1
    This interface expose the Tip.

    Tip is the safe area, created with an expiration time, where Receivers (and optionally)
    Whistleblower can discuss about the submission, comments, collaborative voting, forward,
    promote, and perform other operation in this closed environment.
    In the request is present an unique token, aim to authenticate the users accessing to the
    resource, and giving accountability in resource accesses.
    Some limitation in access, security extensions an special token can exists, implemented by
    the extensions plugins.

    /tip/<tip_id>/
    tip_id is either a receiver_tip_gus or a whistleblower auth token
    """

    @inlineCallbacks
    @transport_security_check('tip')
    def get(self, tip_id, *uriargs):
        """
        Parameters: None
        Response: actorsTipDesc
        Errors: InvalidTipAuthToken

        tip_id can be: a tip_gus for a receiver, or a WhistleBlower receipt, understand
        the format, help in addressing which kind of Tip need to be handled.
        """
        if self.is_whistleblower:
            answer = yield get_internaltip_wb(self.current_user['user_id'])
            answer['files'] = yield get_files_wb(self.current_user['user_id'])
        else:
            yield increment_receiver_access_count(self.current_user['user_id'], tip_id)
            answer = yield get_internaltip_receiver(self.current_user['user_id'], tip_id)
            answer['files'] = yield get_files_receiver(self.current_user['user_id'], tip_id)

        self.set_status(200)
        self.finish(answer)

    @inlineCallbacks
    @transport_security_check('tip')
    def put(self, tip_id, *uriargs):
        """
        Request: actorsTipOpsDesc
        Response: None
        Errors: InvalidTipAuthToken, InvalidInputFormat, ForbiddenOperation

        This interface modify some tip status value. pertinence and complete removal
        are handled here.

        This interface return None, because may execute a delete operation. The client
        know which kind of operation has been requested. If a pertinence vote, would
        perform a refresh on get() API, if a delete, would bring the user in other places.

        When an uber-receiver decide to "total delete" a Tip, is handled by this call.
        """

        if self.is_whistleblower:
            raise errors.ForbiddenOperation

        request = self.validate_message(self.request.body, requests.actorsTipOpsDesc)

        if request['global_delete']:
            yield delete_internal_tip(self.current_user['user_id'], tip_id)

        elif request['is_pertinent']:
            yield manage_pertinence(self.current_user['user_id'], tip_id, request['is_pertinent'])

        self.set_status(202) # Updated
        self.finish()

    @inlineCallbacks
    @transport_security_check('tip')
    def delete(self, tip_id, *uriargs):
        """
        Request: None
        Response: None
        Errors: ForbiddenOperation, TipGusNotFound
        """

        if self.is_whistleblower:
            raise errors.ForbiddenOperation

        yield delete_receiver_tip(self.current_user['user_id'], tip_id)

        self.set_status(200) # Success
        self.finish()


def serialize_comment(comment):
    comment_desc = {
        'comment_id' : unicode(comment.id),
        'source' : unicode(comment.type),
        'content' : unicode(comment.content),
        'author' : unicode(comment.author),
        'creation_date' : unicode(pretty_date_time(comment.creation_date))
    }
    return comment_desc

def get_comment_list(internaltip):
    """
    @param internaltip:
    This function is used by both Receiver and WB.
    """

    comment_list = []
    for comment in internaltip.comments:
        comment_list.append(serialize_comment(comment))

    return comment_list

@transact
def get_comment_list_wb(store, wb_tip_id):
    wb_tip = store.find(WhistleblowerTip,
                        WhistleblowerTip.id == unicode(wb_tip_id)).one()
    if not wb_tip:
        raise errors.TipReceiptNotFound

    return get_comment_list(wb_tip.internaltip)

@transact
def get_comment_list_receiver(store, user_id, tip_id):
    rtip = strong_receiver_validate(store, user_id, tip_id)
    return get_comment_list(rtip.internaltip)

@transact
def create_comment_wb(store, wb_tip_id, request):
    wbtip = store.find(WhistleblowerTip, WhistleblowerTip.id== unicode(wb_tip_id)).one()

    if not wbtip:
        raise errors.TipReceiptNotFound

    comment = Comment()
    comment.content = request['content']
    comment.internaltip_id = wbtip.internaltip.id
    comment.author = u'whistleblower' # The printed line
    comment.type = Comment._types[1] # WB
    comment.mark = Comment._marker[0] # Not notified

    store.add(comment)
    wbtip.internaltip.comments.add(comment)

    return serialize_comment(comment)

@transact
def create_comment_receiver(store, user_id, tip_id, request):
    rtip = strong_receiver_validate(store, user_id, tip_id)

    comment = Comment()
    comment.content = request['content']
    comment.internaltip_id = rtip.internaltip.id
    comment.author = rtip.receiver.name # The printed line
    comment.type = Comment._types[0] # Receiver
    comment.mark = Comment._marker[0] # Not notified

    store.add(comment)
    rtip.internaltip.comments.add(comment)

    return serialize_comment(comment)


class TipCommentCollection(BaseHandler):
    """
    T2
    Interface use to read/write comments inside of a Tip, is not implemented as CRUD because we've not
    needs, at the moment, to delete/update comments once has been published. Comments is intended, now,
    as a stone written consideration about Tip reliability, therefore no editing and rethinking is
    permitted.
    """

    @inlineCallbacks
    @transport_security_check('tip')
    def get(self, tip_id, *uriargs):
        """
        Parameters: None
        Response: actorsCommentList
        Errors: InvalidTipAuthToken
        """

        if self.is_whistleblower:
            comment_list = yield get_comment_list_wb(self.current_user['user_id'])
        else:
            comment_list = yield get_comment_list_receiver(self.current_user['user_id'], tip_id)

        self.set_status(200)
        self.finish(comment_list)

    @inlineCallbacks
    @transport_security_check('tip')
    def post(self, tip_id, *uriargs):
        """
        Request: actorsCommentDesc
        Response: actorsCommentDesc
        Errors: InvalidTipAuthToken, InvalidInputFormat, TipGusNotFound, TipReceiptNotFound
        """

        request = self.validate_message(self.request.body, requests.actorsCommentDesc)

        if self.is_whistleblower:
            answer = yield create_comment_wb(self.current_user['user_id'], request)
        else:
            answer = yield create_comment_receiver(self.current_user['user_id'], tip_id, request)

        self.set_status(201) # Created
        self.finish(answer)


def serialize_receiver(receiver, access_counter, language=GLSetting.memory_copy.default_language):
    receiver_dict = {
        "can_delete_submission": receiver.can_delete_submission,
        "name": unicode(receiver.name),
        "receiver_gus": unicode(receiver.id),
        "receiver_level": int(receiver.receiver_level),
        "contexts": [],
        "tags": receiver.tags,
        "access_counter": access_counter,
    }
    for context in receiver.contexts:
        receiver_dict['contexts'].append(unicode(context.id))

    receiver_dict["description"] = l10n(receiver.description, language)

    return receiver_dict

@transact
def get_receiver_list_wb(store, wb_tip_id, language):
    wb_tip = store.find(WhistleblowerTip, WhistleblowerTip.id == unicode(wb_tip_id)).one()
    if not wb_tip:
        raise errors.TipReceiptNotFound

    receiver_list = []
    for rtip in wb_tip.internaltip.receivertips:

        receiver_list.append(serialize_receiver( rtip.receiver, rtip.access_counter, language ))

    return receiver_list


@transact
def get_receiver_list_receiver(store, user_id, tip_id, language):
    rtip = strong_receiver_validate(store, user_id, tip_id)

    receiver_list = []
    for rtip in rtip.internaltip.receivertips:

        receiver_list.append(serialize_receiver(rtip.receiver, rtip.access_counter, language ))

    return receiver_list



class TipReceiversCollection(BaseHandler):
    """
    T3
    This interface return the list of the Receiver active in a Tip.
    GET /tip/<auth_tip_id>/receivers
    """

    @inlineCallbacks
    @transport_security_check('tip')
    def get(self, tip_id):
        """
        Parameters: None
        Response: actorsReceiverList
        Errors: InvalidTipAuthToken
        """
        if self.is_whistleblower:
            answer = yield get_receiver_list_wb(self.current_user['user_id'], self.request.language)
        elif self.is_receiver:
            answer = yield get_receiver_list_receiver(self.current_user['user_id'], tip_id, self.request.language)
        else:
            raise errors.NotAuthenticated

        self.set_status(200)
        self.finish(answer)

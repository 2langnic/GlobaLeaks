# -*- coding: UTF-8
#
#   rtip
#   ****
#
#   Contains all the logic for handling tip related operations, for the
#   receiver side. These classes are executed in the /rtip/* URI PATH 

from twisted.internet.defer import inlineCallbacks
from storm.expr import Desc

from globaleaks.handlers.base import BaseHandler 
from globaleaks.handlers.authentication import transport_security_check, authenticated
from globaleaks.rest import requests

from globaleaks.utils.utility import log, utc_future_date, datetime_now, \
                                     datetime_to_ISO8601, datetime_to_pretty_str

from globaleaks.utils.structures import Rosetta
from globaleaks.settings import transact, transact_ro, GLSetting
from globaleaks.models import Node, Comment, ReceiverFile, Message, InternalTip,\
    ReceiverTip, InternalFile
from globaleaks.rest import errors
from globaleaks.security import access_tip

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pickle import loads, dumps
from globaleaks import security
from globaleaks.jobs.delivery_sched import create_receivertip,\
    create_receiver_file

def receiver_serialize_internal_tip(internaltip, language=GLSetting.memory_copy.default_language):    
    ret_dict = {
        'context_id': internaltip.context.id,
        'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internaltip.creation_date_nonce,internaltip.creation_date))),
        'expiration_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internaltip.expiration_date_nonce,internaltip.expiration_date))),
        'download_limit' : internaltip.download_limit,
        'access_limit' : internaltip.access_limit,
        'mark' : internaltip.mark,
        'wb_steps' : loads(security.decrypt_with_ServerKey(internaltip.wb_steps_nonce, internaltip.wb_steps)),
        'global_delete' : False,
        # this field "inform" the receiver of the new expiration date that can
        # be set, only if PUT with extend = True is updated
        'potential_expiration_date' : \
            datetime_to_ISO8601(utc_future_date(seconds=internaltip.context.tip_timetolive)),
        'extend' : False,
        'enable_private_messages': internaltip.context.enable_private_messages,
    }

    # context_name and context_description are localized fields
    mo = Rosetta(internaltip.context.localized_strings)
    mo.acquire_storm_object(internaltip.context)
    for attr in ['name', 'description' ]:
        key = "context_%s" % attr
        ret_dict[key] = mo.dump_localized_attr(attr, language)

    return ret_dict

def receiver_serialize_file(internalfile, receiverfile, receivertip_id):
    """
    ReceiverFile is the mixing between the metadata present in InternalFile
    and the Receiver-dependent, and for the client sake receivertip_id is
    required to create the download link
    """

    if receiverfile.status != 'unavailable':

        ret_dict = {
            'id': receiverfile.id,
            'ifile_id': internalfile.id,
            'status': receiverfile.status,
            'href' : "/rtip/" + receivertip_id + "/download/" + receiverfile.id,
            # if the ReceiverFile has encrypted status, we append ".pgp" to the filename, to avoid mistake on Receiver side.
            #'name' : ("%s.pgp" % internalfile.name) if receiverfile.status == u'encrypted' else internalfile.name,
            'name' : security.decrypt_with_ServerKey(internalfile.name_nonce, internalfile.name),
            'content_type' : security.decrypt_with_ServerKey(internalfile.content_type_nonce,internalfile.content_type),
            'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internalfile.creation_date_nonce, internalfile.creation_date))),
            'size': security.decrypt_with_ServerKey(internalfile.size_nonce,internalfile.size),
            'downloads': receiverfile.downloads
            #TODO: Encryption of the filename and perhaps downloadcounter,creation_date and size
      }

    else: # == 'unavailable' in this case internal file metadata is returned.

        ret_dict = {
            'id': receiverfile.id,
            'ifile_id': internalfile.id,
            'status': 'unavailable',
            'href' : "",
             'name' : security.decrypt_with_ServerKey(internalfile.name_nonce, internalfile.name),
            'content_type' : security.decrypt_with_ServerKey(internalfile.content_type_nonce,internalfile.content_type),
            'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(internalfile.creation_date_nonce, internalfile.creation_date))),
            'size': security.decrypt_with_ServerKey(internalfile.size_nonce,internalfile.size),
            'downloads': unicode(receiverfile.downloads) # this counter is always valid
        }

    return ret_dict


@transact_ro
def get_files_receiver(store, user_id, tip_id):
    rtip = access_tip(store, user_id, tip_id)

    receiver_files = store.find(ReceiverFile,
        (ReceiverFile.internaltip_id == rtip.internaltip_id, ReceiverFile.receiver_id == rtip.receiver_id))

    files_list = []
    for receiverfile in receiver_files:
        internalfile = receiverfile.internalfile
        files_list.append(receiver_serialize_file(internalfile, receiverfile, tip_id))

    return files_list


@transact_ro
def get_internaltip_receiver(store, user_id, tip_id, language=GLSetting.memory_copy.default_language):
    rtip = access_tip(store, user_id, tip_id)

    tip_desc = receiver_serialize_internal_tip(rtip.internaltip)

    # are added here because part of ReceiverTip, not InternalTip
    tip_desc['access_counter'] = rtip.access_counter
    tip_desc['id'] = rtip.id
    tip_desc['receiver_id'] = user_id

    node = store.find(Node).one()

    tip_desc['postpone_superpower'] = (node.postpone_superpower or
                                       rtip.internaltip.context.postpone_superpower or
                                       rtip.receiver.postpone_superpower)

    tip_desc['can_delete_submission'] = (node.can_delete_submission or
                                         rtip.internaltip.context.can_delete_submission or
                                         rtip.receiver.can_delete_submission)
    
    tip_desc['can_modify_tip_receivers'] = rtip.receiver.can_modify_tip_receivers

    return tip_desc

@transact
def increment_receiver_access_count(store, user_id, tip_id):
    rtip = access_tip(store, user_id, tip_id)

    rtip.access_counter += 1
    rtip.last_access_nonce = security.get_b64_encoded_nonce()
    rtip.last_access = security.encrypt_with_ServerKey(rtip.last_access_nonce,dumps(datetime_now()))

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
    rtip = access_tip(store, user_id, tip_id)

    comment = Comment()
    comment.creation_date_nonce = security.get_b64_encoded_nonce()
    comment.creation_date = security.encrypt_with_ServerKey(comment.creation_date_nonce,dumps(datetime_now()))
    
    comment.content_nonce = security.get_b64_encoded_nonce()
    comment.content = security.encrypt_with_ServerKey(comment.content_nonce, "%s personally remove from this Tip" % rtip.receiver.name)
    comment.system_content = dict({ "type" : 2,
                                    "receiver_name" : rtip.receiver.name})

    comment.internaltip_id = rtip.internaltip.id
    
    comment.author_nonce = security.get_b64_encoded_nonce()
    comment.author =security.encrypt_with_ServerKey(comment.author_nonce,"System")
    comment.type_nonce = security.get_b64_encoded_nonce()
    comment.type = security.encrypt_with_ServerKey(comment.type_nonce, str(Comment._types[2])) # system
    comment.mark = u'not notified' # Comment._marker[0]

    rtip.internaltip.comments.add(comment)

    store.remove(rtip)


@transact
def delete_internal_tip(store, user_id, tip_id):
    """
    Delete internalTip is possible only to Receiver with
    the dedicated property.
    """
    rtip = access_tip(store, user_id, tip_id)

    node = store.find(Node).one()

    if not (node.can_delete_submission or
            rtip.internaltip.context.can_delete_submission or
            rtip.receiver.can_delete_submission):
        raise errors.ForbiddenOperation

    store.remove(rtip.internaltip)


@transact
def postpone_expiration_date(store, user_id, tip_id):
    rtip = access_tip(store, user_id, tip_id)

    node = store.find(Node).one()

    if not (node.postpone_superpower or
            rtip.internaltip.context.postpone_superpower or
            rtip.receiver.postpone_superpower):

        raise errors.ExtendTipLifeNotEnabled()
    else:
        log.debug("Postpone check: Node %s, Context %s, Receiver %s" %(
            "True" if node.postpone_superpower else "False",
            "True" if rtip.internaltip.context.postpone_superpower else "False",
            "True" if rtip.receiver.postpone_superpower else "False"
        ))

    rtip.internaltip.expiration_date = \
        utc_future_date(seconds=rtip.internaltip.context.tip_timetolive)

    log.debug(" [%s] in %s has extended expiration time to %s" % (
        rtip.receiver.name,
        datetime_to_pretty_str(datetime_now()),
        datetime_to_pretty_str(rtip.internaltip.expiration_date)))

    comment = Comment()
    comment.creation_date_nonce = security.get_b64_encoded_nonce()
    comment.creation_date = security.encrypt_with_ServerKey(comment.creation_date_nonce,dumps(datetime_now()))
    
    comment.system_content = dict({
           'type': "1", # the first kind of structured system_comments
           'receiver_name': rtip.receiver.name,
           'expire_on' : datetime_to_ISO8601(rtip.internaltip.expiration_date)
    })
        # remind: this is put just for debug, it's never used in the flow
    # and a system comment may have nothing to say except the struct
    comment.content_nonce = security.get_b64_encoded_nonce()
    comment.content = security.encrypt_with_ServerKey(comment.content_nonce, str("%s %s %s (UTC)" % (
                   rtip.receiver.name,
                   datetime_to_pretty_str(datetime_now()),
                   datetime_to_pretty_str(rtip.internaltip.expiration_date))))

    comment.internaltip_id = rtip.internaltip.id
    
    comment.author_nonce = security.get_b64_encoded_nonce()
    comment.author =security.encrypt_with_ServerKey(comment.author_nonce,"System")
    
    comment.type_nonce = security.get_b64_encoded_nonce()
    comment.type = security.encrypt_with_ServerKey(comment.type_nonce, str(Comment._types[2])) # system
    
    comment.mark = Comment._marker[4] # skipped

    rtip.internaltip.comments.add(comment)

@transact
def addReceivertoTip(store, tip_id, receiverID):
    print "entering addReceiverToTip"
    # Check if the receiver is not already a receiver of the tip
    try:
        rtip_check = store.find(ReceiverTip, ReceiverTip.id == unicode(tip_id)).one()
        for rtip in rtip_check.internaltip.receivertips:
            if rtip.receiver.id == receiverID:
                return True
        
        # Create a new newReceiverTip
        newReceiverTip = ReceiverTip()
        newReceiverTip.creation_date_nonce = security.get_b64_encoded_nonce()
        newReceiverTip.creation_date = security.encrypt_with_ServerKey(newReceiverTip.creation_date_nonce,dumps(datetime_now()))
        
        newReceiverTip.last_access_nonce = security.get_b64_encoded_nonce()
        newReceiverTip.last_access = security.encrypt_with_ServerKey(newReceiverTip.last_access_nonce,dumps(datetime_now()))
        # Set it to the user
        newReceiverTip.receiver_id = receiverID
        # Find internalTipId from over given ReceiverTip ID
        rtip_old = store.find(ReceiverTip, ReceiverTip.id == unicode(tip_id)).one()
        newReceiverTip.internaltip_id = rtip_old.internaltip.id
        
        # Set Access counter
        newReceiverTip.access_counter = 0
        # Set the mark
        newReceiverTip.mark = u'not notified'
        # Added it into db
        store.add(newReceiverTip)
        
        # for all Files : Add them to receiverTip
        
        internalFilesList = store.find(InternalFile,InternalFile.internaltip_id == rtip_old.internaltip.id)
        for internalFile in internalFilesList:
            create_receiver_file(receiverID, internalFile.id)
            
    except Exception as err:
        log.err("Error in addReceiverToTip " + str(err))
        return False
    
    return True


@transact
def removeReceiverFromTip(store, tip_id, receiverID):
    # Check if the receiver is a receiver of the tip
    try:
        isReceiverInTip = False
        
        rtip_check = store.find(ReceiverTip, ReceiverTip.id == unicode(tip_id)).one()
        internaltip = rtip_check.internaltip
        for rtip in rtip_check.internaltip.receivertips:
            if rtip.receiver.id == receiverID:
                rtip_to_delete = rtip 
                isReceiverInTip = True
        # if the Receiver is not in the tip just go back
        if not isReceiverInTip:
            return True
        store.remove(rtip_to_delete)
        
        if (internaltip.receivertips.count() == 0):
            log.debug("There are no more receiver on the internal tip " + str(rtip.internaltip.id)+" so removing it")
            store.remove(rtip.internaltip)
    except Exception as err:
        log.err("Error in remove Receiver from Tip" + str(err))
        return False
    
    return True

@transact
def checkDeleteSelfFromTip(store, tip_id, receiverID):
    rtip_check = store.find(ReceiverTip, ReceiverTip.id == unicode(tip_id)).one()
    if (rtip_check.receiver_id == receiverID):
        return True
    return False

class ReceiverConfig(BaseHandler):
    """
    This interface handles the changes of the receiver in an existing tip
    """
    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def post(self, tip_id, *uriargs):
        """
        
        """
        request = self.validate_message(self.request.body, requests.receiverConfig)
        if request['action'] == "add":
            receiverID = request['receiverID'] 
            addReceivertoTip(tip_id,receiverID)
            answer  = yield  get_receiver_list_receiver(self.current_user.user_id, tip_id, self.request.language)
            
        if request['action'] == "remove": 
            receiverID = request['receiverID'] 
            checkDeleteSelf = yield checkDeleteSelfFromTip(tip_id,receiverID)
            removeReceiverFromTip(tip_id, receiverID)
            if checkDeleteSelf:
                answer = {}
            else:
                answer  = yield  get_receiver_list_receiver(self.current_user.user_id, tip_id, self.request.language)
        self.set_status(202) # Updated
        self.finish(answer)
   

class RTipInstance(BaseHandler):
    """
    This interface expose the Receiver Tip
    """

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def get(self, tip_id, *uriargs):
        """
        Parameters: None
        Response: actorsTipDesc
        Errors: InvalidTipAuthToken

        tip_id can be a valid tip_id (Receiver case) or a random one (because is
        ignored, only authenticated user with whistleblower token can access to
        the wb_tip, this is why tip_is is not checked if self.is_whistleblower)

        This method is decorated as @unauthenticated because in the handler
        the various cases are managed differently.
        """

        yield increment_receiver_access_count(self.current_user.user_id, tip_id)
        answer = yield get_internaltip_receiver(self.current_user.user_id, tip_id, self.request.language)
        answer['collection'] = '/rtip/' + tip_id + '/collection'
        answer['files'] = yield get_files_receiver(self.current_user.user_id, tip_id)

        self.set_status(200)
        self.finish(answer)

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def put(self, tip_id, *uriargs):
        """
        Some special operation over the Tip are handled here
        """

        request = self.validate_message(self.request.body, requests.actorsTipOpsDesc)

        if request['extend']:
            yield postpone_expiration_date(self.current_user.user_id, tip_id)

        self.set_status(202) # Updated
        self.finish()

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def delete(self, tip_id, *uriargs):
        """
        Request: actorsTipOpsDesc
        Response: None
        Errors: ForbiddenOperation, TipIdNotFound

        global delete: is removed InternalTip and all the things derived
        personal delete: is removed the ReceiverTip and ReceiverFiles
        """

        request = self.validate_message(self.request.body, requests.actorsTipOpsDesc)

        if request['global_delete']:
            yield delete_internal_tip(self.current_user.user_id, tip_id)
        else:
            yield delete_receiver_tip(self.current_user.user_id, tip_id)

        self.set_status(200) # Success
        self.finish()


def receiver_serialize_comment(comment):
    comment_desc = {
        'comment_id' : comment.id,
        'type' : security.decrypt_with_ServerKey(comment.type_nonce,comment.type),
        'content' : security.decrypt_with_ServerKey(comment.content_nonce,comment.content),
        'system_content' : comment.system_content if comment.system_content else {},
        'author' : security.decrypt_with_ServerKey(comment.author_nonce,comment.author),
        'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(comment.creation_date_nonce, comment.creation_date))),
    }
    return comment_desc

@transact_ro
def get_comment_list_receiver(store, user_id, tip_id):
    rtip = access_tip(store, user_id, tip_id)

    comment_list = []
    for comment in rtip.internaltip.comments:
        comment_list.append(receiver_serialize_comment(comment))

    return comment_list


@transact
def create_comment_receiver(store, user_id, tip_id, request):
    rtip = access_tip(store, user_id, tip_id)

    comment = Comment()
    comment.creation_date_nonce = security.get_b64_encoded_nonce()
    comment.creation_date = security.encrypt_with_ServerKey(comment.creation_date_nonce,dumps(datetime_now()))
    
    comment.content_nonce = security.get_b64_encoded_nonce()
    comment.content = security.encrypt_with_ServerKey(comment.content_nonce, str(request['content']))
    
    comment.internaltip_id = rtip.internaltip.id
    comment.author_nonce = security.get_b64_encoded_nonce()
    comment.author =security.encrypt_with_ServerKey(comment.author_nonce,str(rtip.receiver.name))
    comment.type_nonce = security.get_b64_encoded_nonce()
    comment.type = security.encrypt_with_ServerKey(comment.type_nonce, str(Comment._types[0])) # Receiver
    comment.mark = Comment._marker[0] # Not notified

    rtip.internaltip.comments.add(comment)

    return receiver_serialize_comment(comment)

class RTipCommentCollection(BaseHandler):
    """
    Interface use to read/write comments inside of a Tip, is not implemented as CRUD because we've not
    needs, at the moment, to delete/update comments once has been published. Comments is intended, now,
    as a stone written consideration about Tip reliability, therefore no editing and rethinking is
    permitted.
    """

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def get(self, tip_id, *uriargs):
        """
        Parameters: None
        Response: actorsCommentList
        Errors: InvalidTipAuthToken
        """

        comment_list = yield get_comment_list_receiver(self.current_user.user_id, tip_id)

        self.set_status(200)
        self.finish(comment_list)

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def post(self, tip_id, *uriargs):
        """
        Request: actorsCommentDesc
        Response: actorsCommentDesc
        Errors: InvalidTipAuthToken, InvalidInputFormat, TipIdNotFound, TipReceiptNotFound
        """

        request = self.validate_message(self.request.body, requests.actorsCommentDesc)

        answer = yield create_comment_receiver(self.current_user.user_id, tip_id, request)

        self.set_status(201) # Created
        self.finish(answer)


@transact_ro
def get_receiver_list_receiver(store, user_id, tip_id, language=GLSetting.memory_copy.default_language):

    rtip = access_tip(store, user_id, tip_id)

    receiver_list = []
    for rtip in rtip.internaltip.receivertips:

        if rtip.receiver.configuration == 'hidden':
            continue

        receiver_desc = {
            "gpg_key_status": rtip.receiver.gpg_key_status,
            "can_delete_submission": rtip.receiver.can_delete_submission,
            "can_modify_tip_receivers": rtip.receiver.can_modify_tip_receivers,
            "name": unicode(rtip.receiver.name),
            "receiver_id": unicode(rtip.receiver.id),
            "access_counter": rtip.access_counter,
        }

        mo = Rosetta(rtip.receiver.localized_strings)
        mo.acquire_storm_object(rtip.receiver)
        receiver_desc["description"] = mo.dump_localized_attr("description", language)

        receiver_list.append(receiver_desc)

    return receiver_list


class RTipReceiversCollection(BaseHandler):
    """
    This interface return the list of the Receiver active in a Tip.
    GET /tip/<auth_tip_id>/receivers
    """

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def get(self, tip_id):
        """
        Parameters: None
        Response: actorsReceiverList
        Errors: InvalidTipAuthToken
        """
        answer = yield get_receiver_list_receiver(self.current_user.user_id, tip_id, self.request.language)

        self.set_status(200)
        self.finish(answer)


def receiver_serialize_message(msg):

    return {
        'id' : msg.id,
        'creation_date' : datetime_to_ISO8601(loads(security.decrypt_with_ServerKey(msg.creation_date_nonce, msg.creation_date))),
        'content' : security.decrypt_with_ServerKey(msg.content_nonce,msg.content),
        'visualized' : msg.visualized,
        'type' : security.decrypt_with_ServerKey(msg.type_nonce,msg.type),
        'author' : security.decrypt_with_ServerKey(msg.author_nonce,msg.author),
        'mark' : msg.mark
    }

@transact
def get_messages_list(store, user_id, tip_id):

    rtip = access_tip(store, user_id, tip_id)

    msglist = store.find(Message, Message.receivertip_id == rtip.id)
    msglist.order_by(Desc(Message.creation_date))

    content_list = []
    for msg in msglist:
        content_list.append(receiver_serialize_message(msg))

        if not msg.visualized and security.decrypt_with_ServerKey(msg.type_nonce, msg.type)== "whistleblower":
            log.debug("Marking as readed message [%s] from %s" % (msg.content, msg.author))
            msg.visualized = True

    return content_list

@transact
def create_message_receiver(store, user_id, tip_id, request):

    rtip = access_tip(store, user_id, tip_id)

    msg = Message()
    msg.visualized = False
    msg.receivertip_id = rtip.id
    
    msg.content_nonce = security.get_b64_encoded_nonce()
    msg.content = security.encrypt_with_ServerKey(msg.content_nonce, str(request['content']))
 
    msg.author_nonce = security.get_b64_encoded_nonce()
    msg.author = security.encrypt_with_ServerKey(msg.author_nonce, str(rtip.receiver.name))

    msg.type_nonce = security.get_b64_encoded_nonce()
    # remind: is safest use this convention, and probably we've to
    # change in the whole code the usage of Model._type[ndx]
    msg.type = security.encrypt_with_ServerKey(msg.type_nonce, "receiver")
    
    msg.creation_date_nonce = security.get_b64_encoded_nonce()
    msg.creation_date = security.encrypt_with_ServerKey(msg.creation_date_nonce,dumps(datetime_now()))
    
    msg.mark = u'skipped'

    store.add(msg)

    return receiver_serialize_message(msg)


class ReceiverMsgCollection(BaseHandler):
    """
    This interface return the lists of the private messages exchanged.
    """

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def get(self, tip_id):

        answer = yield get_messages_list(self.current_user.user_id, tip_id)

        self.set_status(200)
        self.finish(answer)

    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def post(self, tip_id):
        """
        Request: actorsCommentDesc
        Response: actorsCommentDesc
        Errors: InvalidTipAuthToken, InvalidInputFormat, TipIdNotFound, TipReceiptNotFound
        """

        request = self.validate_message(self.request.body, requests.actorsCommentDesc)

        message = yield create_message_receiver(self.current_user.user_id, tip_id, request)

        self.set_status(201) # Created
        self.finish(message)
        
class Tip_Authentication(BaseHandler):
    """
    This is the authentication Handler for the submissions.
    This is needed due to the new encryption scheme which needs another security level for the data.
    Every Submission in combination with every receiver of the submission has their own key which is used to encrypt the data.
    """
    @transport_security_check('receiver')
    @authenticated('receiver')
    def put(self, tip_id):
        """
        The put is used when a new password is created. This password is not stored in the database. 
        This method just saves the state that a password was set and in later release encrypt the data with this password.
        """
        request = self.validate_message(self.request.body, requests.subKeyDict)

        password = request['password']
        
        create_password_for_tip_and_receiver(self.current_user.user_id, tip_id, password)
        self.set_status(201) # Created
        self.finish()
    
    @transport_security_check('receiver')
    @authenticated('receiver')
    @inlineCallbacks
    def get(self, tip_id, *uriargs):
        """
        The get is to determine if a new password has to be set
        Response: if a password was already set
        """
        password_set = yield get_password_set_for_submission_by_user(self.current_user.user_id, tip_id)

        self.set_status(200)
        self.finish(password_set)
        
@transact
def get_password_set_for_submission_by_user(store, user_id, tip_id):

    rtip = access_tip(store, user_id, tip_id)
    
    password_set = rtip.password_set
    
    return {
        'password_set' : password_set
        }

@transact
def create_password_for_tip_and_receiver(store, user_id, tip_id, password):
    rtip = access_tip(store, user_id, tip_id)
    rtip.password_set = True
    #GLSetting.mainServerKey = password
    #TODO: Encrypt the data with the password
    #nothing to be saved (call by reference, see increment_receiver_access_count(store, user_id, tip_id)
    
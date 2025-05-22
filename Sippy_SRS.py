# Copyright (c) 2018-2023 Sippy Software, Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from argparse import ArgumentParser
from weakref import WeakSet
from functools import partial

from sippy.UA import UA
from sippy.CCEvents import CCEventTry, CCEventConnect, CCEventFail
from sippy.SipTransactionManager import SipTransactionManager
from sippy.SdpOrigin import SdpOrigin
from sippy.Rtp_proxy.session import Rtp_proxy_session, update_params as RPC_up
from sippy.Rtp_proxy.client import Rtp_proxy_client
from sippy.SipLogger import SipLogger
from sippy.SipConf import SipConf
from sippy.Core.EventDispatcher import ED2
from sippy.Time.Timeout import Timeout
from sippy.MsgBody import MsgBody
from sippy.SdpBody import SdpBody
from sippy.SipReason import SipReason
from sippy.UI.Controller import UIController

class SRSParams:
    sippy_c = None
    from_tag = None
    to_tag = None
    source = None
    rsess = None
    rtpp_r_res = None
    rtpp_u_res = None
    sess_sdp = None
    body_tmpl = '\r\n'.join(('v=0', f'o={SdpOrigin()}',
                             's=Sippy_SRS', 't=0 0'))
    def __init__(self, sippy_c, req):
        self.sippy_c = sippy_c
        self.from_tag = req.getHFBody('from').getTag()
        self.source = req.getSource()
        self.sess_sdp = []
        self.rtpp_r_res = []
        self.rtpp_u_res = {}

class SRSFailure(CCEventFail):
    c2m = {488:'Not Acceptable Here',
           502:'Bad Gateway'}
    def __init__(self, reason, code=488):
        msg = self.c2m[code]
        super().__init__((code, msg))
        self.reason = SipReason(protocol='SIP', cause=code,
                                reason=reason)

class SippySRSUAS(UA):
    _p: SRSParams
    cId: 'SipCallId'

    def __init__(self, sippy_c, req, sip_t):
        self._p = SRSParams(sippy_c, req)
        super().__init__(sippy_c, self.outEvent, disc_cbs = (self.sess_term,))
        super().recvRequest(req, sip_t)

    def sess_term(self, ua, rtime, origin, result = 0):
        print('disconnected')
        self._p.rsess.delete()
        del self._p.rsess
        del self._p.sippy_c
        self._p = None

    def rtp_legA_created(self, index, result, _):
        if result is None:
            return self.rtp_rec_created(None)
        up = RPC_up()
        up.rtpps = self._p.rsess
        up.index = index
        up.result_callback = partial(self.rtp_legB_created, index)
        self._p.rsess.callee.update(up)

    def rtp_legB_created(self, index, result, _):
        if result is None:
            return self.rtp_rec_created(None)
        self._p.rtpp_u_res[index] = (result.rtpproxy_address, result.rtpproxy_port)
        self._p.rsess.start_recording(result_callback=self.rtp_rec_created, index=index)

    def rtp_rec_created(self, result):
        self._p.rtpp_r_res.append(result)
        if len(self._p.rtpp_r_res) < len(self._p.sess_sdp):
            return
        nerrs = sum([1 if r is None or r.startswith('E') else 0
                     for r in self._p.rtpp_r_res])
        if nerrs > 0:
            fail = SRSFailure(f'Just Can\'t, {nerrs} times', 502)
            self.recvEvent(fail)
            return
        ah_pass = ('label', 'rtpmap', 'ptime')
        sdp = SdpBody(self._p.body_tmpl)
        for i, sdp_sect in enumerate(self._p.sess_sdp):
            mh = sdp_sect.m_header
            sdp_sect.c_header.addr, mh.port = self._p.rtpp_u_res[i]
            mh.formats = [f for i, f in enumerate(mh.formats) if i == 0]
            ah = sdp_sect.a_headers
            ah = [x for x in ah if x.name in ah_pass]
            sdp_sect.a_headers = ah
            sdp_sect.addHeader('a', 'recvonly')
            sdp.sections.append(sdp_sect)
        sdp = MsgBody(sdp)
        event = CCEventConnect((200, 'OpenSIPIt Is Great Again! :)', sdp))
        self.recvEvent(event)

    def outEvent(self, event, ua):
        if not isinstance(event, CCEventTry):
            return
        cId, cli, cld, mp_body, auth, caller_name = event.getData()
        self.cId = cId
        if mp_body is None:
            self.recvEvent(SRSFailure('body-less INVITE is not supported (yet), open a PR!'))
            return
        mp_body.parse()
        if mp_body.getType() != 'multipart/mixed':
            self.recvEvent(SRSFailure('multipart/mixed body is expected'))
            return
        sdps = [s for s in mp_body.content.parts if s.getType() == 'application/sdp']
        if len(sdps) == 0:
            self.recvEvent(SRSFailure('no application/sdp body found'))
            return
        #print(type(sdp_body.content), type(sdp_body.content.sections))
        rs = Rtp_proxy_session(self._p.sippy_c, cId, self._p.from_tag, self._p.to_tag)
        self._p.rsess = rs
        rs.caller.raddress = self._p.source
        for sdp in sdps:
            sdp.parse()
            for sect in sdp.content.sections:
                up = RPC_up()
                up.rtpps = rs
                up.index = len(self._p.sess_sdp)
                up.result_callback = partial(self.rtp_legA_created, up.index)
                up.remote_ip = sect.c_header.addr
                up.remote_port = sect.m_header.port
                rs.caller.update(up)
                self._p.sess_sdp.append(sect)

class SippySRS_Control(object):
    parser = ArgumentParser(description='Sippy SRS Control Interface')
    parser.add_argument('--rtp_proxy_client', help='RTP proxy client spec string',
                        default='/tmp/rtpp.sock')
    parser.add_argument('--ui', action='store_true',
                        help='Enable the web UI')
    parser.add_argument('--uiparams', type=str, default='',
                        help='UI parameters in key=value;key2=value2 format')
    parser.add_argument('--sip_port', type=int, default=SipConf.my_port,
                        help='SIP port to listen on')
    sippy_c = None

    def __init__(self):
        args = self.parser.parse_args()
        assert args.rtp_proxy_client is not None
        SipConf.my_uaname = 'Sippy SRS'
        logger = SipLogger(SipConf.my_uaname.replace(' ', '_'))
        sippy_c = {'_sip_address':SipConf.my_address,
                   '_sip_port':args.sip_port,
                   '_sip_logger':logger}
        self.sippy_c = sippy_c
        self.active_uas = WeakSet()
        if args.ui:
            sippy_c['_cmap'] = self
            sippy_c['uiparams'] = args.uiparams
            UIController(sippy_c, "Sippy SIP Recording Server")
        udsc, udsoc = SipTransactionManager.model_udp_server
        udsoc.nworkers = 1
        rpc = Rtp_proxy_client(sippy_c, spath = args.rtp_proxy_client)
        def waitonline(_rpc):
            if _rpc.online:
                ED2.breakLoop()
        t = Timeout(waitonline, 0.1, 10, rpc)
        self.run(2.0)
        if not rpc.online:
            raise Exception("Timeout out waiting for the RTPProxy client to come online")
        t.cancel()
        sippy_c['_rtp_proxy_clients'] = (rpc,)
        sippy_c['_sip_tm'] = SipTransactionManager(sippy_c, self.recvRequest)

    def run(self, timeout=None):
        return(ED2.loop(timeout))

    def recvRequest(self, req, sip_t):
        if req.getMethod() in ('NOTIFY', 'PING'):
            # Whynot?
            return (req.genResponse(200, 'OK'), None, None)
        if req.getMethod() == 'INVITE':
            # New dialog
            uaA = SippySRSUAS(self.sippy_c, req, sip_t)
            self.active_uas.add(uaA)
            return
        return (req.genResponse(501, 'Not Implemented'), None, None)

    def listActiveCalls(self):
        rr = []
        for ua in self.active_uas:
            r = [str(ua.cId), 'Dummy']
            (_h, _p), _t = ua.getRAddr0()
            r.append((ua.state.sname, _t, _h, _p, ua.getCLD(), ua.getCLI()))
            r.append(None)  # No uaO side
            rr.append(tuple(r))
        return tuple(rr)

    @property
    def ccmap(self):
        return iter(self.active_uas)

    def safeStop(self, signum=None):
        for ua in self.active_uas:
            ua.disconnect()
        self.sippy_c['_sip_tm'].shutdown()
        Timeout(ED2.breakLoop, 0.2, 1)

if __name__ == '__main__':
    exit(SippySRS_Control().run())

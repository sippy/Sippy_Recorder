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

from sippy.UA import UA
from sippy.CCEvents import CCEventTry, CCEventConnect, CCEventFail
from sippy.SipTransactionManager import SipTransactionManager
from sippy.SdpOrigin import SdpOrigin
from sippy.Rtp_proxy_session import Rtp_proxy_session, update_params as RPC_up
from sippy.Rtp_proxy_client import Rtp_proxy_client
from sippy.SipLogger import SipLogger
from sippy.SipConf import SipConf
from sippy.Core.EventDispatcher import ED2
from sippy.Time.Timeout import Timeout
from sippy.MsgBody import MsgBody
from sippy.SdpBody import SdpBody
from sippy.SipReason import SipReason

class SRSParams:
    sippy_c = None
    from_tag = None
    to_tag = None
    source = None
    invite = None
    rsess = None
    rtpp_res = None
    sess_sdp = None
    body_tmpl = '\r\n'.join(('v=0', f'o={SdpOrigin()}',
                             's=Sippy_SRS', 't=0 0'))

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

    def __init__(self, sippy_c, req, sip_t):
        self._p = SRSParams()
        self._p.sippy_c = sippy_c
        self._p.from_tag = req.getHFBody('from').getTag()
        #self._p.to_tag = req.getHFBody('to').getTag()
        self._p.source = req.getSource()
        self._p.invite = req
        self._p.sess_sdp = []
        self._p.rtpp_res = []
        super().__init__(sippy_c, self.outEvent, disc_cbs = (self.sess_term,))
        super().recvRequest(req, sip_t)

    def sess_term(self, ua, rtime, origin, result = 0):
        print('disconnected')

    def rtp_sess_created(self, result):
        self._p.rtpp_res.append(result)
        if len(self._p.rtpp_res) < len(self._p.sess_sdp):
            return
        nerrs = sum([1 if r is None or r.startswith('E') else 0
                     for r in self._p.rtpp_res])
        tm = self._p.sippy_c['_sip_tm']
        if nerrs > 0:
            fail = SRSFailure(f'Just Can\'t, {nerrs} times', 502)
            self.recvEvent(fail)
            return
        ah_pass = ('label', 'rtpmap', 'ptime')
        sdp = SdpBody(self._p.body_tmpl)
        for i, sdp_sect in enumerate(self._p.sess_sdp):
            rsinfo = self._p.rsess.caller.rinfo_hst[i]
            sdp_sect.c_header.addr = rsinfo.rtpproxy_address
            sdp_sect.m_header.port = rsinfo.rtpproxy_port
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
        rs.caller.raddress = self._p.source
        for sdp in sdps:
            sdp.parse()
            for sect in sdp.content.sections:
                def update_done(res, rtpps, _sect, index):
                    if res is None:
                        self.rtp_sess_created(None)
                        return
                    rs.start_recording(result_callback=self.rtp_sess_created,
                                       index=index)
                up = RPC_up()
                up.rtpps = rs
                up.index = len(self._p.sess_sdp)
                up.result_callback = update_done
                up.remote_ip = sect.c_header.addr
                up.remote_port = sect.m_header.port
                up.callback_parameters = (sect, up.index,)
                rs.callee.update(up)
                self._p.sess_sdp.append(sect)
        self._p.rsess = rs

class SippySRS_Control(object):
    sippy_c = None

    def __init__(self):
        SipConf.my_uaname = 'Sippy SRS'
        logger = SipLogger(SipConf.my_uaname.replace(' ', '_'))
        sippy_c = {'_sip_address':SipConf.my_address,
                   '_sip_port':SipConf.my_port,
                   '_sip_logger':logger}
        udsc, udsoc = SipTransactionManager.model_udp_server
        udsoc.nworkers = 1
        sippy_c['_sip_tm'] = SipTransactionManager(sippy_c, self.recvRequest)
        rpc = Rtp_proxy_client(sippy_c, spath = '/tmp/rtpp.sock')
        def waitonline(_rpc):
            if _rpc.online:
                ED2.breakLoop()
        t = Timeout(waitonline, 0.1, 10, rpc)
        self.run(2.0)
        if not rpc.online:
            raise Exception("Timeout out waiting for the RTPProxy client to come online")
        t.cancel()
        sippy_c['_rtp_proxy_clients'] = (rpc,)
        self.sippy_c = sippy_c

    def run(self, timeout=None):
        return(ED2.loop(timeout))

    def recvRequest(self, req, sip_t):
        if req.getMethod() in ('NOTIFY', 'PING'):
            # Whynot?
            return (req.genResponse(200, 'OK'), None, None)
        if req.getMethod() == 'INVITE':
            # New dialog
            uaA = SippySRSUAS(self.sippy_c, req, sip_t)
            return
        return (req.genResponse(501, 'Not Implemented'), None, None)

if __name__ == '__main__':
    exit(SippySRS_Control().run())

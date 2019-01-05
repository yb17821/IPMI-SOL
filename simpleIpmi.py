from hashlib import sha1
from queue import Queue
# pip install pycryptodome
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

import hmac
import socket
import threading
import time
import math


class SimpleIPMITOOL():

    def __init__(self, username, password, ip, debug=False):
        self.debug = debug
        self.ip = (ip, 623)
        self.Uname = username.encode()
        self.Ulen = len(self.Uname).to_bytes(1, 'big')
        self.Upwd = password.encode()
        self.key = self.hexstr_to_bytes(self.Upwd.hex(), 20)

    def setupsession(self):
        if self.debug:
            print('>>> setupsession')
        self.SIDM = self.hexstr_to_bytes('a4a3a2a0')
        self.RM = get_random_bytes(16)
        self.RC = None
        self.GUIDC = None
        self.RoleM = self.hexstr_to_bytes('14')
        self.SIK = None
        self.udpsoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.udpsoc.bind(('0.0.0.0', 6233))
        self.udpsoc.setblocking(False)
        self.RMCPHEADER = self.hexstr_to_bytes('0600ff07')
        self.auth_type = self.hexstr_to_bytes('06')
        self.paload_type = self.hexstr_to_bytes('c0')
        self.SIDC = None
        self.seqid = 2
        self.rqseq = 1
        self.sol_pkt_seq = 0
        self.last_bmc_pkt_seq = 0
        self.last_sol_pkt_seq = 0
        self.session_activated = False
        self.sol_activated = False
        self.sol_data_q = Queue()
        self.ipmi_data_q = Queue()
        self.ipmi_session_build_q = Queue()
        self.session_activated = True
        self.thread_udprecv = threading.Thread(target=self.udprecv, args=())
        self.thread_udprecv.start()
        self.GetChannelAuthenticationCapabilities()
        self.OpenSession()
        self.RAKP12()
        self.RAKP34()
        self.thread_session_heart_beat = threading.Thread(target=self.session_heart_beat, args=())
        self.thread_session_heart_beat.start()
        # set Privilege Level to admin
        completion_code, rqdata = si.sendipmicmd(netfn=0x06, cmd=0x3b, datalist=[0x04])
        if self.debug:
            print('<<< setupsession')
        if completion_code != '00':
            print('Can not set Privilege Level to admin')
            return False
        return True

    def GetChannelAuthenticationCapabilities(self):
        if self.debug:
            print('>>> GetChannelAuthenticationCapabilities')
        senddata = self.hexstr_to_bytes('0600ff07000000000000000000092018c88100388e04b5')
        self.udpsend(senddata)
        data = self.ipmi_session_build_q.get()
        if self.debug:
            print('<<< GetChannelAuthenticationCapabilities')

    def OpenSession(self):
        if self.debug:
            print('>>> OpenSession')
        senddata = self.hexstr_to_bytes(
            '0600ff0706100000000000000000200000000000a4a3a2a0000000080100000001000008010000000200000801000000')
        self.udpsend(senddata)
        data = self.ipmi_session_build_q.get()
        self.SIDC = data[24:28]
        if self.debug:
            print('<<< OpenSession')

    def RAKP12(self):
        if self.debug:
            print('>>> RAKP12')
        senddata = self.hexstr_to_bytes(
            f'0600ff0706120000000000000000200000000000') + self.SIDC + self.RM + self.hexstr_to_bytes(
            '140000') + self.Ulen + self.Uname
        self.udpsend(senddata)
        data = self.ipmi_session_build_q.get()
        self.RC = data[24:40]
        self.GUIDC = data[40:56]
        if self.debug:
            print('<<< RAKP12')

    def RAKP34(self):

        if self.debug:
            print('>>> RAKP34')
        self.get_rakp3_Key_Exchange_Authentication_Code()
        self.get_sik()
        self.get_k1k2()
        self.get_rakp4_Key_Exchange_Authentication_Code()
        senddata = self.hexstr_to_bytes(
            f'0600ff07061400000000000000001c0000000000') + self.SIDC + self.rakp3_Key_Exchange_Authentication_Code
        self.udpsend(senddata)
        data = self.ipmi_session_build_q.get()
        if self.debug:
            print('<<< RAKP34')

    def get_rakp2_Key_Exchange_Authentication_Code(self):
        if self.debug:
            print('>>> get_rakp2_Key_Exchange_Authentication_Code')
        self.rakp2_mac_buf = (
                self.SIDM +
                self.SIDC +
                self.RM +
                self.RC +
                self.GUIDC +
                self.RoleM +
                self.Ulen +
                self.Uname
        )
        self.rakp2_Key_Exchange_Authentication_Code = self.HMAC_SHA1(self.key, self.rakp2_mac_buf)
        if self.debug:
            print('<<< get_rakp2_Key_Exchange_Authentication_Code')

    def get_rakp3_Key_Exchange_Authentication_Code(self):
        if self.debug:
            print('>>> get_rakp3_Key_Exchange_Authentication_Code')
        self.rakp3_mac_buf = (
                self.RC +
                self.SIDM +
                self.RoleM +
                self.Ulen +
                self.Uname
        )
        self.rakp3_Key_Exchange_Authentication_Code = self.HMAC_SHA1(self.key, self.rakp3_mac_buf)
        if self.debug:
            print('<<< get_rakp3_Key_Exchange_Authentication_Code')

    def get_sik(self):
        if self.debug:
            print('>>> get_sik')
        self.SIK_mac_buf = (
                self.RM +
                self.RC +
                self.RoleM +
                self.Ulen +
                self.Uname
        )
        self.SIK = self.HMAC_SHA1(self.key, self.SIK_mac_buf)
        if self.debug:
            print('<<< get_sik')

    def get_k1k2(self):
        if self.debug:
            print('>>> get_k1k2')
        Const1 = self.hexstr_to_bytes('01' * 20)
        Const2 = self.hexstr_to_bytes('02' * 20)
        self.K1 = self.HMAC_SHA1(self.SIK, Const1)
        self.K2short = self.HMAC_SHA1(self.SIK, Const2)[:16]
        if self.debug:
            print('<<< get_k1k2')

    def get_rakp4_Key_Exchange_Authentication_Code(self):
        if self.debug:
            print('>>> get_rakp4_Key_Exchange_Authentication_Code')
        self.rakp4_mac_buf = (
                self.RM +
                self.SIDC +
                self.GUIDC
        )

        self.rakp4_Key_Exchange_Authentication_Code = self.HMAC_SHA1(self.SIK, self.rakp4_mac_buf)[:12]
        if self.debug:
            print('<<< get_rakp4_Key_Exchange_Authentication_Code')

    def udpsend(self, pkt):
        if self.debug:
            print('>>> udpsend')
        self.udpsoc.sendto(pkt, self.ip)
        if self.debug:
            print('<<< udpsend')

    def udprecv(self):

        while True:
            try:
                data, bmc_ip = self.udpsoc.recvfrom(1024)
                self.analysis_rq(data)
            except BlockingIOError:
                if self.session_activated is False:
                    break
                time.sleep(0.1)
            except Exception as e:
                break

    @staticmethod
    def hexstr_to_bytes(hexstr, length=None):
        if length is None:
            length = math.ceil(len(hexstr) // 2)
            if length == 0:
                length += 1
        else:
            hexstr += (length - len(hexstr) // 2) * '00'
        return int(hexstr, 16).to_bytes(length, 'big')

    @staticmethod
    def HMAC_SHA1(key, rakp_mac_buf):
        return hmac.new(key, rakp_mac_buf, sha1).digest()

    @staticmethod
    def CheckSum(bytes):

        chksum = 0
        for i in bytes:
            chksum = (chksum + i) % 0x100
        if chksum > 0:
            chksum = 0x100 - chksum
        return chksum.to_bytes(1, 'big')

    def session_heart_beat(self):
        if self.debug:
            print('>>> session_heart_beat')
        while self.session_activated:
            code, data = si.sendipmicmd(netfn=0x06, cmd=0x01)
            time.sleep(5)
        if self.debug:
            print('<<< session_heart_beat')

    def create_ipmi_message(self, raw_dict):
        if self.debug:
            print('>>> create_ipmi_message')
        data = b''

        for i in raw_dict['datalist']:
            data += i.to_bytes(1, 'big')

        first_part = raw_dict['rsaddr'].to_bytes(1, 'big') + \
                     (raw_dict['netfn'] << 2 | raw_dict['rslun']).to_bytes(1, 'big')
        checksum1 = self.CheckSum(first_part)
        second_part = raw_dict['rqaddr'].to_bytes(1, 'big') + \
                      (raw_dict['rqseq'] << 2 | raw_dict['rqlun']).to_bytes(1, 'big') + \
                      raw_dict['cmd'].to_bytes(1, 'big') + data
        checksum2 = self.CheckSum(second_part)
        raw_ipmimsg = first_part + checksum1 + second_part + checksum2
        raw_ipmimsg = self.rawmsg_add_pad(raw_ipmimsg)
        if self.debug:
            print('<<< create_ipmi_message')
        return raw_ipmimsg

    def AES_excu(self, msg, mod='encrypt', iv=None):
        if self.debug:
            print('>>> AES_excu')
        if mod == 'encrypt':
            cipher = AES.new(self.K2short, AES.MODE_CBC)
            iv = cipher.iv
            encrypt_ipmimsg = cipher.encrypt(msg)
            result = iv, encrypt_ipmimsg
        else:
            cipher = AES.new(self.K2short, AES.MODE_CBC, iv)
            decrypt_ipmimsg = cipher.decrypt(msg)
            result = decrypt_ipmimsg
        if self.debug:
            print('<<< AES_excu')
        return result

    def create_ipmi_pkt(self, raw_dict, paload_type):
        if self.debug:
            print('>>> create_ipmi_pkt')
        if paload_type == b'\xc0':
            raw_msg = self.create_ipmi_message(raw_dict)
        elif paload_type == b'\xc1':
            raw_msg = self.create_sol_message(raw_dict)
        else:
            raise ValueError('Unknow paload_type:', paload_type.hex())
        iv, encrypt_msg = self.AES_excu(raw_msg)
        self.seqid += 1
        if self.seqid-1 == 0xffffffff:
            self.seqid = 2
        seqid = self.seqid.to_bytes(4, 'little')
        payload_length = len(iv + encrypt_msg).to_bytes(1, 'big') + b'\x00'
        pad = b'\xff\xff'
        padlength = len(pad).to_bytes(1, 'big')
        nextheader = b'\x07'
        try:
            authcode_output = self.auth_type + \
                              paload_type + \
                              self.SIDC + \
                              seqid + \
                              payload_length + \
                              iv + \
                              encrypt_msg + \
                              pad + \
                              padlength + \
                              nextheader
            authcode = self.HMAC_SHA1(self.K1, authcode_output)[:12]
        except:
            a = [self.auth_type,
                 paload_type,
                 self.SIDC,
                 seqid,
                 payload_length,
                 iv,
                 encrypt_msg,
                 pad,
                 padlength,
                 nextheader]
            for i in a:
                print(i, type(i))
            exit()
        pkt = self.RMCPHEADER + authcode_output + authcode
        if self.debug:
            print('<<< create_ipmi_pkt')
        return pkt

    def rawmsg_add_pad(self, raw_msg):
        if self.debug:
            print('>>> rawmsg_add_pad')
        count = 16 - len(raw_msg) % 16
        _pad = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x0f'
        if count == 0:
            result = raw_msg + _pad
        elif count == 1:
            result = raw_msg + b'\x00'
        else:
            result = raw_msg + _pad[:count - 1] + (count - 1).to_bytes(1, 'big')
        if self.debug:
            print('<<< rawmsg_add_pad')
        return result

    def cut_rawmsg_pad(self, rawmsg):
        if self.debug:
            print('>>> cut_rawmsg_pad')
        padlength = rawmsg[-1]
        if padlength == 0:
            result = rawmsg[:-1]
        else:
            result = rawmsg[: -1 - padlength]

        if self.debug:
            print('<<< cut_rawmsg_pad')
        return result

    def analysis_rq(self, data):
        if self.debug:
            print('>>> analysis_rq')
        payload_type = data[5]
        # print(hex(payload_type))
        # print(payload_type in [0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15])
        if payload_type in [0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15]:
            self.ipmi_session_build_q.put(data)
            return

        paload_length = data[14]
        iv = data[16:32]
        encrypt_msg = data[32:-16]
        raw_msg = self.AES_excu(encrypt_msg, mod='decrypt', iv=iv)
        raw_msg_without_pad = self.cut_rawmsg_pad(raw_msg)

        if payload_type == 0xc0:
            rqdata = raw_msg_without_pad[7:-1]
            completion_code = raw_msg_without_pad[6].to_bytes(1, 'big').hex()
            self.ipmi_data_q.put((completion_code, rqdata.hex()))

        elif payload_type == 0xc1:

            rsdata = {
                'pkt_seq': raw_msg_without_pad[0],
                'ack_seq': raw_msg_without_pad[1],
                'recv_char_count': raw_msg_without_pad[2],
                'status': raw_msg_without_pad[3],
                'data': raw_msg_without_pad[4:]
            }
            self.sol_data_q.put(rsdata)
            if rsdata['pkt_seq'] != 0:
                self.send_solcmd(pkt_seq=0x00, ack_seq=rsdata['pkt_seq'], recv_char_count=len(rsdata['data']),
                                 status=0x00, data=None)
        if self.debug:
            print('<<< analysis_rq')

    def sendipmicmd(self, rsaddr=0x20, netfn=0x06, rslun=0x00, rqaddr=0x81, rqseq=0x01, rqlun=0x00, cmd=0x01,
                    datalist=[]):
        if self.debug:
            print('>>> sendipmicmd')
        raw_dict = {
            'rsaddr': rsaddr,
            'netfn': netfn,
            'rslun': rslun,
            'rqaddr': rqaddr,
            'cmd': cmd,
            'datalist': datalist,
            'rqseq': rqseq,
            'rqlun': rqlun
        }
        pkt = self.create_ipmi_pkt(raw_dict, b'\xc0')
        self.udpsend(pkt)
        data = self.ipmi_data_q.get()
        if self.debug:
            print('<<< sendipmicmd')
        return data

    def close_all(self):
        if self.debug:
            print('>>> close_all')

        completion_code, rqdata = si.sendipmicmd(netfn=0x06, cmd=0x3c,
                                                 datalist=[self.SIDC[0], self.SIDC[1], self.SIDC[2], self.SIDC[3]])
        self.session_activated = False
        self.udpsoc.close()
        while True:
            if not si.thread_udprecv.isAlive() and not si.thread_session_heart_beat.isAlive():
                break
            time.sleep(0.1)

        if self.debug:
            print('<<< close_all')
        return completion_code, rqdata

    def activate_payload(self):
        if self.debug:
            print('>>> activate_payload')

        completion_code, rqdata = si.sendipmicmd(netfn=0x06, cmd=0x48, datalist=[0x01, 0x01, 0xc6, 0x00, 0x00, 0x00])
        self.sol_activated = True
        if self.debug:
            print('<<< activate_payload')
        return completion_code, rqdata

    def deactivate_payload(self):
        if self.debug:
            print('>>> deactivate_payload')
        self.sol_activated = False
        self.sol_pkt_seq = 0
        completion_code, rqdata = si.sendipmicmd(netfn=0x06, cmd=0x48, datalist=[0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
        if self.debug:
            print('<<< deactivate_payload')
        return completion_code, rqdata

    def create_sol_message(self, raw_dict):
        if self.debug:
            print('>>> create_sol_message')
        raw_solmsg = raw_dict['pkt_seq'] + raw_dict['ack_seq'] + raw_dict['recv_char_count'] + raw_dict['status'] + \
                     raw_dict['data']
        raw_solmsg = self.rawmsg_add_pad(raw_solmsg)
        if self.debug:
            print('<<< create_sol_message')
        return raw_solmsg

    def send_solcmd(self, pkt_seq=None, ack_seq=0x00, recv_char_count=0x00, status=0x00, data=0x1b5b42):
        if self.debug:
            print('>>> send_solcmd')

        if pkt_seq is None:
            self.sol_pkt_seq += 1
            pkt_seq = self.sol_pkt_seq % 0x100



        raw_dict = {
            'pkt_seq': pkt_seq.to_bytes(1, 'big'),
            'ack_seq': ack_seq.to_bytes(1, 'big'),
            'recv_char_count': recv_char_count.to_bytes(1, 'big'),
            'status': status.to_bytes(1, 'big'),
            'data': b'' if data is None else self.hexstr_to_bytes(hex(data)[2:])
        }
        pkt = self.create_ipmi_pkt(raw_dict, b'\xc1')
        self.udpsend(pkt)
        if self.debug:
            print('<<< send_solcmd')

    def up(self):
        self.send_solcmd(data=0x1b5b41)

    def down(self):
        self.send_solcmd()

    def right(self):
        self.send_solcmd(data=0x1b5b43)

    def left(self):
        self.send_solcmd(data=0x1b5b44)

    def enter(self):
        self.send_solcmd(data=0x0d)

    def esc(self):
        self.send_solcmd(data=0x1b)

    def backspace(self):
        self.send_solcmd(data=0x08)

    def f9(self):
        self.send_solcmd(data=0x1b5b32307e)

    def f10(self):
        self.send_solcmd(data=0x1b5b32317e)

    def typeword(self, string):
        for i in string:
            self.send_solcmd(data=ord(i))
            time.sleep(2)

    def get_sol_char(self, interval):
        if self.debug:
            print('>>> get_sol_data')
        time1 = time.time()
        string = ''
        while True:
            if not si.sol_data_q.empty():
                rsdata = si.sol_data_q.get()
                string += rsdata['data'].decode()
            else:
                time2 = time.time()
                if time2 - time1 >= 2:
                    break
                time.sleep(interval)
        if self.debug:
            print('<<< get_sol_data')
        return string





if __name__ == '__main__':

    si = SimpleIPMITOOL('root', 'superuser', '10.239.55.7', debug=False)
    # create session
    si.setupsession()


    completion_code, rqdata = si.sendipmicmd(netfn=0x06, cmd=0x01)
    print(completion_code, rqdata)

    completion_code, rqdata = si.sendipmicmd(netfn=0x0c, cmd=0x02, datalist=[0x01, 0x03, 0x00, 0x00])
    print(completion_code, rqdata)

    # activate_payload
    completion_code, rqdata = si.activate_payload()
    print(completion_code, rqdata)
    if completion_code == '80':
        exit()


    for i in range(1000000):
        print(i)
        si.enter()
        print(si.get_sol_char(5))
        si.esc()
        print( si.get_sol_char(5))


    # deactivate_payload
    completion_code, rqdata = si.deactivate_payload()
    if completion_code != '80':
        print('Can not deactivate_payload', completion_code, rqdata)

    # close_session
    completion_code, rqdata = si.close_all()
    if completion_code != '00':
        print('Can not close_session', completion_code, rqdata)
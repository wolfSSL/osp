try:
    import uselect
    import wolfssl as ussl
    import io
    import ubinascii as binascii
except ImportError:
    print("SKIP")
    raise SystemExit

from micropython import const

_MP_STREAM_POLL_RD = const(0x0001)
_MP_STREAM_POLL_WR = const(0x0004)
_MP_STREAM_POLL_NVAL = const(0x0020)
_MP_STREAM_POLL = const(3)
_MP_STREAM_CLOSE = const(4)


# This self-signed key/cert pair is randomly generated and to be used for
# testing/demonstration only.  You should always generate your own key/cert.
key = binascii.unhexlify(
    b"308204bd020100300d06092a864886f70d0101010500048204a7308204a3020100028201"
    b"0100ddd15235530b1a22a05c9e4ba7ac53ec77364c34b7996b2ddf4f7bb4552ede4146f1"
    b"71ba0b8f90b773c10c99eabfa70abd42db43b691fd5e1c2ce8c95f19fc88196f06f8e00b"
    b"bf21454e264e718399e14949a2dce2074603e84b987235bba4fd3f06f901a9203f7cc109"
    b"65c3e36b42b05c8347dd013fa32967ca9b1eba2cfc29643909b6223709cba64026a0b7a2"
    b"0336998263290716f9873942bb7fabeca6acf6279aadd557f7b66215ab6b173df8d74e02"
    b"b000e9f9c0fef0d212f4e7b27503175ebe0b5c6dfca16b6a9ba513d0103528c3dd28004f"
    b"5c08f8be639072a6b695e362ace0f22b33177aa603903886186be5f72bd3f59d45cc5e16"
    b"949a25f31f0f02030100010282010015f91247adfe3f8c868e2630205ff5c04adeda15ae"
    b"ca47cfb77b4c29c4f66b95d3cd3f12caea61cf8a6be92fa60d6e22a634e53b83ee5a46e4"
    b"4b9e93b41402ec0878f31bdc35cdad220c67c7057f9fd2ad4bda123f61b111da050308ed"
    b"41b54a50e003f2a22a4b9fb40f96411d5a16b519b4f77d710e38bf7544a0b11e882e424c"
    b"30b43e7fba523c22fe9bc91f50cb45f13d0d31f4050307934e8de2ca8b929ec3998422ef"
    b"685f82a1b8285f1dc62384ab6e6e1d9a3e58b19dc6a18d5767946a1d38048a7e0b842186"
    b"ed745759a29b1edb742b9ecd150fcbd16d1c0b048171cb578bccea0cd62ff75c00052126"
    b"69f37ead5ed20d20221ecd62e2bd5a8fab08e102818100ec319a73a1cdd20cfe9becb8b7"
    b"db0682fd9fc0be92a9e90ce152f718e529e4e5a1c9de5c85f87d287dd9e2e46c579c26cf"
    b"ac3ed9b2f7b9d3329d282628b26a0b34eeae57d38b45faf26403999387d9d931d200bbe3"
    b"2d24b0c01b40f5f65ea1c3fc46be4c0a55d9e8bf3cc11f279204d010c87afba5b1f77314"
    b"4010975cf1b3c302818100f06b1abf1c88afd70e0f378d05da71a19b73a70782308854de"
    b"660504ceb64007c130cacfabfd41056783c8dec167f7a13c201ef9248e22eeeb26970d7c"
    b"66937f785b7c9875e0e482639d41e425d2fcbaa9102ea43d28a609c7aa0478b58530dd85"
    b"aa07e754a8d60bb77e09237ad3d2e9e05284d6f6d47a0f672bd6ed4b126ec50281801028"
    b"187b9e6ed8d680b823ca42f15d91aa4dba3e8f03c668562579b79f3d6d65f3da3e36b007"
    b"5e705da380ecc5287d0afe9bb6b4e7942086fce8592dbb0cf14a10f5dec12d3c52ae26d4"
    b"869683cc002fe6438a3f4ffbef8d93a6899c099d518d797d51591c3fe12715a5cf44154d"
    b"dcbc6ad97be828de72a1d199cc48be57de470281805f81fcef1cf3c3ff07ebcda2ad4799"
    b"4a9d09b5ba0ae322d5ac40151052da1dd7b6cc9e551fbb0d008b9dd3c78247be1d0458b2"
    b"55414b61df4df5579e98e3db069196ae8996928fd4a8a409500c22a419b71de199875e45"
    b"8faf0d0097bf6cb8fbd7a4b35d17c9b6b692df73dbef6884ea3a1e2dfd83b2e7068572e9"
    b"fffc89c70d02818100c6f0a5d971f506e8ad97c4ba2aa75312ebb6ca74eb615cc997416f"
    b"a24ea85c87e23966a7a2da4497777913f5f5acf2022fafc20fbfad70bd9c881cd9449ef6"
    b"5ab19cc4a75d175d157ef4158813ffd0e26b95be65705699d5f926f6e1c39e370b9c0a22"
    b"e246ba6ea164adbedbd9b869104bdda7fc12da2e32c06a43d2d7ed85f0"
)

cert = binascii.unhexlify(
    b"308203ef308202d7a003020102021460c7e11ec6a121f0dd6aef2a7b0301a221a87d7430"
    b"0d06092a864886f70d01010b0500308186310b3009060355040613025858311230100603"
    b"5504080c0953746174654e616d653111300f06035504070c08436974794e616d65311430"
    b"12060355040a0c0b436f6d70616e794e616d65311b3019060355040b0c12436f6d70616e"
    b"7953656374696f6e4e616d65311d301b06035504030c14436f6d6d6f6e4e616d654f7248"
    b"6f73746e616d65301e170d3233303530393031323330345a170d33333035303630313233"
    b"30345a308186310b30090603550406130258583112301006035504080c0953746174654e"
    b"616d653111300f06035504070c08436974794e616d6531143012060355040a0c0b436f6d"
    b"70616e794e616d65311b3019060355040b0c12436f6d70616e7953656374696f6e4e616d"
    b"65311d301b06035504030c14436f6d6d6f6e4e616d654f72486f73746e616d6530820122"
    b"300d06092a864886f70d01010105000382010f003082010a0282010100ddd15235530b1a"
    b"22a05c9e4ba7ac53ec77364c34b7996b2ddf4f7bb4552ede4146f171ba0b8f90b773c10c"
    b"99eabfa70abd42db43b691fd5e1c2ce8c95f19fc88196f06f8e00bbf21454e264e718399"
    b"e14949a2dce2074603e84b987235bba4fd3f06f901a9203f7cc10965c3e36b42b05c8347"
    b"dd013fa32967ca9b1eba2cfc29643909b6223709cba64026a0b7a20336998263290716f9"
    b"873942bb7fabeca6acf6279aadd557f7b66215ab6b173df8d74e02b000e9f9c0fef0d212"
    b"f4e7b27503175ebe0b5c6dfca16b6a9ba513d0103528c3dd28004f5c08f8be639072a6b6"
    b"95e362ace0f22b33177aa603903886186be5f72bd3f59d45cc5e16949a25f31f0f020301"
    b"0001a3533051301d0603551d0e041604145a8348a360553e9126445a3a9a021814587885"
    b"8b301f0603551d230418301680145a8348a360553e9126445a3a9a0218145878858b300f"
    b"0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010036"
    b"ed2d254f450e8aa0a57d09e36338ff2e0cec6a8ea67f713f08235a9e45c1a44e28835b26"
    b"04437149970a1dfee53fe03401f1c679686f838b685d9e29a72c150fdce71c9bf4097b54"
    b"e1024eb65d73cf715c31ea228c00f960373faf962f211401bbdd7ee1c694ad1effa69cdf"
    b"dbfcf042963083995bcd1f8ac98ea7218cab69b78a0ecd7c17a5d95e8f4666210668ee42"
    b"4b1334dcdf300c85ff8e2e2f6bfaa9900e56aae762f6151e78c359741d399ce49b80ece0"
    b"6f05d55c9eb4fe3441b5992167e8614b8f1784e00927a962ac764911f9611aaadc8f613f"
    b"d0bd4c5b1aef90ce3a51c342fb6f28ad6290f8b9ab1434a5e54c862493a4f9928f77f9c0"
    b"e1d210"
)

class _Pipe(io.IOBase):
    def __init__(self):
        self._other = None

        self.block_reads = False
        self.block_writes = False

        self.write_buffers = []
       
        self.last_poll_arg = None

    def readinto(self, buf):
        if self.block_reads or len(self._other.write_buffers) == 0:
            return None

        read_buf = self._other.write_buffers[0]
        l = min(len(buf), len(read_buf))
        buf[:l] = read_buf[:l]
        if l == len(read_buf):
            self._other.write_buffers.pop(0)
        else:
            self._other.write_buffers[0] = read_buf[l:]
        return l

    def write(self, buf):
        if self.block_writes:
            return None

        self.write_buffers.append(memoryview(bytes(buf)))
        return len(buf)

    def ioctl(self, request, arg):
        if request == _MP_STREAM_POLL:
            self.last_poll_arg = arg
            ret = 0
            if arg & _MP_STREAM_POLL_RD:
                if not self.block_reads and self._other.write_buffers:
                    ret |= _MP_STREAM_POLL_RD
            if arg & _MP_STREAM_POLL_WR:
                if not self.block_writes:
                    ret |= _MP_STREAM_POLL_WR
            return ret

        elif request == _MP_STREAM_CLOSE:
            return 0

        raise NotImplementedError()

    @classmethod
    def new_pair(cls):
        p1 = cls()
        p2 = cls()
        p1._other = p2
        p2._other = p1
        return p1, p2


def assert_poll(s, i, arg, expected_arg, expected_ret):
    ret = s.ioctl(_MP_STREAM_POLL, arg)
    assert i.last_poll_arg == expected_arg
    i.last_poll_arg = None
    assert ret == expected_ret


def assert_raises(cb, *args, **kwargs):
    try:
        cb(*args, **kwargs)
        raise AssertionError("should have raised")
    except Exception as exc:
        pass


client_io, server_io = _Pipe.new_pair()

client_io.block_reads = True
client_io.block_writes = True
client_sock = ussl.wrap_socket(client_io, do_handshake=False)

server_sock = ussl.wrap_socket(server_io, key=key, cert=cert, server_side=True, do_handshake=False)

# Do a test read, at this point the TLS handshake wants to write,
# so it returns None:
assert client_sock.read(128) is None

# Polling for either read or write actually check if the underlying socket can write:
assert_poll(client_sock, client_io, _MP_STREAM_POLL_RD, _MP_STREAM_POLL_WR, 0)
assert_poll(client_sock, client_io, _MP_STREAM_POLL_WR, _MP_STREAM_POLL_WR, 0)

# Mark the socket as writable, and do another test read:
client_io.block_writes = False
assert client_sock.read(128) is None

# The client wrote the CLIENT_HELLO message
assert len(client_io.write_buffers) == 1

# At this point the TLS handshake wants to read, but we don't know that yet:
assert_poll(client_sock, client_io, _MP_STREAM_POLL_RD, _MP_STREAM_POLL_RD, 0)
assert_poll(client_sock, client_io, _MP_STREAM_POLL_WR, _MP_STREAM_POLL_WR, _MP_STREAM_POLL_WR)

# Do a test write
client_sock.write(b"foo")

# Now we know that we want to read:
assert_poll(client_sock, client_io, _MP_STREAM_POLL_RD, _MP_STREAM_POLL_RD, 0)
assert_poll(client_sock, client_io, _MP_STREAM_POLL_WR, _MP_STREAM_POLL_RD, 0)

# Unblock reads and nudge the two sockets:
client_io.block_reads = False
while server_io.write_buffers or client_io.write_buffers:
    if server_io.write_buffers:
        assert client_sock.read(128) is None
    if client_io.write_buffers:
        assert server_sock.read(128) is None

# At this point, the handshake is done, try writing data:
client_sock.write(b"foo")
assert server_sock.read(3) == b"foo"

# Test reading partial data:
client_sock.write(b"foobar")
assert server_sock.read(3) == b"foo"
server_io.block_reads = True
assert_poll(
    server_sock, server_io, _MP_STREAM_POLL_RD, None, _MP_STREAM_POLL_RD
)  # Did not go to the socket, just consumed buffered data
assert server_sock.read(3) == b"bar"


# Polling on a closed socket errors out:
client_io, _ = _Pipe.new_pair()
client_sock = ussl.wrap_socket(client_io, do_handshake=False)
client_sock.close()
assert_poll(
    client_sock, client_io, _MP_STREAM_POLL_RD, None, _MP_STREAM_POLL_NVAL
)  # Did not go to the socket

# Errors propagates to poll:
client_io, server_io = _Pipe.new_pair()
client_sock = ussl.wrap_socket(client_io, do_handshake=False)

# The server returns garbage:
server_io.write(b"fooba")  # Needs to be exactly 5 bytes

assert_poll(client_sock, client_io, _MP_STREAM_POLL_RD, _MP_STREAM_POLL_RD, _MP_STREAM_POLL_RD)
assert_raises(client_sock.read, 128)

assert_poll(
    client_sock, client_io, _MP_STREAM_POLL_RD, None, _MP_STREAM_POLL_NVAL
)  # Did not go to the socket


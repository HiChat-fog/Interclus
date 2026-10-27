#!/usr/bin/env python3
"""Stop-and-wait update sender. `send(frame)` emits one wire frame;
`recv()` returns a decoded reply tuple (code, id, next_seq, detail) or
None on timeout. Chunks are resent until the device acknowledges the
expected sequence; BEGIN and COMMIT are idempotent and may be resent.
"""
import time
from update_frame import begin, chunks, commit


class UpdateError(Exception):
    pass


class Client:
    def __init__(self, send, recv, retries=6):
        self.send = send
        self.recv = recv
        self.retries = retries
        self.sends = 0
        self.resends = 0
        self.duplicate_acks = 0

    def _exchange(self, frame_, accept):
        for attempt in range(self.retries):
            self.send(frame_)
            self.sends += 1
            if attempt:
                self.resends += 1
            deadline = time.time() + 1.0
            while time.time() < deadline:
                r = self.recv()
                if r is None:
                    continue
                code, rid, seq, detail = r
                if rid != self.tid:
                    continue
                if accept(code, seq, detail):
                    return code, seq, detail
                if code == 0x81 and detail in (2, 3):
                    break            # corrupt/out-of-order: resend
        raise UpdateError("no acceptable reply")

    def transfer(self, tid, image):
        self.tid = tid
        if not image or len(image) > 480:
            raise UpdateError("image size")
        self._exchange(begin(tid, image),
                       lambda c, s, d: c in (0x80, 0x82, 0x83, 0x84))
        for seq, frame_ in enumerate(chunks(tid, image, 32)):
            code, got, _ = self._exchange(
                frame_,
                lambda c, s, d, want=seq + 1: c == 0x80 and s >= want,
            )
            if got > seq + 1:
                self.duplicate_acks += 1
        code, _, _ = self._exchange(
            commit(tid), lambda c, s, d: c in (0x82, 0x83, 0x84))
        self.codes = [code]
        deadline = time.time() + 6.0
        while code == 0x82 and time.time() < deadline:
            r = self.recv()
            if r and r[0] in (0x83, 0x84):
                code = r[0]
                self.codes.append(code)
        return code == 0x83

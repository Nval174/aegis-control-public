import unittest
from aegis_control.netstat_snapshot import Capture, parse_netstat, NetstatError
class NetstatTests(unittest.TestCase):
 def test_values(self):
  r=parse_netstat(b"TcpExt: ListenDrops ListenOverflows\nTcpExt: 0 17\n",Capture("saved","ns",None,64))
  self.assertEqual((r.ListenDrops.value,r.ListenOverflows.value),(0,17))

 def test_fixtures_missing_and_tail(self):
  from pathlib import Path
  from dataclasses import FrozenInstanceError
  root=Path(__file__).with_name("fixtures")
  c=Capture("saved","ns",None,64)
  r=parse_netstat((root/"netstat-normal.txt").read_bytes(),c)
  self.assertEqual((r.ListenDrops.value,r.ListenOverflows.value),(0,17))
  self.assertEqual(r.capture,c)
  self.assertIsNone(r.capture.generation)
  with self.assertRaises(FrozenInstanceError): r.ListenDrops.value=4
  self.assertEqual(parse_netstat((root/"netstat-missing.txt").read_bytes(),c).ListenOverflows.reason,"field_missing")
  self.assertEqual(parse_netstat((root/"netstat-absent.txt").read_bytes(),c).ListenDrops.reason,"section_missing")
  with self.assertRaises(NetstatError): parse_netstat((root/"netstat-bad-tail.txt").read_bytes(),c)
 def test_syntax_and_numbers(self):
  c=Capture("a","ns","g",64)
  good=b"TcpExt: ListenDrops\nTcpExt: 0"
  for raw in (None,b"",b" \n",b"TcpExt: ListenDrops",good+b"\n"+good,
              b"TcpExt: A A\nTcpExt: 1 2",b"TcpExt: A B\nTcpExt: 1",
              b"TcpExt: A\nOther: 1",good+b"\nIpExt: A\nIpExt: -1",
              good+b"\x00",good+b"\r",good+b"\x7f",good+b"\xff"):
   with self.subTest(raw=raw),self.assertRaises(NetstatError): parse_netstat(raw,c)
  for token in (b"-1",b"1.0",b"1e3",b"+1",b"9"*21):
   with self.assertRaises(NetstatError): parse_netstat(b"TcpExt: A\nTcpExt: "+token,c)
  self.assertEqual(parse_netstat(b"\nTcpExt:\tListenDrops\r\nTcpExt: 0\r\n",c).ListenDrops.value,0)
  for bits in (32,64):
   limit=(1<<bits)-1
   for value,valid in ((limit,True),(limit+1,False)):
    raw=f"TcpExt: ListenDrops\nTcpExt: {value}".encode()
    if valid: self.assertEqual(parse_netstat(raw,Capture("a","n",None,bits)).ListenDrops.value,value)
    else:
     with self.assertRaises(NetstatError): parse_netstat(raw,Capture("a","n",None,bits))


class NetstatLimitTests(unittest.TestCase):
    def test_limits_metadata(self):
        from aegis_control.netstat_snapshot import MAX_BYTES, MAX_LINE
        good = b"TcpExt: ListenDrops\nTcpExt: 0\n"
        c = Capture("a", "n", None, 64)
        # Exactly128 lines, each<=8192, exactly64KiB by bounded blank padding.
        lines = [good.rstrip(b"\n").split(b"\n")[0], b"TcpExt: 0"] + [b" " * 511] * 126
        raw = b"\n".join(lines)
        raw += b" " * (MAX_BYTES - len(raw))
        self.assertEqual(len(raw), MAX_BYTES)
        parse_netstat(raw, c)
        for bad, reason in ((raw + b" ", "byte limit"), (good + b"\n" * 128, "line limit"),
                            (b" " * (MAX_LINE + 1), "line limit")):
            with self.assertRaisesRegex(NetstatError, reason):
                parse_netstat(bad, c)
        names = ["A" + str(i) for i in range(512)]
        raw = ("TcpExt: " + " ".join(names) + "\nTcpExt: " + " ".join(["0"] * 512)).encode()
        parse_netstat(raw, c)
        with self.assertRaisesRegex(NetstatError, "token count"):
            parse_netstat(raw + b" 0", c)
        parse_netstat(("TcpExt: " + "A" * 64 + "\nTcpExt: 0").encode(), c)
        with self.assertRaisesRegex(NetstatError, "field names"):
            parse_netstat(("TcpExt: " + "A" * 65 + "\nTcpExt: 0").encode(), c)
        for meta in (Capture("b", "n", None, 64), Capture("a", "m", None, 64), Capture("a", "n", "g", 64)):
            self.assertNotEqual(parse_netstat(good, meta), parse_netstat(good, c))
        for meta in (None, Capture("PRIVATE/path", "n", None, 64), Capture("a", "n", None, True)):
            with self.assertRaises(NetstatError) as e:
                parse_netstat(good, meta)
            self.assertNotIn("PRIVATE", str(e.exception))

    def test_isolated_line_and_token_ceilings(self):
        c = Capture("a", "n", None, 64)
        line = b"TcpExt: 0" + b" " * (8192 - len(b"TcpExt: 0"))
        parse_netstat(b"TcpExt: ListenDrops\n" + line, c)
        with self.assertRaisesRegex(NetstatError, "line limit"):
            parse_netstat(b"TcpExt: ListenDrops\n" + line + b" ", c)
        raw = ("TcpExt: " + " ".join("A" + str(i) for i in range(513)) + "\nTcpExt: " + " ".join(["0"] * 513)).encode()
        with self.assertRaisesRegex(NetstatError, "token count"):
            parse_netstat(raw, c)

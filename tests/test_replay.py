import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aegis_control.config import load_config
from aegis_control.replay import replay_file, replay_stream
from aegis_control.telemetry import TelemetryError
from test_telemetry import sample

ROOT = Path(__file__).resolve().parents[1]


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.config = load_config(ROOT / "configs/observe.example.toml")
        self.service = self.config.services[0].id

    def encoded(self, **changes):
        return json.dumps(sample(service_id=self.service, **changes)).encode()+b"\n"

    def replay(self, raw, **kw):
        return replay_stream(io.BytesIO(raw), self.config, as_of=160,
                             max_age=60, catalog=("/", "/login"), **kw)

    def test_latest_uses_collection_time_not_file_order_and_no_rates(self):
        raw=self.encoded(value=10, collected_at=110)+self.encoded(value=1)
        r=self.replay(raw)
        self.assertEqual(r["latest"][0]["value"], 10)
        self.assertEqual(r["records"], 2)
        self.assertEqual(r["coverage"], "not_assessed")
        self.assertFalse(r["enforcement"])
        self.assertNotIn("secret", json.dumps(r))
        self.assertEqual(self.replay(raw), r)

    def test_states_and_empty_are_visible(self):
        r=self.replay(self.encoded()+self.encoded(observed_at=99)+
                      self.encoded(state="UNKNOWN", value=None, observed_at=None)+
                      self.encoded(source="cloudfront_waf", state="NOT_APPLICABLE",
                                   value=None, observed_at=None))
        self.assertEqual(r["counts"], dict(OBSERVED=1, STALE=1, UNKNOWN=1, NOT_APPLICABLE=1))
        self.assertEqual(r["status"], "DEGRADED")
        self.assertEqual(self.replay(b"")["status"], "UNKNOWN")

    def test_valid_observation_with_duplicate_field_is_rejected(self):
        raw=self.encoded().rstrip()[:-1]+b',"value":9}\n'
        with self.assertRaises(TelemetryError): self.replay(raw)

    def test_equal_collection_time_uses_file_order(self):
        a,b=self.encoded(value=2),self.encoded(value=7)
        self.assertEqual(self.replay(a+b)["latest"][0]["value"],7)
        self.assertEqual(self.replay(b+a)["latest"][0]["value"],2)

    def test_cli_empty_unknown_disabled_only_and_partial_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"fixture.jsonl"
            args=[sys.executable,"-B","-m","aegis_control","replay",
                  str(ROOT/"configs/observe.example.toml"),str(p),"--as-of","160"]
            cases=((b"",1,"UNKNOWN"),
                   (self.encoded(state="UNKNOWN",observed_at=None,value=None),1,"DEGRADED"),
                   (self.encoded(source="cloudfront_waf",state="NOT_APPLICABLE",
                                 observed_at=None,value=None),0,"COMPLETE"))
            for raw,code,status in cases:
                p.write_bytes(raw)
                r=subprocess.run(args,capture_output=True,text=True)
                self.assertEqual(r.returncode,code,r.stderr)
                self.assertEqual(json.loads(r.stdout)["status"],status)
                self.assertEqual(json.loads(r.stdout)["coverage"],"not_assessed")
            p.write_bytes(self.encoded()+b'{"PRIVATE":')
            r=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(r.returncode,1)
            self.assertEqual(r.stdout,"")
            self.assertNotIn("PRIVATE",r.stderr)

    def test_malformed_encoding_duplicate_keys_and_nonfinite_are_sanitized(self):
        for raw in (b'{"secret":', b'\xff', b'{"state":1,"state":2}',
                    b'NaN', b'[]', b'\n', b'['*2000):
            with self.subTest(raw=raw[:12]):
                with self.assertRaises(TelemetryError) as caught: self.replay(raw)
                self.assertNotIn("secret", str(caught.exception))

    def test_record_total_and_key_limits_reject_not_truncate(self):
        with self.assertRaises(TelemetryError): self.replay(b" "*16385)
        raw=self.encoded()
        self.assertEqual(self.replay(raw*1000)["records"],1000)
        with self.assertRaises(TelemetryError): self.replay(raw*1001)
        # Each record is legal, but the total byte budget is exceeded.
        padded=raw[:-1]+b" "*(16000-len(raw))+b"\n"
        with self.assertRaises(TelemetryError): self.replay(padded*66)
        many=load_config(ROOT / "configs/observe.example.toml")
        # 4 sources are disabled, but each N/A key still consumes bounded space.
        routes=tuple(f"/{i}" for i in range(32))
        sources=("proxy","flask_to_ad","windows_event_forwarding","cloudfront_waf","home_gateway_api")
        lines=[]
        for source in sources:
            for route in routes:
                d=sample(service_id=self.service, source=source, route=route)
                if source!="proxy": d.update(state="NOT_APPLICABLE",observed_at=None,value=None)
                lines.append(json.dumps(d).encode()+b"\n")
        r=replay_stream(io.BytesIO(b"".join(lines[:128])),many,as_of=160,max_age=60,catalog=routes)
        self.assertEqual(len(r["latest"]),128)
        with self.assertRaises(TelemetryError):
            replay_stream(io.BytesIO(b"".join(lines[:129])),many,as_of=160,max_age=60,catalog=routes)

    def test_record_byte_boundary_and_bounded_reads(self):
        raw=self.encoded()
        exact=raw[:-1]+b" "*(16384-len(raw))+b"\n"
        self.assertEqual(len(exact),16384)
        self.assertEqual(self.replay(exact)["records"],1)
        with self.assertRaises(TelemetryError): self.replay(exact[:-1]+b" \n")
        class Guard(io.BytesIO):
            def readline(self, size=-1):
                self_size=size
                if not 0 < self_size <= 16385: raise AssertionError("unbounded read")
                return super().readline(size)
        replay_stream(Guard(raw),self.config,as_of=160,max_age=60)

    def test_file_errors_and_preservation(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"fixture.jsonl"; raw=self.encoded(); p.write_bytes(raw)
            replay_file(p,self.config,as_of=160,max_age=60)
            self.assertEqual(p.read_bytes(),raw)
            for target in (folder, p.with_name("missing"), "https://example.invalid", "//server/share"):
                with self.assertRaises(TelemetryError): replay_file(target,self.config,as_of=160,max_age=60)
            with patch("pathlib.Path.open",side_effect=PermissionError("private")):
                with self.assertRaises(TelemetryError) as caught: replay_file(p,self.config,as_of=160,max_age=60)
                self.assertNotIn("private",str(caught.exception))

    def test_cli_real_execution_exits_help_and_no_doctor_collection(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/"fixture.jsonl"; p.write_bytes(self.encoded())
            prefix=[sys.executable,"-B","-m","aegis_control","replay",
                    str(ROOT/"configs/observe.example.toml"),str(p),"--as-of","160"]
            ok=subprocess.run(prefix,capture_output=True,text=True)
            self.assertEqual(ok.returncode,0,ok.stderr)
            self.assertEqual(json.loads(ok.stdout)["records"],1)
            p.write_bytes(self.encoded(observed_at=99))
            self.assertEqual(subprocess.run(prefix,capture_output=True).returncode,1)
            p.write_bytes(b'{"SECRET":')
            bad=subprocess.run(prefix,capture_output=True,text=True)
            self.assertEqual(bad.returncode,1)
            self.assertNotIn("SECRET",bad.stderr)
            self.assertEqual(subprocess.run(prefix+["--max-age","0"],capture_output=True).returncode,1)
            self.assertEqual(subprocess.run(prefix[:-2],capture_output=True).returncode,2)
            self.assertEqual(subprocess.run(prefix+["--help"],capture_output=True).returncode,0)
            from aegis_control.__main__ import main
            p.write_bytes(self.encoded())
            with patch("aegis_control.__main__.collect_report", side_effect=AssertionError("collector called")):
                with patch("sys.stdout",new_callable=io.StringIO):
                    self.assertEqual(main(prefix[4:]),0)

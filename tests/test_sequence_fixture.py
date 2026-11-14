"""Strict wire boundary and delegated sequence behavior; all data synthetic."""

import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aegis_control.counter_sequence import SequenceEvent, StreamKey, run_counter_sequence
from aegis_control.counters import CounterSample
from aegis_control.telemetry import MAX_TIME, MAX_VALUE, Observation

ROOT = Path(__file__).resolve().parents[1]


def event(seq=1, at=100, value=10, generation="epoch-1", kind="sample"):
    key = dict(service_id="a", source="proxy", metric="requests_total", route="/")
    sample = dict(counter_id="producer-1", generation=generation,
                  observation=key | dict(state="OBSERVED", value=value, observed_at=at, collected_at=at))
    return dict(key=key, sequence=seq, at=at, sample=sample if kind == "sample" else None,
                continuous=True, kind=kind)


def document(*events):
    return dict(schema_version=1, settings=dict(max_keys=16, retention_seconds=60, max_age=60),
                events=list(events or (event(),)))


def encoded(data):
    return json.dumps(data, separators=(",", ":")).encode()


class FixtureTests(unittest.TestCase):
    def setUp(self):
        from aegis_control import sequence_fixture
        self.api = sequence_fixture

    def reject(self, raw):
        with patch.object(self.api, "run_counter_sequence", side_effect=AssertionError("runner called")) as runner:
            with self.assertRaises(self.api.FixtureError) as caught:
                self.api.run_sequence_fixture(raw)
            runner.assert_not_called()
        self.assertLess(len(str(caught.exception)), 180)
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_saved_minimal_immutable_and_input_preserved(self):
        raw = (ROOT / "tests/fixtures/sequence-v1.minimal.json").read_bytes()
        before = bytes(raw)
        decoded = self.api.decode_sequence_fixture(raw)
        self.assertIsInstance(decoded.events, tuple)
        self.assertEqual(decoded.settings.max_keys, 16)
        result = self.api.run_sequence_fixture(raw)
        self.assertEqual((result.results[0].state, result.results[0].count), ("BASELINE", None))
        self.assertEqual(decoded.events[0].sample.observation.value, 0)
        self.assertEqual(raw, before)
        for obj, field in ((decoded, "events"), (decoded.settings, "max_keys"), (decoded.events[0], "sequence")):
            with self.assertRaises(FrozenInstanceError): setattr(obj, field, 0)

    def test_multi_fixture_matches_direct_inputs_and_concrete_oracles(self):
        raw = (ROOT / "tests/fixtures/sequence-v1.recovery.json").read_bytes()
        specs = [(1,100,10,"epoch-1","sample"), (2,110,17,"epoch-1","sample"),
                 (3,120,17,"epoch-1","sample"), (4,130,None,"epoch-1","sample"),
                 (5,140,30,"epoch-1","sample"), (6,150,34,"epoch-1","sample"),
                 (8,160,40,"epoch-1","sample"), (9,170,50,"epoch-1","sample"),
                 (10,180,54,"epoch-1","sample"), (11,190,0,"epoch-1","break"),
                 (12,200,60,"epoch-1","sample"), (13,210,0,"epoch-1","missing"),
                 (14,220,70,"epoch-1","sample"), (15,230,80,"epoch-2","sample"),
                 (16,240,90,"epoch-1","sample"), (17,250,94,"epoch-1","sample")]
        direct = tuple(SequenceEvent(StreamKey("a","proxy","requests_total","/"), seq, at,
                       None if kind != "sample" else CounterSample(Observation("a","proxy","requests_total",
                            "OBSERVED", value, at, at, "/"), "producer-1", generation),
                       True, "break" if kind == "break" else "sample")
                       for seq,at,value,generation,kind in specs)
        decoded = self.api.decode_sequence_fixture(raw)
        self.assertEqual(decoded.events, direct)
        report = self.api.run_sequence_fixture(raw)
        self.assertEqual(report, run_counter_sequence(direct))
        self.assertEqual([r.count for r in report.results], [None,7,0,None,None,4,None,None,4,None,None,None,None,None,None,4])
        self.assertEqual([report.results[i].reason for i in (3,6,9,11,13)],
                         ["invalid_payload","delivery_gap","declared_discontinuity","current_missing","generation_changed"])
        self.assertEqual([report.results[i].state for i in (4,7,10,12,14)], ["BASELINE"]*5)
        self.assertEqual(report, self.api.run_sequence_fixture(raw))

    def test_byte_ceiling_checked_before_decoding_or_parsing(self):
        raw = encoded(document())
        exact = raw + b" " * (self.api.MAX_FIXTURE_BYTES-len(raw))
        self.assertEqual(len(self.api.decode_sequence_fixture(exact).events), 1)
        with patch.object(self.api.json, "loads", side_effect=AssertionError("parser called")):
            for bad in (exact+b" ", b"\xff"*(self.api.MAX_FIXTURE_BYTES+1)):
                with self.assertRaises(self.api.FixtureError) as caught: self.api.decode_sequence_fixture(bad)
                self.assertIn("byte limit", str(caught.exception))
        for bad in (None, "PRIVATE", bytearray(raw), memoryview(raw)):
            self.reject(bad)

    def test_depth_boundary_and_quoted_brackets_escapes(self):
        # Root/events/event/sample/observation reaches exactly five containers.
        raw = encoded(document())
        self.assertEqual(len(self.api.decode_sequence_fixture(raw).events), 1)
        for bad in (b"["*6+b"0"+b"]"*6, b'{"PRIVATE":'+b"["*5+b"0"+b"]"*5+b"}"):
            with patch.object(self.api.json, "loads", side_effect=AssertionError("parser called")):
                self.reject(bad)
        data = document()
        route = '/[]{}"\\label'
        data["events"][0]["key"]["route"] = route
        data["events"][0]["sample"]["observation"]["route"] = route
        self.assertEqual(self.api.decode_sequence_fixture(encoded(data)).events[0].key.route, route)

    def test_incomplete_or_negative_depth_rejects_before_json_parser(self):
        raw = encoded(document())
        malformed = (b"]" + raw, b"][", raw[:-1], b'{"PRIVATE":"unterminated',
                     b'{"PRIVATE":"unterminated' + b"\\", b'"unterminated',
                     b'"unterminated' + b"\\")
        for bad in malformed:
            with self.subTest(raw=bad), patch.object(self.api.json, "loads", wraps=self.api.json.loads) as parser:
                self.reject(bad)
                parser.assert_not_called()

    def test_scan_preserves_quoted_escapes_and_leaves_bracket_types_to_json(self):
        for route in ('/[]{}"\\label', '/trailing\\', '/quoted"', '/\U0001f600'):
            data = document()
            data["events"][0]["key"]["route"] = route
            data["events"][0]["sample"]["observation"]["route"] = route
            with patch.object(self.api.json, "loads", wraps=self.api.json.loads) as parser:
                self.assertEqual(self.api.decode_sequence_fixture(encoded(data)).events[0].key.route, route)
                parser.assert_called_once()
        with patch.object(self.api.json, "loads", wraps=self.api.json.loads) as parser:
            self.reject(b"[}")  # balanced depth, wrong bracket type belongs to json.loads
            parser.assert_called_once()

    def test_duplicates_at_every_object_level_and_escaped_equivalence(self):
        raw = encoded(document())
        pairs = ((b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                 (b'"max_keys":16', b'"max_keys":16,"max_keys":16'),
                 (b'"sequence":1', b'"sequence":1,"sequence":1'),
                 (b'"service_id":"a"', b'"service_id":"a","service_id":"a"'),
                 (b'"counter_id":"producer-1"', b'"counter_id":"producer-1","counter_id":"producer-1"'),
                 (b'"value":10', b'"value":10,"value":10'),
                 (b'"value":10', b'"value":10,"\\u0076alue":10'))
        for old,new in pairs:
            self.reject(raw.replace(old,new,1))

    def test_invalid_utf8_bom_nonfinite_large_numbers_and_json_syntax(self):
        for raw in (b"\xff", b"\xef\xbb\xbf"+encoded(document()), b"", b"{} {}", b'{"PRIVATE":',
                    b"NaN", b"Infinity", b"-Infinity", b"1e400", b"9"*5000,
                    encoded(document()).replace(b'"value":10', b'"value":1e400')):
            self.reject(raw)
        data = document()
        data["events"][0]["key"]["route"] = "/\ud800"
        self.reject(encoded(data))
        data = document()
        for node in (data["events"][0]["key"], data["events"][0]["sample"]["observation"]):
            node["route"] = "/\U0001f600"
        self.assertEqual(self.api.decode_sequence_fixture(encoded(data)).events[0].key.route, "/\U0001f600")

    def test_version_exact_fields_oracles_and_shapes(self):
        original = document()
        for version in (True, False, 0, 2, 1.0, "1", None):
            data = copy.deepcopy(original); data["schema_version"] = version
            self.reject(encoded(data))
        paths = ((), ("settings",), ("events",0), ("events",0,"key"),
                 ("events",0,"sample"), ("events",0,"sample","observation"))
        for path in paths:
            for action in ("extra", "missing"):
                data = copy.deepcopy(original); node = data
                for part in path: node = node[part]
                if action == "extra": node["expected"] = "PRIVATE-secret"
                else: del node[next(iter(node))]
                self.reject(encoded(data))
        for data in ([], None, True, document() | {"events":{}}, document() | {"settings":[]}):
            self.reject(encoded(data))

    def test_integer_boolean_type_and_numeric_bounds(self):
        paths = (("settings","max_keys"),("settings","retention_seconds"),("settings","max_age"),
                 ("events",0,"sequence"),("events",0,"at"),
                 ("events",0,"sample","observation","value"),
                 ("events",0,"sample","observation","observed_at"),
                 ("events",0,"sample","observation","collected_at"))
        for path in paths:
            for value in (True, "1", [], -1, MAX_TIME+1):
                data = document(); node = data
                for part in path[:-1]: node = node[part]
                node[path[-1]] = value
                self.reject(encoded(data))
        for field,value in (("max_keys",0),("max_keys",65),("max_age",0),
                            ("retention_seconds",86401),("max_age",1.0)):
            data = document(); data["settings"][field] = value; self.reject(encoded(data))
        for value in (1.0, MAX_VALUE+1):
            data = document(event(value=value)); self.reject(encoded(data))
        data = document(event(seq=MAX_TIME, at=MAX_TIME, value=MAX_VALUE))
        data["settings"] = dict(max_keys=64, retention_seconds=86400, max_age=86400)
        self.assertEqual(self.api.decode_sequence_fixture(encoded(data)).events[0].sequence, MAX_TIME)
        self.assertEqual(self.api.decode_sequence_fixture(encoded(document(event(at=0,value=0)))).events[0].at, 0)

    def test_field_string_token_and_event_limits(self):
        data = document()
        route = "/"+"x"*2047
        data["events"][0]["key"]["route"] = route
        data["events"][0]["sample"]["observation"]["route"] = route
        data["events"][0]["sample"]["counter_id"] = "x"*64
        self.assertEqual(self.api.decode_sequence_fixture(encoded(data)).events[0].key.route, route)
        for path,value in ((("events",0,"key","route"),route+"x"),
                           (("events",0,"sample","generation"),"x"*65),
                           (("events",0,"sample","counter_id"),"PRIVATE/path"),
                           (("events",0,"key","route"),"/PRIVATE?secret")):
            bad = copy.deepcopy(data); node = bad
            for part in path[:-1]: node = node[part]
            node[path[-1]] = value; self.reject(encoded(bad))
        self.reject(b'{"'+b"x"*65+b'":0}')
        self.reject(b"{"+b",".join(f'"f{i}":0'.encode() for i in range(9))+b"}")
        many = document(*(event(seq=i+1) for i in range(256)))
        self.assertEqual(len(self.api.decode_sequence_fixture(encoded(many)).events),256)
        many["events"].append(event(seq=257)); self.reject(encoded(many))
        empty = document(); empty["events"] = []
        self.assertEqual(self.api.run_sequence_fixture(encoded(empty)).results, ())

    def test_late_failure_is_atomic_and_envelope_time_checked_without_runner(self):
        for change in (dict(PRIVATE="secret"), dict(sequence=True), dict(at=99), dict(continuous="true")):
            bad = event(seq=2,at=110) | change
            self.reject(encoded(document(event(),bad)))
        bad = event(seq=2,at=110); bad["sample"]["observation"]["value"] = True
        self.reject(encoded(document(event(),bad)))

    def test_wire_nullability_enums_missing_break_and_no_coercion(self):
        for change in (dict(kind="missing"),dict(kind="invalid"),dict(continuous=1), dict(sample=[])):
            self.reject(encoded(document(event() | change)))
        self.reject(encoded(document(event() | dict(kind="break"))))
        for field,value in (("source","PRIVATE"),("metric","rate"),("state","BAD")):
            data=document(); data["events"][0]["sample"]["observation"][field]=value
            self.reject(encoded(data))
        missing=event(2,110); missing["sample"]=None
        report=self.api.run_sequence_fixture(encoded(document(event(),missing,event(3,120,30),event(4,130,34))))
        self.assertEqual([r.count for r in report.results],[None,None,None,4])
        self.assertEqual(report.results[1].reason,"current_missing")

    def test_semantic_contradictions_preserved_as_reportable_invalid_payload(self):
        for change in (dict(value=None),dict(observed_at=111),dict(collected_at=120),
                       dict(state="STALE",value=5),dict(state="NOT_APPLICABLE",value=None,observed_at=None),
                       dict(service_id="b")):
            bad=event(2,110,17); bad["sample"]["observation"].update(change)
            raw=encoded(document(event(),bad,event(3,120,30),event(4,130,34)))
            decoded=self.api.decode_sequence_fixture(raw)
            self.assertIsNotNone(decoded.events[1].sample)
            report=self.api.run_sequence_fixture(raw)
            self.assertEqual(report.results[1].reason,"invalid_payload")
            self.assertEqual((report.results[2].state,report.results[3].count),("BASELINE",4))

    def test_stale_unknown_na_other_gauge_freshness_and_retention_delegate(self):
        for change,reason in ((dict(state="STALE",value=None),"current_stale"),
                              (dict(state="UNKNOWN",value=None,observed_at=None),"current_unknown")):
            bad=event(2,110); bad["sample"]["observation"].update(change)
            self.assertEqual(self.api.run_sequence_fixture(encoded(document(event(),bad))).results[-1].reason,reason)
        for settings,at,state in ((dict(retention_seconds=10),110,"AVAILABLE"),
                                  (dict(retention_seconds=10),111,"BASELINE"),
                                  (dict(retention_seconds=100,max_age=10),111,"UNAVAILABLE")):
            data=document(event(),event(2,at,17)); data["settings"].update(settings)
            self.assertEqual(self.api.run_sequence_fixture(encoded(data)).results[-1].state,state)
        for source,metric,route,state,value,observed,reason in (
                ("cloudfront_waf","requests_total","/","NOT_APPLICABLE",None,None,"current_not_applicable"),
                ("proxy","latency_ms","/","OBSERVED",1.5,100,"current_not_counter"),
                ("proxy","requests_total","OTHER","OBSERVED",10,100,"current_ambiguous_route")):
            data=document(); e=data["events"][0]; e["key"].update(source=source,metric=metric,route=route)
            e["sample"]["observation"].update(source=source,metric=metric,route=route,state=state,value=value,observed_at=observed)
            self.assertEqual(self.api.run_sequence_fixture(encoded(data)).results[0].reason,reason)

    def test_settings_eviction_and_delivery_anomalies_preserved(self):
        b=event(1,101); b["key"]["service_id"]="b"; b["sample"]["observation"]["service_id"]="b"
        data=document(event(),b,event(2,102,17)); data["settings"]["max_keys"]=1
        r=self.api.run_sequence_fixture(encoded(data))
        self.assertEqual([x.delivery for x in r.results],["unanchored"]*3)
        self.assertEqual(r.results[-1].state,"BASELINE")
        for seq,reason in ((1,"delivery_duplicate"),(3,"delivery_gap")):
            r=self.api.run_sequence_fixture(encoded(document(event(),event(seq,110,17),event(seq+1,120,30))))
            self.assertEqual(r.results[1].reason,reason)
            self.assertEqual(r.results[2].state,"BASELINE")
        r=self.api.run_sequence_fixture(encoded(document(event(2,100),event(1,110,17),
                                                          event(3,120,30),event(4,130,34))))
        self.assertEqual(r.results[1].reason,"delivery_out_of_order")
        self.assertEqual((r.results[2].state,r.results[3].count),("BASELINE",4))

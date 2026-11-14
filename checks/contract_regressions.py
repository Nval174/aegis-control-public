"""Audit-only literal oracles. No original tests/source are edited."""
from dataclasses import FrozenInstanceError, asdict
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from aegis_control.config import load_config
from aegis_control.telemetry import Observation, TelemetryError, parse_observation
from aegis_control.counters import CounterSample, advance_counter
from aegis_control.netstat_snapshot import Capture, NetstatError, parse_netstat
from aegis_control.replay import replay_file,replay_stream
from aegis_control.sequence_fixture import decode_sequence_fixture, FixtureError
from aegis_control.nginx_access import NginxLogError, parse_nginx_record
from aegis_control.nginx_batch import NginxBatchError, parse_nginx_batch

ROOT=Path(__import__('aegis_control').__file__).resolve().parents[2]

def observation(value=0):
    return dict(service_id='fixture-web',source='proxy',metric='requests_total',state='OBSERVED',
                value=value,observed_at=100,collected_at=101,route='/')

def fixture():
    return b'{"schema_version":1,"settings":{"max_keys":1,"retention_seconds":60,"max_age":60},"events":[]}'

def record(uri='/login'):
    return json.dumps(dict(schema_version=1,msec='100.000',uri=uri,status='200',request_time='0.025'),
                      separators=(',',':')).encode()

class AuditChecks(unittest.TestCase):
    def test_literal_codec_mebibyte(self):
        raw=fixture(); exact=raw+b' '*(1048576-len(raw))
        self.assertEqual(len(exact),1048576)
        self.assertEqual(decode_sequence_fixture(exact).events,())
        with self.assertRaisesRegex(FixtureError,'1-MiB byte limit'): decode_sequence_fixture(exact+b' ')

    def test_literal_proxy_numeric_ceiling(self):
        good=parse_observation(observation(1000000000000),{'fixture-web'},('/',),as_of=160,max_age=60)
        self.assertEqual(good.value,1000000000000); self.assertIs(type(good.value),int)
        with self.assertRaises(TelemetryError):
            parse_observation(observation(1000000000001),{'fixture-web'},('/',),as_of=160,max_age=60)

    def test_counter_zero_has_exact_int_types(self):
        a=CounterSample(Observation(**observation(7)),'producer','epoch')
        b=CounterSample(Observation(**(observation(7)|dict(observed_at=110,collected_at=110))),'producer','epoch')
        r=advance_counter(a,b,as_of=110,continuous=True)
        self.assertEqual((r.state,r.reason,r.count,r.elapsed_seconds),('AVAILABLE','difference',0,10))
        self.assertIs(type(r.count),int); self.assertIs(type(r.elapsed_seconds),int)
        self.assertIs(r.next_baseline,b)

    def test_netstat_unrelated_uint64_with_declared_32(self):
        for n in (4294967296,18446744073709551615):
            raw=f'IpExt: InOctets\nIpExt: {n}\nTcpExt: ListenDrops ListenOverflows\nTcpExt: 0 1\n'.encode()
            s=parse_netstat(raw,Capture('saved','ns',None,32))
            self.assertEqual((s.ListenDrops.value,s.ListenOverflows.value),(0,1))
        with self.assertRaises(NetstatError):
            parse_netstat(b'IpExt: InOctets\nIpExt: 18446744073709551616\n',Capture('saved','ns',None,32))

    def replay_inputs(self):
        config=load_config(ROOT/'configs/observe.example.toml')
        raw=json.dumps(observation()|dict(service_id=config.services[0].id)).encode()
        def row(size): return raw+b' '*(size-len(raw)-1)+b'\n'
        return config,row

    def test_replay_exact_total_stream_and_file(self):
        config,row=self.replay_inputs(); raw=row(16384)*64
        self.assertEqual(len(raw),1048576)
        for mode in ('stream','file'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as folder:
                p=Path(folder)/'audit.jsonl'; p.write_bytes(raw)
                r=(replay_stream(io.BytesIO(raw),config,as_of=160) if mode=='stream' else
                   replay_file(p,config,as_of=160))
                self.assertEqual((r['status'],r['records'],r['coverage']),('COMPLETE',64,'not_assessed'))
                self.assertEqual(len(r['latest']),1); self.assertEqual(r['latest'][0]['value'],0)
                self.assertEqual(p.read_bytes(),raw)

    def test_replay_isolated_total_overflow(self):
        config,row=self.replay_inputs(); raw=row(16384)*63+row(8192)+row(8193)
        self.assertEqual(len(raw),1048577); self.assertEqual(raw.count(b'\n'),65)
        with self.assertRaises(TelemetryError): replay_stream(io.BytesIO(raw),config,as_of=160)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'audit.jsonl';p.write_bytes(raw)
            with self.assertRaises(TelemetryError): replay_file(p,config,as_of=160)

    def test_replay_oversized_exponent_sanitized_atomic(self):
        config,_=self.replay_inputs()
        valid=json.dumps(observation()|dict(service_id=config.services[0].id)).encode()+b'\n'
        for numeric in (b'1e999999',b'0.'+b'1'*14000,b'9'*14000):
            raw=b'{"AUDIT_PRIVATE_MARKER":'+numeric+b'}\n'
            with self.assertRaises(TelemetryError) as caught:
                replay_stream(io.BytesIO(valid+raw),config,as_of=160)
            self.assertLess(len(str(caught.exception)),200)
            self.assertNotIn('AUDIT_PRIVATE_MARKER',str(caught.exception))

    def test_nginx_privacy_and_atomic_tail(self):
        for path in ('/users/AUDIT_PRIVATE_MARKER','/login?AUDIT_PRIVATE_MARKER','/login#AUDIT_PRIVATE_MARKER'):
            raw=record(path); saved=bytes(raw)
            r=parse_nginx_record(raw,service_id='audit',catalog=('/login',))
            self.assertEqual(asdict(r),dict(service_id='audit',route='OTHER',status=200,logged_at_ms=100000,request_time_ms=25))
            self.assertNotIn('AUDIT_PRIVATE_MARKER',repr(r)+json.dumps(asdict(r)))
            self.assertEqual(raw,saved)
            with self.assertRaises(FrozenInstanceError):r.route='bad'
        with self.assertRaises(NginxLogError):
            parse_nginx_record(record()+b'\n{}',service_id='audit',catalog=('/login',))

    def test_batch_preflight_before_decoder_and_unexpected_exception(self):
        raw=record()+b'\n'+record()
        with patch('aegis_control.nginx_batch.parse_nginx_record',side_effect=AssertionError('called')) as spy:
            with self.assertRaisesRegex(NginxBatchError,'unterminated_tail'):
                parse_nginx_batch(raw,service_id='audit',catalog=('/login',))
            spy.assert_not_called()
        marker=RuntimeError('AUDIT_PRIVATE_MARKER')
        with patch('aegis_control.nginx_batch.parse_nginx_record',side_effect=marker):
            try: parse_nginx_batch(record()+b'\n',service_id='audit',catalog=('/login',))
            except RuntimeError as error:self.assertIs(error,marker)
            else:self.fail('unexpected exception swallowed')

if __name__=='__main__':unittest.main(verbosity=2)

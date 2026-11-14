"""Pure saved namespace counters; no native reads, arithmetic or continuity inference."""
from dataclasses import dataclass
import re

MAX_BYTES = 65536
MAX_LINES = 128
MAX_LINE = 8192
MAX_TOKENS = 513
NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}", re.ASCII)
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", re.ASCII)

class NetstatError(ValueError):
    """Sanitized fatal document or metadata error."""

@dataclass(frozen=True)
class Capture:
    source: str
    namespace: str
    generation: str | None
    word_bits: int

@dataclass(frozen=True)
class CounterValue:
    value: int | None
    reason: str

@dataclass(frozen=True)
class NetstatSnapshot:
    capture: Capture
    ListenDrops: CounterValue
    ListenOverflows: CounterValue

def parse_netstat(raw, capture):
    if type(raw) is not bytes:
        raise NetstatError("snapshot requires bytes")
    if len(raw) > MAX_BYTES:
        raise NetstatError("snapshot byte limit exceeded")
    if type(capture) is not Capture:
        raise NetstatError("capture metadata required")
    for token in (capture.source, capture.namespace, capture.generation):
        if token is None and token is capture.generation:
            continue
        if type(token) is not str or LABEL.fullmatch(token) is None:
            raise NetstatError("invalid capture label")
    if capture.source is None or capture.namespace is None:
        raise NetstatError("source and namespace labels required")
    if type(capture.word_bits) is not int or capture.word_bits not in (32,64):
        raise NetstatError("declared TcpExt width must be 32 or 64")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise NetstatError("snapshot must be ASCII") from None
    text = text.replace("\r\n", "\n")
    if any(ord(c)<32 and c not in " \t\n" or ord(c)==127 for c in text):
        raise NetstatError("snapshot contains unsupported controls")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines)>MAX_LINES or any(len(line)>MAX_LINE for line in lines):
        raise NetstatError("snapshot line limit exceeded")
    rows = [line.split() for line in lines if line.strip()]
    if not rows:
        raise NetstatError("empty snapshot input")
    if len(rows)%2:
        raise NetstatError("truncated snapshot pair")
    seen=set()
    targets=None
    for i in range(0,len(rows),2):
        header, values=rows[i:i+2]
        if not 2<=len(header)<=MAX_TOKENS or len(header)!=len(values):
            raise NetstatError("snapshot token count invalid")
        section=header[0]
        if not section.endswith(":") or NAME.fullmatch(section[:-1]) is None or values[0]!=section:
            raise NetstatError("snapshot pair labels invalid")
        if section in seen:
            raise NetstatError("repeated snapshot section")
        seen.add(section)
        names=header[1:]
        if any(NAME.fullmatch(n) is None for n in names) or len(set(names))!=len(names):
            raise NetstatError("snapshot field names invalid or duplicate")
        maximum=(1<<capture.word_bits)-1 if section=="TcpExt:" else (1<<64)-1
        selected={}
        for name,token in zip(names,values[1:]):
            if not 1<=len(token)<=20 or any(c not in "0123456789" for c in token):
                raise NetstatError("snapshot counter token invalid")
            value=int(token)
            if value>maximum:
                raise NetstatError("snapshot counter exceeds supported unsigned domain")
            if section=="TcpExt:" and name in ("ListenDrops","ListenOverflows"):
                selected[name]=value
        if section=="TcpExt:":
            targets=selected
    def result(name):
        if targets is None:
            return CounterValue(None,"section_missing")
        if name not in targets:
            return CounterValue(None,"field_missing")
        return CounterValue(targets[name],"observed")
    return NetstatSnapshot(capture,result("ListenDrops"),result("ListenOverflows"))

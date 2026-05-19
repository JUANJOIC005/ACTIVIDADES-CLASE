from __future__ import annotations

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer


class LabAuthoritativeResolver(BaseResolver):
    zone = "lab.local."
    records = {
        "www.lab.local.": "10.10.30.200",
        "dns.lab.local.": "10.10.30.100",
    }

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=0), q=request.q)
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        if qtype in ("A", "ANY") and qname in self.records:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.records[qname]), ttl=30))
        elif qname.endswith(self.zone):
            reply.header.rcode = RCODE.NXDOMAIN
        else:
            reply.header.rcode = RCODE.REFUSED

        return reply


def main() -> None:
    resolver = LabAuthoritativeResolver()
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger)
    print("Servidor DNS autoritativo escuchando en 0.0.0.0:53 para lab.local.", flush=True)
    server.start()


if __name__ == "__main__":
    main()

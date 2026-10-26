"""Use maintained warcio to verify records; never infer integrity from a crawl exit."""
import gzip
import json
import sys
from pathlib import Path
from warcio.archiveiterator import ArchiveIterator


def verify(directory):
    records = []
    for path in sorted(Path(directory).rglob('*.warc.gz')):
        # Also verify gzip trailers: a valid leading WARC is insufficient for a truncated object.
        with gzip.open(path, 'rb') as stream:
            while stream.read(1024 * 1024):
                pass
        with path.open('rb') as stream:
            for record in ArchiveIterator(stream, check_digests=True):
                payload = record.raw_stream.read()
                if record.payload_length >= 0 and len(payload) != record.payload_length:
                    raise ValueError('Truncated WARC payload')
                if record.rec_type in ('response','resource'):
                    if record.digest_checker.passed is not True:
                        raise ValueError('Missing or invalid WARC digest')
                    if record.rec_headers.get_header('WARC-Truncated'):
                        raise ValueError('WARC records truncated content')
                    row = {'id':record.rec_headers.get_header('WARC-Record-ID'), 'url':record.rec_headers.get_header('WARC-Target-URI'), 'type':record.rec_type,'bytes':len(payload)}
                    if record.http_headers:
                        row['status'] = int(record.http_headers.get_statuscode())
                        row['contentType'] = record.http_headers.get_header('Content-Type') or ''
                        declared = record.http_headers.get_header('Content-Length')
                        if declared is not None and int(declared) != len(payload):
                            raise ValueError('HTTP payload length mismatch')
                    if row['url'].startswith(('urn:comparison:','urn:text:','urn:pageinfo:')):
                        row['text'] = payload.decode('utf-8')
                    records.append(row)
    if not records:
        raise ValueError('No readable WARC response/resource records')
    return {'integrityState':'verified','records':records}


if __name__ == '__main__':
    print(json.dumps(verify(sys.argv[1])))

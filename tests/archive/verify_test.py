import gzip
import importlib.util
import io
import pathlib
import tempfile
import unittest
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

spec=importlib.util.spec_from_file_location('verify','/tools/verify.py')
verify=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyTests(unittest.TestCase):
    def make(self,root,length=3):
        path=pathlib.Path(root)/'fixture.warc.gz'
        with path.open('wb') as output:
            writer=WARCWriter(output,gzip=True)
            record=writer.create_warc_record('https://example.org/','response',payload=io.BytesIO(b'abc'),http_headers=StatusAndHeaders('200 OK',[('Content-Type','text/html'),('Content-Length',str(length))],protocol='HTTP/1.1'))
            writer.write_record(record)
            record.raw_stream.close()
        return path

    def test_real_records_pass_and_changed_payload_digest_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path=self.make(root)
            result=verify.verify(root)
            self.assertEqual(result['integrityState'],'verified')
            self.assertEqual(result['records'][0]['bytes'],3)
            raw=gzip.decompress(path.read_bytes()).replace(b'\r\n\r\nabc',b'\r\n\r\nxyz')
            path.write_bytes(gzip.compress(raw))
            with self.assertRaises(ValueError): verify.verify(root)

    def test_truncated_gzip_and_wrong_http_length_fail(self):
        with tempfile.TemporaryDirectory() as root:
            path=self.make(root)
            path.write_bytes(path.read_bytes()[:-8])
            with self.assertRaises((EOFError,ValueError)): verify.verify(root)
            self.make(root,length=999)
            with self.assertRaises(ValueError): verify.verify(root)


if __name__=='__main__': unittest.main()

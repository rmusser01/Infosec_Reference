import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('policy', ROOT / 'tools/archive/policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def test_public_dns_is_pinned_and_mixed_private_answers_are_rejected(self):
        self.assertEqual(policy.public_address('example.org', 443, lambda h,p: ['93.184.215.14']), '93.184.215.14')
        for addresses in [['127.0.0.1'], ['::1'], ['169.254.169.254'], ['224.0.0.1'], ['::ffff:127.0.0.1'], ['64:ff9b::7f00:1'], ['2002:7f00:1::'], ['93.184.215.14','10.0.0.1']]:
            with self.assertRaises(ValueError):
                policy.public_address('example.org', 443, lambda h,p: addresses)

    def test_seed_documents_only_and_no_image_body_until_article_membership_is_known(self):
        config = {'documents':['https://example.org/article?q=1'], 'images':[]}
        self.assertTrue(policy.request_allowed('https://example.org/article?q=1','',config))
        self.assertFalse(policy.request_allowed('https://example.org/article?q=2','document',config))
        self.assertFalse(policy.request_allowed('https://example.org/figure.png','image',config))
        config['images'] = ['https://example.org/figure.png']
        self.assertTrue(policy.request_allowed('https://example.org/figure.png','image',config))
        self.assertFalse(policy.request_allowed('https://example.org/advert.png','image',config))
        self.assertFalse(policy.request_allowed('https://video.example/movie','video',config))
        self.assertFalse(policy.request_allowed('https://example.org/frame','iframe',config))
        self.assertFalse(policy.request_allowed('https://tracker.example/collect','empty',config))
        self.assertFalse(policy.request_allowed('https://example.org/theme/js/count.js','script',config))

    def test_headers_reject_mislabeled_nontext_before_body(self):
        config = {'documents':['https://example.org/article'], 'images':['https://example.org/figure']}
        for mime in ['application/pdf','video/mp4','application/octet-stream','application/zip']:
            self.assertFalse(policy.response_allowed('https://example.org/article',mime,config))
        self.assertTrue(policy.response_allowed('https://example.org/article','text/html; charset=utf-8',config))
        self.assertTrue(policy.response_allowed('https://example.org/figure','image/png',config))
        self.assertFalse(policy.response_allowed('https://example.org/ad','image/png',config))
        self.assertTrue(policy.response_allowed('https://example.org/style','text/css',config))
        self.assertFalse(policy.response_allowed('https://example.org/frame','text/html',config))

    def test_unsafe_schemes_credentials_and_ports_are_rejected(self):
        for url in ['file:///etc/passwd','https://user:pass@example.org/','http://example.org:2375/']:
            self.assertFalse(policy.request_allowed(url,'document',{'documents':[url],'images':[]}))

    def test_redirects_do_not_exempt_nontext_bodies(self):
        config={'documents':['https://example.org/start'],'images':[]}
        self.assertFalse(policy.redirect_body_allowed('https://example.org/start','video/mp4',0,config))
        self.assertFalse(policy.redirect_body_allowed('https://example.org/start','application/pdf',0,config))
        self.assertFalse(policy.redirect_body_allowed('https://example.org/start','',100,config))
        self.assertTrue(policy.redirect_body_allowed('https://example.org/start','',0,config))
        self.assertTrue(policy.redirect_body_allowed('https://example.org/start','text/html',200,config))


if __name__ == '__main__':
    unittest.main()

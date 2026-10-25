"""Synthetic public URLs: fixtures are served before DNS; the production guard stays installed."""
import base64
from mitmproxy import http

TEXT = 'This controlled article explains archive verification, preserving readable text and its inline figure while excluding advertising and standalone media. ' * 4
BODY = '<article><h1>Archive fixture</h1><p>'+TEXT+'</p><figure><img src="/figure.png" alt="Required figure"></figure><aside><img src="/advert.png"></aside><video src="/movie.mp4" preload="auto"></video><a href="/paper.pdf">Paper</a></article>'
PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aRZkAAAAASUVORK5CYII=')


def request(flow):
    if flow.error or flow.request.host != 'archive-fixture.invalid':
        return
    path = flow.request.path.split('?')[0]
    status, mime, body = 200, 'text/html', ''
    if path == '/redirect':
        flow.response = http.Response.make(302,b'',{'Location':'/article'})
        return
    if path == '/redirect-media':
        flow.response = http.Response.make(302,b'media-must-not-be-captured',{'Location':'/article','Content-Type':'video/mp4'})
        return
    if path == '/private':
        flow.response = http.Response.make(302,b'',{'Location':'http://127.0.0.1/'})
        return
    if path == '/challenge':
        body='<title>Just a moment...</title><main>Verify you are human</main>'
    elif path == '/article':
        body='<title>Static archive fixture</title><nav><img src="/logo.png"></nav><main>'+BODY+'</main>'
    elif path == '/lazy':
        body='<title>Lazy figure fixture</title><main>'+BODY.replace('<img src="/figure.png"','<img loading="lazy" style="margin-top:5000px" src="/figure.png"')+'</main>'
    elif path == '/javascript':
        body='<title>JavaScript archive fixture</title><main id="root"></main><script src="/app.js"></script>'
    elif path == '/app.js':
        import json
        mime='application/javascript'
        body='document.getElementById("root").innerHTML='+json.dumps(BODY)+';'
    elif path.endswith('.png'):
        mime,body='image/png',PNG
    elif path in ('/paper.pdf','/mislabeled'):
        mime,body='application/pdf',b'%PDF-not-in-article-pipeline'
    elif path.endswith('.mp4'):
        mime,body='video/mp4',b'media-must-not-be-captured'
    else:
        status,body=404,'<title>Missing</title><main>Not found</main>'
    flow.response=http.Response.make(status,body,{'Content-Type':mime})

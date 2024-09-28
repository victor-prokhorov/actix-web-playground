- [actix web static files example](https://github.com/actix/examples/tree/c42b85587dd6f6606d4d21921d02ca565e5d683a/basics/static-files)
- [HTML validator](https://validator.w3.org/)
```sh
curl http://127.0.0.1:3001/signup \
     -d "username=username&password=password"
```
- [actix forms extractor example](https://github.com/actix/examples/blob/c42b85587dd6f6606d4d21921d02ca565e5d683a/forms/form/src/main.rs)
- [setting up rustls example](https://github.com/actix/examples/blob/c42b85587dd6f6606d4d21921d02ca565e5d683a/https-tls/rustls/src/main.rs)
```sh
curl -v https://127.0.0.1:3000/index.html --compressed -k
# -k is shorthand for --insecure
```
```sh
curl -v https://127.0.0.1:3001/signup \
    -d "username=username&password=password" \
    --cacert ./cert.pem 
```
- mTLS seems also possible
- [PR](https://github.com/actix/actix-web/issues/1727)
- [implementation example](https://github.com/actix/examples/blob/master/https-tls/rustls-client-cert/src/main.rs)
- [jwt crate](https://github.com/Keats/jsonwebtoken)
- [from_fn middleware example](https://github.com/LukeMathWalker/zero-to-production/blob/970987c5f793af6fc8e557731c9bbb23b620451e/src/authentication/middleware.rs#L28)
- [websocket echo server example](https://github.com/actix/examples/blob/master/websockets/echo-actorless/src/handler.rs)
- [html page to test ws](https://github.com/actix/examples/blob/master/websockets/echo/static/index.html)
- [grpc via tonic hello world](https://github.com/hyperium/tonic/blob/master/examples/helloworld-tutorial.md)

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

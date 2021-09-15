# picohttpclient

A generic, lightweight HTTP 1.1 client.
It was born out of the need to quickly do very simple HTTP requests, without adding larger dependencies to a project.

License: MIT

* no complex features, no chunking, no keepalive ...
* not very tested, use at your own risk!
* it PURPOSELY does not use any feature-complete libraries (like cURL) to stay lean and header-only.
* it does not use C++11 features to fit well in legacy code bases
* it has some suboptimal properties (like many string copy ops)

Usage as easy as (see `main.cpp` for an example):

```C++
HTTPResponse response = HTTPClient::request(HTTPClient::GET, URI("http://example.com"));
cout << response.body << endl;
```

optional support for https
--------------------------

1) You need to set a macro :
```C++
#define PICOHTTP_SSL
#include "picohttpclient.hpp"
```

2) You need to add two extra linker flags (openssl library)
```sh
   c++ -lssl -lcrypto snippet.cpp
```

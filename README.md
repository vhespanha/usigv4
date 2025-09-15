# usigv4

minimal aws signature version 4 implementation for micropython/embedded use.

## why

while the sigv4 algorithm is very straightforward, this implementation tries to
optimize it for microcontrollers and the like by making most of the string
manipulation in-place.

## what it does

- signs http requests per aws sigv4 spec
- zero dependencies beyond stdlib and micropython-lib
- micropython compatible (no datetime, string ops in-place)

## todo (patches are welcome):

- support querystring signing
- support multiple headers
- support presigned urls

## usage

```python
from usigv4 import sign_request_headers
import requests

headers = sign_request_headers(
    method="POST",
    host="lambda.us-west-2.amazonaws.com",
    path="/2025-03-31/functions/my-func/invocations",
    body=b'{"hello": "world"}', # byte representation of header data
    ak="AKIA...",
    sk="wJal...",
    region="us-west-2",
    service="lambda"
)

resp = requests.post(
    "https://lambda.us-west-2.amazonaws.com/2025-03-31/functions/my-func/invocations",
    headers=headers, # signed headers
    data=b'{"hello": "world"}' # must be identical to headers' body
)
```

## caveats

- body must be bytes for hashing
- only signs host header (sufficient for some aws apis)
- hardcoded json content-type
- depends on time.gmtime()'s accuracy

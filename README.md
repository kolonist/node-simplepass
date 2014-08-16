Simple authorisation library based on one plain text file with simple structure.


# Installation

The library is in `npm` repository, so you need simply run in command string:

```
npm i simplepass
```

# Usage

Require library:

```JavaScript
var simplepass = require('simplepass');
```

Open passwords file:

```JavaScript
simplepass.open('test/passwd.tmp', function(err) {
    // place your code here
});
```


Add user:

```JavaScript
var username    = 'user';
var password    = 'pA$$w0rD';
var permissions = [1, 0, 1, 0, 0, 1, 0];

// add user
simplepass.add(username, password, permissions, function(err) {
    // place your code here
});
```


Authorisation:

```JavaScript
var username = 'user';
var password = 'pA$$w0rD';
var permissions;

// authorise
simplepass.auth(username, password, function(err, access, permissions) {
    // place your code here
});
```




If you want this library always stay actual you can:
- donate (more info: http://xinit.ru/donate/)
- use sms.ru from this access point: http://xinit.sms.ru/ (it makes no
  differences for you but allow me to get a little money)
- send SMS messages with this library (here is my agent code which makes no
  differences for you but allow me to get a little money)
- comment, share, spread this library
- send issues, pull requests


@license MIT
@version 0.0.1
@author Alexander Zubakov <developer@xinit.ru>

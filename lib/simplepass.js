// Generated by CoffeeScript 2.2.4
'use strict';
var E_CANT_CREATE_FILE, E_CANT_READ_FILE, E_CANT_SAVE_FILE, E_FILE_NOT_OPENED, E_NOT_ENOUGHT_ENTROPY, E_NO_SUCH_USER, E_PBKDF2_ERROR, E_PERMS_NOT_SUITABLE, E_WRONG_USERNAME, add, auth, crypto, digest, events, exists, fs, iterations, keylen, open, parsePasswd, passwd, passwdFilename, path, preparePermissions, re_username, remove, saltlen, save, updatePassword, updatePermissions;

fs = require('fs');

path = require('path');

events = require('events');

crypto = require('crypto');

// ############################ Private data ################################## #

// Error message constants

E_FILE_NOT_OPENED = 'You should open database before perform any other actions';

E_CANT_CREATE_FILE = 'Can\'t create empty password file';

E_CANT_READ_FILE = 'Can\'t read password file';

E_CANT_SAVE_FILE = 'Can\'t save password file';

E_NOT_ENOUGHT_ENTROPY = 'Not enought entropy to create password salt';

E_PBKDF2_ERROR = 'Can\'t execute PBKDF2() with given parameters';

E_PERMS_NOT_SUITABLE = 'Permissions parameter is not in suitable format';

E_WRONG_USERNAME = 'Username contains wrong characters';

E_NO_SUCH_USER = 'User does not exist';

// RegExp to validate username.

re_username = new RegExp(/^[a-zA-Z\d._@-]+$/);

// Crypto constants

saltlen = 32; // 32 bytes, 256 bits

keylen = 32; // 32 bytes, 256 bits

iterations = 8192; // iterations count for PBKDF2

digest = 'sha512'; // HMAC digest algorithm


// Object with usernames and passwords with the following structure:
// {
//     'username': {
//         password   : Buffer('password hash'),
//         salt       : Buffer('salt used to produce password hash'),
//         permissions: 0  // permissions bitmask
//     }
// }

passwd = null;

// Filename of database file.

passwdFilename = null;

// ########################## Private methods ################################# #

// Parse user and password database into `passwd` structure.

// @param string data Plain text data in the following format:
//                    [ USERNAME ":" PASS ":" SALT ":" PERM "\n" ]
//                    PASS and SALT are in base64.
// @return object Literal object with the structure described in `passwd`.

parsePasswd = function(data) {
  var lines, passwdRes;
  if (typeof data === 'string') {
    if (data.trim() !== '') {
      passwdRes = {};
      // parse each line
      lines = data.trim().split('\n');
      lines.forEach(function(line) {
        var parts;
        parts = line.split(':');
        // line format is correct
        if (parts.length === 4) {
          // add new user description object
          return passwdRes[parts[0]] = {
            password: new Buffer(parts[1], 'base64'),
            salt: new Buffer(parts[2], 'base64'),
            permissions: parts[3]
          };
        }
      });
      return passwdRes;
    } else {
      return {};
    }
  } else {
    return {};
  }
};

// Parse permissions and return it as integer number (bitmask).

// @param [number, array] permissions Optional permissions of user. If number
//                                    then used as is. If array then every
//                                    element is 0 or 1 (false or true), indicate
//                                    exactly one bit of number to store in
//                                    database. If not set then 0 will be stored.
// @return [number, boolean] Number representation of permissions or false if
//                           `permissions` is wrong.

preparePermissions = function(permissions) {
  var compiledPermissions;
  // transform permissions
  if (typeof permissions !== 'number') {
    // transform array elements into permissions bits
    if (Array.isArray(permissions)) {
      compiledPermissions = 0;
      permissions.forEach(function(e, i) {
        var mask;
        if (Boolean(e)) {
          mask = 1 << permissions.length - i - 1; // mask to set bit
          return compiledPermissions |= mask; // apply mask
        }
      });
      return compiledPermissions;
    } else {
      // permissions is not in suitable format
      return false;
    }
  } else {
    // just return permissions number (bitmask)
    return permissions;
  }
};

// Save previously opened database.

// @param string filename Name of password file. If no file exists then it will
//                        be created.
// @param callback onReady Function (err). Err will not be null if file
//                         `filename` does not exist and can't be created or if
//                         it can't be read from.

save = function(onReady) {
  var data, username, userobj;
  // form data to save
  data = '';
  for (username in passwd) {
    userobj = passwd[username];
    data += username + ':' + userobj.password.toString('base64') + ':' + userobj.salt.toString('base64') + ':' + userobj.permissions + '\n';
  }
  // write it to file system
  return fs.writeFile(passwdFilename, data, {
    encoding: 'utf8'
  }, function(err) {
    return onReady(err != null ? new Error(E_CANT_SAVE_FILE) : null);
  });
};

// ########################### Public methods ################################# #

// Read user and password database (plain text file).

// @param string filename Name of password file. If no file exists then it will
//                        be created.
// @param callback onReady Function (err). Err will not be null if file
//                         `filename` does not exist and can't be created or if
//                         it can't be read from.

open = function(filename, onReady) {
  return fs.exists(filename, function(exists) {
    // read file and parse it
    if (exists) {
      return fs.readFile(filename, {
        encoding: 'utf8'
      }, function(err, data) {
        if (err == null) {
          passwd = parsePasswd(data);
          passwdFilename = filename;
          return onReady(null);
        } else {
          return onReady(new Error(E_CANT_READ_FILE));
        }
      });
    } else {
      // create empty file
      return fs.writeFile(filename, '', function(err) {
        if (err == null) {
          passwd = {};
          passwdFilename = filename;
          return onReady(null);
        } else {
          return onReady(new Error(E_CANT_CREATE_FILE));
        }
      });
    }
  });
};

// Add new user to database. Note that if user with given username already exists
// then it will be replaced by provided.

// @param string username Name of user. Only latin letters, digits, '.', '_', '-'
//                        and '@' allowed.
// @param string password Password.
// @param [number, array] permissions Optional permissions of user. If number
//                                    then used as is. If array then every
//                                    element is 0 or 1 (false or true), indicate
//                                    exactly one bit of number to store in
//                                    database. If not set then 0 will be stored.
// @param callback onReady Function (err).

add = function(username, password, permissions, onReady) {
  // permissions is not set
  if (onReady == null) {
    onReady = permissions;
    permissions = 0;
  }
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  // check username
  if (!re_username.test(username)) {
    onReady(new Error(E_WRONG_USERNAME));
    return;
  }
  // transform permissions
  permissions = preparePermissions(permissions);
  if (permissions === false) {
    onReady(new Error(E_PERMS_NOT_SUITABLE));
    return;
  }
  // create salt for password hash
  return crypto.randomBytes(saltlen, function(err, salt) {
    if (err == null) {
      // create password hash
      return crypto.pbkdf2(password, salt, iterations, keylen, digest, function(err, derivedKey) {
        if (err == null) {
          password = derivedKey;
          // append global `passwd` object
          passwd[username] = {
            password: password,
            salt: salt,
            permissions: permissions
          };
          return save(function(err) {
            return onReady(err);
          });
        } else {
          return onReady(new Error(E_PBKDF2_ERROR));
        }
      });
    } else {
      return onReady(new Error(E_NOT_ENOUGHT_ENTROPY));
    }
  });
};

// Check if user with given username exists.

// @param string username Name of user.
// @param callback onReady Function (err, exists). True if user exists or false
//                         in case there is no such user.
// @return boolean True if user exists or false if there is no such user.

exists = function(username, onReady) {
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (passwd[username] != null) {
    if (onReady != null) {
      onReady(null, true);
    }
    return true;
  } else {
    if (onReady != null) {
      onReady(null, false);
    }
    return false;
  }
};

// Remove user from database.

// @param string username Name of user.
// @param callback onReady Function (err, removed). Removed is true if user
//                         removed from database or false otherwise. Also if
//                         there is no user in database then `err` will be not
//                         null.

remove = function(username, onReady) {
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (passwd[username] != null) {
    delete passwd[username];
    return save(function(err) {
      return onReady(err, true);
    });
  } else {
    return onReady(new Error(E_NO_SUCH_USER));
  }
};

// Change password.

// @param string username Name of user.
// @param string password Password.
// @param callback onReady Function (err, changed). Changed is true if password
//                         changed in database or false otherwise. Also if
//                         there is no user in database then `err` will be not
//                         null.

updatePassword = function(username, password, onReady) {
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (passwd[username] != null) {
    // create salt for password hash
    return crypto.randomBytes(saltlen, function(err, salt) {
      if (err == null) {
        // create password hash
        return crypto.pbkdf2(password, salt, iterations, keylen, digest, function(err, derivedKey) {
          if (err == null) {
            passwd[username].password = derivedKey;
            return save(function(err) {
              if (err == null) {
                return onReady(null, true);
              } else {
                return onReady(err);
              }
            });
          } else {
            return onReady(new Error(E_PBKDF2_ERROR));
          }
        });
      } else {
        return onReady(new Error(E_NOT_ENOUGHT_ENTROPY));
      }
    });
  } else {
    return onReady(new Error(E_NO_SUCH_USER));
  }
};

// Change permissions.

// @param string username Name of user.
// @param [number, array] permissions Optional permissions of user. If number
//                                    then used as is. If array then every
//                                    element is 0 or 1 (false or true), indicate
//                                    exactly one bit of number to store in
//                                    database. If not set then 0 will be stored.
// @param callback onReady Function (err, changed). Changed is true if
//                         permissions changed or false otherwise. Also if
//                         there is no user in database then `err` will be not
//                         null.

updatePermissions = function(username, permissions, onReady) {
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (passwd[username] != null) {
    permissions = preparePermissions(permissions);
    if (permissions !== false) {
      passwd[username].permissions = permissions;
      return save(function(err) {
        if (err == null) {
          return onReady(null, true);
        } else {
          return onReady(err);
        }
      });
    } else {
      return onReady(new Error(E_PERMS_NOT_SUITABLE));
    }
  } else {
    return onReady(new Error(E_NO_SUCH_USER));
  }
};

// Check if username and password exists in passwords database and password
// corresponds to username.

// @param string username Username.
// @param string password Password.
// @param callback onReady Function (err, access, permissions). If username and
//                         password are correct then access is true. Access is
//                         false if user does not exist or if password is wrong.
//                         permissions is number (bitmask) with user permissions.

auth = function(username, password, onReady) {
  if (passwd[username] != null) {
    // create password hash
    return crypto.pbkdf2(password, passwd[username].salt, iterations, keylen, digest, function(err, derivedKey) {
      if (err == null) {
        return onReady(null, passwd[username].password.toString('base64') === derivedKey.toString('base64'), passwd[username].permissions);
      } else {
        return onReady(new Error(E_PBKDF2_ERROR));
      }
    });
  } else {
    return onReady(null, false);
  }
};

exports.open = open;

exports.auth = auth;

exports.add = add;

exports.remove = remove;

exports.updatePassword = updatePassword;

exports.updatePermissions = updatePermissions;

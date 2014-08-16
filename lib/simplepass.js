// Generated by CoffeeScript 1.7.1
'use strict';
var E_CANT_CREATE_FILE, E_CANT_READ_FILE, E_CANT_SAVE_FILE, E_FILE_NOT_OPENED, E_NOT_ENOUGHT_ENTROPY, E_NO_SUCH_USER, E_PBKDF2_ERROR, E_PERMS_NOT_SUITABLE, E_WRONG_USERNAME, add, auth, crypto, events, exists, fs, iterations, keylen, open, parsePasswd, passwd, passwdFilename, path, preparePermissions, re_username, remove, saltlen, save, updatePassword, updatePermissions;

fs = require('fs');

path = require('path');

events = require('events');

crypto = require('crypto');

E_FILE_NOT_OPENED = 'You should open database before perform any other actions';

E_CANT_CREATE_FILE = 'Can\'t create empty password file';

E_CANT_READ_FILE = 'Can\'t read password file';

E_CANT_SAVE_FILE = 'Can\'t save password file';

E_NOT_ENOUGHT_ENTROPY = 'Not enought entropy to create password salt';

E_PBKDF2_ERROR = 'Can\'t execute PBKDF2() with given parameters';

E_PERMS_NOT_SUITABLE = 'Permissions parameter is not in suitable format';

E_WRONG_USERNAME = 'Username contains wrong characters';

E_NO_SUCH_USER = 'User does not exist';

re_username = new RegExp(/^[a-zA-Z\d._@-]+$/);

saltlen = 32;

keylen = 32;

iterations = 8192;

passwd = null;

passwdFilename = null;

parsePasswd = function(data) {
  var lines, passwdRes;
  if (typeof data === 'string') {
    if (data.trim() !== '') {
      passwdRes = {};
      lines = data.trim().split('\n');
      lines.forEach(function(line) {
        var parts;
        parts = line.split(':');
        if (parts.length === 4) {
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

preparePermissions = function(permissions) {
  var compiledPermissions;
  if (typeof permissions !== 'number') {
    if (Array.isArray(permissions)) {
      compiledPermissions = 0;
      permissions.forEach(function(e, i) {
        var mask;
        if (Boolean(e)) {
          mask = 1 << permissions.length - i - 1;
          return compiledPermissions |= mask;
        }
      });
      return compiledPermissions;
    } else {
      return false;
    }
  } else {
    return permissions;
  }
};

save = function(onReady) {
  var data, username, userobj;
  data = '';
  for (username in passwd) {
    userobj = passwd[username];
    data += username + ':' + userobj.password.toString('base64') + ':' + userobj.salt.toString('base64') + ':' + userobj.permissions + '\n';
  }
  return fs.writeFile(passwdFilename, data, {
    encoding: 'utf8'
  }, function(err) {
    return onReady(err != null ? new Error(E_CANT_SAVE_FILE) : null);
  });
};

open = function(filename, onReady) {
  return fs.exists(filename, function(exists) {
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

add = function(username, password, permissions, onReady) {
  if (onReady == null) {
    onReady = permissions;
    permissions = 0;
  }
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (!re_username.test(username)) {
    onReady(new Error(E_WRONG_USERNAME));
    return;
  }
  permissions = preparePermissions(permissions);
  if (permissions === false) {
    onReady(new Error(E_PERMS_NOT_SUITABLE));
    return;
  }
  return crypto.randomBytes(saltlen, function(err, salt) {
    if (err == null) {
      return crypto.pbkdf2(password, salt, iterations, keylen, function(err, derivedKey) {
        if (err == null) {
          password = derivedKey;
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

updatePassword = function(username, password, onReady) {
  if (passwd == null) {
    onReady(new Error(E_FILE_NOT_OPENED));
    return;
  }
  if (passwd[username] != null) {
    return crypto.randomBytes(saltlen, function(err, salt) {
      if (err == null) {
        return crypto.pbkdf2(password, salt, iterations, keylen, function(err, derivedKey) {
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

auth = function(username, password, onReady) {
  if (passwd[username] != null) {
    return crypto.pbkdf2(password, passwd[username].salt, iterations, keylen, function(err, derivedKey) {
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
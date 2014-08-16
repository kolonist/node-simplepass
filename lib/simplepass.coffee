'use strict'
fs     = require 'fs'
path   = require 'path'
events = require 'events'
crypto = require 'crypto'


# ############################ Private data ################################## #

# Error message constants
#
E_FILE_NOT_OPENED     = 'You should open database before perform any other actions'
E_CANT_CREATE_FILE    = 'Can\'t create empty password file'
E_CANT_READ_FILE      = 'Can\'t read password file'
E_CANT_SAVE_FILE      = 'Can\'t save password file'
E_NOT_ENOUGHT_ENTROPY = 'Not enought entropy to create password salt'
E_PBKDF2_ERROR        = 'Can\'t execute PBKDF2() with given parameters'
E_PERMS_NOT_SUITABLE  = 'Permissions parameter is not in suitable format'
E_WRONG_USERNAME      = 'Username contains wrong characters'
E_NO_SUCH_USER        = 'User does not exist'


# RegExp to validate username.
#
re_username = new RegExp(/^[a-zA-Z\d._@-]+$/)


# Crypto constants
#
saltlen    = 32    # 32 bytes, 256 bits
keylen     = 32    # 32 bytes, 256 bits
iterations = 8192  # iterations count for PBKDF2


# Object with usernames and passwords with the following structure:
# {
#     'username': {
#         password   : Buffer('password hash'),
#         salt       : Buffer('salt used to produce password hash'),
#         permissions: 0  // permissions bitmask
#     }
# }
#
passwd = null


# Filename of database file.
#
passwdFilename = null


# ########################## Private methods ################################# #

# Parse user and password database into `passwd` structure.
#
# @param string data Plain text data in the following format:
#                    [ USERNAME ":" PASS ":" SALT ":" PERM "\n" ]
#                    PASS and SALT are in base64.
# @return object Literal object with the structure described in `passwd`.
#
parsePasswd = (data) ->
    if typeof data is 'string'
        if data.trim() isnt ''
            passwdRes = {}

            # parse each line
            lines = data.trim().split '\n'
            lines.forEach (line) ->
                parts = line.split ':'

                # line format is correct
                if parts.length is 4

                    # add new user description object
                    passwdRes[parts[0]] =
                        password   : new Buffer(parts[1], 'base64')
                        salt       : new Buffer(parts[2], 'base64')
                        permissions: parts[3]
            passwdRes
        else
            {}
    else
        {}


# Parse permissions and return it as integer number (bitmask).
#
# @param [number, array] permissions Optional permissions of user. If number
#                                    then used as is. If array then every
#                                    element is 0 or 1 (false or true), indicate
#                                    exactly one bit of number to store in
#                                    database. If not set then 0 will be stored.
# @return [number, boolean] Number representation of permissions or false if
#                           `permissions` is wrong.
#
preparePermissions = (permissions) ->
    # transform permissions
    if typeof permissions isnt 'number'
        # transform array elements into permissions bits
        if Array.isArray(permissions)
            compiledPermissions = 0
            permissions.forEach (e, i) ->
                if Boolean(e)
                    mask = 1 << permissions.length - i - 1  # mask to set bit
                    compiledPermissions |= mask             # apply mask
            compiledPermissions

        # permissions is not in suitable format
        else
            false

    # just return permissions number (bitmask)
    else
        permissions


# Save previously opened database.
#
# @param string filename Name of password file. If no file exists then it will
#                        be created.
# @param callback onReady Function (err). Err will not be null if file
#                         `filename` does not exist and can't be created or if
#                         it can't be read from.
#
save = (onReady) ->
    # form data to save
    data = ''
    for username, userobj of passwd
        data += username                            + ':' +
                userobj.password.toString('base64') + ':' +
                userobj.salt.toString('base64')     + ':' +
                userobj.permissions                 + '\n'

    # write it to file system
    fs.writeFile passwdFilename, data, { encoding: 'utf8' }, (err) ->
        onReady if err? then new Error(E_CANT_SAVE_FILE) else null


# ########################### Public methods ################################# #

# Read user and password database (plain text file).
#
# @param string filename Name of password file. If no file exists then it will
#                        be created.
# @param callback onReady Function (err). Err will not be null if file
#                         `filename` does not exist and can't be created or if
#                         it can't be read from.
#
open = (filename, onReady) ->
    fs.exists filename, (exists) ->
        # read file and parse it
        if exists
            fs.readFile filename, {encoding: 'utf8'}, (err, data) ->
                if not err?
                    passwd = parsePasswd data
                    passwdFilename = filename
                    onReady null
                else
                    onReady new Error(E_CANT_READ_FILE)

        # create empty file
        else
            fs.writeFile filename, '', (err) ->
                if not err?
                    passwd = {}
                    passwdFilename = filename
                    onReady null
                else
                    onReady new Error(E_CANT_CREATE_FILE)


# Add new user to database. Note that if user with given username already exists
# then it will be replaced by provided.
#
# @param string username Name of user. Only latin letters, digits, '.', '_', '-'
#                        and '@' allowed.
# @param string password Password.
# @param [number, array] permissions Optional permissions of user. If number
#                                    then used as is. If array then every
#                                    element is 0 or 1 (false or true), indicate
#                                    exactly one bit of number to store in
#                                    database. If not set then 0 will be stored.
# @param callback onReady Function (err).
#
add = (username, password, permissions, onReady) ->
    # permissions is not set
    if not onReady?
        onReady     = permissions
        permissions = 0

    if not passwd?
        onReady new Error(E_FILE_NOT_OPENED)
        return

    # check username
    if not re_username.test(username)
        onReady new Error(E_WRONG_USERNAME)
        return

    # transform permissions
    permissions = preparePermissions permissions
    if permissions is false
        onReady new Error(E_PERMS_NOT_SUITABLE)
        return

    # create salt for password hash
    crypto.randomBytes saltlen, (err, salt) ->
        if not err?
            # create password hash
            crypto.pbkdf2 password, salt, iterations, keylen, (err, derivedKey) ->
                if not err?
                    password = derivedKey

                    # append global `passwd` object
                    passwd[username] =
                        password   : password
                        salt       : salt
                        permissions: permissions

                    save (err) ->
                        onReady err
                else
                    onReady new Error(E_PBKDF2_ERROR)
        else
            onReady new Error(E_NOT_ENOUGHT_ENTROPY)


# Check if user with given username exists.
#
# @param string username Name of user.
# @param callback onReady Function (err, exists). True if user exists or false
#                         in case there is no such user.
# @return boolean True if user exists or false if there is no such user.
#
exists = (username, onReady) ->
    if not passwd?
        onReady new Error(E_FILE_NOT_OPENED)
        return

    if passwd[username]?
        onReady(null, true) if onReady?
        true
    else
        onReady(null, false) if onReady?
        false


# Remove user from database.
#
# @param string username Name of user.
# @param callback onReady Function (err, removed). Removed is true if user
#                         removed from database or false otherwise. Also if
#                         there is no user in database then `err` will be not
#                         null.
#
remove = (username, onReady) ->
    if not passwd?
        onReady new Error(E_FILE_NOT_OPENED)
        return

    if passwd[username]?
        delete passwd[username]
        save (err) ->
            onReady err, true
    else
        onReady new Error(E_NO_SUCH_USER)


# Change password.
#
# @param string username Name of user.
# @param string password Password.
# @param callback onReady Function (err, changed). Changed is true if password
#                         changed in database or false otherwise. Also if
#                         there is no user in database then `err` will be not
#                         null.
#
updatePassword = (username, password, onReady) ->
    if not passwd?
        onReady new Error(E_FILE_NOT_OPENED)
        return

    if passwd[username]?
        # create salt for password hash
        crypto.randomBytes saltlen, (err, salt) ->
            if not err?
                # create password hash
                crypto.pbkdf2 password, salt, iterations, keylen, (err, derivedKey) ->
                    if not err?
                        passwd[username].password = derivedKey
                        save (err) ->
                            if not err?
                                onReady null, true
                            else
                                onReady err
                    else
                        onReady new Error(E_PBKDF2_ERROR)
            else
                onReady new Error(E_NOT_ENOUGHT_ENTROPY)
    else
        onReady new Error(E_NO_SUCH_USER)


# Change permissions.
#
# @param string username Name of user.
# @param [number, array] permissions Optional permissions of user. If number
#                                    then used as is. If array then every
#                                    element is 0 or 1 (false or true), indicate
#                                    exactly one bit of number to store in
#                                    database. If not set then 0 will be stored.
# @param callback onReady Function (err, changed). Changed is true if
#                         permissions changed or false otherwise. Also if
#                         there is no user in database then `err` will be not
#                         null.
#
updatePermissions = (username, permissions, onReady) ->
    if not passwd?
        onReady new Error(E_FILE_NOT_OPENED)
        return

    if passwd[username]?
        permissions = preparePermissions permissions
        if permissions isnt false
            passwd[username].permissions = permissions
            save (err) ->
                if not err?
                    onReady null, true
                else
                    onReady err
        else
            onReady new Error(E_PERMS_NOT_SUITABLE)
    else
        onReady new Error(E_NO_SUCH_USER)


# Check if username and password exists in passwords database and password
# corresponds to username.
#
# @param string username Username.
# @param string password Password.
# @param callback onReady Function (err, access, permissions). If username and
#                         password are correct then access is true. Access is
#                         false if user does not exist or if password is wrong.
#                         permissions is number (bitmask) with user permissions.
#
auth = (username, password, onReady) ->
    if passwd[username]?
        # create password hash
        crypto.pbkdf2 password, passwd[username].salt, iterations, keylen, (err, derivedKey) ->
            if not err?
                onReady(
                    null,
                    passwd[username].password.toString('base64') is derivedKey.toString('base64'),
                    passwd[username].permissions
                )
            else
                onReady new Error(E_PBKDF2_ERROR)
    else
        onReady null, false


exports.open   = open
exports.auth   = auth
exports.add    = add
exports.remove = remove

exports.updatePassword    = updatePassword
exports.updatePermissions = updatePermissions

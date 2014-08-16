'use strict'
events = require 'events'

console.log '\nSTART TEST\n'

console.log 'require lib'
simplepass = require '../lib/simplepass.coffee'


simplepass.open 'test/passwd.tmp', (err) ->
    console.log 'open not existant passwords file'
    console.log 'Error:', err

    if not err?
        emitter = new events.EventEmitter
        count = 10

        console.log '\nADD USERS\n'
        do ->  # 1
            username = 'root'
            password = 'pA$$w0rD'

            simplepass.add username, password, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with no permissions"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 2
            username    = 'user1'
            password    = 'pA$$w0rD'
            permissions = [1, 0, 1, 0, 0, 1, 0]

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 3
            username    = 'user2'
            password    = 'pA$$w0rD--2'
            permissions = [0, 0, 1, 1, 0, 0, 1]

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 4
            username    = 'user3'
            password    = 'pA$$w0rD--3'
            permissions = 64

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 5
            username    = 'user4'
            password    = 'pA$$w0rD--4'
            permissions = 0

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 6
            username    = 'user5'
            password    = 'pA$$w0rD--5'
            permissions = 1

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 7
            username    = 'user6'
            password    = 'pA$$w0rD--6'
            permissions = [1, 1, 1, 1, 1, 1, 1]

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 8
            username    = 'user-21$'
            password    = 'pA$$w0rD--6'
            permissions = [1, 1, 1, 1, 1, 1, 1]

            simplepass.add username, password, permissions, (err) ->
                console.log "add wrong user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 9
            username    = 'user7'
            password    = 'pA$$w0rD--7'
            permissions = [on, 0, 1, off, off, on, 0]

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        do ->  # 10
            username    = 'user8'
            password    = 'pA$$w0rD--8'
            permissions = 25

            simplepass.add username, password, permissions, (err) ->
                console.log "add user `#{username}` with password `#{password}` and with permissions `#{permissions}`"
                console.log 'Error:', err
                count--
                emitter.emit 'useradded'

        # authorize
        emitter.on 'useradded', ->
            # all users added
            if count <= 0
                count = 4

                console.log '\nAUTHORISATION\n'
                do ->  # 1
                    username = 'root'
                    password = 'pA$$w0rD'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauth'

                do ->  # 2
                    username = 'user7'
                    password = 'pA$$w0rD--7'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauth'

                do ->  # 3
                    username = 'user'
                    password = 'password'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauth'

                do ->  # 4
                    username = 'root'
                    password = 'pA$$w0rD2'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauth'


        # authorize
        emitter.on 'userauth', ->
            # all authorisations passed
            if count <= 0
                count = 4

                console.log '\nREMOVE SOME USERS\n'
                do ->  # 1
                    username = 'user7'
                    simplepass.remove username, (err, removed) ->
                        console.log "remove user `#{username}`: #{removed}"
                        console.log 'Error:', err
                        count--
                        emitter.emit 'usersremoved'

                do ->  # 2
                    username = 'user5'
                    simplepass.remove username, (err, removed) ->
                        console.log "remove user `#{username}`: #{removed}"
                        console.log 'Error:', err
                        count--
                        emitter.emit 'usersremoved'

                do ->  # 3
                    username = 'user100500'
                    simplepass.remove username, (err, removed) ->
                        console.log "remove user `#{username}`: #{removed}"
                        console.log 'Error:', err
                        count--
                        emitter.emit 'usersremoved'

                do ->  # 4
                    username = 'user2'
                    simplepass.remove username, (err, removed) ->
                        console.log "remove user `#{username}`: #{removed}"
                        console.log 'Error:', err
                        count--
                        emitter.emit 'usersremoved'


        # try authorize removed (not existing) user
        emitter.on 'usersremoved', ->
            if count <= 0
                count = 2

                console.log '\nAUTHORISATION REMOVED\n'
                do ->  # 1
                    username = 'user7'
                    password = 'pA$$w0rD--7'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize removed user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauthremoved'

                do ->  # 2
                    username = 'user2'
                    password = 'pA$$w0rD--2'

                    simplepass.auth username, password, (err, access) ->
                        console.log "authorize removed user `#{username}` with password `#{password}`"
                        console.log 'Error:', err
                        console.log "Access [#{if access then 'GRANTED' else 'DENIED'}]"
                        count--
                        emitter.emit 'userauthremoved'


        # update something
        emitter.on 'userauthremoved', ->
            # all authorisations passed
            if count <= 0
                console.log '\nUPDATE SMTH\n'

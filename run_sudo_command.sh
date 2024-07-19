#!/usr/bin/expect -f
set CMD [lindex $argv 0]
set PASSWORD [lindex $argv 1]
set USERNAME [lindex $argv 2]

spawn sudo sh -c "$CMD"
expect {
    "password for $USERNAME:" {
        send "$PASSWORD\r"
        exp_continue
    }
    eof
}

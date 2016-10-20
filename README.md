# cleanup close_wait

The script will close all in the half-close state of the client socket connection,
only support UNIX/LINUX.

command: cleanup_closewait -s --server ipaddr:port [-c --client ipaddr:port]
                           --all
                           -h --help

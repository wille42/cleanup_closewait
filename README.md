# cleanup close_wait

The script will close all in the half-close state of the client socket connection,
only support UNIX/LINUX.

__command:__ 

```
-- close all
python cleanup_closewait.py --all

python cleanup_closewait.py -s 192.168.0.1:50010
```

nfs.lua
=============

LUA extention for wireshark to print time spent by server
to process NFS requests.

Usage:
```bash
# for life capture
$ tshark -q -X lua_script:nfs.lua -f "port 2049"

# or if nfs trafic is not on a standard port ( pNFS DS )
$ tshark -q -X lua_script:nfs.lua -f "port 32049" -d tcp.port==32049,rpc

# for read from existing capture file capture file
$ tshark -q -r nfs.dump -X lua_script:nfs.lua

# or if you need to avoid temp files
$ dumpcap -q -w - -f "port 2049" 2>/dev/null | tshark -r - -q -X lua_script:nfs.lua
```

Eventually, you need to enable LUA extension on some distributions (RHEL6) in **/usr/share/wireshark/init.lua**
```
run_user_scripts_when_superuser = true
disable_lua = false
```
An example output looks like:

|**timestamp** |  **client ip** | **server ip** | **time in sec.ms** | **nfs op / compound main op**|

```
# v4
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.001 v4_EXCHANGE_ID
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.001 v4_CREATE_SESSION
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.001 v4_PUTROOTFH
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.002 v4_RECLAIM_COMPLETE
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.001 v4_PUTROOTFH
"Aug 27, 2014 16:44:43.000 CEST" aaaa:bbbb:ccc:10a0::1:7f <=> aaaa:bbbb:ccc:10bf::1:8c 0.001 v4_DESTROY_SESSION
"Aug 27, 2014 16:44:43.000 CEST" a.b.161.127 <=> a.b.191.140 0.001 v4_EXCHANGE_ID
"Aug 27, 2014 16:44:43.000 CEST" a.b.161.127 <=> a.b.191.140 0.001 v4_CREATE_SESSION
"Aug 27, 2014 16:44:43.000 CEST" a.b.161.127 <=> a.b.191.140 0.003 v4_PUTROOTFH
"Aug 27, 2014 16:44:43.000 CEST" a.b.161.127 <=> a.b.191.140 0.002 v4_RECLAIM_COMPLETE
"Aug 27, 2014 16:44:43.000 CEST" a.b.161.127 <=> a.b.191.140 0.004 v4_PUTROOTFH

# v3
"Oct 21, 2014 18:46:26.000 CEST" a.b.67.142 <=> a.b.13.53 5.286 v3_GETATTR
"Oct 21, 2014 18:46:26.000 CEST" a.b.67.142 <=> a.b.13.53 3.478 v3_ACCESS
"Oct 21, 2014 18:46:32.000 CEST" a.b.67.142 <=> a.b.13.53 5.324 v3_ACCESS
"Oct 21, 2014 18:46:32.000 CEST" a.b.67.142 <=> a.b.13.53 5.322 v3_GETATTR
"Oct 21, 2014 18:46:37.000 CEST" a.b.67.142 <=> a.b.13.53 5.243 v3_GETATTR
"Oct 21, 2014 18:46:37.000 CEST" a.b.67.142 <=> a.b.13.53 5.243 v3_ACCESS
"Oct 21, 2014 18:46:42.000 CEST" a.b.67.142 <=> a.b.13.53 5.241 v3_ACCESS
"Oct 21, 2014 18:46:42.000 CEST" a.b.67.142 <=> a.b.13.53 5.242 v3_LOOKUP
"Oct 21, 2014 18:46:47.000 CEST" a.b.67.142 <=> a.b.13.53 5.396 v3_GETATTR
"Oct 21, 2014 18:46:47.000 CEST" a.b.67.142 <=> a.b.13.53 5.395 v3_ACCESS
"Oct 21, 2014 18:46:53.000 CEST" a.b.67.142 <=> a.b.13.53 5.297 v3_ACCESS
"Oct 21, 2014 18:46:53.000 CEST" a.b.67.142 <=> a.b.13.53 5.297 v3_LOOKUP
"Oct 21, 2014 18:46:58.000 CEST" a.b.67.142 <=> a.b.13.53 5.318 v3_GETATTR
```

**License under**  [GNU General Public License](http://www.gnu.org/licenses/gpl-2.0.html)

-- nfs.lua
--
-- Copyright (c) 2014 Deutsches Elektronen-Synchroton,
-- Member of the Helmholtz Association, (DESY), HAMBURG, GERMANY
--
-- This program is free software licensed under GPL version 2.
--
-- wireshark extention to process NFS packets
--
-- Example:
--  $ tshark -q -X lua_script:nfs.lua -f "port 2049"
--  $ tshark -q -X lua_script:nfs.lua -r nfs.dump
--  # with tshark > 1.12
--  $ tshark -q -X lua_script:nfs.lua -X lua_script1:0.01 -r nfs.dump

local nfs_opnum4 = {
    [3] = 'ACCESS',
    [4] = 'CLOSE',
    [5] = 'COMMIT',
    [6] = 'CREATE',
    [7] = 'DELEGPURGE',
    [8] = 'DELEGRETURN',
    [9] = 'GETATTR',
    [10] = 'GETFH',
    [11] = 'LINK',
    [12] = 'LOCK',
    [13] = 'LOCKT',
    [14] = 'LOCKU',
    [15] = 'LOOKUP',
    [16] = 'LOOKUPP',
    [17] = 'NVERIFY',
    [18] = 'OPEN',
    [19] = 'OPENATTR',
    [20] = 'OPEN_CONFIRM',
    [21] = 'OPEN_DOWNGRADE',
    [22] = 'PUTFH',
    [23] = 'PUTPUBFH',
    [24] = 'PUTROOTFH',
    [25] = 'READ',
    [26] = 'READDIR',
    [27] = 'READLINK',
    [28] = 'REMOVE',
    [29] = 'RENAME',
    [30] = 'RENEW',
    [31] = 'RESTOREFH',
    [32] = 'SAVEFH',
    [33] = 'SECINFO',
    [34] = 'SETATTR',
    [35] = 'SETCLIENTID',
    [36] = 'SETCLIENTID_CONFIRM',
    [37] = 'VERIFY',
    [38] = 'WRITE',
    [39] = 'RELEASE_LOCKOWNER',
    [40] = 'BACKCHANNEL_CTL',
    [41] = 'BIND_CONN_TO_SESSION',
    [42] = 'EXCHANGE_ID',
    [43] = 'CREATE_SESSION',
    [44] = 'DESTROY_SESSION',
    [45] = 'FREE_STATEID',
    [46] = 'GET_DIR_DELEGATION',
    [47] = 'GETDEVICEINFO',
    [48] = 'GETDEVICELIST',
    [49] = 'LAYOUTCOMMIT',
    [50] = 'LAYOUTGET',
    [51] = 'LAYOUTRETURN',
    [52] = 'SECINFO_NO_NAME',
    [53] = 'SEQUENCE',
    [54] = 'SET_SSV',
    [55] = 'TEST_STATEID',
    [56] = 'WANT_DELEGATION',
    [57] = 'DESTROY_CLIENTID',
    [58] = 'RECLAIM_COMPLETE',
    [10044] = 'ILLEGAL',
};

local nfs_opnum3 = {
    [0] = 'NULL',
    [1] = 'GETATTR',
    [2] = 'SETATTR',
    [3] = 'LOOKUP',
    [4] = 'ACCESS',
    [5] = 'READLINK',
    [6] = 'READ',
    [7] = 'WRITE',
    [8] = 'CREATE',
    [9] = 'MKDIR',
    [10] = 'SYM_LINK',
    [11] = 'MKNODE',
    [12] = 'REMOVE',
    [13] = 'RMDIR',
    [14] = 'RENAME',
    [15] = 'LINK',
    [16] = 'READDIR',
    [17] = 'READDIRPLUS',
    [18] = 'FSSTAT',
    [19] = 'FSINFO',
    [20] = 'PATHINFO',
    [21] = 'COMMIT',
};

-- in s.ms
local min_time_delta = 0.0

-- with wireshark 1.12 you can specify max time on a command line
local arg = {...}
if #arg > 0 then
  min_time_delta = tonumber(arg[1])
end

local function timediff_to_string(s)

  local days_in_sec = 86400
  local hour_in_sec = 3600
  local min_in_sec = 60
  local t = s
  local result = ""

  local days = math.floor(t / days_in_sec)
  if days > 0.9 then
    t = t - days * days_in_sec
    result = result .. days .. " day"
    if days > 2 then result = result .. "s" end
  end

  local hours = math.floor(t / hour_in_sec)
  if hours > 0.9 then
    t = t - hours * hour_in_sec
    result = result .. " " .. hours .. " hour"
    if hours > 2 then result = result .. "s" end
  end

  local mins = math.floor(t / min_in_sec)
  if mins > 0.9 then
    t = t - mins * min_in_sec
    result = result .. " " .. mins .. " min"
  end

  result = result .. " " .. string.format("%.3f",t) .. " sec"
  return result
end

do

  local ip4_dst = Field.new("ip.dst")
  local ip4_src = Field.new("ip.src")
  local ip6_dst = Field.new("ipv6.dst")
  local ip6_src = Field.new("ipv6.src")
  local ip_version = Field.new("ip.version")

  local tcp_dstport = Field.new("tcp.dstport")
  local tcp_srcport = Field.new("tcp.srcport")

  local frame_time = Field.new("frame.time")
  local frame_epochtime = Field.new("frame.time_epoch")

  local rpc_xid =  Field.new("rpc.xid")
  local rpc_msgtyp = Field.new("rpc.msgtyp")

  local nfs4_op = Field.new("nfs.main_opcode")
  local nfs3_op = Field.new("nfs.procedure_v3")
  local nfs_vers = Field.new("rpc.programversion")

  local packets = {}
  local ops = {}
  local avg_times = {}

  local first_packet = nil
  local last_packet = nil

  local function init_listener()

    local tap = Listener.new("rpc", "nfs")

    function get_main_opcode()

      local nfs_version = tonumber(tostring(nfs_vers()))

      if nfs_version == 4 then
          return "v4_"..nfs_opnum4[ tonumber(tostring(nfs4_op())) ]
      else
          return "v3_"..nfs_opnum3[ tonumber(tostring(nfs3_op())) ]
      end
    end

    function update_avg_time(op, v)
      local count = ops[op]
      local current_avg = avg_times[op] or 0
      avg_times[op] = (current_avg * (count - 1) + v) / count
    end

    --
    -- print a dtrace like histogram
    --
    function histogramm()
      local max = 0;
      local term_size = 48
      for n, v in pairs(ops) do
        if v > max then max = v end
      end
      print("             NFS operation  |  Count | Avg(t)|")
      print("----------------------------+--------+-------+-----------------------------------------------------------")
      for op,count in pairs(ops) do
        local hit = string.rep("#", (count*term_size) / max)
        print("   "  .. string.format("%24s",op) .. " | " .. string.format("%6d", count) .. " | " .. string.format("%3.3f", avg_times[op]) .. " | " .. hit)
      end
    end

    function tap.draw()

        local time_delta = 0;
        if first_packet ~= nil then
          time_delta = last_packet - first_packet
        end
        print()
        print("Total capture time: " .. timediff_to_string(time_delta))
        print("Capture statistics:")
        print()
        histogramm()
    end

    function tap.packet(pinfo,tvb)
      local xid = tonumber(tostring(rpc_xid()))
      local msgtyp = tonumber(tostring(rpc_msgtyp()))
      local ipsrc = nil
      local ipdst = nil
      local ip_vers = tonumber(tostring(ip_version()))
      local dstport = tcp_dstport()
      local srcport = tcp_srcport()
      local frametime = tostring(frame_time())
      local frameepochtime = tonumber(tostring(frame_epochtime()))
      local nfs_op = get_main_opcode()


      if ip_vers == 6 then
        ipsrc = ip6_src()
        ipdst = ip6_dst()
      else
        ipsrc = ip4_src()
        ipdst = ip4_dst()
      end

      if first_packet == nil then
        first_packet = frameepochtime
      end
      last_packet = frameepochtime

      if msgtyp == 0 then
        packets[xid] = {
           timestamp = frameepochtime,
           source = tostring(ipsrc),
           destination = tostring(ipdst),
           op_code = nfs_op
        };
        local op_count = ops[nfs_op] or 0
        ops[nfs_op] = op_count + 1
      else
        local l = packets[xid]
        if l ~= nul then
          packets[xid] = nil
          local time_delta = frameepochtime - l.timestamp
          update_avg_time(l.op_code, time_delta)
          if time_delta > min_time_delta then
            print(frametime .. " " .. l.source .. " <=> " .. l.destination .. " " .. string.format("%.3f",time_delta) .. " " .. l.op_code)
          end
        end
     end
    end
  end

  init_listener()

end


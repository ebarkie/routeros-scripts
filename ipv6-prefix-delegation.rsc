# This script allows specifying prefix ID's when using IPv6 prefix delegation with
# pools.
#
# For example, if your ISP provides a /56 prefix, you have 255 /64 networks available
# (ranging from 0-ff) and it's nice to be able to choose which ones are used for
# each interface rather than having them randomly allocated from the pool.
#
# To use this script setup interfaces without specifying a from-pool but instead
# specify the tags somewhere in the comment, for example:
#
# /ipv6 address
# add address=::1 comment="LAN from-pool=google-fiber token=::a:0:0:0:1" interface=vlan-lan
# add address=::1 comment="DMZ from-pool=google-fiber token=::b:0:0:0:1" interface=vlan-dmz
#
# The script will maintain the interface addresses accordingly.
#
# It will also update IPv6 firewall address lists in the same way.

# split slices s into all substrings separated by sep and returns an array of all
# substrings between those separators.
:global split do={
  :local parts
  :local part ""

  :for i from=0 to=[:len $s] do={
    :local c [:pick $s $i ($i+1)]
    :if ($c != $sep) do={
      :set $part ($part.$c)
    } else {
      :set ($parts->[:len $parts]) $part
      :set $part ""
    }
  }

  :if ([:len $part] > 0) do={
    :set ($parts->[:len $parts]) $part
  }

  :return $parts
}

# getTag finds the first occurrence of tag in a string and returns the value.
:global getTag do={
  :global split

  :foreach word in=[$split s=$s sep=" "] do={
    :local kv [$split s=$word sep="="]
    :if ([:len $kv] = 2 and $kv->0 = $tag) do={
      :return ($kv->1)
    }
  }

  :return ""
}

# calcPoolAddr calculates an address for a given prefix, prefixlen, and token.
:global calcPoolAddr do={
  :local net [:toip6 [:pick $prefix 0 [:tonum [:find $prefix "/"]]]]

  :return (($net | [:toip6 $token])."/".$prefixLen)
}

:local test false

/ipv6/address
:foreach a in=[find where comment~("token=.*")] do={
  :local fromPool [$getTag s=[get $a comment] tag="from-pool"]
  :local token [$getTag s=[get $a comment] tag="token"]

  :local interface [get $a interface];
  :local haveAddr [get $a address];
  :local pool [/ipv6/pool/get $fromPool]
  :local wantAddr [$calcPoolAddr prefix=($pool->"prefix") prefixLen=($pool->"prefix-length") token=$token]
  :log debug ("ipv6 address interface:".$interface." from-pool:".$fromPool." (".$pool->"prefix".") token ".$token)

  :if ($haveAddr = $wantAddr) do={
    :log debug ("ipv6 address interface:".$interface." address:".$haveAddr." address is set correctly")
  } else={
    :log warning ("ipv6 address interface:".$interface." address:".$haveAddr." changing to ".$wantAddr)
    :if (!test) do={
      /ipv6/address/set $a address=$wantAddr
    }
  }
}

/ipv6/firewall/address-list
:foreach a in=[find where comment~("token=.*")] do={
  :local fromPool [$getTag s=[get $a comment] tag="from-pool"]
  :local token [$getTag s=[get $a comment] tag="token"]

  :local list [get $a list];
  :local haveAddr [get $a address];
  :local pool [/ipv6/pool/get $fromPool]
  :local wantAddr [$calcPoolAddr prefix=($pool->"prefix") prefixLen=128 token=$token ]
  :log debug ("ipv6 address list:".$list.": from-pool:".$fromPool." (".$pool->"prefix"."), token ".$token)

  :if ($haveAddr = $wantAddr) do={
    :log debug ("ipv6 address list:".$list." address:".$haveAddr." address is set correctly")
  } else={
    :log warning ("ipv6 address list:".$list." address:".$haveAddr." changing to ".$wantAddr)
    :if (!test) do={
      /ipv6/firewall/address-list/set $a address=$wantAddr
    }
  }
}

# TODO: update network discovery DNS servers

# TODO: update WireGuard peers
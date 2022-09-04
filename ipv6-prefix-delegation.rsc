# This script allows specifying prefix ID's when using IPv6 prefix delegation with
# pools and maintaining IPv6 address lists and network detection DNS servers based
# on prefix delegations.
#
# For example, if your ISP provides a /56 prefix, you have 255 /64 networks available
# (ranging from 0-ff) and it's nice to be able to choose which ones are used for
# each interface rather than having them randomly allocated from the pool.
#
# To use this script setup interfaces without specifying a "from-pool" but instead
# specify the tags somewhere in the comment, for example:
#
# /ipv6 address
# add address=::1 comment="LAN from-pool=google-fiber token=::a:0:0:0:1" interface=vlan-lan
# add address=::1 comment="DMZ from-pool=google-fiber token=::b:0:0:0:1" interface=vlan-dmz
#
# The script will maintain the interface addresses accordingly.
#
# Address lists and static DNS records work the same way:
#
# /ipv6 firewall address-list
# add address=::5/128 comment="from-pool=google-fiber token=::a:0:0:0:5" list=ns
#
# /ip/dns/static
# add address=::5 comment="from-pool=google-fiber token=::a:0:0:0:5" name=ns1.local ttl=1m type=AAAA
#
# Network detection DNS broadcasts work by having one or more addresses tagged with
# service=dns.  The address may be disabled.
#
# /ipv6 address
# add address=::5 advertise=no comment="service=dns from-pool=google-fiber token=::a:0:0:0:5" disabled=yes interface=\
#   vlan-lan no-dad=yes
# /ipv6 nd
# add dns=::5 hop-limit=64 interface=vlan-lan

:local test false

# split slices s into all substrings separated by sep and returns an array of all
# substrings between those separators.
:global split do={
  :local parts
  :local part ""

  :for i from=0 to=[:len $s] do={
    :local c [:pick $s $i ($i+1)]
    :if ($c!=$sep) do={
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
    :if ([:len $kv]=2 and $kv->0=$tag) do={
      :return ($kv->1)
    }
  }

  :return ""
}

# calcPoolAddr calculates an address for a given prefix and token.
:global calcPoolAddr do={
  :local net [:toip6 [:pick $prefix 0 [:tonum [:find $prefix "/"]]]]

  :return ($net | [:toip6 $token])
}

:local dnsServers
/ipv6/address
:foreach a in=[find where (comment~("from-pool=.*") and comment~("token=.*"))] do={
  :local service [$getTag s=[get $a comment] tag="service"]
  :local fromPool [$getTag s=[get $a comment] tag="from-pool"]
  :local token [$getTag s=[get $a comment] tag="token"]

  :local interface [get $a interface];
  :local haveAddr [get $a address];
  :local pool [/ipv6/pool/get $fromPool]
  :local wantAddr ([$calcPoolAddr prefix=($pool->"prefix") token=$token]."/".($pool->"prefix-length"))
  :log debug ("ipv6 address interface:".$interface." from-pool:".$fromPool." (".$pool->"prefix".") token ".$token)

  :if ($haveAddr=$wantAddr) do={
    :log debug ("ipv6 address interface:".$interface." address:".$haveAddr." address is set correctly")
  } else={
    :log warning ("ipv6 address interface:".$interface." address:".$haveAddr." changing to ".$wantAddr)
    :if (!test) do={
      set $a address=$wantAddr
    }
  }

  :if ($service = "dns") do={
    :set ($dnsServers->[:len $dnsServers]) [$calcPoolAddr prefix=($pool->"prefix") token=$token]
  }
}

/ipv6/nd
:foreach nd in=[find where dns!=""] do={
  :local interface [get $nd interface];
  :local dns [get $nd dns]

  :if ($dns=$dnsServers) do={
    :log debug ("ipv6 nd interface:".$interface." dns:".$dns." servers are set correctly")
  } else={
    :log warning ("ipv6 nd interface:".$interface." dns:".$dns." changing to ".$dnsServers)
    :if (!test) do={
      set $n dns=$dnsServers
    }
  }
}

/ipv6/firewall/address-list
:foreach al in=[find where (comment~("from-pool=.*") and comment~("token=.*"))] do={
  :local fromPool [$getTag s=[get $al comment] tag="from-pool"]
  :local token [$getTag s=[get $al comment] tag="token"]

  :local list [get $al list];
  :local haveAddr [get $al address];
  :local pool [/ipv6/pool/get $fromPool]
  :local wantAddr ([$calcPoolAddr prefix=($pool->"prefix") token=$token]."/128")
  :log debug ("ipv6 address list:".$list.": from-pool:".$fromPool." (".$pool->"prefix"."), token ".$token)

  :if ($haveAddr=$wantAddr) do={
    :log debug ("ipv6 address list:".$list." address:".$haveAddr." address is set correctly")
  } else={
    :log warning ("ipv6 address list:".$list." address:".$haveAddr." changing to ".$wantAddr)
    :if (!test) do={
      set $a address=$wantAddr
    }
  }
}

/ip/dns/static
:foreach n in=[find where (type="AAAA" and comment~("from-pool=.*") and comment~("token=.*"))] do={
  :local fromPool [$getTag s=[get $n comment] tag="from-pool"]
  :local token [$getTag s=[get $n comment] tag="token"]

  :local name [get $n name];
  :local regexp [get $n regexp];
  :local haveAddr [get $n address];
  :local pool [/ipv6/pool/get $fromPool]
  :local wantAddr ([$calcPoolAddr prefix=($pool->"prefix") token=$token])
  :log debug ("dns static name:".$name." regexp:".$regexp." from-pool:".$fromPool." (".$pool->"prefix"."), token ".$token)

  :if ($haveAddr=$wantAddr) do={
    :log debug ("dns static name:".$name." regexp:".$regexp." address:".$haveAddr." address is set correctly")
  } else={
    :log warning ("dns static name:".$name." regexp:".$regexp." address:".$haveAddr." changing to ".$wantAddr)
    :if (!test) do={
      set $n address=$wantAddr
    }
  }
}

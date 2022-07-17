; Nicklist themer
; Does not support spectators (when room is moderated, or non-subscriber)
; Do not use with non-IRC8 networks.

;;;;; Events ;;;;;

on 1:CONNECT:{
  .parseline -itq : $+ $server 005 $me $+(PREFIX=, $chr(40), qov, $nonspecmodechar, $chr(41), .@+=)
  rmNicklistTable
  hmake NICKLIST. $+ $cid 100
}

on 1:DISCONNECT:rmNicklistTable

on *:JOIN:#:{
  if ($nick == $me) {
    ; Setup nickLUST
    var %chan $right($chan, -2)
    nicklust Mark $window($chan).hwnd nickLust_cb hideempty
    nicklust AddIcon %chan > $nicklist.icon(away)
    nicklust AddIcon %chan > $nicklist.icon(msn)
    nicklust AddIcon %chan > $nicklist.icon(owner)
    nicklust AddIcon %chan > $nicklist.icon(host)
    nicklust AddIcon %chan > $nicklist.icon(spec)
    nicklust AddIcon %chan > $nicklist.icon(blank)
    nicklust AddIcon %chan > $nicklist.icon(PX)
    nicklust AddIcon %chan > $nicklist.icon(MX)
    nicklust AddIcon %chan > $nicklist.icon(FX)
    nicklust AddIcon %chan > $nicklist.icon(PY)
    nicklust AddIcon %chan > $nicklist.icon(MY)
    nicklust AddIcon %chan > $nicklist.icon(FY)
    nicklust AddGroup %chan 2 . 3 > Owners
    nicklust AddGroup %chan 3 @ 4 > Hosts
    nicklust AddGroup %chan 4 + 6 > Voiced
    nicklust AddGroup %chan 5 = 6 > Users
    nicklust SetGroupText %chan 1 > Spectators ; Unused
    nicklust SetGroupIcon %chan 1 5
    nicklust SetGroupPos %chan 1 end
  }
}

; Don't show fake modes used in this script
on ^*:RAWMODE:#:if ($nick == :) haltdef

; Add any user data to hash table
on *:SIGNAL:MSNPROFILE:hadd -m100 $+(NICKLIST., $cid) $2-

raw 305:*:awaystatus $1 H
raw 306:*:awaystatus $1 G
raw 821:*:awaystatus $nick H
raw 822:*:awaystatus $nick G

;;;;; Aliases ;;;;;

; /awaystatus <nick> <H|G>
alias -l awaystatus {
  var %status = $hget($+(NICKLIST., $cid), $1)
  if (!%status) return
  hadd -m100 $+(NICKLIST., $cid) $1 $puttok(%status, $2, 1, 44)
  ; Loop all channels
  var %i = 1
  while (%i <= $comchan($1, 0)) {
    updateicon $comchan($1, %i) $1
    inc %i
  }
}

; $geticon(<chan>, <nick>) returns boolean
alias -l geticon {
  var %status = $hget($+(NICKLIST., $cid), $2)
  if ($gettok(%status, 1, 44) == G) return 1
  elseif ($gettok(%status, 2, 44) != U) return 2
  elseif ($2 isowner $1) return 3
  elseif ($2 isop $1) return 4
  ;var %chmodes = $gettok($chan($2).mode, 1, 32)
  var %picon = $left($gettok(%status, 3, 44), -1)
  if (%picon == RX) return 6
  elseif (%picon == PX) return 7
  elseif (%picon == MX) return 8
  elseif (%picon == FX) return 9
  elseif (%picon == PY) return 10
  elseif (%picon == MY) return 11
  elseif (%picon == FY) return 12
  ; The only else should be G.
  else return 6
}

; $nicklist.icon(spec) returns C:\path\to\spec.ico
alias -l nicklist.icon {
  return $+($scriptdir,icons\,$1,.ico)
}

alias -l nicklust {
  var %file = $qt($+($scriptdirnickLUST3.dll))
  var %res = $dll(%file, $1, $2-)
  return %res
}

; Called by nickLUST.dll
alias nickLUST_cb {
  var %chan = $+($chr(37), $chr(35), $2)
  ; Which icon
  if ($1 == nickAdded) {
    ; MSNify nicks
    var %nick = $3
    if (%nick isop %chan) %nick = %nick (Host)
    if ($left(%nick, 1) == ') %nick = $right(%nick, -1)
    elseif ($left(%nick, 1) == >) %nick = $+(Guest_, $right(%nick, -1))

    ; Return icon code.
    return $geticon(%chan, $3) $color($color(Listbox Text)) > %nick
  }

  ; Which group
  if ($1 == nickAdding) {
    ; If users fall into the default group, nickLUST does not allow you to set the icon.
    if (= !isin $nick(%chan, $3).pnick) .parseline -itq :: MODE %chan + $+ $nonspecmodechar $3
  }
}

alias -l nonspecmodechar return ©

alias -l rmNicklistTable if ($hget(NICKLIST. $+ $cid)) hfree $ifmatch

; /updateicon <chan> <nick>
alias -l updateicon {
  ; Only apply if user is not spec - Splitting onto 2 parselines stops nickLUST crashing.
  if ($len($nick($1, $nick($1, $2))) < $len($nick($1, $2).pnick)) {
    .parseline -itq :: MODE $1 $+(-, $nonspecmodechar) $2 $2
    .parseline -itq :: MODE $1 $+(+, $nonspecmodechar) $2 $2
  }
}

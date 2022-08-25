; MSNLD Connection Script
; Compatible with IRC8 channel servers
; Currently supports GateKeeper (Guest) mode - See: https://github.com/MSNLD/msnld-mirc/issues/3

;;;;; Events ;;;;;

on ^*:LOGON:*:{
  if ($IRCX.KnownServer) {
    haltdef
    raw -q IRCVERS IRC8 MSN-OCX!9.02.0310.2401 en-us
    Gatekeeper.Send GateKeeper 3 1
  }
}

on *:PARSELINE:*:*:{
  ; Only affect known IRCX servers.
  if (!$IRCX.KnownServer) return
  ; Incoming Message
  if ($parsetype === in) {
    tokenize 32 $parseline
    if ($1 == AUTH) {
      if ($findtok(GateKeeper GateKeeperPassport, $2, 0, 32) >= 1) {
        ; Prevent UTF8 encoding
        .parseline -itu0 $1-
      }
    }
    elseif ($2 == JOIN) {
      .parseline -it $1-2 $4-
      var %modes = $gettok($3, 4, 44)
      var %target = $right($gettok($1, 1, 33), -1)
      if (%modes) .parseline -itq $+(:, $server MODE $right($4, -1) +, $replace(%modes, ., q, @, o, +, v)) $str(%target $+ $chr(32), $len(%modes))
      ;.parseline -itqp $+(:, $server) PROFILE %target $gettok($3, 1-3, 44)
      .signal MSNPROFILE $right($4, -1) %target $gettok($3, 1-3, 44)
      return
    }
    elseif ($2 == PRIVMSG) {
      .parseline -it $1-3 $msnTextToMirc($4-)
    }
    elseif ($2 == WHISPER) {
      .parseline -it $1 PRIVMSG $4 $msnTextToMirc($5-)
    }
    elseif ($2 == 353) {
      if ($chr(44) isin $6) {
        var %onames = $right($6-, -1)
        var %i = 1
        var %names
        while (%i <= $numtok(%onames, 32)) {
          var %name = $gettok(%onames, %i, 32)
          var %profile = $gettok(%name, 1-3, 44)
          var %target = $gettok(%name, 4, 44)
          %names = %names %target
          .signal MSNPROFILE $5 $remove(%target, ., @, +) %profile
          inc %i
        }
        .parseline -it $1-5 $+(:, %names)
        ;parseline -it
        return
      }
    }
  }
}

raw AUTH:GateKeeper*:{
  ; Sequence should always be subsequent (S)
  if ($1-2 === GateKeeper *) {
    raw -q NICK $+(>, $remove($me, >))
  }
  if ($2 !== S) return
  if ($3 === OK) {
    echo -st [AUTH] Auth Successful. Sending credentials
    ; Send passport and ticket data
  }
  else {
    echo -st [AUTH] Calculating Hash.
    GateKeeper.calculate $1 $3-
  }
  haltdef
}

;;;;; Aliases ;;;;;

; Converts a mIRC binary representation of an Int32 to a number
; eg. $binInt32ToN(3 0 0 0) returns 3
alias -l binInt32ToN {
  var %x $1-
  var %result
  var %i = $numtok(%x, 32)
  while (%i > 0) {
    %result = %result $gettok(%x, %i, 32)
    dec %i
  }
  return $longip($replace(%result, $chr(32), .))
}

alias -l bool return $iif($1, $true, $false)

; Returns mIRC binary respresentation of "GKSSP\0"
alias -l GateKeeper.binSig {
  return 71 75 83 83 80 0
}

alias GateKeeper.calculate {
  var %x $IRCX.binUnescape($strToBinStr($2-))
  ;Remove front colon as AdiIRC includes it in the RAW event
  if ($numtok(%x, 32) == 25 && $gettok(%x,1,32) == 58) {
    %x = $remtok(%x, 58, 1, 32)
  }
  var %cur = 1
  var %siglen = $numtok($GateKeeper.binSig, 32)
  var %sig = $gettok(%x, $+(%cur, -, %siglen), 32)
  inc %cur %siglen
  ; Ignore unknown bytes (2)
  inc %cur 2
  var %ver = $binInt32ToN($gettok(%x, $+(%cur, -, $calc(%cur + 3)), 32))
  inc %cur 4
  var %seq = $binInt32ToN($gettok(%x, $+(%cur, -, $calc(%cur + 3)), 32))
  inc %cur 4
  bset -ac &data 1 $gettok(%x, $+(%cur, -, $numtok(%x, 32)), 32)
  var %errmsg  echo -st [ATUH] Authentication failed.
  if (!$bvar(&date, 0) === 8) %errmsg (invalid length)
  elseif (%sig !== $GateKeeper.binSig) %errmsg (invalid signature)
  elseif ((%ver < 1) || (%ver > 3)) %errmsg (invalid version)
  elseif (%seq !== 2) %errmsg (invalid sequence)
  else {
    ; GateKeeper v3 adds hostname to key
    if (%ver === 3) bset -act &data 9 $servertarget
    ; Calculate hash
    var %hash = $mh.hex2bin($hmac(&data, SRFMKSJANDRESKKC, md5, 1))
    ; Send response
    gatekeeper.send $1 %ver 3 %hash $GateKeeper.getGUID(%ver)
  }
  bunset &data
}

alias -l GateKeeper.getGUID {
  ; Version 1 did not support GUIDs
  if ($1 == 1) return
  ; Rough implementation of random GUID
  return $mh.hex2bin($md5($+($ticks,$window(*,1).hwnd)))
}

; /gatekeeper.send <package> <version> <sequence> <data>
alias GateKeeper.send {
  var %seq = $iif($3 === 1, I, S)
  var %x $strToBinStr(AUTH $1 %seq :) $GateKeeper.write($2, $3, $4-)
  bset -ac &data 1 %x
  .parseline -obqnu0 &data
  bunset &data
}

; $GateKeeper.Write(Version, Sequence, Data)
alias GateKeeper.write {
  return $IRCX.binEscape($GateKeeper.binSig 74 68 $nToBinInt32($1) $nToBinInt32($2) $3)
}

alias -l IRCX.binEscape {
  var %i = 1
  var %result
  while (%i <= $len($1)) {
    var %cur $gettok($1, %i, 32)
    if (%cur === 0) %result = %result 92 48
    elseif (%cur === 9) %result = %result 92 116
    elseif (%cur === 10) %result = %result 92 110
    elseif (%cur === 13) %result = %result 92 114
    elseif (%cur === 32) %result = %result 92 98
    elseif (%cur === 44) %result = %result 92 99
    elseif (%cur === 92) %result = %result 92 92
    else {
      %result = %result %cur
    } 
    inc %i
  }
  return %result
}

alias -l IRCX.binUnescape {
  var %i = 1
  var %result
  while (%i <= $numtok($1, 32)) {
    var %cur $gettok($1, %i, 32)
    if (%cur === 92) {
      inc %i | %cur = $gettok($1, %i, 32)
      if (%cur === 48) %result = %result 0
      elseif (%cur === 116) %result = %result 9
      elseif (%cur === 110) %result = %result 10
      elseif (%cur === 114) %result = %result 13
      elseif (%cur === 98) %result = %result 32
      elseif (%cur === 99) %result = %result 44
      elseif (%cur === 92) %result = %result 92
    }
    else {
      %result = %result %cur
    }
    inc %i
  }
  inc %i
  return %result
}

alias -l IRCX.KnownServer {
  var %serverlist irc.irc7.com chat.msnld.com
  return $iif($findtok(%serverlist, $servertarget, 0, 32) >= 1, $true, $false)
}

; Thanks to eXonyte
alias -l mh.hex2bin {
  var %l 1, %r
  while (%l <= $len($1)) {
    %r = %r $base($mid($1,%l,2),16,10)
    inc %l 2
  }
  return %r
}

alias -l msnColorToMirc {
  if ($1 == 2) return 05
  elseif ($1 == 4) return 02
  ; We used to show this as 07 (orange), but 42 is more accurate
  elseif ($1 == 5) return 30
  elseif ($1 == 7) return 10
  elseif ($1 == 8) return 15
  elseif ($1 == 9) return 14
  elseif ($1 == 10) return 04
  elseif ($1 == 11) return 09
  elseif ($1 == 13) return 08
  elseif ($1 == 14) return 13
  elseif ($1 == 15) return 11
  else return $base($1, 10, 10, 2)
}

alias -l msnTextToMirc {
  if ($+(:,$chr(1),S *,$chr(1)) iswm $1-) {
    tokenize 32 $1-
    var %bindata = $IRCX.binUnescape($strToBinStr($2))
    var %color = $calc($gettok(%bindata, 1, 32) - 1)
    var %mircColor = $msnColorToMirc(%color)
    if (%mircColor == $color(Background).dd) %mircColor = $color(Normal).dd
    var %style = $calc($gettok(%bindata, 2, 32) - 1)
    ; Make it match MSN Chat Control
    if ((%style < 1) || (%style > 8)) %style = 8
    var %bold = $bool($and(%style, 1))
    var %italic = $bool($and(%style, 2))
    var %underline = $bool($and(%style, 4))
    echo -at [bold] %bold [italic] %italic [underline] %underline
    ; I left the following in (commented) as it allows decoding of font/script if someone needs it in the future.
    ;bset -ac &data 1 $gettok(%bindata, 3-, 32)
    ;var %data = $bvar(&data, 1, $bvar(&data, 0)).text
    ;var %scripttok = $numtok(%data, 59)
    ;var %script = $gettok(%data, %scripttok, 59)
    ;var %font = $deltok(%data, %scripttok, 59)
    ;echo -at [script] %script [font] %font
    return $+(, %mircColor, $iif(%bold, $chr(2)), $iif(%italic, $chr(29)), $iif(%underscore, $chr(31)), $left($3-, -1))
    ;bunset &data
  }
  else {
    return $1-
  }
}

; Converts a number to mIRC binary representation of an Int32
; eg. $nToBinInt32(3) returns 3 0 0 0
alias -l nToBinInt32 {
  var %x = $longip($1)
  var %result
  var %i = $numtok(%x, 46)
  while (%i > 0) {
    %result = %result $gettok(%x, %i, 46)
    dec %i
  }
  return %result
}

; Converts a string to a mIRC binary representation of a string
; eg. $strToBinStr(GKSSP) returns 71 75 83 83
alias strToBinStr {
  var %result
  var %i = 1
  while (%i <= $len($1)) {
    %result = %result $asc($mid($1, %i, 1))
    inc %i
  }
  return %result
}

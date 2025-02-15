//
// Copyright 2020 FoxyUtils ehf. All rights reserved.
//
// This is a commercial product and requires a license to operate.
// A trial license can be obtained at https://unidoc.io
//
// DO NOT EDIT: generated by unitwist Go source code obfuscator.
//
// Use of this source code is governed by the UniDoc End User License Agreement
// terms that can be accessed at https://unidoc.io/eula/

package wildcard ;func Match (pattern ,name string )(_ge bool ){if pattern ==""{return name ==pattern ;};if pattern =="\u002a"{return true ;};_gb :=make ([]rune ,0,len (name ));_bc :=make ([]rune ,0,len (pattern ));for _ ,_fe :=range name {_gb =append (_gb ,_fe );};for _ ,_de :=range pattern {_bc =append (_bc ,_de );};_dc :=false ;return _c (_gb ,_bc ,_dc );};func _db (_fcd ,_bg []rune ,_ac int )int {for len (_bg )> 0{switch _bg [0]{default:if len (_fcd )==0{return -1;};if _fcd [0]!=_bg [0]{return _db (_fcd [1:],_bg ,_ac +1);};case '?':if len (_fcd )==0{return -1;};case '*':if len (_fcd )==0{return -1;};_fdc :=_db (_fcd ,_bg [1:],_ac );if _fdc !=-1{return _ac ;}else {_fdc =_db (_fcd [1:],_bg ,_ac );if _fdc !=-1{return _ac ;}else {return -1;};};};_fcd =_fcd [1:];_bg =_bg [1:];};return _ac ;};func Index (pattern ,name string )(_bd int ){if pattern ==""||pattern =="\u002a"{return 0;};_bda :=make ([]rune ,0,len (name ));_da :=make ([]rune ,0,len (pattern ));for _ ,_fg :=range name {_bda =append (_bda ,_fg );};for _ ,_bcd :=range pattern {_da =append (_da ,_bcd );};return _db (_bda ,_da ,0);};func MatchSimple (pattern ,name string )bool {if pattern ==""{return name ==pattern ;};if pattern =="\u002a"{return true ;};_d :=make ([]rune ,0,len (name ));_f :=make ([]rune ,0,len (pattern ));for _ ,_ff :=range name {_d =append (_d ,_ff );};for _ ,_a :=range pattern {_f =append (_f ,_a );};_g :=true ;return _c (_d ,_f ,_g );};func _c (_gf ,_cd []rune ,_fc bool )bool {for len (_cd )> 0{switch _cd [0]{default:if len (_gf )==0||_gf [0]!=_cd [0]{return false ;};case '?':if len (_gf )==0&&!_fc {return false ;};case '*':return _c (_gf ,_cd [1:],_fc )||(len (_gf )> 0&&_c (_gf [1:],_cd ,_fc ));};_gf =_gf [1:];_cd =_cd [1:];};return len (_gf )==0&&len (_cd )==0;};
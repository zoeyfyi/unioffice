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

package mergesort ;func MergeSort (array []float64 )[]float64 {if len (array )<=1{_a :=make ([]float64 ,len (array ));copy (_a ,array );return _a ;};_bd :=len (array )/2;_af :=MergeSort (array [:_bd ]);_f :=MergeSort (array [_bd :]);_e :=make ([]float64 ,len (array ));_ea :=0;_ab :=0;_ff :=0;for _ab < len (_af )&&_ff < len (_f ){if _af [_ab ]<=_f [_ff ]{_e [_ea ]=_af [_ab ];_ab ++;}else {_e [_ea ]=_f [_ff ];_ff ++;};_ea ++;};for _ab < len (_af ){_e [_ea ]=_af [_ab ];_ab ++;_ea ++;};for _ff < len (_f ){_e [_ea ]=_f [_ff ];_ff ++;_ea ++;};return _e ;};
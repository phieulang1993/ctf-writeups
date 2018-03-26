We has 40 equations in these functions:
sub_402060, sub_403250, sub_403C90, sub_405740, sub_403470, sub_402640, sub_401490, sub_403680, sub_4042A0, sub_402840, sub_405B80, sub_402E40, sub_405FC0, sub_401A60, sub_405DA0, sub_4061D0, sub_4040B0, sub_403050, sub_402A40, sub_4048D0, sub_405540, sub_401870, sub_404EF0, sub_405310, sub_401260, sub_403890, sub_402C50, sub_403EA0, sub_405100, sub_4046B0, sub_403A80, sub_401E60, sub_401C70, sub_404CD0, sub_404AD0, sub_4044A0, sub_402260, sub_402440, sub_405960, sub_401670

For each function, first agrument is FLAG, second agrument is global variable checkFlag (1 = correct, 0 = incorrect).
From information about format flag: Flags match **/VolgaCTF{[\x20-\x7F]+}/**, I know 10 character from flag and condition for each other character is **/[\x20-\x7F]/**
I wrote a python script using z3 find flag [solve.py](/2018/VolgaCTF/You_Shall_Not_Pass/solve.py).
Flag: **VolgaCTF{D1$guis3_y0ur_code_and_y0u_@re_s@fe}**
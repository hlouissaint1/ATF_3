set cnx [bps::connect 172.16.192.100 rsautotestv7 60times]
set chs [$cnx getChassis]
$chs reservePort 2 0 -group 12
$chs reservePort 2 1 -group 12
set test [$cnx createTest -name {20190530T133446_1559223286.Performance1_Master_Performance-bit-blaster-1024} -template {Master_Performance-bit-blaster-1024}]
set cmp [$test createComponent bitblaster atf_bitblaster]
$cmp configure -sizeDist.max 200
$cmp configure -sizeDist.min 100
set result [$test run -group 12]
set tid [$test resultId]
puts $result,$tid
$chs unreservePort 2 0
$chs unreservePort 2 1
exit


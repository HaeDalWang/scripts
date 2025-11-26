#!/bin/bash


ds="`date`"

dt="`date "+%Y%m%d%H%M"`"
acc=$1
com=$(hostname -s)
com_syschk=$com\_syschk\_$dt

rm -rf $com_syschk
mkdir $com_syschk


clear

s01=$com_syschk"/s01.uptime.log"
s02=$com_syschk"/s02.kernel_version.log"
s03=$com_syschk"/s03.ip_addr_disk.log"

report=$com_syschk"/System_Report.log"


kr01=$com_syschk"/z01.kernel_rootkit.log"


pr01=$com_syschk"/p01.kernel_tainted.log"
pr02=$com_syschk"/p02.Journal_tainted.log"
pr03=$com_syschk"/p03.known_path.log"



chkk_journalctl() {
  local out
  out="$(journalctl -k --no-pager 2>/dev/null | grep -i 'taint' | grep -E 'vmwfxs:|mpt_mirror:|ipmc_si:' || true)"

  if [[ -n "$out" ]]; then
    echo "[!!][Suspicious] journalctl tained message"                                 >> $pr02
    echo "$out"                                 >> $pr02
  else
    echo "[+] clean: not found in kernel log"                                 >> $pr02
  fi
}



chkk_tainted() {
  local taint_file="/proc/sys/kernel/tainted"

  if [[ ! -f "$taint_file" ]]; then
    echo "tainted 파일이 존재하지 않습니다: $taint_file"                                 >> $pr01
    return 1
  fi

echo "# dmesg | grep taint"                                                              >> $pr01
dmesg | grep taint                                                                        >> $pr01
echo "# journalctl -k --no-pager | grep taint"                                            >> $pr01
journalctl -k --no-pager 2>/dev/null | grep taint                                         >> $pr01

  local taint_value
  taint_value="$(cat "$taint_file")"

  case "$taint_value" in
    4096)
      echo "[!!][Suspicious] out-of-tree module loaded"                                 >> $pr01
      ;;
    8192)
      echo "[!!][Suspicious] unsigned module loaded"                                 >> $pr01
      ;;
    12288)
      echo "[!!][Suspicious] out-of-tree unsigned module loaded"                                 >> $pr01
      ;;
    *)
      echo "kenel taint not found (value=$taint_value)"                                 >> $pr01
      ;;
  esac
}

chkk_knownpath() {
  local files=(
    "/etc/init.d/tracker-fs"
    "/etc/rc2.d/S55tracker-fs"
    "/etc/rc3.d/S55tracker-fs"
    "/etc/rc3.d/S55tracker-fs"
    "/usr/include/tracker-fs/tracker-efs"

    "/etc/init.d/loadmaxm"
    "/etc/rc2.d/loadmaxm"
    "/etc/rc3.d/loadmaxm"
    "/etc/rc4.d/loadmaxm"
    "/usr/local/etc/loadmaxm"

    "/var/adm/was-patch/was_sys_relay"
    "/usr/local/etc/was-patch"
    "/etc/init.d/was-patch"

  )

  if [ `which stat | wc -l` -eq 1 ]
  then
  	for f in "${files[@]}"; do
    	echo "===== Checking: $f ====="                                 >> $pr03
    	if stat "$f" >/dev/null 2>&1; then
      		echo "[!!][Critical] $f"                                    >> $pr03
      		echo "--- stat information ---"                               >> $pr03
      		stat "$f" 2>/dev/null                                         >> $pr03
    	else
      		echo "[-] not found: $f"                                      >> $pr03
    	fi
  	done
   else
        echo "[-] stat command not found" >> $pr03
   fi
}


event_check_new(){

echo -e "\033[1;36m============================================"
echo -e "* Event Check"
echo -e "============================================\033[0;0m"

echo "* 1. Kernel Tainted Check"
echo "* 2. Journalctl Tainted Check"
echo "* 3. Known Rootkit Path Check"

echo "======================================================================"                         >> $pr01
echo " 1. Kernel Tainted Check"                                                                       >> $pr01
echo "======================================================================"                         >> $pr01
echo "Check> /proc/sys/kernel/tainted Value Check"                            >> $pr01
chkk_tainted



echo "======================================================================"                         >> $pr02
echo " 2. Journalctl Tainted Check"                                                                       >> $pr02
echo "======================================================================"                         >> $pr02
echo "Check> journalctl -k | grep taint "                            >> $pr02
chkk_journalctl


echo "======================================================================"                         >> $pr03
echo " 3. Known Rootkit Path Check"                                                                       >> $pr03
echo "======================================================================"                         >> $pr03
chkk_knownpath




}


sys_check_new(){


echo -e "\033[1;36m============================================"
echo -e "* Kernel RootKit"
echo -e "============================================\033[0;0m"

echo "* 1. Hidden Kernel Modudle Check"
echo "* 2. Modified Systemcall Table Check"
echo "* 3. Modified Kernel Function Check"

echo "======================================================================"                         >> $kr01
echo " 1. Kernel RootKit"                                                                             >> $kr01
echo "======================================================================"                         >> $kr01
echo "Check> Hidden Kernel Modudle, Systemcall Table Modification, Detour"                            >> $kr01
echo "----------------------------------------------------------------------"                         >> $kr01
echo "# sudo ./rootkit_detect"                                                                        >> $kr01

./rootkit_detect 2>/dev/null                                                                          >> $kr01

echo "----------------------------------------------------------------------"                         >> $kr01
echo                                                                                                  >> $kr01
echo                                                                                                  >> $kr01


}

sys_check(){




echo -e "\033[1;36m============================================"
echo -e "* File system "
echo -e "============================================\033[0;0m"

echo "* 1. System UPTIME"
    echo "======================================================================"       >> $s01
    echo " 1.1. System UPTIME  "                                                        >> $s01
    echo "======================================================================"       >> $s01
    echo "Check> System UPTIME"                                                         >> $s01
    echo "----------------------------------------------------------------------"       >> $s01
echo "# uptime"                                                                         >> $s01
if [ `uptime | wc -l` -eq 1 ]
  then
    uptime                                                                              >> $s01
    echo "----------------------------------------------------------------------"       >> $s01
  else
    echo "Command Not Found"                                                            >> $s01
    echo "----------------------------------------------------------------------"       >> $s01
fi
echo                                                                                    >> $s01

echo "* 2. Kernel Version"
    echo "======================================================================"       >> $s02
	echo " 2. Kernel Version "                                                          >> $s02
    echo "======================================================================"       >> $s02
    echo "Check> Kernel Version"                                                        >> $s02
    echo "----------------------------------------------------------------------"       >> $s02
echo "# uname -a"                                                                       >> $s02
if [ `uname -a | wc -l` -eq 1 ]
  then
    uname -a                                                                            >> $s02
    echo "----------------------------------------------------------------------"       >> $s02
  else
    echo "Command Not Found"                                                            >> $s02
    echo "----------------------------------------------------------------------"       >> $s02	
fi
echo                                                                                    >> $s02

echo "* 3. IP addres, Disk"
    echo "======================================================================"       >> $s03
    echo " 3.1. IP address"                                                              >> $s03
    echo "======================================================================"       >> $s03
    echo "Check> ip net, ifconfig"                                                              >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
echo "# ip addr"                                                                          >> $s03
if [ `ip addr 2>/dev/null | wc -l` -ge 1 ]
  then
    ip addr                                                                               >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
  else
    echo "Command Not Found"                                                            >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
fi
echo "# ifconfig -a"                                                                          >> $s03
if [ `ifconfig -a 2>/dev/null | wc -l` -ge 1 ]
  then
    ifconfig -a                                                                               >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
  else
    echo "Command Not Found"                                                            >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
fi

echo                                                                                    >> $s03
    echo "======================================================================"       >> $s03
    echo " 3.2. Disk Use"                                                              >> $s03
    echo "======================================================================"       >> $s03
    echo "Check> Disk Use"                                                              >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
echo "# df -h"                                                                          >> $s03
if [ `df -h 2>/dev/null | wc -l` -ge 1 ]
  then
    df -h                                                                               >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
  else
    echo "Command Not Found"                                                            >> $s03
    echo "----------------------------------------------------------------------"       >> $s03
fi
echo                                                                                    >> $s03


}


create_report(){
df="`date`" 
echo "====================================================="                           >> $report
echo "  SYSTEM CHECK TIME"                                                             >> $report
echo "-----------------------------------------------------"                           >> $report
echo " *  Start  - $ds"                                                                >> $report
echo " *  Finish - $df"                                                                >> $report
echo "====================================================="                           >> $report
echo                                                                                   >> $report
echo "----------------------------------------------------------------------"          >> $report
echo                                                                                   >> $report
echo "============================"                                                    >> $report
echo "  SYSTEM CHECK LIST"                                                             >> $report
echo "============================"                                                    >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report


echo "[FILE SYSTEM]"                                                                   >> $report
echo "s01. Uptime"                                                                     >> $report
echo "s02. Kernerl Version"                                                            >> $report
echo "s03. IP address, Disk use"                                                       >> $report
echo                                                                                   >> $report

echo "[Version 3.0]"                                                                   >> $report
echo "z01. Kernel Rootkit"                                                             >> $report


echo "----------------------------------------------------------------------"          >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report

echo                                                                                   >> $report
echo "########################## "                                                     >> $report
echo "#  FILE SYSTEM             "                                                     >> $report
echo "########################## "                                                     >> $report
echo                                                                                   >> $report
cat $s01                                                                               >> $report
echo                                                                                   >> $report
cat $s02                                                                               >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report
cat $s03                                                                               >> $report
echo                                                                                   >> $report

echo                                                                                   >> $report
echo "########################## "                                                     >> $report
echo "#  Kernel RootKit          "                                                     >> $report
echo "########################## "                                                     >> $report
echo                                                                                   >> $report
cat $kr01                                                                              >> $report
echo                                                                                   >> $report


echo                                                                                   >> $report
echo "########################## "                                                     >> $report
echo "#  Event Check          "                                                     >> $report
echo "########################## "                                                     >> $report
echo                                                                                   >> $report
cat $pr01                                                                              >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report
cat $pr02                                                                              >> $report
echo                                                                                   >> $report
echo                                                                                   >> $report
cat $pr03                                                                              >> $report
echo                                                                                   >> $report

echo                                                                                   >> $report
echo "----------------------------------------------------------------------"          >> $report
echo                                                                                   >> $report

}

tar_result() {

echo -e "\033[1;36m============================================"
echo -e "* FINISH - Result File Packing"
echo -e "============================================\033[0;0m"
echo "# tar -czf $com_syschk.tar.gz $com_syschk"
if [ `which tar | wc -l` -eq 1 ]
  then
    tar -czf $com_syschk.tar.gz $com_syschk
	rm -rf $com_syschk
	rm -f $0
	rm -f rootkit_detect
  else
    echo "  => tar Command Not Found "
	rm -f $0
	rm -f rootkit_detect
fi

echo
}


report_result() {

echo -e "\033[1;36m============================================"
echo -e "* FINISH - Result File Checking"
echo -e "============================================\033[0;0m"


  grep -q "Critical" "$report" 2>/dev/null
  local critical_status=$?

  if [[ $critical_status -eq 0 ]]; then
    echo -e "\033[1;36m============================================"
    echo -e "Critical Events Found !!!!!"
    echo -e "Please Report $report file !!!!"
    echo -e "\033[1;36m============================================"
  else
    echo -e "\033[1;36m============================================"
    echo "There's No Critical entries"
    echo -e "\033[1;36m============================================"
  fi

  echo


}


chkk_kernel_23() {
    sys_check
    event_check_new
    touch $kr01
}

chkk_kernel_4() {
    sys_check
    event_check_new
    sys_check_new
}



version_check() {
  local REF="4.18.0"

  local KVER_RAW
  KVER_RAW="$(uname -r)"
  local KVER="${KVER_RAW%%-*}"

  if [[ "$(printf '%s\n' "$KVER" "$REF" | sort -V | tail -n1)" == "$KVER" ]]; then
    chkk_kernel_4
  else
    chkk_kernel_23
  fi
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo -e "\033[1;36m============================================"
    echo -e "!!! Root Privileges are required !!!!"
    echo -e "    sudo $0"
    echo -e "\033[1;36m============================================"
    echo
    exit 1
  fi
}



main(){


    require_root				
    version_check
    create_report	
    report_result

    tar_result
}

main
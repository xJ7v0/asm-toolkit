#!/bin/bash
#if [[ ! -z $asmdev ]];then
#UNSAFE_CFLAGS="-U_FORTIFY_SOURCE -O2 -Wl,-z,lazy,-z,norelro -fno-stack-protector -D_FORTIFY_SOURCE=0 -ggdb"
#LDPIE="-I /lib64/ld-linux-x86-64.so.2 -pie -o"
#IO32_CFLAGS="-Wall -ggdb -O0 -fno-stack-protector -fno-pie -fno-pic -Wl,-z,execstack,-z,norelro,-z,lazy -U_FORTIFY_SOURCE -m32"

#ld -s -x --gc-sections --no-dynamic-linker -pie --no-eh-frame-hdr --disable-new-dtags pie-test.o -o pie-test
#ld level10.o -o level10 -lc -e _start -dynamic-linker /lib/ld-linux.so.2
#nasm -f elf r0pme.asm -o r0pme.o && ld -m elf_i386 r0pme.o -o r0pme -lc -e main -dynamic-linker /lib/ld-linux.so.2

BITS=0
# bc -l <<<scale=$BC_SCALE;
BC_SCALE=10

# TODO: use a function
# Max cores for parralel operations
JOBS="4"

# Ram for tasks
RAM="4G"

# TODO:
# Assemble/Disassmeble, GDB syntax
#	SYNTAX="intel"
#	SYNTAX="att"
# ARM disassembly GDB
#	raw	- Select raw register names
#	gcc	- Select register names used by GCC
#	std	- Select register names used in ARM's ISA documentation
#	apcs	- Select register names used in the APCS
#	atpcs	- Select register names used in the ATPCS
#	special-atpcs - Select special register names used in the ATPCS
# The default is "std".

# GDB
# set arch i386:x86-64:intel

# Assemble, Calculator, Link
#	BITS="32"
#	BITS="64"

# Assemble, Link, GDB, qemu, gcc use ${CROSS_COMPILE}
#	ARCH="x86_64"
#	ARCH="i386"
#	ARCH="powerpc"
#	ARCH="mipsel"

# functions that replace command names
function cpp() { `which ${CROSS_COMPILE}cpp` $CPPFLAGS $CPPFLAGS_PROFILE "$@"; }
function g++() { `which ${CROSS_COMPILE}g++` $CXXFLAGS $CXXFLAGS_PROFILE "$@"; }
function gcc() { `which ${CROSS_COMPILE}gcc` $CFLAGS $CFLAGS_PROFILE "$@"; }

function ar() { `which ${CROSS_COMPILE}ar` "$@"; }
function as() { `which ${CROSS_COMPILE}as` $ASFLAGS $ASFLAGS_PROFILE "$@"; }
#function ld() { `which ${CROSS_COMPILE}ld` $LDFLAGS $LDFLAGS_PROFILE "$@"; }
function ld.bfd() { `which ${CROSS_COMPILE}ld.bfd` $LDFLAGS $LDFLAGS_PROFILE "$@"; }
function ld.gold() { `which ${CROSS_COMPILE}ld.gold` $LDFLAGS $LDFLAGS_PROFILE "$@"; }
function nm() { `which ${CROSS_COMPILE}nm` "$@"; }
function objcopy() { `which ${CROSS_COMPILE}objcopy` "$@"; }
function objdump() { `which ${CROSS_COMPILE}objdump` $OBJDUMP_PROFILE "$@"; }
function pkg-config() { `which ${CROSS_COMPILE}pkg-config` "$@"; }
function ranlib() { `which ${CROSS_COMPILE}ranlib` "$@"; }
function readelf() { `which ${CROSS_COMPILE}readelf` "$@"; }
function size() { `which ${CROSS_COMPILE}size` "$@"; }
function srconv() { `which ${CROSS_COMPILE}srconv` "$@"; }
function strings() { `which ${CROSS_COMPILE}strings` "$@"; }
function strip() { `which ${CROSS_COMPILE}strip` "$@"; }

function diff() { `which diff` -W $COLUMNS "$@"; }
function sort() { `which sort` --compress-program=xz --parallel=$JOBS -S $RAM "$@"; }
function xargs() { `which xargs` -P $JOBS "$@"; }

export WEAKCFLAGS="-O0 -g3 -ggdb -Wl,-z,execstack,-z,execheap,-z,norelro,-z,lazy -fno-stack-protector -fno-omit-frame-pointer -fno-pic -fno-pie -fno-PIC -fno-PIE -pipe -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
export WEAKCXXFLAGS="$CFLAGS"

alias abicheck="gcc -dM -E - < /dev/null"
alias broaden="sed 's/$/\n/g'"
alias coredump_off="ulimit -S -c 0"
alias coredump_on="ulimit -S -c 999999"
alias g++w="g++ $WEAKCXXFLAGS"
alias gccw="gcc $WEAKCFLAGS"
alias gdb="gdb -q"
alias px="paxctl-ng -pemrs"
alias pycompile="python -m py_compile"
alias pycompileall="python -m compileall"
alias readelf="readelf -W"
alias strace="strace -s 9999"
alias unassemble="disassemble"

# calculate binary
#function calcb() { echo 0b$(bc<<<"obase=2;ibase=10;$(($@))") }
# calculate hex
#function calcx() { echo 0x$(bc<<<"obase=16;ibase=10;$(($@))") }

#[[ ! ${PATH} == /usr/local/bin* ]] && PATH="${PATH}:/usr/local/bin"

# TODO: add 8/16/32/64 bit lengths to calc
alias calcb="calc %b"
alias calcd="calc %d"
alias calco="calc %o"
alias calcx="calc %x"

alias calcms="calc %ms"
alias calcms="calc %mu"

alias calcsb="calc %sb"
alias calcsx="calc %sx"

# properly `roll` a number thats larger than 32 bits
# to fit in a 32 bit number
#function rollx32() {
#
#	NUM=$(calcx $@)
#
#	if [[ $(echo -n ${NUM} | wc -m) > 10 ]]; then
#		NUM=$(($NUM-0xffffffff-0x1))
#	fi
#	calcx $NUM
#}

function devprofile()
{
# invocation

# nasm		- set elf32/elf64/bin
# ld		- set linker format
# gdb		- set arch and endianess
# gcc		- set -masm=
# objdump	- set -M(intel/att)
# template	- setup .s/asm files

	BITS=32
	ENDIAN=le
	unset SUBARCH	# this breaks when `devprofile 32`
	target="$@"
	# host
	[[ "$target" == *host* ]] && { ARCH=$(arch); BITS=$(getconf LONG_BIT); [[ $(printf '\1' | od -dAn) == *1* ]] &&\
	ENDIAN=le || ENDIAN=be; unset CROSS_COMPILE; target="$(gcc -v 2>&1 | grep Target | cut -d ' ' -f2)"; }

	ARCH=${ARCH:=$(arch)}
	BITS=${BITS:=$(getconf LONG_BIT)}
	[[ $(printf '\1' | od -dAn) == *1* ]] && ENDIAN=le || ENDIAN=be

	# TODO: fix x32/ILP32 detection
	#source <(cpp <<_EOF
	#// Get X32/ILP32 subarch
	##if defined(__ILP32__) && ! (__LP64__)
	##ifdef __x86_64__
	#SUBARCH=x32
	##else
	#SUBARCH=ilp32
	##endif
	##endif
	#_EOF
	#);;
	# Bits
	case "$target" in
		*32*) BITS=32; ASFLAGS_PROFILE="--32";;&
		*64*) BITS=64; ASFLAGS_PROFILE="--64";;&
		# Arch
		*arm*) ARCH=arm;;&						# LE
		*aarch64*) ARCH=aarch64;;&					# LE
		*alpha*) ARCH=alpha; BITS=64;;&					# LE
		*hppa[!64]*|*parisc[!64]*) ARCH=hppa; ENDIAN=be;;&
		*hppa64*|*parisc64*) ARCH=hppa64; ENDIAN=be;;&
		*m68k*) ARCH=m68k; ENDIAN=be;;&
		*mips[!64]*) ARCH=mips; ENDIAN=be;;&
		*mips64*) ARCH=mips64; ENDIAN=be;;&
		*powerpc[!64]*|*ppc[!64]*) ARCH=powerpc; ENDIAN=be;;&
		*powerpc64*|*ppc64*) ARCH=powerpc64; ENDIAN=be;;&		# powerpc64ilp32 - still shows as 64 bit
		*riscv[!64]*|*risc-v[!64]*) ARCH=riscv;;&			# LE
		*riscv64*|*risc-v64*) ARCH=riscv64;;&				# LE
		*sh4*) ARCH=sh4;;&						# LE
		*sparc[!64]*) ARCH=sparc; ENDIAN=be;;&
		*sparc64*) ARCH=sparc64; ENDIAN=be;;&
		*ia64*) ARCH=ia64;;&						# LE
		*i?86*) ARCH=i386;
		s_CODE=".intel_syntax noprefix
.intel_mnemonic
.global _start
.section .text

_start:

_exit:
	mov	 al, SYS_exit		// 0x3
	xor	 bl, bl			// 0x0
	int	80h
";
;;&						# LE

		*x86_64*|*amd64*|*EMT64*) ARCH=x86_64;
		s_CODE=".intel_syntax noprefix
.intel_mnemonic
.global _start
.section .text

_start:

_exit:
	mov	 al, SYS_exit		// 0x3c
	xor	edi, edi		// 0x0
	syscall
"
;;&			# LE
		# Subarch
		# armv4l	- ARMv4,  little endian, soft float, OABI
		# armv4tl	- ARMv4t, little endian, soft float, EABI
		# armv5tejl	- armv5tej,
		# armv5l	- ARMv5,  little endian, VFP, EABI
		# armv6l	- ARMv6,  little endian, VFP, EABI
		*hf*) SUBARCH=hf;;&
		*ilp32*) BITS=64; SUBARCH=ilp32;;&
		*spe*) SUBARCH=spe;;&
		*x32*) ARCH=x86_64; BITS=64; SUBARCH=x32;;&			# LE
		# Endianness
		*eb*|*be*) ENDIAN=be;;&
		*el*|*le*) ENDIAN=le;;&
		# Libc
		*dietlibc*) LIBC=dietlibc;;&
		*eglibc*) LIBC=eglibc;;&
		*gnu*|*glibc*) LIBC=gnu;;&
		*musl*) LIBC=musl;;&
		*uclibc*) LIBC=uclibc;;&
		# ABI
		*linux*) ABI=linux;;&
		*freebsd*) ABI=freebsd;;&
		#*darwin18
		#*darwin17
		#*darwin16
		# Vendor
# Vendors can also contain specs for soft/hard float for arm
#*unknown*) ;;&
# Output type
# *debug*) OBJDUMP_PROFILE_FLAGS+="-g";;&
*release*) LD_PROFILE_FLAGS+="-z noexecstack -z relro -z now -pie --no-dynamic-linker -s -x --gc-sections";;&
#*) echo "Usage: devprofile" ;;&


# objdump
# -EB -EL && --architecture=machine

# debug
# -g3 -ggdb
# minimal
# -nostartfiles -static -nostdlib -nodefaultlibs

# release
# weak
esac

# Aliases
if [[ $(arch) != $ARCH ]]; then
alias strace="qemu-$ARCH -strace"
alias gdb-server="qemu-$ARCH -g 12345"
else
# need to fix as strace/gdb-server has an alias already, so we need to save and restore somehow
alias strace="strace -s 9999"
unalias gdb-server 2>/dev/null
fi

if [[ $target != *host* ]]; then
# CROSS_COMPILE
CROSS_COMPILE="$(echo /usr/$ARCH*$VENDOR*$LIBC*$SUBARCH*)"
if [[ $CROSS_COMPILE == *" "* ]]; then
	echo ambiguous cross compiler request, be more specific:
	echo ${CROSS_COMPILE/\/usr\//}
	unset CROSS_COMPILE
	return 1
elif [[ ! -d $CROSS_COMPILE ]]; then
	echo non existent toolchain directory
	return 1
else
	CROSS_COMPILE=${CROSS_COMPILE#"/usr/"}-
fi
fi
}

template()
{
for i in $@; do
case "$i" in
# For assembly files we need to add syntax directives,
# elf headers, ABI specs for reference at the top

*.asm) [[ ! -e "$i" ]] && { cat <<_EOF >"$i"
global  _start
_start:
_exit:
_EOF
} || echo "refusing to clobber file: $i";;

*.s) [[ ! -e "$i" ]] && { cat <<_EOF >"$i"
divert(-1)
#include <sys/syscall.h>
divert(0)
$s_CODE

_EOF
} || echo "refusing to clobber file: $i";;


*.ld) echo "linker script";;
configure) echo "configure script";;
[Mm]akefile) echo "makefile";;

*) cat <<_EOF
template $i doesnt exist, here is a list:
.asm		- Nasm assembly file for target
.s		- GNU as assembly file for target
.ld		- GNU ld linker script
configure	- configure script for targets
Makefile	- Makefile for configure script
asproject	- GNU assembler project incorporating multi targets,
		  creates or updates the current directory to
		  accomadate the current devprofile target
cproject	- A modular based approach to creating binaries and libraries
_EOF
;;

esac
done
}

function examples()
{
	echo "How to write lookup tables in assembly"
	echo "How to strlen, scasb, sse*/avx, "
	echo "How to scan for character, scasb, sse*/avx, "
	echo "How to setup stack for file buffers"
}


# negate properly ie: unsigned
# $((~0x1010101 & 0x111111))

gdb_dashboard="/opt/git/gdb-dashboard/.gdbinit"
gef="/opt/git/gef/gef.py"
peda="/opt/git/peda/peda.py"
peda_arm="/opt/git/peda-arm/peda-arm.py"
pwndbg="/opt/git/pwndbg/gdbinit.py"
voltron="$HOME/.local/bin/voltron"

### voltron ###
alias vstack="$voltron view stack"
alias vbt="$voltron view bt"
alias vreg="$voltron view reg -v"
alias vreg-sse="$voltron view reg -vsf"
alias vcode="$voltron view disasm"
alias vmem="$voltron view memory"
alias vbreak="$voltron view breakpoints"


# Name: obj2shell
# Description: Convert object file to shellcode
obj2shell() {
	objdump -D -M intel $1 | awk '/Disassembly of section .note.gnu.property:/ {exit} {print}' |\
grep -vi ">:" | cut -d '	' -f 2 | sed -r '1,6d ; s/ //g; s/([0-9a-f]{2})/\x\1/g' | tr -d '\n' && echo
}

# Name: disassemble
# Alias: unassemble
# Description:
# <function name> [FILE]
disassemble() {
	# TODO:  declare -a array && array=( $(readelf -l cat | tail -n1) )
	if [[ $# -eq 2 ]]; then
		if [[ -f "$1" ]]; then
			peda -ex "disassemble $2" -ex "quit" "$1"
		elif [[ -f "$2" ]]; then
			peda -ex "disassemble $1" -ex "quit" "$2"
		fi

	# TODO: expand arguments via a variable that switches environments, ie: att/intel syntax
	# TODO: disassemble different arch automatically
	elif [[ $# -eq 1 ]]; then
		objdump -dMintel "$1"
	fi
}

assemble() {
	[[ "$1" == "${1%.*}" ]] && OUT="a.out" || OUT="${1%.*}"
	[[ "${test##*.}" == "asm" ]] && alias asmbin="nasm " || alias asmbin="as - -g --noexecstack -o"
	FILE=$(echo "# 1 \"$1\"" "$(cpp -ftabstop=2 -x assembler-with-cpp $1 | m4)")
	MESSAGES=$(echo "$FILE" | asmbin "${1%.*}.o" 2>&1 && ld -o "$OUT" "${1%.*}.o")
	LINES=$(echo "$MESSAGES" | grep -oP '(?<=:)[0-9]+(?=:)')

	# Range of sed lines
	#unset SED_; for i in $LINES;do SED_+="$(($i-1)),$(($i+1)) p";done

	# One line
	unset SED_; for i in $LINES;do SED_+="$(($i+1)),$(($i+1)) p\n";done
	echo "$MESSAGES" | head -n1
	# TODO: allow user to set if they want tabs or spaces <t/s>mov<t/s>rax, rax
	paste <(echo "$MESSAGES" | tail -n +2) <(echo "$FILE" | sed -e 's/	/ /g' \
	-e 's/^ /	/g' -e 's/ /	/1' -e 's/ /	/2'  -nf <(echo -e "$SED_")) -d '\n' |\
	sed -E -e "s/:([0-9]+:)/:\x1B[38;5;2m\1\x1B[0m /" -e "s/(Error:)/\x1B[38;5;1m\1\x1B[0m /" #-e '1~3 a\\'
	# 	s/get_line_numbers/color_me_green/		s/get_error_str/color_me_red/
}

function assemble-obj() {
	cpp -P -pipe -x assembler-with-cpp "$1" | m4 | as - -g --noexecstack -o "${1%.*}.o"
}

function diagnose() {
	cpp -P -pipe -x assembler-with-cpp "$1" | m4 | nano -lv -
}

# TODO: test to see if this works on assembly source code and turns them into static files
# that way we can intergrate this into the ld() above
function ld-shared() {
	if [[ ! -z $CROSS_COMPILE ]]; then
		ld -dynamic-linker=/usr/${CROSS_COMPILE%-}/usr/lib/libc.so -lc $@
	else
		ld -dynamic-linker=/usr/lib/libc.so -lc $@
	fi
}

function n32() { [[ "$1" == "${1%.*}" ]] && OUT="a.out" || OUT="${1%.*}"
	nasm -f elf32 "$1" && ld -m elf_i386 -o "$OUT" "${1%.*}.o"
}

function n64() { [[ "$1" == "${1%.*}" ]] && OUT="a.out" || OUT="${1%.*}"
	nasm -f elf64 "$1" && ld -m elf_x86_64 -o "$OUT" "${1%.*}.o"
}

# Name: dumpsect
# Description: dump section header contents of an elf file
# Args: <grep> [FILE]
function dumpsect()
{
	local sects
	FILE="${!#}"
	[[ ! -e "$FILE" ]] && echo "dumpsect: <grep> [FILE]"
	[[ $# < 2 ]] && elfsect=$(readelf -S "$FILE") || elfsect=$(readelf -S "$FILE" | grep ${@:1:$#-1})
	for i in $(grep -oP '(?<=[[:digit:]]] ).*(?= [I,F,N,P,S])'<<<$elfsect);do sects+="-j $i ";done
	objdump -s $sects "$FILE"
}

### gdb ###
# TODO: Add gdb function to save break points and load them from a file
# TODO: Add gdb function to break at _start/main and run it
function fix_exec_dubugging() {
	if [[ $(id -u) != 0 ]]; then
		for argument in "$@"; do
			[[ -x "${argument}" ]] && px "${argument}" && break
		done
	fi
}

function gdb-dashboard() { gdb -iex "source $gdb_dashboard" "$@"; }

function gdb-tui() { gdb -tui -iex "set auto-load-scripts off" "$@"; }

function gdbi() {
	local FILE=$1 CMD=$2
	gdb -batch -ex "file $FILE" -ex "$CMD"
}

function gef() { gdb -iex "source $gef" "$@"; }

function peda() { fix_exec_dubugging $@

	`which gdb` -q -iex "source $peda" -iex "pset option autosave off" -iex "pset option clearscr off" "$@"
}

function peda-armv5() { fix_exec_dubugging $@

	`which armv5tel-softfloat-linux-gnueabi-gdb` -q -iex "source $peda_arm" -iex "set arch arm" -iex "set endian big" "$@"
}

function pwndbg() { gdb -iex "source $pwndbg" "$@"; }

function sde64() { /opt/gdb-extensions/sde-external-9.14.0-2022-10-25-lin/sde64 -debug -- "$@"; }

function voltron() { gdb -iex 'source /opt/git/voltron/voltron/entry.py' "$@"; }

function voltron_lldb() { lldb -o "command script import /opt/git/voltron/voltron/entry.py" "$@"; }


function esc_bytes() {
	xxd -ps | sed -r 's/([[:xdigit:]]{2})/\\\x\1/g' | tr -d '\n'; echo
}
#fi

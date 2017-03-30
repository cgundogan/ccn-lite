# ccn-lite Makefile for Linux and OS X

# Compile time options: variables can either be exported at the
# shell level (% export USE_NFN=1) or be given as parameter to
# make (% make <target> <VAR>=<val>)

#  for compiling the Linux Kernel module, export          USE_KRNL=1
#  for named-function support (NFN), export               USE_NFN=1
#  for NACK support in NFN, export                        USE_NACK=1


# OS name: Linux or Darwing (OSX) supported
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC?=gcc

# Get version of gcc with two digits, e.g. 40902
GCC_VERSION := $(shell ${CC} -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/')
GCC_GTEQ_40900 := $(shell expr ${GCC_VERSION} \>= 40900)

# include path
INCLUDES += -Iinclude

# general flags used on both linux and OSX
CCNLCFLAGS=-Wall -Werror -std=c99 -g ${INCLUDES}

ifeq ($(RIOTBASE),)
	CCNLCFLAGS += -pedantic -O0
endif

# Linux flags
LINUX_CFLAGS=-D_XOPEN_SOURCE=500 -D_XOPEN_SOURCE_EXTENDED -Dlinux
ifeq ($(GCC_GTEQ_40900),1)
    LINUX_CFLAGS += -Wno-date-time
endif

# OSX, ignore deprecated warnings for libssl
OSX_CFLAGS=-Wno-error=deprecated-declarations

CREATE_BIN=mkdir -p ../bin && cd ../bin && ln -f -s ../src/$@ $@
EXTLIBS=  -lcrypto
EXTMAKE=
EXTMAKECLEAN=

# CCNL_NFN_MONITOR to log messages to nfn-scala montior
NFNFLAGS += -DUSE_NFN #-DUSE_NFN_MONITOR
NACKFLAGS += -DUSE_NACK -DUSE_NFN_MONITOR
NFN_TIMEOUT_KEEPALIVE_FLAGS += -DUSE_TIMEOUT_KEEPALIVE
NFN_TIMEOUT_KEEPCONTENT_FLAGS += -DUSE_TIMEOUT_KEEPCONTENT

PROGS =
INST_PROGS= ccn-lite-relay

# Linux specific (adds kernel module)
ifeq ($(uname_S),Linux)
    $(info *** Configuring for Linux ***)
    EXTLIBS += -lrt
    ifdef USE_KRNL
        $(info *** With Linux Kernel ***)
        PROGS += ccn-lite-lnxkernel
    endif
    ifdef USE_WPAN
        $(info *** With WPAN support ***)
        CCNLCFLAGS += -DUSE_WPAN
    endif

    # Some investigation needed to compile ccn-lite-simu with OSX
    PROGS += ccn-lite-simu
    CCNLCFLAGS += ${LINUX_CFLAGS}
endif

# OSX specific
ifeq ($(uname_S),Darwin)
    $(info *** Configuring for OSX ***)
    CCNLCFLAGS += ${OSX_CFLAGS}

    # removes debug compile artifacts
    EXTMAKECLEAN += rm -rf *.dSYM
endif

ifdef USE_NFN
    $(info *** With NFN ***)
    INST_PROGS += ccn-nfn-relay
    CCNLCFLAGS += ${NFNFLAGS}
endif

ifdef USE_TIMEOUT_KEEPALIVE
ifdef USE_TIMEOUT_KEEPCONTENT
$(error USE_TIMEOUT_KEEPALIVE and USE_TIMEOUT_KEEPCONTENT both defined. Only one is allowed)
endif
    #$(info *** With NFN2 ***)
	ifdef USE_NFN
		CCNLCFLAGS += ${NFN_TIMEOUT_KEEPALIVE_FLAGS}
		#INST_PROGS += ccn-lite-simplenfn-keepalive
	endif
endif

ifdef USE_TIMEOUT_KEEPCONTENT
    #$(info *** With NFN2 ***)
	ifdef USE_NFN
		CCNLCFLAGS += ${NFN_TIMEOUT_KEEPCONTENT_FLAGS}
	endif
endif

ifdef USE_NACK
    $(info *** With NFN_NACK ***)
    INST_PROGS += ccn-lite-relay-nack
    ifdef USE_NFN
        INST_PROGS += ccn-nfn-relay-nack
    endif
endif

PROGS += ${INST_PROGS}

ifdef USE_CHEMFLOW
    CHEMFLOW_HOME=./chemflow/chemflow-20121006
    EXTLIBS=-lcf -lcfserver -lcrypto
    EXTMAKE=cd ${CHEMFLOW_HOME}; $(MAKE)
    EXTMAKECLEAN=cd ${CHEMFLOW_HOME}; $(MAKE) clean
    CCNLCFLAGS+=-DUSE_CHEMFLOW -I${CHEMFLOW_HOME}/include -L${CHEMFLOW_HOME}/staging/host/lib
endif

EXTRA_CFLAGS := -g $(OPTCFLAGS) -std=gnu99
ifeq ($(GCC_GTEQ_40900),1)
    EXTRA_CFLAGS += -Wno-date-time
endif
obj-m += ccn-lite-lnxkernel.o

PKTSWITCH_LIB = include/ccnl-pkt-switch.h pkt-formats/switch.c
CCNB_LIB =   include/ccnl-pkt-ccnb.h pkt-formats/ccnb.c lib-sha256.c
CCNTLV_LIB = include/ccnl-pkt-ccntlv.h pkt-formats/ccntlv.c
CISTLV_LIB = include/ccnl-pkt-cistlv.h pkt-formats/cistlv.c
IOTTLV_LIB = include/ccnl-pkt-iottlv.h pkt-formats/iottlv.c
NDNTLV_LIB = include/ccnl-pkt-ndntlv.h pkt-formats/ndntlv.c
LOCALRPC_LIB = include/ccnl-pkt-localrpc.h pkt-formats/localrpc.c ext/localrpc.c
SUITE_LIBS = ${PKTSWITCH_LIB} ${CCNB_LIB} ${CCNTLV_LIB} ${CISTLV_LIB} ${IOTTLV_LIB} ${NDNTLV_LIB} ${LOCALRPC_LIB}

UTIL_OBJS := util/base64.o util/common.o
SUITE_OBJS := pkt-formats/ccnb.o pkt-formats/ccntlv.o pkt-formats/cistlv.o \
              pkt-formats/iottlv.o pkt-formats/ndntlv.o pkt-formats/localrpc.o pkt-formats/switch.o

CCNL_CORE_LIB = include/ccnl-defs.h include/ccnl-core.h core/core.c core/fwd.c core/util.c

CCNL_RELAY_LIB = platforms/ccn-lite-relay.c ${SUITE_LIBS} \
                 ${CCNL_CORE_LIB} ${CCNL_PLATFORM_LIB} \
				 ext/echo.c ext/hmac.c ext/mgmt.c ext/http.c  ext/crypto.c

CCNL_PLATFORM_LIB = include/ccnl-os-includes.h \
                    ext/debug.c include/ccnl-ext.h ext/logging.c \
                    ccnl-os-time.c ext/frag.c ext/sched.c

NFN_LIB = ext/nfn.c krivine.c krivine-common.c

OMNET_DEPS = core/core.c core/fwd.c include/ccnl-core.h core/util.c include/ccnl-defs.h \
             ext/crypto.c ext/debug.c include/debug.h ext/echo.c \
             ext/frag.c include/ccnl-ext.h ext/hmac.c ext/http.c \
             ext/localrpc.c ext/logging.c ext/mgmt.c ext/sched.c \
             pkt-formats/ccnb.c include/ccnb.h pkt-formats/ccntlv.c include/ccntlv.h \
             pkt-formats/cistlv.c include/cistlv.h pkt-formats/iottlv.c include/iottlv.h \
             pkt-formats/localrpc.c include/localrpc.h pkt-formats/ndntlv.c include/ndntlv.h \
             pkt-formats/switch.c ccnl-uapi.c include/ccnl-uapi.h lib-sha256.c \
             util/base64.c util/common.c

# ----------------------------------------------------------------------

all: ${PROGS}
	$(MAKE) -C util

lib-ccn-lite.a: platforms/ccn-lite-riot.c \
	${SUITE_LIBS} ${CCNL_CORE_LIB} ${CCNL_PLATFORM_LIB}
	${CC} -o $@ ${RIOT_CFLAGS} ${CCNLCFLAGS} -c $<

lib-ccn-lite-utils.a: ${UTIL_OBJS} util/base64.c util/common.c
	${AR} rcs $@ ${UTIL_OBJS}

lib-ccn-lite-suite.a: ${SUITE_OBJS}
	${AR} rcs $@

%.o: %.c
	${CC} -o $@ ${RIOT_CFLAGS} ${CCNLCFLAGS} -c $<

ccn-lite-minimalrelay: platforms/ccn-lite-minimalrelay.c \
	${SUITE_LIBS} ${CCNL_CORE_LIB}
	${CC} -o $@ ${CCNLCFLAGS} $< ${SUITE_LIBS}
	@${CREATE_BIN}

ccn-nfn-relay: ${CCNL_RELAY_LIB}
	${CC} -o $@ ${CCNLCFLAGS} $< ${EXTLIBS}
	@${CREATE_BIN}

ccn-nfn-relay-nack: ${CCNL_RELAY_LIB}
	${CC} -o $@ ${CCNLCFLAGS} ${NACKFLAGS} $< ${EXTLIBS}
	@${CREATE_BIN}

ccn-lite-relay: CCNLCFLAGS += -DCCNL_UNIX -DUSE_CCNxDIGEST -DUSE_DEBUG -DUSE_DEBUG_MALLOC -DUSE_DUP_CHECK -DUSE_ECHO -DUSE_LINKLAYER -DUSE_HMAC256 -DUSE_HTTP_STATUS \
	-DUSE_IPV4 -DUSE_IPV6 -DUSE_MGMT -DUSE_NFN_NSTRANS -DUSE_STATS -DUSE_SUITE_CCNB -DUSE_SUITE_CCNTLV -DUSE_SUITE_CISTLV -DUSE_SUITE_IOTTLV -DUSE_SUITE_NDNTLV \
	-DUSE_SUITE_LOCALRPC -DUSE_UNIXSOCKET -DNEEDS_PREFIX_MATCHING
ccn-lite-relay: ${CCNL_RELAY_LIB}
	${CC} -o $@ ${CCNLCFLAGS} $< ${SUITE_LIBS} ${EXTLIBS}
	@${CREATE_BIN}
%.o: %.c
	${CC} -o $@ ${RIOT_CFLAGS} ${CCNLCFLAGS} -c $<

ccn-lite-relay-nack: ${CCNL_RELAY_LIB}
	${CC} -o $@ ${CCNLCFLAGS} ${NACKFLAGS} $< ${EXTLIBS}
	@${CREATE_BIN}

ccn-lite-simu: CCNLCFLAGS += -DNEEDS_PREFIX_MATCHING -DNEEDS_PACKET_CRAFTING -DUSE_FRAG \
	-DUSE_SUITE_NDNTLV -DUSE_SUITE_CCNB -DUSE_SUITE_CCNTLV -DUSE_DEBUG -DUSE_DEBUG_MALLOC \
	-DUSE_DUP_CHECK -DUSE_LINKLAYER -DUSE_IPV4 -DUSE_LOGGING -DUSE_SUITE_CISTLV -DUSE_SUITE_IOTTLV \
	-DCCNL_UNIX -DCCNL_SIMULATION
ccn-lite-simu: platforms/ccn-lite-simu.c  ${SUITE_OBJS} \
	${CCNL_CORE_LIB} ${CCNL_PLATFORM_LIB} \
	ccnl-simu-client.c
	${EXTMAKE}
	${CC} -o $@ ${CCNLCFLAGS} $< ${SUITE_LIBS} ${EXTLIBS}
	@${CREATE_BIN}

ccn-lite-omnet:  ${OMNET_DEPS}
	rm -rf ccn-lite-omnet
	rm -rf ccn-lite-omnet.tgz
	cp -a omnet ccn-lite-omnet
	mkdir ccn-lite-omnet/src/ccn-lite
	cp -a $^ ccn-lite-omnet/src/ccn-lite/
	tar -zcvf ccn-lite-omnet.tgz ccn-lite-omnet
	rm -rf ccn-lite-omnet

ccn-lite-lnxkernel:
	$(MAKE) modules

modules: platforms/ccn-lite-lnxkernel.c  ${SUITE_LIBS} \
    ${CCNL_CORE_LIB} ${CCNL_PLATFORM_LIB} ext/crypto.c
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules

datastruct.pdf: datastruct.dot
	dot -Tps -o datastruct.ps datastruct.dot
	epstopdf datastruct.ps
	rm -f datastruct.ps

install: all
	install ${INST_PROGS} ${INSTALL_PATH}/bin && cd util && $(MAKE) install && cd ..

uninstall:
	cd ${INSTALL_PATH}/bin && rm -f ${PROGS} && cd - > /dev/null \
	&& cd util && $(MAKE) uninstall && cd ..

clean:
	${EXTMAKECLEAN}
	rm -rf *~ *.o ${PROGS} ccn-lite-lnxkernel ccn-lite-simu ccn-nfn-relay ccn-lite-relay-nack ccn-nfn-relay-nack ccn-lite-repo256
	rm -rf .ccn-lite-lnxkernel* *.ko *.mod.c *.mod.o .tmp_versions modules.order Module.symvers
	rm -rf ccn-lite-omnet.tgz
	rm -rf ../bin
	$(MAKE) -C util clean

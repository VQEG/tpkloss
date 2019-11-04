#####################################################################
#
# Telchemy PCAP Packet Loss Insertion Tool
#
# This software introduces losses to a pcap capture file using a
# 2-state or 4-state Markov model.
# The Markov models can either be parameterized in detail or through
# default values. For the use in subjective tests the tool has been
# extended such that it will prohibit either the start, the end of the
# capture file or both for X amounts of milliseconds from being
# impaired.
#
# This software is provided at no cost for experimental use in lab 
# environments and Telchemy makes no warranty with regard to its 
# operation or to any issues that may arise from its use.  
# Telchemy is not aware of any intellectual property issues that may 
# result from the use of this software however makes no warranty with 
# regard to patent infringement.  Telchemy has made no IPR claims with
# regard to this software with the exception of the requirements 
# contained in this header.  The software may be modified, copied and
# made available to other parties however this header must be retained
# intact. The software may not be sold or incorporated into commercial
# applications.  Telchemy would appreciate any technical feedback and 
# improvements - support@telchemy.com
#
##################################################################### 


BUILDTARGET=tpkloss
TARGETSRC= tpklmain.c tpklutil.c tpkloss.c tpklcap.c
TARGETOBJ=$(TARGETSRC:.c=.o)
OBJDIR=./obj
CC=gcc
LINK=gcc


usage:
	@echo ""
	@echo "make <target>"
	@echo ""
	@echo "Supported Targets:"
	@echo ""
	@echo "  debug           Debug Version of '$(BUILDTARGET)'"
	@echo "  release         Release Version of '$(BUILDTARGET)'"
	@echo "  clean           Remove *.o and executable"
	@echo ""


ifdef DEBUG
CFLAGS += -g -DDEBUG
BUILDTYPE=debug
else
CFLAGS += -O2
BUILDTYPE=release
endif

%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $(OBJDIR)/$(BUILDTYPE)/$@

debug:
	 @$(MAKE) bldtarget DEBUG=1

release:
	 @$(MAKE) bldtarget RELEASE=1


bldtarget: bldmsg preproc $(TARGETOBJ) postproc
	@$(LINK) -o $(BUILDTARGET) \
	           $(foreach $file, $(OBJDIR)/$(BUILDTYPE), \
				$(wildcard $(OBJDIR)/$(BUILDTYPE)/*.o))

preproc:
	@if [ ! -f $(OBJDIR)/$(BUILDTYPE) ]; then \
		mkdir -p $(OBJDIR)/$(BUILDTYPE); \
	fi;

postproc:
	@echo ""
	@echo "Built $(BUILDTYPE) version of '$(BUILDTARGET)'"

bldmsg:
	@echo ""
	@echo "Building $(BUILDTYPE) version of '$(BUILDTARGET)'"

clean:
	@echo ""
	@echo "Removing $(OBJDIR) and '$(BUILDTARGET)'"
	@rm  -rf $(OBJDIR)
	@rm  $(BUILDTARGET)
	@echo ""



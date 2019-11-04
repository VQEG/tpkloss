/*********************************************************************
*
* Telchemy PCAP Packet Loss Insertion Tool
*
* This software introduces losses to a pcap capture file using a
* 2-state or 4-state Markov model.
* The Markov models can either be parameterized in detail or through
* default values. For the use in subjective tests the tool has been
* extended such that it will prohibit either the start, the end of the
* capture file or both for X amounts of milliseconds from being
* impaired.
*
* This software is provided at no cost for experimental use in lab 
* environments and Telchemy makes no warranty with regard to its 
* operation or to any issues that may arise from its use.  
* Telchemy is not aware of any intellectual property issues that may 
* result from the use of this software however makes no warranty with 
* regard to patent infringement.  Telchemy has made no IPR claims with
* regard to this software with the exception of the requirements 
* contained in this header.  The software may be modified, copied and
* made available to other parties however this header must be retained
* intact. The software may not be sold or incorporated into commercial
* applications.  Telchemy would appreciate any technical feedback and 
* improvements - support@telchemy.com
*
*********************************************************************/


/*
 * tpklutil.h
 */

#ifndef _TELCHEMY_TPKLUTIL_H_
#define _TELCHEMY_TPKLUTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

TCMY_PUBLIC(void)
tcmyLossPrintUsage(
    tcmyS32 argc, 
    tcmyCHAR  *argv[]
    );

TCMY_PUBLIC(tcmy_result_t)
tcmyLossParseArg(
    tloss_args_t *pArgs,
    tcmyS32   argc,
    tcmyCHAR *argv[]
    );
    

#ifdef __cplusplus
}
#endif

#endif  /* _TELCHEMY_TPKLUTIL_H_ */

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
 * tpklcap.c
 */

#include <stdlib.h>
#include <time.h>
#include "tpkldef.h"
#include "tpklcap.h"

/* determine the duration of the capture file */
tcmy_result_t GetPcapFeatures(tcmyS32 *_pPacketCnt,
                            tcmyS32 *_pSequenceLenInMS,
                            FILE* _hInFile){
    
    tcmy_result_t _result = TCMY_ESUCCESS;
    
    tcmyU8  _aBuffer[2048];
    tcmyS32 _nBufferLen = 2048;
    tcmyS32 _nBytesRead = 0;
    
    tloss_time_t _tRelTime={0};
    
    /* read global header */
    if (ReadData(_aBuffer, _nBufferLen, &_nBytesRead,
    sizeof(pcap_hdr_t), _hInFile)!=TCMY_ESUCCESS) return TCMY_EFAILURE;
    /* read the first packet header */
    if (ReadData(_aBuffer, _nBufferLen, &_nBytesRead,
    sizeof(pcaprec_hdr_t), _hInFile)!=TCMY_ESUCCESS) return TCMY_EFAILURE;
    
    /* initialize relative signal timing */
    _tRelTime.prevUsec = ((pcaprec_hdr_t*) _aBuffer)->ts_usec;    
    
    while (!feof(_hInFile))       
    {
        /* determine current signal timing */
        GetRelativeTime(&_tRelTime, (pcaprec_hdr_t*) _aBuffer);
        
        /* read packet payload */
        if(ReadData(_aBuffer+sizeof(pcaprec_hdr_t),
        _nBufferLen, &_nBytesRead, ((pcaprec_hdr_t*) _aBuffer)->incl_len,
        _hInFile) != TCMY_ESUCCESS) break;
        (*_pPacketCnt)++;
        /* read second packet header */
        if(ReadData(_aBuffer, _nBufferLen,&_nBytesRead, sizeof(pcaprec_hdr_t),
        _hInFile) != TCMY_ESUCCESS) break;
#if 0
#ifdef DEBUG
    printf("# %4d, %10d\n", *_pPacketCnt, (tcmyS32)(_tRelTime.sec*1000.0+_tRelTime.usec/1000.0) );
#endif
#endif
    }
    
    *_pSequenceLenInMS = (tcmyS32)(_tRelTime.sec*1000.0+_tRelTime.usec/1000.0);
    
    rewind(_hInFile);
    
    return _result;
}

/* derive global PCAP file header information */
tcmy_result_t CheckGlobalPcapHeader(tcmyU8* _pBuffer){
    
    tcmy_result_t _result = TCMY_ESUCCESS;
    
    pcap_hdr_t* _globalHeader=NULL;
    tcmyBOOL    _bSwapped = FALSE;
    
    /* write global wireshark header to output file */
    _globalHeader=(pcap_hdr_t*)_pBuffer;    
    
    /* check byte order */
    if(0xa1b2c3d4 == _globalHeader->magic_number)
    {
        /*TCMY_DBGPRINT(" byte-order: not swapped\n");*/
        _bSwapped = FALSE;
    }
    else if (0xd4c3b2a1 == _globalHeader->magic_number)
    {
        /* this is not tested */
        /*TCMY_DBGPRINT(" byte-order: swapped\n");*/
        _bSwapped = TRUE;
        _globalHeader->snaplen = ntohl(_globalHeader->snaplen);
        _globalHeader->network = ntohl(_globalHeader->network);
    }
    else
    {
        printf("ERROR: unrecognized header\n");        
        return TCMY_EFAILURE;
    }
    /*
    TCMY_DBGPRINT(" max snaplen: %d\n",_globalHeader->snaplen);
    TCMY_DBGPRINT(" data link type: %d\n", _globalHeader->network);
    */
    /* currently only ethernet capture files are accepted */
    if(1 != _globalHeader->network)
    {            
        printf("ERROR: data link type %x not supported\n", _globalHeader->network);        
        return TCMY_EFAILURE;
    }
    
    return _result;
}

/* Generic function: read data from the input (PCAP) file */
tcmy_result_t ReadData(tcmyU8* _pBuffer,
                        tcmyS32 _nBufferLen,
                        tcmyS32* _pBytesRead,
                        tcmyS32 _nBytesToRead,
                        FILE* _hInFile){
    
    tcmy_result_t _result = TCMY_ESUCCESS;
    tcmyS32        _nBytesRead = 0;
    
    /*
     * read/decode wireshark packet header and find out how long the packet is
     */
    _nBytesRead = fread(_pBuffer, 1, _nBytesToRead, _hInFile);
    
    if (!feof(_hInFile)){
        if (_nBytesRead < _nBytesToRead)
        {
            printf("ERROR: packet too short/corrupt\n");
            _result = TCMY_EFAILURE;
        }
    }
    else{
        _result = TCMY_EFAILURE;
    }
    *_pBytesRead = _nBytesRead;
    return _result;    
}


/* Generic function: write data to the output (PCAP) file */
tcmy_result_t WriteData(tcmyU8* _pBuffer,
                        tcmyS32 _nBufferLen,
                        tcmyS32 _nBytesToWrite,
                        FILE* _hOutFile){
    
    tcmy_result_t _result = TCMY_ESUCCESS;
    tcmyS32 _nBytesWritten = 0;
    
    if (_nBufferLen >= _nBytesToWrite){
        _nBytesWritten = fwrite(_pBuffer, 1, _nBytesToWrite, _hOutFile);
        if (_nBytesToWrite != _nBytesWritten) {
            _result = TCMY_EFAILURE;
        }
    }
    else{
        _result = TCMY_EFAILURE;
    }
    return _result;
}

/* determine the current time within a PCAP file derived from the RTP timestamp */
void GetRelativeTime(tloss_time_t* _tRelTime, pcaprec_hdr_t* _packetHeader){
    
    
    _tRelTime->usec += (tcmyS32)(_packetHeader->ts_usec)-_tRelTime->prevUsec;
#if 0
#ifdef DEBUG
    printf("Relative time: %32d.%06ds, %06d, %06d\n", _tRelTime->sec, _tRelTime->usec, _packetHeader->ts_usec, _tRelTime->prevUsec);
#endif
#endif
        if (((tcmyS32)(_packetHeader->ts_usec)-_tRelTime->prevUsec) < 0) {
        _tRelTime->usec += 1000000;
    }
    if (_tRelTime->usec >=1000000) {
        _tRelTime->sec++;
        _tRelTime->usec -= 1000000;
    }

    _tRelTime->prevUsec = (tcmyS32)(_packetHeader->ts_usec);
}

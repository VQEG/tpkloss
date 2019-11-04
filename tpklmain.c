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

#include <sys/time.h>
#include "tpkldef.h"
#include "tpklver.h"
#include "tpklutil.h"
#include "tpkloss.h"
#include "tpklcap.h"


/* 
 1. assess pcap format
 2. copy global header
 3. check number of packets
 4. check timestamps
 5. is file long enough for specified packet loss and skips at end and start?
 6. determine when to start loss and when to stop (first and last part will not be corrupted)
 7. introduce losses into the PCAP file
 */

int main(int argc, char* argv[])
{
    
    FILE* _hOutFile=NULL;
    FILE* _hInFile=NULL;
    FILE* _hLossFile = NULL;
    
    tcmy_result_t _result = TCMY_ESUCCESS;
    tloss_args_t   _tLossArgs;
    
    tcmyU8  _aBuffer[2048];
    tcmyS32 _nBufferLen = 2048;
    tcmyS32 _nBytesRead = 0;
    tcmyS32 _nPacketCnt=0;
    tcmyS32 _nSequenceLenInMS=0;
    tcmyS32 _nCurrentRelTimeMS=0;
    tcmyS32 _nPacketsInNoLossArea=0;
    
    tloss_time_t _tRelTime={0};
    
    struct timeval _time={0};
    
    tcmyBOOL _bLoss = FALSE;
    tcmyS32  _nLost = 0;
    
    printf("\n%s Version: %s\n\n", VER_PRODUCTNAME_STR, TSCR_VER_STRING);
    
    /* get the information from the command line */
    if (TCMY_ESUCCESS != tcmyLossParseArg(
                                          &_tLossArgs,
                                          argc,
                                          argv))
    {
        tcmyLossPrintUsage(argc, argv);
        return TCMY_EFAILURE;
    }
    
    /* check if the required data can be opened */
    do{
    
        if ((_hInFile = fopen(_tLossArgs.input_fn,"rb"))==0){
            printf("Error: Could not open file %s\n",_tLossArgs.input_fn);
            _result = TCMY_EFAILURE;
            break;
        }
        if ((_hOutFile = fopen(_tLossArgs.output_fn,"wb"))==0){
            printf("Error: Could not open file %s\n",_tLossArgs.output_fn);
            _result = TCMY_EFAILURE;
            break;
        }
        if(CREATE_LOSS_FILE & _tLossArgs.op_mode){
            if ((_hLossFile = fopen(_tLossArgs.loss_fn,"wb"))==0){
                printf("Error: Could not open file %s\n",_tLossArgs.loss_fn);
                _result = TCMY_EFAILURE;
                break;
            }
        }
        else if(READ_LOSS_FILE == _tLossArgs.op_mode){
            if ((_hLossFile = fopen(_tLossArgs.loss_fn,"rb"))==0){
                printf("Error: Could not open file %s\n",_tLossArgs.loss_fn);
                _result = TCMY_EFAILURE;
                break;
            }
        }
        
        if( GetPcapFeatures(&_nPacketCnt, &_nSequenceLenInMS, _hInFile) != TCMY_ESUCCESS){
            _result = TCMY_EFAILURE;
            break;
        }
        
        printf("\t%30s: %d\n","Number of Packets", _nPacketCnt);
        printf("\t%30s: %0.2fsec\n","Duration of Sequence", (float)(_nSequenceLenInMS/1000.0));
        
        if(_tLossArgs.skipEnd+_tLossArgs.skipStart > _nSequenceLenInMS){
            printf("Error: The time skipped in the signal is longer than the input signal\n");
            _result = TCMY_EFAILURE;
            break;
        }
        
        if (ReadData(_aBuffer, _nBufferLen, &_nBytesRead, sizeof(pcap_hdr_t), _hInFile)!=TCMY_ESUCCESS) {
            printf("Error: Could not read from file %s\n",_tLossArgs.input_fn);
            _result = TCMY_EFAILURE;
            break;
        }
        if (CheckGlobalPcapHeader(_aBuffer)!=TCMY_ESUCCESS) {
            printf("Error: Invalid PCAP file\n");
            _result = TCMY_EFAILURE;
            break;
            
        }
        if (WriteData(_aBuffer, _nBufferLen, _nBytesRead, _hOutFile)!=TCMY_ESUCCESS) {
            printf("Error: Could not write to file %s\n",_tLossArgs.output_fn);
            _result = TCMY_EFAILURE;
            break;
        }
        /* read the first packet header */
        if (ReadData(_aBuffer, _nBufferLen, &_nBytesRead, sizeof(pcaprec_hdr_t), _hInFile)!=TCMY_ESUCCESS) {
            printf("Error: Could not read from file %s\n",_tLossArgs.input_fn);
            _result = TCMY_EFAILURE;
            break;
        }
        
        /* initialize relative signal timing */
        _tRelTime.prevUsec = ((pcaprec_hdr_t*) _aBuffer)->ts_usec;    
        
        /*
         * init random number generation
         */
         gettimeofday(&_time, NULL);
#ifdef WIN32
        srand((unsigned long)_time.tv_usec);
#else
        srand48((unsigned long)_time.tv_usec);
#endif
        /* main routine */
        while (!feof(_hInFile))       
        {
            /* determine current signal timing */
            GetRelativeTime(&_tRelTime, (pcaprec_hdr_t*) _aBuffer);
            
            /* read first payload */
            if (ReadData(_aBuffer+sizeof(pcaprec_hdr_t), _nBufferLen, &_nBytesRead, 
                         ((pcaprec_hdr_t*) _aBuffer)->incl_len , _hInFile) != TCMY_ESUCCESS) break;
            
            /* determine if current packet gets lost or will be copied */
            _bLoss = Lost(&_tLossArgs, _hLossFile);
            
            _nCurrentRelTimeMS = (tcmyS32)(_tRelTime.sec*1000.0+_tRelTime.usec/1000.0);
            
            /* exclude N milliseconds from losses from the beginning and towards the end */
            if ((_nCurrentRelTimeMS < _tLossArgs.skipStart) ||
                (_nCurrentRelTimeMS > (_nSequenceLenInMS- _tLossArgs.skipEnd))){
                _nPacketsInNoLossArea++;
                _bLoss = FALSE;
            }
            
            /* losses are introduced by only copying the packets that did not get lost */
            _bLoss==TRUE ? _nLost++ :
            (_result = WriteData(_aBuffer, _nBufferLen, _nBytesRead + sizeof(pcaprec_hdr_t), _hOutFile));
            if(_result!= TCMY_ESUCCESS) break;
            
            if(ReadData(_aBuffer, _nBufferLen, &_nBytesRead, sizeof(pcaprec_hdr_t), _hInFile) != TCMY_ESUCCESS) break;
            
        } /* end while */
        
        printf("\n\t%30s: %f\n\n","Loss rate in loss region", _nLost/(float)(_nPacketCnt-_nPacketsInNoLossArea));
        
    }while(FALSE);
    
    /* clean up */
	if(_hInFile) fclose(_hInFile);
	if(_hOutFile) fclose(_hOutFile);
    if(_hLossFile) fclose(_hLossFile);
    
	return 0;
}

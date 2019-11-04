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
 * tpkloss.c
 */

#include <stdlib.h>
#include "tpkldef.h"
#include "tpkloss.h"


void chomp(tcmyCHAR *s) {
    while(*s && *s != '\n' && *s != '\r') s++;
    *s = 0;
}
/* determine if a loss occurred or not */
tcmyBOOL Lost(tloss_args_t* _tLossArgs, FILE* _hLossFile){
    
    tcmyBOOL _loss = FALSE;
    unsigned int _nloss = 1;
    
    unsigned int state=_tLossArgs->state; /* recover previous state */
    
    /* read losses from file */
    if(READ_LOSS_FILE == _tLossArgs->op_mode){
        
        tcmyCHAR _c[256] = "";
        
        fgets(_c,256,_hLossFile);
        /* 
         * in case the capture file at the input is longer than the loss
         * pattern file the loss pattern will be read from the beginning
         * as soon as we reach the end of the loss pattern file
         */
        if (feof(_hLossFile)) {
            rewind(_hLossFile);
            fgets(_c,1,_hLossFile);
        }
        chomp(_c);
        
        return TCMY_STRCMP(_c,"0")?FALSE:TRUE;
    }
    else if(FOUR_STATE_MM & _tLossArgs->op_mode){
        
        /*
         * 4-state Markov Model states:
         * 0 - Gap with random non-consecutive loss
         * 1 - Gap lossless state
         * 2 - Burst lossy state
         * 3 - Burst lossless state
         */
        
        double pab = _tLossArgs->pab; /* 1.0  */
        double pba = _tLossArgs->pba;
        double pbc = _tLossArgs->pbc;
        double pcb = _tLossArgs->pcb; /* 0.3  */
        double pcd = _tLossArgs->pcd; /* 0.05 */
        double pdc = _tLossArgs->pdc; /* 0.25 */
#if 0        
        float pbb = _tLossArgs->pbb; /* obsolete pbb = 1-(pbc+pba) */
        float pcc = _tLossArgs->pcc; /* obsolete pcc = 1-(pcd+pcb) */ /* 0.65 */
        float pdd = _tLossArgs->pdd; /* obsolete pdd = 1-pdc */       /* 0.75 */
#endif        
        double *gbloss = &(_tLossArgs->gbloss[0]);
        
        double fRnd = 0;
        
        /* Gap states */
        
        switch (state) {
            case 0:
                /* gap state with random loss */
                _nloss = tcmyrand() < gbloss[0] ? 0:1;
#ifdef DEBUG
                printf("%u,%u\n",_nloss,state);
#endif
                if(_tLossArgs->op_mode & CREATE_LOSS_FILE) fprintf(_hLossFile,"%u\n",_nloss);
                
                /* state change ? */
                if(tcmyrand() <= pab) state++;
                break;
            case 1:
#ifdef DEBUG
                printf("%u,%u\n",_nloss,state);
#endif
                if(_tLossArgs->op_mode & CREATE_LOSS_FILE) fprintf(_hLossFile,"%u\n",_nloss);
                
                /* gap state without loss */
                fRnd = tcmyrand();
                if(fRnd < pbc){
                    state++;
                }
                /*else if(fRnd > pbc+pbb){*/
                else if(fRnd > (1-pba)){
                    state--;
                }
                break;
            case 2:
                /* lossy burst state */
                _nloss = tcmyrand() < gbloss[1] ? 0:1;
#ifdef DEBUG
                printf("%u,%u\n",_nloss,state);
#endif
                if(_tLossArgs->op_mode & CREATE_LOSS_FILE) fprintf(_hLossFile,"%u\n",_nloss);
                
                /* state change ? */
                fRnd = tcmyrand();
                if(fRnd < pcd){
                    state++;
                }
                /*else if(fRnd > pcd+pcc){*/
                else if(fRnd > (1-pcb)){
                    state--;
                }
                break;                
            case 3:
                /* burst state without loss */
#ifdef DEBUG
                printf("%u,%u\n",_nloss,state);
#endif
                if(_tLossArgs->op_mode & CREATE_LOSS_FILE) fprintf(_hLossFile,"%u\n",_nloss);
                
                if(tcmyrand() < pdc) state--;
                break;
            default:
                printf("Error: Unknown State\n");
                return FALSE;
        }

        /* save previous state */
        _tLossArgs->state = state;
    }
    else if(TWO_STATE_MM & _tLossArgs->op_mode){
        
        /* Gilbert-Elliott Model */        
        /* 
         * 2-state Markov Model states:
         * 0 - Gap state with low loss
         * 1 - Burst state with high loss
         */
        
        /* packet loss */
        _nloss = tcmyrand()<_tLossArgs->gbloss[state] ? 0:1;
        
#ifdef DEBUG
        printf("%u,%u\n",_nloss,state);
#endif

        if(_tLossArgs->op_mode & CREATE_LOSS_FILE) fprintf(_hLossFile,"%u\n",_nloss);
        
        /* state switch */
        double rnd = tcmyrand();
        if(rnd<_tLossArgs->gbtrans[state])
            state=1-state;
                     
        /* save previous state */
        _tLossArgs->state = state;
    }
        
    /* return whether a packet got lost or not */
    return _nloss==1?FALSE:TRUE;
}

/* create a random number */
/* Note: the initialization occurred in the main function */
double tcmyrand(){
#ifdef WIN32
    /* state switch */
    return fRand = (double)rand()/((double)(RAND_MAX)+1L);
#else
    return drand48();
#endif
    
}

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
 * tpklutil.c
 */

#include <stdio.h>
#include "tpkldef.h"


TCMY_PUBLIC(void)
tcmyLossPrintUsage(tcmyS32 argc, tcmyCHAR  *argv[])
{
    printf("Usage: \n");
    printf("\nWhere options are:\n");
    printf("\t -i <filename>: Input capture file name\n");
    printf("\t -o <filename>: Output capture file name including losses\n");
    printf("\t -m <2|4>     : Specify 2-state (2) or 4-state (4) Markov model\n");
    printf("\t -s <time[ms]>: Time at the beginning of the pcap file that is not exposed to packet losses\n");
    printf("\t -e <time[ms]>: Time at the end of the pcap file that is not exposed to packet losses\n");
    
    printf("\n");
    printf("For a 2-state Markov loss model please specify:\n");
    printf("\t -pcb <float>: Transition probability from burst to gap state\n");
    printf("\t -pbc <float>: Transition probability from gap to burst state\n");
    printf("\t -g  <float>: Loss probability in gap state\n");
    printf("\t -b  <float>: Loss probability in burst state\n");
    
    printf("\n");
    printf("For a 4-state Markov loss model please specify:\n");
    printf("\t -pba <float>: Transition probability from gap lossless to gap lossy state\n");
    printf("\t -pbc <float>: Transition probability from gap to burst state\n");
    
    printf("\t -pdc <float>: Transition probability from burst lossless to burst lossy state (default 0.25)\n");
    printf("\t -pcd <float>: Transition probability from burst lossy to burst lossless state (default 0.05)\n");
    printf("\t -pcb <float>: Transition probability from burst to gap state (default 0.3)\n");
    
    /*  
     obsolete:
     printf("\t -pab <float>: Transition probability from gap lossy to gap state lossless\n");
     printf("\t -pbb <float>: Transition probability from/to lossless gap state\n");
     printf("\t -pcc <float>: Transition probability from/to lossy burst state\n");
     printf("\t -pdd <float>: Transition probability from/to lossless burst state\n");
     */
    
    printf("\t -g  <float>: Loss probability in gap state\n");
    printf("\t -b  <float>: Loss probability in burst state\n");
    
    printf("\n");
    printf("For a P.NAMS/P.NBAMS 4-state Markov loss model please specify:\n");
    printf("\t -loss_ratio  <float>: Target average loss probability\n");
    printf("\t -gap_ratio   <float>: Percentage of time in which the process resides in the gap state\n");
    
    
    printf("\n");
    printf("Note: All probabilities and loss rates are within a range of [0,1]\n");
    printf("Note 2: Certain restrictions to the combination of the transitions probs apply\n");
    
    printf("\n");
    printf("Create a loss pattern file or read from loss pattern file:\n");
    printf("\t -r <filename>: Read loss pattern txt-file with the numbers 0 or 1 per\n");
    printf ("\t\t\tline indicate loss or no-loss respectively\n");
    printf("\t -c <filename>: Create loss pattern txt-file with the numbers 0 or 1 per\n");
    printf ("\t\t\tline indicate loss or no-loss respectively\n");
    printf("\n");
    printf("\n");
    
    return;
}


TCMY_PUBLIC(tcmy_result_t)
tcmyLossParseArg(
                 tloss_args_t *pArgs,
                 tcmyS32   argc,
                 tcmyCHAR *argv[]
                 )
{
    tcmyU32       _i = 0;
    
    tcmyU8 _nbbflag=0;
    tcmyU8 _nccflag=0;
    tcmyU8 _nddflag=0;
    
    tcmyU8 _nabflag=0;
    tcmyU8 _nbaflag=0;
    tcmyU8 _nbcflag=0;
    tcmyU8 _ncbflag=0;
    tcmyU8 _ncdflag=0;
    tcmyU8 _ndcflag=0;
    
    tcmyU8 _ngflag=0;
    tcmyU8 _nbflag=0;
    
    tcmyU8 _nlrflag=0;
    tcmyU8 _ngrflag=0;
    double _loss_ratio=0;
    double _gap_ratio=0;
    
    
    if (argc < 2)
    {
        return TCMY_EFAILURE;
    }
    
    TCMY_MEMCLEAR(pArgs, sizeof(tloss_args_t));
    
    for (_i = 1; _i < argc;)
    {
        if (0 == TCMY_STRICMP("-h", argv[_i]))
        {
            return TCMY_EFAILURE;
        }
        else if (0 == TCMY_STRICMP("-loss_ratio", argv[_i]))
        {
            if(_i+1 < argc){
                _loss_ratio=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nlrflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-gap_ratio", argv[_i]))
        {
            if(_i+1 < argc){
                _gap_ratio=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _ngrflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-m", argv[_i]))
        {
            if(_i+1 < argc){
                if(atoi(argv[_i+1]) == 2){
                    pArgs->op_mode |= TWO_STATE_MM;
                }
                else if(atoi(argv[_i+1]) == 4){
                    pArgs->op_mode |= FOUR_STATE_MM;
                }
                else {
                    return TCMY_EFAILURE;
                }
            }
            else{
                return TCMY_EFAILURE;
            }
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pab", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pab=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nabflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pba", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pba=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nbaflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pbc", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->gbtrans[0] = pArgs->pbc=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nbcflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pcb", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->gbtrans[1] = pArgs->pcb=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _ncbflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pcd", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pcd=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _ncdflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pdc", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pdc=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _ndcflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pbb", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pbb=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nbbflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pcc", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pcc=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nccflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-pdd", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->pdd=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nddflag=1;
            _i += 2;
        }        
        else if (0 == TCMY_STRICMP("-g", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->gbloss[0]=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _ngflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-b", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->gbloss[1]=atof(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _nbflag=1;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-s", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->skipStart=atoi(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-e", argv[_i]))
        {
            if(_i+1 < argc){
                pArgs->skipEnd=atoi(argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _i += 2;
        }
        else if  (0 == TCMY_STRICMP("-i", argv[_i]))
        {
            if(_i+1 < argc){
                TCMY_STRCPY(pArgs->input_fn,argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _i += 2;
        }
        else if  (0 == TCMY_STRICMP("-o", argv[_i]))
        {
            if(_i+1 < argc){
                TCMY_STRCPY(pArgs->output_fn,argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-r", argv[_i])){
            if(_i+1 < argc){
                TCMY_STRCPY(pArgs->loss_fn,argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            pArgs->op_mode = READ_LOSS_FILE;
            _i += 2;
        }
        else if (0 == TCMY_STRICMP("-c", argv[_i])){
            if(_i+1 < argc){
                TCMY_STRCPY(pArgs->loss_fn,argv[_i+1]);
            }
            else{
                return TCMY_EFAILURE;
            }
            pArgs->op_mode |= CREATE_LOSS_FILE;
            _i += 2;
        }
        else
        {
            return TCMY_EFAILURE;
        }
    }
        
    if((pArgs->input_fn[0] != '\0') && (pArgs->output_fn[0] != '\0'))
    {
        printf("\t%30s: %s\n", "Input File", pArgs->input_fn);
        printf("\t%30s: %s\n", "Output File", pArgs->output_fn);
    }
    else
    {
        return TCMY_EFAILURE;
    }
    
    if(READ_LOSS_FILE == pArgs->op_mode) {
        printf("\t%20s: %s\n", "Loss File (read)", pArgs->loss_fn);
        return TCMY_ESUCCESS;
    }
    else if(CREATE_LOSS_FILE & pArgs->op_mode) {
        printf("\t%20s: %s\n", "Loss File (write)", pArgs->loss_fn);
    }
    
    
    /* P.NAMS/P.NBAMS proprietary settings */
    if ((_ngrflag == 1) && (_nlrflag == 1)) {
        double a = _loss_ratio * _gap_ratio;
        double c = _loss_ratio * (1 - _gap_ratio);
        
        if((_loss_ratio>1)||(_loss_ratio<0)){
            printf("Error: Loss ratio out of range [0,1]\n");
            return TCMY_EFAILURE;
        }
        if((_gap_ratio>1)||(_gap_ratio<0)){
            printf("Error: Gap ratio out of range [0,1]\n");
            return TCMY_EFAILURE;
        }

        /* override any previous settings */
        if(pArgs->op_mode & CREATE_LOSS_FILE){
            pArgs->op_mode = FOUR_STATE_MM;
            pArgs->op_mode |= CREATE_LOSS_FILE;
        }
        else{
            pArgs->op_mode = FOUR_STATE_MM;
        }
        
        pArgs->gbloss[0]=1.0;
        pArgs->gbloss[1]=1.0;
        
        pArgs->pba = a / (1-a-1.2*c);
        pArgs->pbc = 0.3*c/(1-a-1.2*c);
        
        /* make sure we pass the following tests */
        _nbcflag = 1;
        _nbaflag = 1;
        _ngflag = 1;
        _nbflag = 1;
    }

    /* is the mode set appropriately ? */
    if (READ_LOSS_FILE != pArgs->op_mode){
        if(!(TWO_STATE_MM & pArgs->op_mode)){
            if (!(FOUR_STATE_MM & pArgs->op_mode)){
                return TCMY_EFAILURE;
            }
        }
    }
    /* mandtory parameters for both models */
    if(_nbcflag ==0){
        printf("Error: -pbc must be set\n");
        return TCMY_EFAILURE;
    }else {
        if((pArgs->pbc>1)||(pArgs->pbc<0)){
            printf("Error: pbc out of range [0,1]\n");
            return TCMY_EFAILURE;
        }
    }
    if(_ngflag ==0){
        printf("Error: -g must be set\n");
        return TCMY_EFAILURE;
    }
    else {
        if((pArgs->gbloss[0]>1)||(pArgs->gbloss[0]<0)){
            printf("Error: -g out of range [0,1]\n");
            return TCMY_EFAILURE;
        }
    }
    if(_nbflag ==0){
        printf("Error: -b must be set\n");
        return TCMY_EFAILURE;
    }
    else {
        if((pArgs->gbloss[1]>1)||(pArgs->gbloss[1]<0)){
            printf("Error: -b out of range [0,1]\n");
            return TCMY_EFAILURE;
        }
    }
    
    /* parameter check for 4-state model */
    if ((FOUR_STATE_MM & pArgs->op_mode)){
        /* mandatory parameters for the 4-state model */
        if(_nbaflag ==0){
            printf("Error: -pba must be set\n");
            return TCMY_EFAILURE;
        }
        else {
            if((pArgs->pba>1)||(pArgs->pba<0)){
                printf("Error: -pba out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        /* optional parameters for the 4-state model */
        if(_nabflag==0){
            pArgs->pab = 1.0L;
        }else {
            if((pArgs->pab>1)||(pArgs->pab<0)){
                printf("Error: -pab out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        if(_ncbflag==0){
            pArgs->pcb = 0.3L;
        }else {
            if((pArgs->pcb>1)||(pArgs->pcb<0)){
                printf("Error: -pcb out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        if(_ncdflag==0){
            pArgs->pcd = 0.05L;
        }
        else {
            if((pArgs->pcd>1)||(pArgs->pcd<0)){
                printf("Error: -pcd out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        if(_ndcflag==0){
            pArgs->pdc = 0.25L;
        }
        else {
            if((pArgs->pdc>1)||(pArgs->pdc<0)){
                printf("Error: -pdc out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        /* parameter verification */
        if(pArgs->pba+pArgs->pbc>1){
            printf("Error: pba+pbc>1 out of range [0,1]\n");
            return TCMY_EFAILURE;
        }
        if(pArgs->pcd+pArgs->pcb>1){
            printf("Error: pcb+pcd>1 out of range [0,1]\n");
            return TCMY_EFAILURE;
        }        
        /* predicted loss rate */
        double _dGapLoss = pArgs->pba * pArgs->gbloss[0]/(pArgs->pab + pArgs->pba);
        double _dBurstLoss = pArgs->pdc * pArgs->gbloss[1]/(pArgs->pdc + pArgs->pcd);
        double _dGapPeriod = pArgs->pcb * (pArgs->pab + pArgs->pba) / pArgs->pab;
        double _dBurstPeriod = pArgs->pbc * (pArgs->pdc + pArgs->pcd) / pArgs->pdc;
        double _dPredLoss = _dGapPeriod * _dGapLoss/(_dGapPeriod + _dBurstPeriod) + 
                            _dBurstPeriod * _dBurstLoss/(_dGapPeriod + _dBurstPeriod);
        printf("\t%30s: %f\n", "Predicted Loss rate", _dPredLoss);     
    }
    
    /* mandatory parameters for the 2-state model */
    if ((TWO_STATE_MM & pArgs->op_mode)){
        if(_ncbflag ==0){
            printf("Error: -pcb must be set\n");
            return TCMY_EFAILURE;
        }else {
            if((pArgs->pcb>1)||(pArgs->pcb<0)){
                printf("Error: -pcb out of range [0,1]\n");
                return TCMY_EFAILURE;
            }
        }
        /* parameter verification */
        /* obsolete */
        
        /* predicted loss rate */
        double _dPredLoss = (pArgs->pcb * pArgs->gbloss[0] + pArgs->pbc * pArgs->gbloss[1])/
                            (pArgs->pcb + pArgs->pbc);
        printf("\t%30s: %f\n", "Predicted Loss rate", _dPredLoss);        
    }
    
    printf("\n");
    return TCMY_ESUCCESS;
}


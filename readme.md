Telchemy PCAP Loss Insertion Tool V1.0.4
======================================================================

Release date:  3-March-2011  
Release version: 1.0.004

This software introduces losses to a pcap capture file using a 2-state or 4-state Markov model. The Markov models can either be parameterized in detail or through default values. For the use in subjective tests the tool has been extended such that it will prohibit either the start, the end of the capture file or both for X amounts of milliseconds from being impaired.

System Requirements
----------------------------------

* Written in standard ANSI 'C', the application is targeted for most C compilers (suggested compilers include gcc 3.3.x and gcc 4.x and derivatives)

* Dependencies: none

Compiling the application
----------------------------------

Makefiles to build on Linux and Win32 platforms are provided.

Below is a list of supported targets:

Supported Targets:

- `debug`: Debug Version of 'tscramble'
- `release`: Release Version of 'tscramble'
- `clean`: Remove `*.o` and executable

For example:

Linux:

    $ cd tpkloss
    $ make release

Win32:

    $ cd tpkloss
    $ nmake /f Makefile.vc release


Using the application
----------------------------------

The PCAP loss insertion tool can be used to operate to process trace files in the Wireshark PCAP format as explained below.

    tpkloss [-options] -i Infile -o Outfile

Note 1: All probabilities and loss rates are within a range of [0,1]  
Note 2: Certain restrictions to the combination of the transitions probs apply

Where the required options are:

- `-i <filename>`: Input capture file name
- `-o <filename>`: Output capture file name including losses
- `-m <2|4>`: Specify 2-state (2) or 4-state (4) Markov model
- `-s <time[ms]>`: Time at the beginning of the pcap file that is not exposed to packet losses
- `-e <time[ms]>`: Time at the end of the pcap file that is not exposed to packet losses

For a 2-state Markov loss model please specify:

- `-pcb <float>`: Transition probability from burst to gap state
- `-pbc <float>`: Transition probability from gap to burst state
- `-g  <float>`: Loss probability in gap state
- `-b  <float>`: Loss probability in burst state

For a 4-state Markov loss model please specify:

- `-pba <float>`: Transition probability from gap lossless to gap lossy state
- `-pbc <float>`: Transition probability from gap to burst state
- `-pdc <float>`: Transition probability from burst lossless to burst lossy state (default 0.25)
- `-pcd <float>`: Transition probability from burst lossy to burst lossless state (default 0.05)
- `-pcb <float>`: Transition probability from burst to gap state (default 0.3)
- `-g  <float>`: Loss probability in gap state
- `-b  <float>`: Loss probability in burst state

For a P.NAMS/P.NBAMS 4-state Markov loss model please specify:

- `-loss_ratio <float>`: Target average loss probability
- `-gap_ratio <float>`: Percentage of time in which the process resides in the gap state

Create a loss pattern file or read from loss pattern file:

- `-r <filename>`: Read loss pattern txt-file with the numbers 0 or 1 per line indicate loss or no-loss respectively
- `-c <filename>`: Create loss pattern txt-file with the numbers 0 or 1 per line indicate loss or no-loss respectively

Some examples
----------------------------------

Random loss model:

    tpkloss -m 2 -s 1000 -e 1000 -pcb 1.0 -pbc 0 -g 0.05 -b 0 -i in.cap -o out.cap

2-state Markov loss model:

    tpkloss -m 2 -s 1000 -e 1000 -pcb 0.3 -pbc 0.01 -g 0.05 -b 0.3 -i in.cap -o out.cap

4-state Markov loss model (using default values):

    tpkloss -m 4 -s 2000 -e 500 -pba 0.3 -pbc 0.02 -g 0.05 -b 0.3 -i in.cap -o out.cap

4-state Markov loss model (custom values):

    tpkloss -m 4 -s 2000 -e 500 -pba 0.3 -pbc 0.02 -pdc 0.4 -pcd 0.02 -pcb 0.5 -g 0.05 -b 0.3 -i in.cap -o out.cap

4-state Markov loss model (custom values, write loss file):

    tpkloss -m 4 -s 2000 -e 500 -pba 0.3 -pbc 0.02 -pdc 0.4 -pcd 0.02 -pcb 0.5 -g 0.05 -b 0.3 -i in.cap -o out.cap -c loss.txt

P.NAMS/P.NBAMS 4-state Markov loss model:

    tpkloss -loss_ratio 0.03 -gap_ratio 0.7 -i in.cap -o out.cap

Read from loss file which may be created by either loss model:

    tpkloss -i in.cap -o out.cap -r loss.txt

Reporting a Bug
----------------------------------

To report a suspected bug, please contact Telchemy Product Support via phone, e-mail, or web at the following:

- Phone:     +1 866 TELCHEMY x300 (toll-free), +1 678 387 3000 x300
- E-mail:    support@telchemy.com
- Web:       http://www.telchemy.com/support.html

Please have information such as your development or deployment environment details and software release number on hand.

License
-------

This software is provided at no cost for experimental use in lab environments and Telchemy makes no warranty with regard to its operation or to any issues that may arise from its use. Telchemy is not aware of any intellectual property issues that may result from the use of this software however makes no warranty with regard to patent infringement.  Telchemy has made no IPR claims with regard to this software with the exception of the requirements contained in this header.  The software may be modified, copied and made available to other parties however this header must be retained intact. The software may not be sold or incorporated into commercial applications.
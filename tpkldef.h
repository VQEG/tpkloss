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
 * tpkldef.h
 */

#ifndef _TELCHEMY_TPKLDEF_H_
#define _TELCHEMY_TPKLDEF_H_

#ifdef __cplusplus
extern "C" {
#endif
    
#if defined(TCMY_HOSTOS_WIN32)
    
    /*
     * The default function includes and declarations for the Windows
     * development platform. Windows is a 32-bit platform, so make sure
     * the MAXVALUE is defined as a 32-bit value.
     */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <io.h>
    
#ifdef DEBUG
    
    int TelchemyWin32DbgPrint(const char *format, ...);
#define TCMY_DBGPRINT                      TelchemyWin32DbgPrint
    
#include <assert.h>
#define TCMY_ASSERT(_x)                    assert(_x)
    
#else
    
#ifndef NDEBUG
#define NDEBUG
#endif
#define TCMY_ASSERT(_x)
    
#endif  /* DEBUG */
    
    
#define TCMY_MEMALLOC(_size)               malloc(_size)
#define TCMY_MEMCLEAR(_d, _size)           ZeroMemory((PVOID)_d, _size)
#define TCMY_MEMSET(_d, _b, _size)         FillMemory((PVOID)_d, _size, (BYTE)_b)
#define TCMY_MEMCOPY(_d, _s, _size)        CopyMemory((PVOID)_d, (CONST PVOID*)_s, _size)
#define TCMY_MEMCMP(_d, _s, _size)         memcmp(_d, _s, _size)
#define TCMY_MEMFREE(_d)                   free(_d)
#define TCMY_MEMREALLOC(_d, _size)         realloc(_d, _size)
    
#define TCMY_STRLEN(_x)                    strlen(_x)
#define TCMY_STRCPY(_d, _s)                strcpy(_d, _s)
#define TCMY_STRCMP(_s1, _s2)              strcmp(_s1, _s2)
#define TCMY_STRICMP(_s1, _s2)             stricmp(_s1, _s2)
#define TCMY_STRCAT(_s1, _s2)              strcat(_s1, _s2)
#define TCMY_SNPRINTF                      _snprintf
    
#define TCMY_NTOHL(_x)                     ntohl(_x)
#define TCMY_NTOHS(_x)                     ntohs(_x)
#define TCMY_HTONL(_x)                     htonl(_x)
#define TCMY_HTONS(_x)                     htons(_x)
    
#define TCMY_IOWRITE(_x, _y, _z)           _write(_x, _y, _z)
#define TCMY_IOFILENO(_x)                  fileno(_x)
    
#define TCMY_ATOI(_x)                      atoi(_x)
    typedef int socklen_t;
    
    /*
     * Define the function protection descriptors used in the Windows environment.
     */
#ifndef TCMY_PROTECTED
#define TCMY_PROTECTED(_t)                 _t
#endif
#ifndef TCMY_PRIVATE
#define TCMY_PRIVATE(_t)                   static _t
#endif
#ifndef TCMY_PUBLIC
#define TCMY_PUBLIC(_t)                    _t
#endif
    
    /*
     * Define the Telchemy base types used in the Windows environment.
     */
#ifndef TCMY_BASETYPES
#define TCMY_BASETYPES
    
    typedef UCHAR               tcmyU8;
    typedef USHORT              tcmyU16;
    typedef UINT                tcmyU32;
    typedef ULONGLONG           tcmyU64;
    
    typedef CHAR                tcmyS8;
    typedef SHORT               tcmyS16;
    typedef INT                 tcmyS32;
    typedef LONGLONG            tcmyS64;
    
    typedef BOOL                tcmyBOOL;
    typedef CHAR                tcmyCHAR;
    
#endif  /* TCMY_BASETYPES */
    
    
    
#else /* TCMY_HOST_PLATFORM_* */
    /*
     * Define the host platform to be a POSIX-compliant environment.
     */
#ifndef TCMY_HOSTOS_POSIX
#define TCMY_HOSTOS_POSIX
#endif  /* TCMY_HOSTOS_POSIX */
    
    /*
     * The default function includes and declarations for a POSIX-
     *   compatible 32-bit development platform. 
     */
    
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <netinet/in.h>
    
#ifdef DEBUG
#include <assert.h>
#define TCMY_DBGPRINT                      printf
#define TCMY_ASSERT(_x)                    assert(_x)
#else   /* DEBUG */
#define TCMY_ASSERT(_x)
#define TCMY_DBGPRINT                      printf
#endif  /* DEBUG */
    
    
#define TCMY_MEMALLOC(_size)               malloc(_size)
#define TCMY_MEMCLEAR(_d, _size)           memset(_d, 0, _size)
#define TCMY_MEMSET(_d, _b, _size)         memset(_d, _b, _size)
#define TCMY_MEMCOPY(_d, _s, _size)        memcpy(_d, _s, _size)
#define TCMY_MEMCMP(_d, _s, _size)         memcmp(_d, _s, _size)
#define TCMY_MEMFREE(_d)                   free(_d)
#define TCMY_MEMREALLOC(_d, _size)         realloc(_d, _size)
    
#define TCMY_STRLEN(_x)                    strlen((tcmyCHAR*)_x)
#define TCMY_STRCPY(_d, _s)                strcpy(_d, _s)
#define TCMY_STRCMP(_s1, _s2)              strcmp(_s1, _s2)
#define TCMY_STRICMP(_s1, _s2)             strcasecmp(_s1, _s2)
#define TCMY_STRCAT(_s1, _s2)              strcat(_s1, _s2)
#define TCMY_SNPRINTF(_x, _y...)           snprintf((tcmyCHAR*)_x, _y)
    
#define TCMY_NTOHL(_x)                     ntohl(_x)
#define TCMY_NTOHS(_x)                     ntohs(_x)
#define TCMY_HTONL(_x)                     htonl(_x)
#define TCMY_HTONS(_x)                     htons(_x)
    
#define TCMY_IOWRITE(_x, _y, _z)           write(_x, _y, _z)
#define TCMY_IOFILENO(_x)                  fileno(_x)
    
#define TCMY_ATOI(_x)                      atoi(_x)
    /*
     * Define the function protection descriptors
     */
#ifndef TCMY_PROTECTED
#define TCMY_PROTECTED(_t)                 _t
#endif
#ifndef TCMY_PRIVATE
#define TCMY_PRIVATE(_t)                   static _t
#endif
#ifndef TCMY_PUBLIC
#define TCMY_PUBLIC(_t)                    _t
#endif
    
    /*
     * Define the Telchemy base types used in the POSIX environment.
     */
#ifndef TCMY_BASETYPES
#define TCMY_BASETYPES
    
    typedef unsigned char       tcmyU8;
    typedef unsigned short      tcmyU16;
    typedef unsigned int        tcmyU32;
    typedef unsigned long long  tcmyU64;
    
    typedef signed char         tcmyS8;
    typedef signed short        tcmyS16;
    typedef signed int          tcmyS32;
    typedef signed long long    tcmyS64;
    
    typedef char                tcmyCHAR;
    typedef tcmyU8              tcmyBOOL;
    
#endif  /* TCMY_BASETYPES */
#endif
    
    typedef signed int          tcmy_result_t;
    typedef signed int          tcmy_socket_t;
    
    /*
     * Generic constants and macros used by Telchemy's PLI-Tool.
     */
#ifndef TRUE
#define TRUE                                (1)
#endif
#ifndef FALSE
#define FALSE                               (0)
#endif
#ifndef NULL
#define NULL                                (0)
#endif
#ifndef UNUSED
#define UNUSED(_x)                          ((void)_x)
#endif
    
    /*
     * Error result codes
     */
#define TCMY_ESUCCESS                      (0)
#define TCMY_EFAILURE                      (-1)
#define TCMY_ENOMEM                        (-2)
#define TCMY_EOUTOFRANGE                   (-3)
#define TCMY_EINVALOP                      (-4)
#define TCMY_EBUFSIZE                      (-5)
#define TCMY_EBADHANDLE                    (-6)
#define TCMY_EINVALPARAM                   (-7)
#define TCMY_ESTREAMINPROGRESS             (-8)
#define TCMY_EEXISTS                       (-9)
#define TCMY_ENOBUFS                       (-10)
#define TCMY_EPENDING                      (-11)
#define TCMY_EFIRSTANOMALOUSPKT            (-12)
#define TCMY_ECONSECANOMALOUSPKT           (-13)
#define TCMY_ELCNSKEYINVALID               (-14)
#define TCMY_ELCNSKEYEXPIRED               (-15)
#define TCMY_ELCNSERROR                    (-16)
#define TCMY_ENOTSUPPORTED                 (-17)
#define TCMY_EAGAIN                        (-18)
#define TCMY_ECALLINPROG                   (-19)
    
#define TCMY_EINVALHANDLE                  TCMY_EBADHANDLE
    
    /*
     * Debug levels
     */
#define TCMY_DBG_NONE                      (0)
#define TCMY_DBG_FATAL                     (1)
#define TCMY_DBG_ERROR                     (2)
#define TCMY_DBG_WARN                      (3)
#define TCMY_DBG_INFO                      (4)
#define TCMY_DBG_VERBOSE                   (5)
    
#define TCMY_DBG_MAXLEVELS                 (6)
    
    /* 
     * Defining macros to convert a network pointer to host format
     */
#define TCMY_NPTRTOHS(_ptr)                                                \
((((tcmyU16)(_ptr)[0] << 8) & 0xFF00) | ((tcmyU16)(_ptr)[1] & 0x00FF))
#define TCMY_NPTRTOHL(_ptr)                                                \
((((tcmyU32)(_ptr)[0] << 24) & 0xFF000000) | (((tcmyU32)(_ptr)[1] << 16) \
& 0x00FF0000) | (((tcmyU32)(_ptr)[2] << 8)  & 0x0000FF00) |              \
((tcmyU32)(_ptr)[3] & 0x000000FF))
    
    
    /*
     * Defining data structures and enumerations used
     */
#define MAX_FILENAME_LEN 256
    
    typedef enum _tloss_op_mode_s
    {
        UNSPECIFIED_MODE=0x00,
        CREATE_LOSS_FILE=0x01,
        READ_LOSS_FILE=0x02,
        TWO_STATE_MM=0x04,
        FOUR_STATE_MM=0x08
    } tloss_op_mode_t;
    
    typedef struct _tloss_args_s
    {
        tcmyCHAR output_fn[MAX_FILENAME_LEN];
        tcmyCHAR input_fn[MAX_FILENAME_LEN];
        tcmyCHAR loss_fn[MAX_FILENAME_LEN]; 
        
        double sequ_len;
        
        double pab;
        double pba;
        double pbc;
        double pcb;
        double pcd;
        double pdc;
        
        double pbb;
        double pcc;
        double pdd;
        
        double gbloss[2];
        double gbtrans[2];
        
        tcmyU32 skipStart;
        tcmyU32 skipEnd;
        
        unsigned int state;
        
        tloss_op_mode_t     op_mode;
    }tloss_args_t;
    
    typedef struct _tloss_time_s{
        tcmyS32 sec;
        tcmyS32 usec;
        tcmyS32 prevUsec;
    }tloss_time_t;
    
    
    /* libpcap global header */
    /* reference: http://wiki.wireshark.org/Development/LibpcapFileFormat */
    typedef struct _pcap_hdr_s
    {
        tcmyU32 magic_number;   /* magic number */
        tcmyU16 version_major;  /* major version number */
        tcmyU16 version_minor;  /* minor version number */
        tcmyS32  thiszone;       /* GMT to local correction */
        tcmyU32 sigfigs;        /* accuracy of timestamps */
        tcmyU32 snaplen;        /* max length of captured packets, in octets */
        tcmyU32 network;        /* data link type */
    }pcap_hdr_t;
    
    
    /* lipcap packet header */    
    /* reference: http://wiki.wireshark.org/Development/LibpcapFileFormat */
    typedef struct _pcaprec_hdr_s {
        tcmyU32 ts_sec;         /* timestamp seconds */
        tcmyU32 ts_usec;        /* timestamp microseconds */
        tcmyU32 incl_len;       /* number of octets of packet saved in file */
        tcmyU32 orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;    
    
    /* ethernet packet header */    
    typedef struct _eth_hdr_s {
        tcmyU8 dest_mac[6];
        tcmyU8 src_mac[6];
        tcmyU16   type_len_field;
    } eth_hdr_t;
    
    /* udp packet header */
    typedef struct _udp_hdr_s {
        tcmyU16 dest_port;
        tcmyU16 src_port;
        tcmyU16 packet_len;
        tcmyU16 checksum;
    } udp_hdr_t;
    
    
#ifdef __cplusplus
}
#endif

#endif  /* _TELCHEMY_TPKLDEF_H_ */

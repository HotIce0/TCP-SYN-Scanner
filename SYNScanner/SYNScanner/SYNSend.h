#pragma once

#define TCP_WINDOW_SIZE	64240

/*
* IP HEADER (no optional part)
*/
typedef struct ip_header {
	UINT8 ucVerAndLen;//4bit Version | 4bit Header length
	UINT8 ucTos;//8bit Server type
	UINT16 usTotalLen;//16bit Total length
	UINT16 usMark;//16bit Mark(Identification)
	UINT16 usFlagAndOffset;//3bit Falgs | 13bit Offset
	UINT8 ucTTL;//8bit TTL
	UINT8 ucProtocol;//8bit Protocol
	UINT16 usCheckSum;//16bit Check sum
	UINT32 uiSrcIp;//32bit Source IP
	UINT32 uiDstIp;//32bit Destination IP
}IP_HEADER, *PIP_HEADER;
/*
* TCP HEADER (no optional part)
*/
typedef struct tcp_header {
	UINT16 usSrcPort;//16bit Source Port
	UINT16 usDstPort;//16bit Distination Port
	UINT32 uiSerialNum;//32bit Serial number
	UINT32 uiConfirmSerialNum;//32bit Confirm serial number
	UINT16 usHeaderLenAndFlag;//4bit Header length | 6bit Reservation bit | 6bit URG ACK PSH RST SYN FIN
	UINT16 usWindowSize;//16bit Window Size
	UINT16 usCheckSum;//16bit Check Sum
	UINT16 usUrgentPointer;//16bit Urgent data of offset pointer
}TCP_HEADER, *PTCP_HEADER;

/*
* TCP PSD HEADER
*/
typedef struct tcp_psd_header
{
	UINT32 uiSrcIp;//32bit Source IP
	UINT32 uiDstIp;//32bit Destination IP
	UINT8 ucZeros;//8bit Reservation byte
	UINT8 ucProtocol;//8bit Protocol
	UINT16 usTcpLen;//16bit TCP total length(data field included)
}TCP_PSD_HEADER, *PTCP_PSD_HEADER;

//(no data part)
typedef struct tcp_check_sum {
	TCP_PSD_HEADER tcpPsdHeader;
	TCP_HEADER tcpHeader;
}TCP_CHECK_SUM, *PTCP_CHECK_SUM;

struct SEND_DATA {
	IP_HEADER ipHeader;
	TCP_HEADER tcpHeader;
};

IP_HEADER getIpHeader(UINT32 uihostIPSRC, UINT32 uihostIPDST, UINT16 ushostIdentification);
TCP_HEADER getTCPHeader(const PIP_HEADER const pIpHeader, UINT16 uihostSrcPort, UINT16 uihostDstPort);
#include "stdafx.h"
#include "SYNSend.h"

//得到host字节序的校验和
UINT16 getCheckSum(UINT8 *pBuf, UINT32 uLen)
{
	UINT32 uCheckSum = 0, uLoop = 0;

	for (; uLoop < uLen; uLoop++)
	{
		if (0 == uLoop % 2) {
			uCheckSum += pBuf[uLoop] << 8;
		}
		else {
			uCheckSum += pBuf[uLoop];
		}
	}
	uCheckSum = (uCheckSum >> 16) + (uCheckSum & 0x0000FFFF);

	return (UINT16)(~uCheckSum);
}

IP_HEADER getIpHeader(UINT32 uihostIPSRC, UINT32 uihostIPDST, UINT16 ushostIdentification) {
	IP_HEADER ipHeader = { 0 };
	ipHeader.ucVerAndLen = ((UINT8)IPPROTO_IPV4 << 4) | (UINT8)(sizeof(IP_HEADER) / 4);
	ipHeader.ucTos = (UINT8)0x00;
	ipHeader.usTotalLen = htons((UINT16)0);//this field should be set after when calculate check num.
	ipHeader.usMark = htons((UINT16)ushostIdentification);//Unique for each msg.
	ipHeader.usFlagAndOffset = htons(0x02 << 13);//this field should be set when dgram need fragment
	ipHeader.ucTTL = (UINT8)64;
	ipHeader.ucProtocol = (UINT8)IPPROTO_TCP;
	ipHeader.usCheckSum = htons((UINT16)0);//this field should be set after.
	ipHeader.uiSrcIp = htonl(uihostIPSRC);
	ipHeader.uiDstIp = htonl(uihostIPDST);
	ipHeader.usTotalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));

	return ipHeader;
}

TCP_HEADER getTCPHeader(const PIP_HEADER const pIpHeader, UINT16 uihostSrcPort, UINT16 uihostDstPort) {
	TCP_HEADER tcpHeader = { 0 };
	tcpHeader.usSrcPort = htons(uihostSrcPort);
	tcpHeader.usDstPort = htons(uihostDstPort);
	tcpHeader.uiSerialNum = htonl((UINT32)0);
	tcpHeader.uiConfirmSerialNum = htonl((UINT32)0);//this field is valid when ACK valid.
	tcpHeader.usHeaderLenAndFlag = htons(((UINT16)(sizeof(TCP_HEADER)) / 4 << 12) | 0x2);//0x2 SYN valid.
	tcpHeader.usWindowSize = htons(TCP_WINDOW_SIZE);
	tcpHeader.usCheckSum = htons((UINT16)0);//this field should be set after.
	tcpHeader.usUrgentPointer = htons((UINT16)0);
	//Fill TCP PSD Header
	TCP_PSD_HEADER tcpPsdHeader = { 0 };
	tcpPsdHeader.uiSrcIp = pIpHeader->uiSrcIp;
	tcpPsdHeader.uiDstIp = pIpHeader->uiDstIp;
	tcpPsdHeader.ucZeros = (UINT8)0;
	tcpPsdHeader.ucProtocol = (UINT8)IPPROTO_TCP;
	tcpPsdHeader.usTcpLen = htons(sizeof(TCP_HEADER));
	//Calculate check sum
	TCP_CHECK_SUM tcpCheckSum = { tcpPsdHeader, tcpHeader };
	tcpHeader.usCheckSum = htons(getCheckSum((UINT8 *)&tcpCheckSum, sizeof(TCP_CHECK_SUM)));
	return tcpHeader;
}
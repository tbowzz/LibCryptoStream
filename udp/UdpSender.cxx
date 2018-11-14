//
// Created by Tyler Bowers on 8/24/18.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "UdpSender.h"
#include "../Utilities/Utility.h"

UdpSender::~UdpSender()
{
	close(mSockSender);
}

bool UdpSender::init(std::string server, int port)
{
	mServer = server;
	mPort = port;

	/* create a socket */

	if ((mSockSender = socket(AF_INET, SOCK_DGRAM, 0)) == ERROR)
	{
		UTIL.log(DEBUG_LOG, "UDPSENDER: Socket created");
	}

	/* bind it to all local addresses and pick any port number */

	memset((char *) &mMyAddress, 0, sizeof(mMyAddress));
	mMyAddress.sin_family = AF_INET;
	mMyAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	mMyAddress.sin_port = htons(0);

	if (bind(mSockSender, (struct sockaddr *)&mMyAddress, sizeof(mMyAddress)) < 0)
	{
		UTIL.log(ERROR_LOG, "UDPSENDER: Unable to bind to uav_ground.");
		return false;
	}

	/* now define remoteAddress, the address to whom we want to send messages */
	/* For convenience, the host address is expressed as a numeric IP address */
	/* that we will convert to a binary format via inet_aton */

	memset((char *) &mRemoteAddress, 0, sizeof(mRemoteAddress));
	mRemoteAddress.sin_family = AF_INET;
	mRemoteAddress.sin_port = htons(mPort);
	UTIL.log(DEBUG_LOG, "UDPSENDER: Will send to %s:%d", mServer.c_str(), mPort);

	if (inet_aton(mServer.c_str(), &mRemoteAddress.sin_addr) == 0)
	{
		UTIL.log(ERROR_LOG, "UDPSENDER: inet_aton() failed.");
		return false;
	}
	return true;
}

bool UdpSender::send(std::vector<unsigned char> &packet)
{
	socklen_t slen=sizeof(mRemoteAddress);
	unsigned char buf[BUF_LEN]; // message buffer

	memcpy(buf, packet.data(), packet.size()); // copy the packet to the buffer
	UTIL.log(DEBUG_LOG, "UDPSENDER: Sending %d bytes.", packet.size());
	if (sendto(mSockSender, buf, packet.size(), 0, (struct sockaddr *) &mRemoteAddress, slen)==-1)
	{
		UTIL.log(ERROR_LOG, "UDPSENDER: Sending failed!");
		return false;
	}

	// Comment in if ack'ing is enabled
//	int receiveLength; // # bytes in acknowledgement message
//	receiveLength = recvfrom(mSockSender, buf, BUF_LEN, 0, (struct sockaddr *) &mRemoteAddress, &slen);
//	if (receiveLength >= 0)
//	{
//		buf[receiveLength] = 0; // expect a printable string - terminate it
//		UTIL.log(INFO_LOG, "UDPSENDER: received message: \"%s\"", buf);
//	}

	return true;
}

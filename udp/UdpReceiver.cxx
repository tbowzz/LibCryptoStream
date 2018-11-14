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
#include "UdpReceiver.h"

UdpReceiver::UdpReceiver(const std::string &name) : NetworkReceiver(name)
{
}

UdpReceiver::~UdpReceiver()
{
	close(mSockReceiver);
}

bool UdpReceiver::init(int port)
{
	mPort = port;

	/* create a UDP socket */

	if ((mSockReceiver = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		UTIL.log(ERROR_LOG, "%s: cannot create socket", mName.c_str());
		return false;
	}

	/* bind the socket to any valid IP address and a specific port */

	memset((char *)&mMyAddress, 0, sizeof(mMyAddress));
	mMyAddress.sin_family = AF_INET;
	mMyAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	mMyAddress.sin_port = htons(mPort);
	UTIL.log(DEBUG_LOG, "%s: Using port %d", mName.c_str(), mPort);

	if (bind(mSockReceiver, (struct sockaddr *)&mMyAddress, sizeof(mMyAddress)) < 0)
	{
		UTIL.log(ERROR_LOG, "%s: Unable to bind.", mName.c_str());
		return false;
	}

	return true;
}

bool UdpReceiver::receive(std::vector<unsigned char> &packet)
{
	ssize_t receiveLen; // # bytes received
	socklen_t addrlen = sizeof(mRemoteAddress); // length of addresses
	unsigned char buf[BUF_LEN]; // receive buffer

	// Receive data and print what was received
	UTIL.log(DEBUG_LOG, "%s: Waiting to receive...", mName.c_str());
	receiveLen = recvfrom(mSockReceiver, buf, BUF_LEN, 0, (struct sockaddr *)&mRemoteAddress, &addrlen);
	if (receiveLen > 0)
	{
		UTIL.log(DEBUG_LOG, "%s: received %d bytes", mName.c_str(), receiveLen);

		// Add the received bytes to the packet vector
		packet.insert(packet.end(), &buf[0], &buf[receiveLen]);

		buf[receiveLen] = 0;
		return true;
	}
	else if (mRunThread)
	{
		UTIL.log(ERROR_LOG, "%s: uh oh - something went wrong!", mName.c_str());
		return false;
	}

	// Comment back in to enable ack'ing
//		sprintf(buf, "ack %d", msgcnt++);
//		UTIL.log(INFO_LOG, "sending response \"%s\"\n", buf);
//		if (sendto(mSockReceiver, buf, strlen(buf), 0, (struct sockaddr *)&mRemoteAddress, addrlen) < 0)
//		{
//			UTIL.log(ERROR_LOG, "%s: Ack failed.", mName.c_str());
//		}

	return true;
}

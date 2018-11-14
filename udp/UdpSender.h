//
// Created by Tyler Bowers on 8/24/18.
//

#pragma once

#include <netinet/in.h>
#include "../NetworkSender.h"

#define BUF_LEN 2048

class UdpSender : public NetworkSender
{
public:
	~UdpSender();

	bool init(std::string server, int port) override;
	bool send(std::vector<unsigned char> &packet) override;

private:
	int mSockSender;
	struct sockaddr_in mMyAddress;
	struct sockaddr_in mRemoteAddress;

};


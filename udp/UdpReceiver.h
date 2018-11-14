//
// Created by Tyler Bowers on 8/24/18.
//

#pragma once

#include <netinet/in.h>
#include <string>
#include "../NetworkReceiver.h"

#define BUF_LEN 2048


class UdpReceiver : public NetworkReceiver
{
public:
	UdpReceiver(const std::string &name);

	~UdpReceiver();

	bool init(int port) override;
	bool receive(std::vector<unsigned char> &packet) override;

private:
	int mSockReceiver;
	struct sockaddr_in mMyAddress;
	struct sockaddr_in mRemoteAddress;
};

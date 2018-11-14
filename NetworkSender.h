//
// Created by Tyler Bowers on 8/24/18.
//

#pragma once

#include <string>

class NetworkSender
{
public:
	virtual bool init(std::string server, int port) = 0;
	virtual bool send(std::vector<unsigned char> &packet) = 0;

protected:
	std::string mServer;
	int mPort;
};

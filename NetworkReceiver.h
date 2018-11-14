//
// Created by Tyler Bowers on 8/24/18.
//

#pragma once

#include "Utilities/Thread.h"

class NetworkReceiver : public Thread
{
public:
	NetworkReceiver(std::string name);
	virtual ~NetworkReceiver();

	virtual bool init(int port) = 0;
	virtual bool receive(std::vector<unsigned char> &packet) = 0;
	void run() override;
	void checkThread();

protected:
	int mPort;
};

//
// Created by Tyler Bowers on 8/24/18.
//

#include <string>
#include <vector>
#include "NetworkReceiver.h"

NetworkReceiver::NetworkReceiver(std::string name) : Thread(name)
{
}

NetworkReceiver::~NetworkReceiver()
{
}

void NetworkReceiver::run() // gets called by the thread
{
	std::vector<unsigned char> receivedPacket;
	receive(receivedPacket);
	// TODO: Do something with the packet
}

void NetworkReceiver::checkThread()
{
	if (mPauseThread)
	{
		resumeThread();
	}
}

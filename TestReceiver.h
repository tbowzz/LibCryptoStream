//
// Created by Tyler Bowers on 11/11/18.
//

#pragma once


#include "udp/UdpReceiver.h"

class TestReceiver : public Thread
{
public:
	TestReceiver(std::string name = "RECV");

	void run() override;

private:
	UdpReceiver receiver_;
};

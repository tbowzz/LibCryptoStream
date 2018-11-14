//
// Created by Tyler Bowers on 11/11/18.
//

#pragma once

#include "Utilities/Thread.h"
#include "udp/UdpSender.h"

class TestSender
{
public:
	TestSender(std::string name, std::string hostIp);

	void run();

private:
	UdpSender sender_;
};

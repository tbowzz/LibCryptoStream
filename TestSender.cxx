//
// Created by Tyler Bowers on 11/11/18.
//

#include "TestSender.h"
#include "State.h"

TestSender::TestSender(std::string name, std::string hostIp)
{
	sender_.init(hostIp, PORT);
}

void TestSender::run()
{
	std::vector<unsigned char> packet;
	for (int ii = 0; ii < PACKET_SIZE_BYTES; ii++)
	{
		packet.push_back(0x01);
	}

	// Send packets
	int counter = (int) PACKET_COUNT;
	UTIL.log(INFO_LOG, "Sending %d %d-byte packets...", counter, PACKET_SIZE_BYTES);

	STATE.senderRunning_ = true;
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	while (counter--)
	{
		sender_.send(packet);
	}
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	STATE.senderRunning_ = false;

	auto durationUsec = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
	auto durationSec = durationUsec * 1e-6;

	auto bytesSent = PACKET_COUNT * PACKET_SIZE_BYTES;
	auto mbitsSent = bytesSent * 8e-6;
	auto avgMbps = mbitsSent / durationSec;

	UTIL.log(INFO_LOG, "Send: Send duration: %f seconds", durationSec);
	UTIL.log(INFO_LOG, "Send: Average send speed: %f Mbps", avgMbps);
}

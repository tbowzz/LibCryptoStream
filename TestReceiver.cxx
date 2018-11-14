//
// Created by Tyler Bowers on 11/11/18.
//

#include "TestReceiver.h"
#include "State.h"

TestReceiver::TestReceiver(std::string name) : Thread(name), receiver_(name)
{
	receiver_.init(PORT);
}

void TestReceiver::run()
{
	std::vector<unsigned char> packet;
	int counter = 0;

	while (!STATE.senderRunning_) {}

	UTIL.log(INFO_LOG, "Receiving packets...");
//	receiver_.receive(packet); // receive one packet first to start the timer
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	do
	{
		receiver_.receive(packet);
		counter++;
	}
	while (STATE.senderRunning_);
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

	sleep(1); // sleep so sender can print results first

	auto durationUsec = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
	auto durationSec = durationUsec * 1e-6;

	auto bytesSent = counter * PACKET_SIZE_BYTES;
	auto mbitsSent = bytesSent * 8e-6;
	auto avgMbps = mbitsSent / durationSec;

	UTIL.log(INFO_LOG, "Recv: Receive duration: %f seconds", durationSec);
	UTIL.log(INFO_LOG, "Recv: Average receive speed: %f Mbps", avgMbps);
	double lossPercentage = ((double)counter / (double) PACKET_COUNT) * 100.0;
	UTIL.log(INFO_LOG, "Recv: [%d/%d] packets received = %f%%", counter, (int)PACKET_COUNT, lossPercentage);
}

#include <iostream>
#include <vector>
#include "Utilities/Utility.h"
#include "TestSender.h"
#include "TestReceiver.h"

int main(int argc, char **argv)
{
	UTIL.setLogLevel(4);
	UTIL.setLogPattern("[%D %T] [%^%l%$] %v");

	std::vector<std::string> args(argv + 1, argv + argc);

	if (args.size() < 1)
	{
		UTIL.log(ERROR_LOG, "USAGE:\n"
				"\t ./UdpQueue send 10.0.0.100\n"
				"\t ./UdpQueue recv");
		return ERROR;
	}

	TestReceiver testReceiver;
	testReceiver.start();

	TestSender testSender("SENDER", args[0]);
	testSender.run();

	Thread::sleep(2);
	exit(OK);
}
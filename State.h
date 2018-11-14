//
// Created by Tyler Bowers on 11/11/18.
//

#pragma once

#define PORT 5000
#define PACKET_COUNT 800000.0f
#define PACKET_SIZE_BYTES 64

#include "Singleton.h"

class State : public Singleton<State>
{
	friend class Singleton<State>;

public:
	bool senderRunning_;
	bool receiverRunning_;

protected:
	State(){};

};

#define STATE State::getInstance()

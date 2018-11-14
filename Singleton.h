//
// Created by Tyler Bowers on 8/21/18.
//

#pragma once

template<typename T>
class Singleton
{
public:
	static T& getInstance()
	{
		static T instance;
		return instance;
	}
};

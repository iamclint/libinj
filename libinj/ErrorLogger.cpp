#include "stdafx.h"
#include "ErrorLogger.h"
#include "libinj.h"

ErrorLogger::ErrorLogger()
= default;

//ErrorLogger::PrevError = GetLastError();
bool ErrorLogger::Log(const std::string& logMsg, const bool bypassGetlasterror)
{
	if (PrevError != GetLastError() || bypassGetlasterror)
	{
		stringstream msg;
		msg << logMsg << " [" << getLastErrorAsString() << "]" << endl;
		LastErrorMsg = msg.str();
		return true;
	}
	else {
		return false;
	}
}

ErrorLogger::~ErrorLogger()
= default;

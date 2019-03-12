#pragma once
#include <sstream>
#include <string>
class ErrorLogger
{
public:
	ErrorLogger();
	static inline DWORD PrevError;
	static inline std::string LastErrorMsg;
	static bool Log(const std::string& logMsg, const bool bypassGetlasterror = false);
	~ErrorLogger();
};


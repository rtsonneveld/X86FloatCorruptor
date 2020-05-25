// X86FloatCorruptor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include "X86FloatCorruptor.h"
#include <vector>
#include <map>
#include <random>
#include <mutex>

#define recheck_interval 600000
#define minimum_floats 5000

std::default_random_engine rng;

bool isValidFloat(float a) {
	return (abs(a) > 1.15f && abs(a) < 90.0f);
}

float getRandomFloat(float min, float max) {
	std::uniform_real_distribution<> distribution(min, max);
	return distribution(rng);
	//return static_cast <float> (rng()) / static_cast <float> (rng.max());
}

std::mutex bigListMutex;

void findFreshAddresses(HANDLE handle, std::vector<LPVOID> * bigAddressList, std::vector<int> * blackList) {

	std::cout << "Search for fresh floats" << std::endl;

	bool firstTime = blackList->size() == 0;

	std::map<int, std::vector<LPVOID>*> addressesPerPage;

	MEMORY_BASIC_INFORMATION mBI;
	UINT memoryRegionStart = 0x1FFFFF;
	UINT memoryRegionEnd = 0x7FFFFFF;// FFFF;

	int currentPage = 0;

	std::cout << "Start scan" << std::endl;
	do {

		// not in blacklist
		SIZE_T vQe = VirtualQueryEx(handle, (void*)memoryRegionStart, &mBI, sizeof(MEMORY_BASIC_INFORMATION));
		if (vQe == 0) { break; }

		if (std::find(blackList->begin(), blackList->end(), currentPage) == blackList->end()) {
			std::vector<LPVOID> * floatAddresses = new std::vector<LPVOID>();
			addressesPerPage.insert(std::pair<int, std::vector<LPVOID>*>(currentPage, floatAddresses));

			if ((mBI.State == MEM_COMMIT) && (mBI.Type == MEM_PRIVATE) && (mBI.Protect == PAGE_READWRITE)) {
				UINT start, end;
				start = (UINT)mBI.BaseAddress;
				end = (UINT)mBI.BaseAddress + mBI.RegionSize;
				//ready memory
				float valueFound;
				SIZE_T byteToRead = 4;

				for (start; start < end; start = start + 4) {
					if (ReadProcessMemory(handle, (LPCVOID)start, &valueFound, sizeof(valueFound), &byteToRead)) {
						if (isValidFloat(valueFound)) {
							// address not in big list yet?
							if (std::find(bigAddressList->begin(), bigAddressList->end(), (LPVOID)start) == bigAddressList->end())
								floatAddresses->push_back((LPVOID)start);
						}
					}
				}

				//}

			}
		}
		memoryRegionStart += mBI.RegionSize;

		std::cout << "Read page " << currentPage << std::endl;
		currentPage++;
	} while (memoryRegionStart < memoryRegionEnd);
	std::cout << "End scan" << std::endl;


	for (auto page : addressesPerPage) {
		std::cout << "Page " << page.first << " has " << page.second->size() << " floats" << std::endl;

		if (page.second->size() < minimum_floats && firstTime) {
			blackList->push_back(page.first);
		} else {
			for (auto it : *page.second) {
				bigAddressList->push_back(it);
			}
		}
	}

}

void corruptFloats(HANDLE handle, std::vector<LPVOID> * addressesToCorrupt) {

	int corrupted = 0;

	//std::unique_lock<std::mutex> guard(bigListMutex);
	//guard.lock();
	for (auto address : *addressesToCorrupt) {
		float value;
		ReadProcessMemory(handle, address, &value, sizeof(float), NULL);

		if (isValidFloat(value) && rng() % 200 == 0) {
			rng.seed(round(value));
			value = value * getRandomFloat(0.9f, 1.1f);
			WriteProcessMemory(handle, address, &value, sizeof(float), NULL);
			corrupted++;
			//
		}
	}
	std::cout << "Corrupted " << corrupted << " out of " << addressesToCorrupt->size() << " values" << std::endl;
}

void corruptProcess(HANDLE handle) {

	std::vector<LPVOID> * addressesToCorrupt = new std::vector<LPVOID>;
	int lastChecked = GetTickCount();

	std::vector<int> * blackList = new std::vector<int>();

	while (true) {
		if (GetTickCount() - lastChecked > recheck_interval || addressesToCorrupt->size()==0) {
			findFreshAddresses(handle, addressesToCorrupt, blackList);
			lastChecked = GetTickCount();
		}
		corruptFloats(handle, addressesToCorrupt);
	}
	

}

int main()
{
	rng.seed(GetTickCount());

	while (true) {

		std::cout << "Looking for process Rayman2.exe" << std::endl;

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				auto exeName = entry.szExeFile;
				char * exeName_cptr = new char[128];
				wcstombs(exeName_cptr, exeName, 128);

				std::cout << "Check " << exeName_cptr;

				if (_stricmp(exeName_cptr, "Rayman2.exe") == 0)
				{
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

					Beep(440, 200);

					corruptProcess(hProcess);

					std::cout << "Found process woop" << std::endl;

					CloseHandle(hProcess);
				}
			}
		}

		CloseHandle(snapshot);

		Sleep(1000);
	}
}


#ifndef RANDOMNUMBERGENERATOR_H
#define RANDOMNUMBERGENERATOR_H


#include <utility>
#include <vector>
#include <random>
#include <mutex>
#include "vm_declarations.h"

template <typename Number>
class RandomNumberGenerator {
public:
    typedef std::vector<std::pair<Number, Number>> NumberLimits;
    RandomNumberGenerator(int seed);
    Number getRandomNumber(const NumberLimits& limits);
    Number getRandomNumber();
    std::vector<Number> getRandomNumbers(const NumberLimits& limits, int number);
private:
    Number getRandomNumberNonThreadSafe(const NumberLimits& limits);

    // std::random_device randomDevice;
    std::minstd_rand randomGenerator;
    std::mutex mutex;
};

typedef RandomNumberGenerator<VirtualAddress> VirtualAddressGenerator;

#endif //RANDOMNUMBERGENERATOR_H

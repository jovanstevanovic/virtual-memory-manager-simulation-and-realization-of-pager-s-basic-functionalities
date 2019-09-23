#include "RandomNumberGenerator.h"

template <typename Number>
RandomNumberGenerator<Number>::RandomNumberGenerator(int seed) : randomGenerator(seed), mutex() {
}

template <typename Number>
Number RandomNumberGenerator<Number>::getRandomNumber(const typename RandomNumberGenerator::NumberLimits &limits) {
    std::lock_guard<std::mutex> guard(mutex);

    return getRandomNumberNonThreadSafe(limits);
}

template <typename Number>
std::vector<Number>
RandomNumberGenerator<Number>::getRandomNumbers(const typename RandomNumberGenerator::NumberLimits &limits, int number) {
    std::lock_guard<std::mutex> guard(mutex);

    std::vector<Number> ret;

    Number lower = limits[0].first;
    Number upper = limits[0].second;
    std::uniform_int_distribution<Number> randomNumber(lower, upper);
    ret.emplace_back(randomNumber(randomGenerator));

    for (int i = 1; i < number; i++) {
        ret.emplace_back(getRandomNumberNonThreadSafe(limits));
    }
    return ret;
}

template <typename Number>
Number RandomNumberGenerator<Number>::getRandomNumberNonThreadSafe(const typename RandomNumberGenerator::NumberLimits &limits) {
    std::uniform_int_distribution<int> randomLimit(1, limits.size() - 1);
    int limit = randomLimit(randomGenerator);
    Number lower = limits[limit].first;
    Number upper = limits[limit].second;

    std::uniform_int_distribution<Number> randomNumber(lower, upper);
    int ret = randomNumber(randomGenerator);
    if (ret == 0) {
        return 0;
    }
    return ret;
}

template <typename Number>
Number RandomNumberGenerator<Number>::getRandomNumber() {
    std::lock_guard<std::mutex> guard(mutex);
    std::uniform_int_distribution<Number> randomNumber;
    return randomNumber(randomGenerator);
}

template class RandomNumberGenerator<VirtualAddress>;

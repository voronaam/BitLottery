# Bit Lottery

## Overview
Major Cryptocurrencies reached a point where they can be used as a lottery. Since both major blockchains (BTC and ETH) use just 160-bit addresses on the chain,
the chance of finding a keypair matching a non-empty address are not astronomically low. The chance is still very low, but just not astronomically so.

Further, the shared approach in BTC and ETH address generation makes the code fairly efficient in checking a random point for a match against any "point of interest" on the blockchain.

A consumer-grade laptop is capable of comfortably checking ~100M addresses a second without impacting its primary use.

This makes participating in the Crypto Lottery free for people like me - the ones living in Canada in a home with electric heating. Some of the heating happens through the GPU instead
of the baseboard heater, but I'd have to pay for that heating electricity anyway. Tnis quirk makes participating in Crypto Lottery to make economic sense, even though the chance of "winning"
is still lower than the traditional lotteries offer. Simply because traditional lotteries are not free.

## The way the code works

It generates a large number of "lottery tickets" - points on secp256k1 curve. It then increments the points on the GPU checking for matches.

The code does not care for saving the tickets already checked. The odds of repeating work are as low as the odds of winning.

The code does not care for printing the easy to use result in case of winning. The winner must do a bit of extra work of computing the actual private key if they really want it.

The code does not care about portability. I wrote it to run on my laptop and its GPU. I actually deleted a bits of more portable code - this made it easier for me to profile it.

The code does not care for overflowing and hitting any special points (it can hit zero and identity special points, but not the infinity). Really, what are the odds?

The application terminates after about a week worth of runtime. If you want to enroll in the next "weekly lottery" you have to launch it again.

It is pretty much a "CUDA-script", the very minimal C code to automate a computation.

But I tried to structure it to resemble the regular lotteries as much as possible. Including the [Skill Testing Question](https://en.wikipedia.org/wiki/Skill_testing_question) required to claim the winnings.

I am pretty sure I am not the first one to write such a lottery. If you want to see the past winnings claimed by other people just do a web search for news articles about "bitcoin dormant address wakes up".

## Prerequisites
- GNU Make (version 4.0 or higher)
- GCC (GNU Compiler Collection) or any other compatible compiler
- CUDA compiler

## Building the Project
To build the project, simply run:
```sh
make
```

## Cleaning the Build
To clean the build artifacts, run:
```sh
make clean
```

## Running the Project
After building the project, you can run the executable with:
```sh
make run
# or
./collide
```

## Makefile Targets
- `all`: Default target to build the project.
- `clean`: Removes all build artifacts.
- `run`: Builds and runs the project.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request. I have no idea why you would want to do that though.

## License
This project contains files licensed under the MIT License, GNU GPL license and NVidia public license. Plus a few files written by me without any explicit license granted.

This code is shared for educational purposes and is not suitable for use in any commercial or even public non-commercial use.

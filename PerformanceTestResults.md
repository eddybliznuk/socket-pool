# SPOOL Performance Test Results #
The goal of this performance test was to compare performance of two versions of the same network application. The first version uses traditional epoll()-based architecture, the second one uses SPOOL. I also made few tests with the real Nginx server just for generic comparison.

The tests is based on simple HTTP traffic. The client is configured the way it has "unlimited" (in the framework of this test) CPU resources, the server is limited by running its main worker process on a single core only.  So during the tests we actually compare performance of different architecture approaches on a single CPU core.


## Tests Software ##

As the network application I used **Spate** - the HTTP performance test tool that I wrote earlier: https://code.google.com/p/spate-tool/. I adopted for using SPOOL, so now it can be compiled in two "flavors" - with standard socket interface or with SPOOL.

Once Spate can work as both HTTP client and HTTP server I used it in both roles.

Spate client opens the required number of TCP connections. For each connection it sends a simple HTTP request, receives reply and performs minimal parsing just in order to determine when request is finished. When the reply is received it sends another request. This process loops on every connection until the number of requests sent reaches the configured value. Once it happens the connection is closed by the client. When all connections are closed the client stops. For better performance it can utilize multiple worker process running on different CPU cores.

Spate server functions opposite to the Spate client. It listens on a port and accepts connections. For every connection it receives a requests, performs minimal parsing and sends back a reply of the configured size.

## Test Environment and Hardware ##
  * Laptop computer with Intel Core i7 CPU
  * VmPlayer 6.0.3
  * Client virtual machine - 4 virtual cores, 2G RAM
  * Server virtual machine - 3 virtual cores, 1G RAM
  * OS - Linux Centos 6.5
  * Networking - every virtual machines uses for data exchange two 1Gps virtual e1000 adapters connected via VmWare virtual switch. Different IP subnets defined on these adapters. (The reason why I used two adapters is that CPU load of software interrupts processing TCP traffic for a single adapter goes too high and becomes a bottle neck of the performance)

## Test Conditions ##
  * The client application runs 3 worker processes on 3 CPU cores. It never reaches 100% CPU usage. The number of simultaneous TCP connections vary from 100 to 15000.
  * The server application runs one worker on a single dedicated CPU core (affinity is used).
  * Request size is 66 byte.
  * Response size is 1104 byte (1024 byte HTTP payload).
  * TCP connections are not closed during the test.
  * 10 millions of requests are processed in every test.
  * The value that is measured and analysed is number of successful HTTP transactions (request+reply) per second (Tps).
  * the following number of simultaneous connections are tested: 100, 1000, 5000, 15000. Further increase of this number causes socket errors on the client.
  * Every test is performed three times. The final result is calculated as average of the three tests.


## Test Results ##

| **Connections** | **spate-epoll** | **spate-spool(100)** | **spate-spool(1k)** | **spate-spool(5k)** | **Best gain** |
|:----------------|:----------------|:---------------------|:--------------------|:--------------------|:--------------|
|15000|43801|45769|45042|44993|3 |
|5000|28360|31998|31936|31967|13|
|1000|39251|49602|49432|N/A|26|
|100|43629|48520|49193|N/A|13|


![http://www.ljplus.ru/img4/a/p/apelsinov/SPOOL-Performance-Test.png](http://www.ljplus.ru/img4/a/p/apelsinov/SPOOL-Performance-Test.png)

## Resume ##

Even though the results are not as dramatic as I expected we can resume that usage of SPOOL provides stable performance increase up to 26% when the number of open sockets is not too high.

The test was done with very row first version of SPOOL. We can consider fine-tuning SPOOL itself and functions that use it in order to gain more performance.  However we have to take into consideration that the biggest part of CPU power is spent on TCP stack functions. SPOOL just improves interface but it can't influence TCP stack performance.

**My final conclusion so far: SPOOL may be useful when you want to get a limited performance increase by making minimal changes in Kernel networking.**

### P.S. ###
Currently I can't explain the performance decrease at 5000 connections while performance on 15000 connections is higher. Would appreciate if somebody gives me a clue...
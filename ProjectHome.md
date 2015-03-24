SPOOL (Socket Pool) is a Linux Kernel module that helps user space applications efficiently serve multiple connections
on stream sockets (TCP or other). It offers asynchronous bulk read/write socket interface that alters the traditional
approach based on select/poll/epoll calls combined with reads and writes on single sockets.

Performance of a simple HTTP server integrated with SPOOL is up to 26% higher than performance of the same server built using the traditional epoll()-based architecture.
The detailed test description is here: PerformanceTestResults
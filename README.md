# TOCTTOU Attacks

TOCTTOU (Time-of-check to Time-of-use) attacks refer to system security exploits that result from race conditions of a value being checked compared to when it is actually used. 

The idea behind this attack is that during the initial check, the value can be valid, but when it is used, it isn't checked for validity again. Therefore, during that difference in instructions, another process/thread could modify that data, resulting in corrupted data and a race condition. 

We have tackled this problem by re-implementing syscalls in the Linux kernel to create custom benchmarks that we then have attacked. We are now working on implementing Copy-on-Write to fix these TOCTTOU attacks. 
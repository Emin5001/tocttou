import subprocess
import numpy as np
import pandas as pd
import os

step = 8
    
subprocess.run(["sudo", "bash", "-c", "echo off > /sys/devices/system/cpu/smt/control"])
subprocess.run(["sudo", "cpufreq-set", "-c", "2", "-g", "performance"])
subprocess.run(["sudo", "cpufreq-set", "-c", "2", "--min", "2200MHz", "--max", "2200MHz"])
subprocess.run(["sudo", "cset", "shield", "-c", "2", "-k", "on"])

binaries = ["bin/writev_copy", "bin/writev_no_copy", "bin/writev_cow"]
sizes = np.arange(0, 9, step)
counters = ["cache-misses", "cache-references", "cycles", "instructions", "context-switches", "page-faults", "dTLB-load-misses"]

counter_map = {
    "bin/writev_copy": np.zeros((len(sizes), len(counters) + 1), dtype=np.int64),
    "bin/writev_no_copy": np.zeros((len(sizes), len(counters) + 1), dtype=np.int64),
    "bin/writev_cow": np.zeros((len(sizes), len(counters) + 1), dtype=np.int64)
}

size_index = 0
for size in sizes:
    for binary in binaries:
        counter_map[binary][size_index, 0] = size_index * step
        counter_index = 1
        for counter in counters:
            command = f"perf stat -e {counter} ../{binary} {size}"
            result = subprocess.run(command, shell=True, stderr=subprocess.PIPE, text=True)
            assert(result is not None)
            output = result.stderr.splitlines()
            for line in output:
                if counter in line:
                    value = line.strip().split()[0].replace(",", "")
                    counter_map[binary][size_index, counter_index] = int(value)
                    counter_index += 1
        print(f"Completed {binary} with size {size}")
    size_index += 1

columns = ["Size"] + counters
df_copy = pd.DataFrame(counter_map["bin/writev_copy"], columns=columns)
df_no_copy = pd.DataFrame(counter_map["bin/writev_no_copy"], columns=columns)
df_cow = pd.DataFrame(counter_map["bin/writev_cow"], columns=columns)

df_copy.to_csv("copy_results.csv", index=False)
df_no_copy.to_csv("no_copy_results.csv", index=False)
df_cow.to_csv("cow_results.csv", index=False)

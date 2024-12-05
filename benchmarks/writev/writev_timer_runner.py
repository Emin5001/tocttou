import subprocess
import numpy as np
import pandas as pd
import os

step = 8
    
# subprocess.run(["sudo", "bash", "-c", "echo off > /sys/devices/system/cpu/smt/control"])
# subprocess.run(["sudo", "cpufreq-set", "-c", "2", "-g", "performance"])
# subprocess.run(["sudo", "cpufreq-set", "-c", "2", "--min", "2200MHz", "--max", "2200MHz"])
# subprocess.run(["sudo", "cset", "shield", "-c", "2", "-k", "on"])

binaries = ["bin/writev_copy_time", "bin/writev_no_copy_time", "bin/writev_cow_time"]
sizes = np.arange(0, 9, step)

counter_map = {
    "bin/writev_copy_time": np.zeros((len(sizes), 2), dtype=float),
    "bin/writev_no_copy_time": np.zeros((len(sizes), 2), dtype=float),
    "bin/writev_cow_time": np.zeros((len(sizes), 2), dtype=float)
}

size_index = 0
for size in sizes:
    for binary in binaries:
        counter_map[binary][size_index, 0] = size_index * step
        command = f"../{binary} {size}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
        assert(result is not None)
        output = result.stdout.splitlines()
        for line in output:
            if "time" in line.lower():
                value = line.strip().split()[2].replace(",", "")
                print("value: ", float(value))
                counter_map[binary][size_index, 1] = float(value)
        print(f"Completed {binary} with size {size}")
    size_index += 1

columns = ["Size", "Time"]
df_copy = pd.DataFrame(counter_map["bin/writev_copy_time"], columns=columns)
df_no_copy = pd.DataFrame(counter_map["bin/writev_no_copy_time"], columns=columns)
df_cow = pd.DataFrame(counter_map["bin/writev_cow_time"], columns=columns)

df_copy.to_csv("copy_time_results.csv", index=False)
df_no_copy.to_csv("no_copy_time_results.csv", index=False)
df_cow.to_csv("cow_time_results.csv", index=False)

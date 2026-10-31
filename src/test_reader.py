log_file = "sample_logs/auth_sample.log"

with open(log_file, "r") as file:
    for line in file:
        print(line.strip())

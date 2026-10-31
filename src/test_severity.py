from severity import calculate_severity


print("=== SEVERITY ENGINE TEST ===")

print(
    "3 failed attempts:",
    calculate_severity("SSH_BRUTE_FORCE", 3)
)

print(
    "5 failed attempts:",
    calculate_severity("SSH_BRUTE_FORCE", 5)
)

print(
    "10 failed attempts:",
    calculate_severity("SSH_BRUTE_FORCE", 10)
)

print(
    "3 failures + successful login:",
    calculate_severity("SSH_FAILURES_THEN_SUCCESS", 3)
)

print(
    "5 failures + successful login:",
    calculate_severity("SSH_FAILURES_THEN_SUCCESS", 5)
)

def calculate_severity(alert_type, failed_attempts=0):
    """
    Calculate alert severity based on the detection type
    and number of failed authentication attempts.
    """

    # SSH brute-force detection
    if alert_type == "SSH_BRUTE_FORCE":

        if failed_attempts >= 10:
            return "CRITICAL"

        elif failed_attempts >= 5:
            return "HIGH"

        elif failed_attempts >= 3:
            return "MEDIUM"

        else:
            return "LOW"

    # Failed logins followed by successful login
    # (AUTH_FAILURES_THEN_SUCCESS is the name emitted by the detector)
    if alert_type in ("SSH_FAILURES_THEN_SUCCESS", "AUTH_FAILURES_THEN_SUCCESS"):

        if failed_attempts >= 5:
            return "CRITICAL"

        elif failed_attempts >= 3:
            return "HIGH"

        else:
            return "MEDIUM"

    # Unknown detection
    return "LOW"

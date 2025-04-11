import pandas as pd

def generate_report(stats_file="locust_results_stats.csv", failures_file="locust_results_failures.csv"):
    # Load the CSV data
    df_stats = pd.read_csv(stats_file)
    df_failures = pd.read_csv(failures_file)

    # Extract key metrics
    total_requests = df_stats["Request Count"].sum()
    avg_response_time = df_stats["Average Response Time"].mean()
    failure_count = df_failures["Occurrences"].sum() if not df_failures.empty else 0
    failure_rate = (failure_count / total_requests) * 100 if total_requests > 0 else 0

    # Requests per second
    total_rps = df_stats["Requests/s"].sum()

    # Generate report
    report = f"""
    ====== Load Test Report ======
    Total Requests: {total_requests}
    Average Response Time: {avg_response_time:.2f} ms
    Requests Per Second (RPS): {total_rps:.2f}
    Total Failures: {failure_count}
    Failure Rate: {failure_rate:.2f}%
    ===============================
    """
    print(report)

    # Save report to file
    with open("load_test_report.txt", "w") as f:
        f.write(report)

# Run report generation
generate_report()


# ====== Load Test Report ======
# Total Requests: 25000
# Average Response Time: 230.45 ms
# Requests Per Second (RPS): 98.6
# Total Failures: 1200
# Failure Rate: 4.8%
# ===============================
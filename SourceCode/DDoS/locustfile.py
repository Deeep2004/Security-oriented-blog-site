from locust import HttpUser, task, between

class StressTestUser(HttpUser):
    wait_time = between(0.1, 0.5)  # Simulates rapid-fire requests

    @task
    def flood_server(self):
        """Simulate a DoS attack with repeated requests"""
        self.client.get("/")  # Modify if your API uses different endpoints

# Run without generating a report summarizing: 
#   locust -f locustfile.py --host http://localhost:8080


# Run with report summarizing: 
#   locust -f locustfile.py --host http://localhost:8080 --headless 
#       --users 500 --spawn-rate 100 --run-time 5m --csv=locust_results

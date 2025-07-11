import requests

for i in range(15):  # simulate 15 failed attempts
    r = requests.post("http://localhost:5000/login", data={"username": "bad", "password": "wrong"})
    print(f"Attempt {i+1}: {r.status_code}")


import time
import os
import requests
from flask import Flask, request, render_template

API_KEY = "df67970815fc9dec441323991614f9213f77aa9069de09a120812ab879a3fc82"  # Replace with your actual API key

app = Flask(__name__)

# Function to scan a file using VirusTotal API
def scan_file_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    
    with open(file_path, "rb") as file:
        response = requests.post(url, headers=headers, files={"file": file}).json()
    
    analysis_id = response["data"]["id"]
    time.sleep(10)  # Wait for scanning to complete

    # Fetch scan results
    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(result_url, headers=headers).json()
    
    return result_response
# Webpage Route
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded_file = request.files["file"]
        if uploaded_file:
            file_path = os.path.join("uploads", uploaded_file.filename)
            uploaded_file.save(file_path)
            result = scan_file_virustotal(file_path)
            return render_template("result.html", result=result)

    return render_template("index.html")

if __name__ == "__main__":
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)

# from asyncio import sleep
from time import sleep
from flask import Flask, render_template, request, jsonify
import nmap
import json
import subprocess

app = Flask(__name__)

nm = nmap.PortScanner()

def find_services_and_find_vulnerabilities_with_service(ip):
    global nm
    nm.scan(ip, arguments='-O -sV', timeout=None, sudo=True) 

    nmapScanResult = nm[ip]

    ip = nmapScanResult["addresses"]

    os=[]

    for i in nmapScanResult["osmatch"]:
        os.append(i["name"])

    serviceAndVersion = {}
    for i in nmapScanResult["tcp"]:
        serviceAndVersion[nmapScanResult["tcp"][i]["name"]] = nmapScanResult["tcp"][i]["version"]
    print(ip,os,serviceAndVersion)
    # ########################################################
    vulnResult = []
    tmp = """"""
    for i in serviceAndVersion:
        if "http" in i:
            continue
        try:
            tmp = subprocess.run(['searchsploit', "-j", i], capture_output=True, text=True, check=True)
            if tmp.returncode == 0:
                tmp = json.loads(tmp.stdout)
            else:
                print("Error executing the command:", tmp.stderr) 
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
        # vulnResult.append(tmp)
        vulnResultTmp = []
        for j in tmp["RESULTS_EXPLOIT"]:
            if  serviceAndVersion[i] in j["Title"]:
                vulnResultTmp.append({"vulnerabilities":{"Title":j["Title"], "Author":j["Author"], "Type":j["Type"]}})
        vulnResult.append({i:vulnResultTmp})
        
    return {"address":ip,"os":os,"running_service_And_Version":serviceAndVersion,"vulnerabilities_with_service":vulnResult}


# Function to save result to log file
def save_to_log(ip, result):
    with open('log.txt', 'a') as f:
        f.write(f"Scan result for IP: {ip}\n")
        f.write(f"result :{nm[ip]}\n")

# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route to handle form submission
@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form['ip']
    result = find_services_and_find_vulnerabilities_with_service(ip)
    save_to_log(ip, result)
    result = jsonify({'result': result})
    return result

if __name__ == '__main__':
    app.run(debug=True)

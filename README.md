# A simple MERN stack application

**Note** - To run this project using `docker compose`, follow the below steps.

Switch to the `compose` branch to learn the

1. Implementation of `Dockerfile` for `client` and `server`.
2. Run the containers using `Docker Compose`.

## Run it local without Docker

### Prerequisite

- Install `npm`

#### Start Server:

```
cd mern/server
npm install
npm start
```

#### Start Client

```
cd mern/client
npm install
npm run dev
```

<img width="1790" alt="Screenshot 2024-08-31 at 11 07 58 PM" src="https://github.com/user-attachments/assets/f414230b-8bd6-4393-b8de-6a10444a8dfd">



## Running Tests

To run tests, run the following command

```bash
  npm run test
```

# Ubuntu System Setup & Security Hardening Guide

This guide details the steps to update, upgrade, and secure your Ubuntu system by installing essential tools and security solutions.

---

## Table of Contents
- [Step 1: Update & Upgrade System](#step-1-update--upgrade-system)
- [Step 2: Install Core Utilities & Dependencies](#step-2-install-core-utilities--dependencies)
- [Step 3: Install Docker & Docker Compose](#step-3-install-docker--docker-compose)
- [Step 4: Install Falco (Behavioral Threat Detection)](#step-4-install-falco-behavioral-threat-detection)
- [Step 5: Install Trivy (Vulnerability Scanner)](#step-5-install-trivy-vulnerability-scanner)
- [Step 6: Install Sigstore (Cosign for Image Signing)](#step-6-install-sigstore-cosign-for-image-signing)
- [Step 7: Install OpenSCAP (Compliance & Benchmarking)](#step-7-install-openscap-compliance--benchmarking)
- [Step 8: Install Open Policy Agent (OPA) & Gatekeeper](#step-8-install-open-policy-agent-opa--gatekeeper)
- [Step 9: Install Istio (Service Mesh for Network Security)](#step-9-install-istio-service-mesh-for-network-security)
- [Step 10: Install Elasticsearch & Grafana (For Security Dashboards)](#step-10-install-elasticsearch--grafana-for-security-dashboards)

---

## Step 1: Update & Upgrade System
#### First, update your system’s package list and upgrade any default packages:

```sh
sudo apt update && sudo apt upgrade -y

```

## Step 2: Install Core Utilities & Dependencies

Install essential tools like `curl`, `wget`, `git`, `unzip`, and `jq`:

```sh
sudo apt install -y curl wget git unzip jq

```
 
## Step 3: Install Docker & Docker Compose
 ### 1. Remove any old versions (just in case):
```sh

sudo apt remove docker docker-engine docker.io containerd runc
```
### 2. Install dependencies:

```sh

sudo apt install -y ca-certificates gnupg lsb-release
```
### 3. Add Docker’s official GPG key:
```sh

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.gpg > /dev/null

```
### 4. Set up the stable Docker repository:
```sh

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

```
### 5. Install Docker and Docker Compose:
```sh

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
### 6. Enable & start Docker service:
```sh
sudo systemctl enable --now docker
```
### 7. Verify installation:
```sh
docker --version
docker compose version
```
## Step 4: Install Falco (Behavioral Threat Detection)
#### Falco detects suspicious activity inside containers:

```sh

curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo tee /etc/apt/trusted.gpg.d/falco.asc > /dev/null
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falco.list
sudo apt update && sudo apt install -y falco
```
## Step 5: Install Trivy (Vulnerability Scanner)
#### Trivy scans for vulnerabilities in containers, dependencies, and Infrastructure as Code (IaC):

```sh

sudo apt install -y apt-transport-https
curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo tee /etc/apt/trusted.gpg.d/trivy.asc > /dev/null
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy
```
## Jenkins Pipeline: Automated Container Security and Auto-Remediation

#### This Jenkins pipeline automates the security validation and remediation process for our containerized Java application
```sh
pipeline {
    agent any

    environment {
        IMAGE_NAME = "my-java-app"
        IMAGE_TAG = "latest"
        CONTAINER_PORT = "8082"
        CVE_THRESHOLD = "CRITICAL"
    }

    stages {
        stage('Check Image Locally') {
            steps {
                script {
                    def imageExists = sh(
                        script: "docker images -q ${IMAGE_NAME}:${IMAGE_TAG}", 
                        returnStdout: true
                    ).trim()
                    if (!imageExists) {
                        error "Image ${IMAGE_NAME}:${IMAGE_TAG} not found locally!"
                    }
                    echo "✅ Image exists locally, skipping pull."
                }
            }
        }

        stage('Run Trivy Scan') {
            steps {
                script {
                    def scanOutput = sh(
                        script: "trivy image --format json ${IMAGE_NAME}:${IMAGE_TAG}", 
                        returnStdout: true
                    ).trim()
                    writeFile file: 'trivy-results.json', text: scanOutput
                }
            }
        }

        stage('Check for Critical CVEs') {
            steps {
                script {
                    def cveCount = sh(
                        script: "jq '[.Results[].Vulnerabilities[]? | select(.Severity == \"${CVE_THRESHOLD}\")] | length' trivy-results.json", 
                        returnStdout: true
                    ).trim()
                    if (cveCount.toInteger() > 0) {
                        echo "⚠️ Found ${cveCount} CRITICAL vulnerabilities! Initiating auto-remediation..."
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        echo "✅ No CRITICAL vulnerabilities found. Proceeding normally."
                    }
                }
            }
        }

        stage('Auto-Remediate (Restart Container)') {
            when {
                expression { currentBuild.result == 'UNSTABLE' }
            }
            steps {
                script {
                    echo "⚠️ Restarting container due to critical vulnerabilities..."

                    // Cleanup container before restarting
                    sh """
                        CONTAINER_ID=\$(docker ps -q --filter "name=${IMAGE_NAME}")
                        if [ ! -z "\$CONTAINER_ID" ]; then
                            echo "Stopping and removing existing container with ID: \$CONTAINER_ID"
                            docker stop \$CONTAINER_ID
                            docker rm \$CONTAINER_ID
                        fi
                        docker run -d --name ${IMAGE_NAME} -p ${CONTAINER_PORT}:8080 ${IMAGE_NAME}:${IMAGE_TAG}
                    """
                }
            }
        }

        stage('Verify Fix') {
            when {
                expression { currentBuild.result == 'UNSTABLE' }
            }
            steps {
                script {
                    def reScanOutput = sh(
                        script: "trivy image --format json ${IMAGE_NAME}:${IMAGE_TAG}", 
                        returnStdout: true
                    ).trim()
                    writeFile file: 'trivy-results-after.json', text: reScanOutput

                    def reCveCount = sh(
                        script: "jq '[.Results[].Vulnerabilities[]? | select(.Severity == \"${CVE_THRESHOLD}\")] | length' trivy-results-after.json", 
                        returnStdout: true
                    ).trim()

                    if (reCveCount.toInteger() == 0) {
                        echo "✅ Fix Verified! No CRITICAL vulnerabilities found in the new container."
                    } else {
                        echo "⚠️ WARNING: ${reCveCount} CRITICAL vulnerabilities still exist. Manual intervention required!"
                    }
                }
            }
        }
    }
}
```
## Step 6: Install Sigstore (Cosign for Image Signing)
#### Sigstore ensures your container images are securely signed and verified:

```sh

curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
```
## Step 7: Install OpenSCAP (Compliance & Benchmarking)
```sh

# Add the universe repository and update
sudo add-apt-repository universe
sudo apt update

# Install OpenSCAP and Ubuntu Advantage Tools
sudo apt install -y scap-security-guide
sudo apt update
sudo apt install -y ubuntu-advantage-tools

# Replace <your-token> with your Ubuntu Advantage token
sudo pro attach <your-token>
sudo pro enable usg
sudo apt install -y usg
sudo usg audit disa_stig
sudo usg fix disa_stig
sudo usg generate-tailoring disa_stig mytailoringfile.xml

# Install additional dependencies for ComplianceAsCode content build
sudo apt install -y cmake make libopenscap8 libxml2-utils ninja-build python3-jinja2 python3-yaml python3-setuptools xsltproc

# Clone and build the ComplianceAsCode content
git clone -b master https://github.com/ComplianceAsCode/content.git
cd content/build/
cmake ../
make -j4

# Evaluate using oscap
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server --results result.xml ssg-ubuntu2204-ds.xml
```
## Step 8: Install Open Policy Agent (OPA) & Gatekeeper
#### OPA helps enforce security policies for Kubernetes and containers:

```sh
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
```
## Step 9: Install Istio (Service Mesh for Network Security)
#### Istio provides a robust service mesh to enhance network security and observability:

```sh
curl -L https://istio.io/downloadIstio | sh -
cd istio-*
sudo mv bin/istioctl /usr/local/bin/
```
## Step 10: Install Elasticsearch & Grafana (For Security Dashboards)
#### Elasticsearch (Stores logs & scan reports):
```sh
sudo apt install -y elasticsearch
sudo systemctl enable --now elasticsearch

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install -y elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch


```
## Grafana (Dashboard for visualization):
#### Add the Grafana APT Repository:
```sh
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update

```
## Install and start Grafana:
```sh
sudo apt install -y grafana
sudo systemctl start grafana-server
sudo systemctl enable --now grafana
```


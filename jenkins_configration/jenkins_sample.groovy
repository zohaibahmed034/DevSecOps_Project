pipeline {
    agent {
        kubernetes {
            yaml """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: sonar-scanner
    image: sonarsource/sonar-scanner-cli:latest
    command: ['cat']
    tty: true
  - name: owasp-check
    image: owasp/dependency-check:latest
    command: ['cat']
    tty: true
    securityContext:
      runAsUser: 0
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
    - name: odc-data
      mountPath: /usr/share/dependency-check/data
  - name: checkov
    image: bridgecrew/checkov:latest
    command: ['cat']
    tty: true
    securityContext:
      runAsUser: 0
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: trivy
    image: aquasec/trivy:latest
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: snyk
    image: snyk/snyk:alpine
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: python-risk
    image: python:3.9-slim
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: docker-daemon
    image: docker:24.0.7-dind
    securityContext:
      privileged: true
    env:
    - name: DOCKER_TLS_CERTDIR
      value: ""
  - name: scanner
    image: docker:24.0.7
    command: ["cat"]
    tty: true
    env:
    - name: DOCKER_HOST
      value: "tcp://localhost:2375"
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: tools
    image: alpine:3.18
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  - name: zap-scanner
    image: ghcr.io/zaproxy/zaproxy:stable
    command: ['sh', '-c', 'sleep 3600']
    tty: true
    securityContext:
      runAsUser: 1000
    volumeMounts:
    - name: report-storage
      mountPath: /zap/wrk
  - name: sec-tools
    image: python:3.9-slim
    command: ['sh', '-c', 'sleep 3600']
    tty: true
    securityContext:
      runAsUser: 0
    volumeMounts:
    - name: report-storage
      mountPath: /var/reports-dir
  volumes:
  - name: report-storage
    hostPath:
      path: /var/reports-dir
      type: DirectoryOrCreate
  - name: odc-data
    hostPath:
      path: /var/owasp-dependency-check/data
      type: DirectoryOrCreate
"""
        }
    }

    environment {
        REPO_NAME        = "zohaibahmed034/DevSecOps_Project"
        DOCKER_IMAGE_TAG = "v1"
        SONAR_URL        = "http://44.195.24.196:32353"
        CLAIR_URL        = "http://clair-api.devsecops.svc.cluster.local:6060"
        VAULT_ADDR       = "http://44.195.24.196:30853"
        DOCKER_USER      = "zuhaibahmed034"
        IMAGES           = "ghost-devsecops,mysql-devsecops"
        REPORT_DIR       = "/var/reports-dir/build-${env.BUILD_NUMBER}"
        TARGET_URL       = "http://44.195.24.196:30005/"
        REPORT_NAME      = "dast-report-build-${env.BUILD_NUMBER}.html"
        BUILD_REPORT_DIR = "/var/reports-dir/build-${env.BUILD_NUMBER}/threat-modeling"
        REPO_URL         = "https://github.com/zohaibahmed034/DevSecOps_Project.git"
    }

    stages {
        stage('Step 1: Checkout & Setup') {
            steps {
                checkout scmGit(
                    branches: [[name: 'main']], 
                    userRemoteConfigs: [[url: "https://github.com/${REPO_NAME}.git", credentialsId: 'github-creds']]
                )
                container('scanner') {
                    sh "apk add --no-cache curl wget tar git || true" 
                    sh "mkdir -p ${env.REPORT_DIR}"
                }
            }
        }

        stage('Step 1.1: Checkout Source Code (Threat Modeling)') {
            steps {
                script {
                    echo "Cloning repository from GitHub..."
                    git url: "${env.REPO_URL}", branch: "main"
                }
            }
        }

        stage('Step 1.2: Initialize Modeling Environment') {
            steps {
                container('sec-tools') {
                    sh "mkdir -p ${env.BUILD_REPORT_DIR}"
                    sh "pip install pytm"
                    echo "Environment ready for Build #${env.BUILD_NUMBER}"
                }
            }
        }

        stage('Step 1.3: Threat Modeling - Python pytm') {
            steps {
                container('sec-tools') {
                    script {
                        echo "Running Automated Threats-as-Code for Build #${env.BUILD_NUMBER}..."
                        sh "python3 threat_model.py > pytm_report.md"
                    }
                }
            }
        }

        stage('Step 1.4: Threat Modeling - OWASP Threat Dragon') {
            steps {
                container('sec-tools') {
                    script {
                        echo "Validating Design-level Threats from OWASP Threat Dragon..."
                        sh """
                            if [ -f "threat_dragon_model.json" ]; then
                                echo "SUCCESS: Threat Dragon Model (JSON) found."
                                cp threat_dragon_model.json pytm_report.md ${env.BUILD_REPORT_DIR}/ || true
                            else
                                echo "ERROR: threat_dragon_model.json is missing!"
                                exit 1
                            fi
                        """
                    }
                }
            }
        }

        stage('Step 1.5: Evidence Collection') {
            steps {
                container('sec-tools') {
                    script {
                        echo "Archiving artifacts for Build #${env.BUILD_NUMBER}..."
                        sh "cp pytm_report.md ${env.BUILD_REPORT_DIR}/compliance_report_${env.BUILD_NUMBER}.md"
                        archiveArtifacts artifacts: "pytm_report.md", allowEmptyArchive: false
                    }
                }
            }
        }

        stage('Step 2: Static Code Analysis (SonarQube)') {
            steps {
                container('sonar-scanner') {
                    script {
                        def secrets = [[path: 'secret/devsecops/creds', secretValues: [[envVar: 'SONAR_TOKEN', vaultKey: 'sonar_token']]]]
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                            sh """
                                sonar-scanner \
                                -Dsonar.projectKey=DevSecOps_Project \
                                -Dsonar.host.url=${env.SONAR_URL} \
                                -Dsonar.login=${env.SONAR_TOKEN}
                            """
                        }
                    }
                }
            }
        }

        stage('Step 3: Security Scans (Parallel)') {
            parallel {
                stage('Snyk Scan') {
                    steps {
                        container('snyk') {
                            script {
                                def secrets = [[path: 'secret/devsecops/creds', secretValues: [[envVar: 'SNYK_TOKEN', vaultKey: 'snyk_token']]]]
                                withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                                    sh "snyk auth ${env.SNYK_TOKEN} && snyk test --all-projects --json > ${env.REPORT_DIR}/snyk-report.json || true"
                                }
                            }
                        }
                    }
                }
                stage('OWASP Dependency Check') {
                    steps {
                        container('owasp-check') {
                            script {
                                def secrets = [[path: 'secret/devsecops/creds', secretValues: [[envVar: 'NVD_API_KEY', vaultKey: 'nvd_api_key']]]]
                                withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                                    sh """
                                        /usr/share/dependency-check/bin/dependency-check.sh \
                                        --scan . --format ALL \
                                        --out ${env.REPORT_DIR}/ \
                                        --nvdApiKey ${env.NVD_API_KEY} \
                                        --failOnCVSS 7 || true
                                    """
                                }
                            }
                        }
                    }
                }
            }
        }

        stage('Step 4.3: AWS Security Scan (Prowler)') {
            steps {
                script {
                    def secrets = [[
                        path: 'secret/devsecops/creds', 
                        engineVersion: 2, 
                        secretValues: [
                            [envVar: 'AWS_AK', vaultKey: 'aws_access_key'],
                            [envVar: 'AWS_SK', vaultKey: 'aws_secret_key']
                        ]
                    ]]
        
                    // Hum 'sec-tools' container use karein gy kyunke usme Python pehle se hai
                    container('sec-tools') {
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                            sh """
                                echo "--- 🛠️ Installing Prowler ---"
                                pip install prowler --quiet
                                
                                export AWS_ACCESS_KEY_ID=${env.AWS_AK}
                                export AWS_SECRET_ACCESS_KEY=${env.AWS_SK}
                                export AWS_REGION="us-east-1"
        
                                echo "--- 🔍 Running Prowler Scan (S3 Only for speed) ---"
                                # Aap sirf S3 scan kar sakte hain ya poora account
                                prowler aws --services s3 --output-directory /var/reports-dir/build-${BUILD_NUMBER}/prowler/
                                
                                echo "--- ✅ Prowler Scan Completed ---"
                            """
                        }
                    }
                }
            }
        }
        stage('Step 4.1: IaC Analysis') {
            steps {
                container('checkov') {
                    sh "checkov -d . --download-external-modules --output json > ${env.REPORT_DIR}/checkov-report.json || true"
                }
                container('scanner') {
                    sh """
                        if ! command -v conftest &> /dev/null; then
                            curl -L -s https://github.com/open-policy-agent/conftest/releases/download/v0.45.0/conftest_0.45.0_Linux_x86_64.tar.gz | tar xz
                            mv conftest /usr/local/bin/
                        fi
                        mkdir -p policy
                        cat <<EOF > policy/base.rego
                        package main
                        deny[msg] {
                            input.kind == "Deployment"
                            not input.spec.template.spec.securityContext.runAsNonRoot
                            msg := sprintf("Security Risk: Root user detected in %s", [input.metadata.name])
                        }
EOF
                        if ls *.yaml >/dev/null 2>&1; then
                            conftest test *.yaml --policy policy/ --no-color > ${env.REPORT_DIR}/conftest-report.txt || true
                        else
                            echo "No YAML files found for Conftest" > ${env.REPORT_DIR}/conftest-report.txt
                        fi
                        if ! command -v terrascan &> /dev/null; then
                            curl -L -s https://github.com/tenable/terrascan/releases/download/v1.18.11/terrascan_1.18.11_Linux_x86_64.tar.gz | tar xz
                            if [ -f terrascan ]; then install terrascan /usr/local/bin; fi
                        fi
                        terrascan scan -i k8s -d . > ${env.REPORT_DIR}/terrascan-report.txt || true
                    """
                }
            }
        }

        stage('Step 5: Container Security') {
            steps {
                script {
                    def secrets = [[path: 'secret/devsecops/creds', secretValues: [
                        [envVar: 'DOCKER_USER', vaultKey: 'docker_user'],
                        [envVar: 'SNYK_TOKEN', vaultKey: 'snyk_token']
                    ]]]
                    withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                        def images = ['mysql-devsecops', 'ghost-devsecops']
                        images.each { imageName ->
                            def fullImage = "${env.DOCKER_USER}/${imageName}:${env.DOCKER_IMAGE_TAG}"
                            container('docker-daemon') { sh "docker pull ${fullImage} || true" }
                            container('scanner') {
                                sh """
                                    if [ -d "./clair-scanner" ]; then rm -rf ./clair-scanner; fi
                                    if [ ! -f ./clair-scanner ]; then
                                        curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o clair-scanner
                                        chmod +x clair-scanner
                                    fi
                                    ./clair-scanner --ip \$(hostname -i) --clair ${env.CLAIR_URL} ${fullImage} > ${env.REPORT_DIR}/clair-${imageName}.txt || true
                                """
                            }
                            container('trivy') { sh "trivy image --format json --output ${env.REPORT_DIR}/trivy-${imageName}.json ${fullImage} || true" }
                            container('snyk') { sh "snyk auth ${env.SNYK_TOKEN} && snyk container test ${fullImage} --json > ${env.REPORT_DIR}/snyk-image-${imageName}.json || true" }
                        }
                    }
                }
            }
        }

        stage('Step 5.1: Image Signing') {
            steps {
                script {
                    def secrets = [[path: 'secret/devsecops/creds', engineVersion: 2, secretValues: [
                        [envVar: 'COSIGN_KEY', vaultKey: 'cosign_private_key'],
                        [envVar: 'COSIGN_PUB', vaultKey: 'cosign_public_key'],
                        [envVar: 'COSIGN_PASSWORD', vaultKey: 'cosign_password'],
                        [envVar: 'D_PASS', vaultKey: 'docker_pass']
                    ]]]
                    withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                        container('scanner') {
                            sh """
                                if ! command -v cosign &> /dev/null; then
                                    curl -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign
                                    chmod +x /usr/local/bin/cosign
                                fi
                                echo '${env.COSIGN_KEY}' > cosign.key
                                echo '${env.COSIGN_PUB}' > cosign.pub
                                echo "${env.D_PASS}" | docker login -u "${env.DOCKER_USER}" --password-stdin
                            """
                            def imageList = env.IMAGES.split(',')
                            for (imgName in imageList) {
                                def fullImage = "${env.DOCKER_USER}/${imgName.trim()}:${env.DOCKER_IMAGE_TAG}"
                                sh """
                                    export COSIGN_PASSWORD=${env.COSIGN_PASSWORD}
                                    for i in {1..3}; do
                                        cosign sign --key cosign.key ${fullImage} --yes && break || sleep 60
                                    done
                                    cosign verify --key cosign.pub ${fullImage} --insecure-ignore-tlog > ${env.REPORT_DIR}/${imgName.trim()}-cosign-verify.txt || true
                                """
                            }
                            sh "rm -f cosign.key cosign.pub"
                        }
                    }
                }
            }
        }

        stage('Step 6: Smart Deploy & Validation') {
            steps {
                script {
                    container('scanner') {
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], 
                                  vaultSecrets: [[path: 'secret/devsecops/creds', secretValues: [[envVar: 'ARGO_TOKEN', vaultKey: 'argo_token']]]]) {
                            sh """
                                if ! command -v argocd &> /dev/null; then
                                    curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
                                    chmod +x /usr/local/bin/argocd
                                fi
                                if argocd app get devsecops-project --server 44.195.24.196:31436 --auth-token ${ARGO_TOKEN} --insecure > /dev/null 2>&1; then
                                    argocd app sync devsecops-project --server 44.195.24.196:31436 --auth-token ${ARGO_TOKEN} --insecure
                                else
                                    argocd app create devsecops-project \
                                        --server 44.195.24.196:31436 \
                                        --auth-token ${ARGO_TOKEN} \
                                        --repo https://github.com/zohaibahmed034/DevSecOps_Project.git \
                                        --path k8s/manifests \
                                        --dest-server https://kubernetes.default.svc \
                                        --dest-namespace default \
                                        --sync-policy automated \
                                        --self-heal --auto-prune --insecure
                                fi
                            """
                        }
                    }
                }
            }
        }

        stage('Step 7: DAST Environment Check') {
            steps {
                container('zap-scanner') {
                    echo "Starting DAST Security Scan on: ${env.TARGET_URL}"
                    sh "ls -ld /zap/wrk"
                }
            }
        }

        stage('Step 7.1: Run DAST Baseline Scan') {
            steps {
                container('zap-scanner') {
                    script {
                        sh "zap-baseline.py -t ${env.TARGET_URL} -r ${env.REPORT_NAME} || true"
                    }
                }
            }
        }

        stage('Step 7.2: DAST Verification') {
            steps {
                container('zap-scanner') {
                    echo "--- DAST Scan Completed ---"
                    sh "ls -lh /zap/wrk/${env.REPORT_NAME} || true"
                    archiveArtifacts artifacts: "**/dast-report-build-*.html", allowEmptyArchive: true
                }
            }
        }

        stage('Step 8: Final Release & GitHub Assets') {
            steps {
                container('scanner') {
                    script {
                        def secrets = [[path: 'secret/devsecops/creds', engineVersion: 2, secretValues: [[envVar: 'GH_TOKEN', vaultKey: 'github_token']]]]
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token'], vaultSecrets: secrets) {
                            sh '''
                                if ! command -v gh &> /dev/null || ! command -v zip &> /dev/null; then
                                    apk add --no-cache zip github-cli
                                fi
                                export GITHUB_TOKEN=$GH_TOKEN
                                TAG="v1.0.${BUILD_NUMBER}"
                                ZIP_NAME="all-security-reports-build-${BUILD_NUMBER}.zip"
                                if [ -d "${REPORT_DIR}" ]; then
                                    cd ${REPORT_DIR} && zip -r ../$ZIP_NAME . && cd ..
                                else
                                    echo "Reports directory not found!" && exit 1
                                fi
                                gh release delete "$TAG" --repo "$REPO_NAME" --yes || echo "Clean start."
                                gh release create "$TAG" "$ZIP_NAME" \
                                    --title "DevSecOps Release - Build #${BUILD_NUMBER}" \
                                    --notes "Automated Security Reports for Build #${BUILD_NUMBER}" \
                                    --repo "$REPO_NAME"
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            echo "Pipeline and DAST Scan successful. Evidence stored in /var/reports-dir/"
        }
        failure {
            echo "Pipeline failed. Check logs for issues."
        }
        always {
            echo "Pipeline Finished."
        }
    }
}


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

        stage('Step 4: IaC Analysis') {
            steps {
                container('checkov') {
                    // --download-external-modules flag add kiya hai modules fetch karne ke liye
                    sh "checkov -d . --download-external-modules --output json > ${env.REPORT_DIR}/checkov-report.json || true"
                }
                container('scanner') {
                    sh """
                        # 1. Conftest Installation
                        if ! command -v conftest &> /dev/null; then
                            curl -L -s https://github.com/open-policy-agent/conftest/releases/download/v0.45.0/conftest_0.45.0_Linux_x86_64.tar.gz | tar xz
                            mv conftest /usr/local/bin/
                        fi
        
                        # 2. Policy Creation
                        mkdir -p policy
                        cat <<EOF > policy/base.rego
        package main
        deny[msg] {
            input.kind == "Deployment"
            not input.spec.template.spec.securityContext.runAsNonRoot
            msg := sprintf("Security Risk: Root user detected in %s", [input.metadata.name])
        }
        EOF
        
                        # 3. Conftest Scan (File check add kiya hai taake 'no such file' error na aaye)
                        if ls *.yaml >/dev/null 2>&1; then
                            conftest test *.yaml --policy policy/ --no-color > ${env.REPORT_DIR}/conftest-report.txt || true
                        else
                            echo "No YAML files found for Conftest" > ${env.REPORT_DIR}/conftest-report.txt
                        fi
                        
                        # 4. Terrascan Installation & Scan
                        if ! command -v terrascan &> /dev/null; then
                            curl -L -s https://github.com/tenable/terrascan/releases/download/v1.18.11/terrascan_1.18.11_Linux_x86_64.tar.gz | tar xz
                            # Terrascan binary check
                            if [ -f terrascan ]; then
                                install terrascan /usr/local/bin
                            fi
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
                            
                            // Docker Pull: Isay 'docker-daemon' container mein hona chahiye
                            container('docker-daemon') {
                                sh "docker pull ${fullImage} || true"
                            }
        
                            container('scanner') {
                                sh """
                                    # Fix: Agar 'clair-scanner' naam ka folder hai toh usay hatao
                                    if [ -d "./clair-scanner" ]; then rm -rf ./clair-scanner; fi
                                    
                                    if [ ! -f ./clair-scanner ]; then
                                        curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o clair-scanner
                                        chmod +x clair-scanner
                                    fi
                                    # Scan command
                                    ./clair-scanner --ip \$(hostname -i) --clair ${env.CLAIR_URL} ${fullImage} > ${env.REPORT_DIR}/clair-${imageName}.txt || true
                                """
                            }
        
                            container('trivy') {
                                // Trivy ko docker socket ki zaroorat hoti hai, ensure karein trivy image mein docker installed ho ya client ho
                                sh "trivy image --format json --output ${env.REPORT_DIR}/trivy-${imageName}.json ${fullImage} || true"
                            }
        
                            container('snyk') {
                                sh "snyk auth ${env.SNYK_TOKEN} && snyk container test ${fullImage} --json > ${env.REPORT_DIR}/snyk-image-${imageName}.json || true"
                            }
                        }
                    }
                }
            }
        }
        stage('Step 5.1: Image Signing & SLSA Attestation') {
            steps {
                script {
                    def secrets = [[
                        path: 'secret/devsecops/creds', 
                        engineVersion: 2, 
                        secretValues: [
                            [envVar: 'COSIGN_KEY',      vaultKey: 'cosign_private_key'],
                            [envVar: 'COSIGN_PUB',      vaultKey: 'cosign_public_key'],
                            [envVar: 'COSIGN_PASSWORD', vaultKey: 'cosign_password'],
                            [envVar: 'D_PASS',          vaultKey: 'docker_pass']
                        ]
                    ]]
        
                    withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], vaultSecrets: secrets) {
                        container('scanner') {
                            sh """
                                # Cosign Install if not exists
                                if ! command -v cosign &> /dev/null; then
                                    curl -L https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign
                                    chmod +x /usr/local/bin/cosign
                                fi
                                
                                echo '${env.COSIGN_KEY}' > cosign.key
                                echo '${env.COSIGN_PUB}' > cosign.pub
                                
                                # Docker Login (Rate limit se bachne ke liye)
                                echo "${env.D_PASS}" | docker login -u "${env.DOCKER_USER}" --password-stdin
                            """
                            
                            def imageList = env.IMAGES.split(',')
                            for (imgName in imageList) {
                                def fullImage = "${env.DOCKER_USER}/${imgName}:${env.DOCKER_IMAGE_TAG}"
                                
                                sh """
                                    export COSIGN_PASSWORD=${env.COSIGN_PASSWORD}
                                    
                                    # Rate limit hit hone ki surat mein retry logic
                                    for i in {1..3}; do
                                        cosign sign --key cosign.key ${fullImage} --yes && break || sleep 60
                                    done
        
                                    # Baki steps (Attest & Verify)...
                                    cosign verify --key cosign.pub ${fullImage} --insecure-ignore-tlog > ${env.REPORT_DIR}/${imgName}-cosign-verify.txt
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
                    container('scanner') { // 'scanner' use karein kyunki usme curl/shell behtar chalta hai
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token', engineVersion: 2], 
                                  vaultSecrets: [[path: 'secret/devsecops/creds', secretValues: [[envVar: 'ARGO_TOKEN', vaultKey: 'argo_token']]]]) {
                            
                            sh """
                                # ArgoCD installation check
                                if ! command -v argocd &> /dev/null; then
                                    echo "Downloading ArgoCD CLI..."
                                    curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
                                    chmod +x /usr/local/bin/argocd
                                fi
        
                                # Check if App exists, if not Create
                                if argocd app get devsecops-project --server 44.195.24.196:31436 --auth-token ${ARGO_TOKEN} --insecure > /dev/null 2>&1; then
                                    echo "App exists, syncing..."
                                    argocd app sync devsecops-project --server 44.195.24.196:31436 --auth-token ${ARGO_TOKEN} --insecure
                                else
                                    echo "Creating new App..."
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

        stage('Final Release & GitHub Assets') {
            steps {
                // 'scanner' ya 'tools' dono mein se koi bhi container use kar sakte hain
                container('scanner') { 
                    script {
                        def secrets = [[
                            path: 'secret/devsecops/creds', 
                            engineVersion: 2, 
                            secretValues: [[envVar: 'GH_TOKEN', vaultKey: 'github_token']]
                        ]]
                        
                        withVault(configuration: [vaultUrl: "${VAULT_ADDR}", vaultCredentialId: 'vault-root-token'], vaultSecrets: secrets) {
                            sh '''
                                # 1. Tools Install (Alpine image check)
                                if ! command -v gh &> /dev/null || ! command -v zip &> /dev/null; then
                                    apk add --no-cache zip github-cli
                                fi
        
                                export GITHUB_TOKEN=$GH_TOKEN
                                TAG="v1.0.${BUILD_NUMBER}"
                                ZIP_NAME="all-security-reports-build-${BUILD_NUMBER}.zip"
        
                                # 2. Zip Reports
                                if [ -d "${REPORT_DIR}" ]; then
                                    cd ${REPORT_DIR} && zip -r ../$ZIP_NAME . && cd ..
                                else
                                    echo "Reports directory not found!" && exit 1
                                fi
                                
                                # 3. The 422 Fix: Clean and Atomic Create
                                echo "Deleting old release if exists to avoid 422 error..."
                                gh release delete "$TAG" --repo "$REPO_NAME" --yes || echo "Clean start."
        
                                echo "Creating release and uploading assets in one command..."
                                gh release create "$TAG" "$ZIP_NAME" \
                                    --title "DevSecOps Release - Build #${BUILD_NUMBER}" \
                                    --notes "Automated Security Reports for Build #${BUILD_NUMBER}" \
                                    --repo "$REPO_NAME"
                                
                                echo "Successfully uploaded assets to GitHub!"
                            '''
                        }
                    }
                }
            }
        }
    }
}


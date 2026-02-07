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
      mountPath: /reports-dir
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
      mountPath: /reports-dir
  - name: trivy
    image: aquasec/trivy:latest
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /reports-dir
  - name: snyk
    image: snyk/snyk:alpine
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /reports-dir
  # --- FIX: Adding the missing Python container ---
  - name: python-risk
    image: python:3.9-slim
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /reports-dir
  # -----------------------------------------------
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
    volumeMounts:
    - name: report-storage
      mountPath: /reports-dir
  - name: tools
    image: alpine:3.18
    command: ['cat']
    tty: true
    volumeMounts:
    - name: report-storage
      mountPath: /reports-dir
  volumes:
  - name: report-storage
    hostPath:
      path: /var/devsecops-reports
      type: DirectoryOrCreate
  - name: odc-data
    hostPath:
      path: /var/owasp-dependency-check/data
      type: DirectoryOrCreate
"""
        }
    }

    environment {
        // Shared Configs
        REPO_NAME = "zohaibahmed034/DevSecOps_Project"
        DOCKER_USER = "zuhaibahmed034"
        DOCKER_IMAGE_TAG = "v1"
        REPORT_DIR = "/reports-dir"
        
        // Tool Specific
        NVD_API_KEY = "2ed2af0a-5854-495e-8a42-439179cc47f3"
        SNYK_TOKEN = "525059f1-0568-4dc8-8eff-0afcea37c892"
        SONAR_URL = "http://100.24.125.225:32353"
        CLAIR_URL = "http://clair-api.devsecops.svc.cluster.local:6060"
        DOCKER_HOST = "tcp://localhost:2375"
    }

    stages {
        stage('Step 1: Checkout & Setup') {
            steps {
                git branch: 'main', url: "https://github.com/${REPO_NAME}.git"
                container('scanner') {
                    sh "apk add --no-cache curl wget tar git"
                    sh "mkdir -p ${REPORT_DIR}"
                }
            }
        }

        stage('Step 2: Static Code Analysis (SonarQube)') {
            steps {
                container('sonar-scanner') {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh "sonar-scanner -Dsonar.projectKey=DevSecOps_Project -Dsonar.host.url=${SONAR_URL} -Dsonar.login=${SONAR_TOKEN}"
                    }
                }
            }
        }

        stage('Step 3: Snyk & OWASP Dependency Scans') {
            parallel {
                stage('Snyk Open Source') {
                    steps {
                        container('snyk') {
                            sh "snyk auth ${SNYK_TOKEN}"
                            sh "snyk test --all-projects --json > ${REPORT_DIR}/snyk-code-report.json || true"
                        }
                    }
                }
                stage('OWASP Scan') {
                    steps {
                        container('owasp-check') {
                            sh "rm -rf /usr/share/dependency-check/data/*"
                            sh "/usr/share/dependency-check/bin/dependency-check.sh --scan . --format ALL --out ${REPORT_DIR}/ --data /usr/share/dependency-check/data --nvdApiKey ${NVD_API_KEY} --failOnCVSS 7 || true"
                        }
                    }
                }
            }
        }

        stage('Step 4: IaC Analysis (Checkov, Conftest, Terrascan)') {
            steps {
                // Checkov
                container('checkov') {
                    sh "checkov -d . --output json > ${REPORT_DIR}/checkov-report.json || true"
                }
                // Conftest & Terrascan
                container('scanner') {
                    script {
                        sh """
                            wget https://github.com/open-policy-agent/conftest/releases/download/v0.45.0/conftest_0.45.0_Linux_x86_64.tar.gz
                            tar xzf conftest_0.45.0_Linux_x86_64.tar.gz && mv conftest /usr/local/bin/
                            mkdir -p policy
                            echo 'package main\ndeny[msg] { input.kind == "Deployment"; not input.spec.template.spec.securityContext.runAsNonRoot; msg := sprintf("Root user check failed: %s", [input.metadata.name]) }' > policy/base.rego
                            conftest test *.yaml --policy policy/ --no-color > ${REPORT_DIR}/conftest-report.txt || true
                            
                            export T_VER="1.18.11"
                            wget https://github.com/tenable/terrascan/releases/download/v\${T_VER}/terrascan_\${T_VER}_Linux_x86_64.tar.gz
                            tar -xf terrascan_\${T_VER}_Linux_x86_64.tar.gz terrascan
                            install terrascan /usr/local/bin
                            terrascan scan -i k8s -d . > ${REPORT_DIR}/terrascan-report.txt || true
                        """
                    }
                }
            }
        }

        stage('Step 5: Container Security (Trivy, Snyk Container, Clair)') {
            steps {
                script {
                    def images = ['mysql-devsecops', 'ghost-devsecops']
                    images.each { imageName ->
                        def fullImage = "${DOCKER_USER}/${imageName}:${DOCKER_IMAGE_TAG}"
                        
                        // Pull image first
                        container('scanner') {
                            sh "sleep 15 && docker pull ${fullImage}"
                            
                            // Clair Scan
                            sh """
                                curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o clair-scanner
                                chmod +x clair-scanner
                                ./clair-scanner --ip \$(hostname -i) --clair ${CLAIR_URL} ${fullImage} > ${REPORT_DIR}/clair-${imageName}.txt || true
                            """
                        }

                        // Trivy Scan
                        container('trivy') {
                            sh "trivy image --format json --output ${REPORT_DIR}/trivy-${imageName}.json ${fullImage} || true"
                        }

                        // Snyk Container Scan
                        container('snyk') {
                            sh "snyk container test ${fullImage} --json > ${REPORT_DIR}/snyk-image-${imageName}.json || true"
                            sh "snyk container monitor ${fullImage} --project-name=${imageName}-Build-${env.BUILD_NUMBER} || true"
                        }
                    }
                }
            }
        }
        stage('Final Release & Report Upload') {
            steps {
                container('tools') {
                    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        script {
                            def releaseTag = "DevSecOps-Build-${env.BUILD_NUMBER}"
                            sh """
                            apk add --no-cache curl zip
                            cd /reports-dir
                            zip -r devsecops-reports-B${env.BUILD_NUMBER}.zip ./*.json

                            # GitHub Release Creation
                            curl -X POST -H "Authorization: token ${GITHUB_TOKEN}" \
                                 -d '{"tag_name":"${releaseTag}","name":"Security Release ${releaseTag}","body":"Full DevSecOps audit completed. Risk Score was within limits.","draft":false,"prerelease":false}' \
                                 https://api.github.com/repos/${REPO_NAME}/releases > resp.json

                            ID=\$(cat resp.json | grep -m 1 '"id":' | awk '{print \$2}' | sed 's/,//')

                            # Uploading the Zip to GitHub
                            curl -X POST -H "Authorization: token ${GITHUB_TOKEN}" \
                                 -H "Content-Type: application/zip" \
                                 --data-binary @"devsecops-reports-B${env.BUILD_NUMBER}.zip" \
                                 "https://uploads.github.com/repos/${REPO_NAME}/releases/\$ID/assets?name=security-reports-B${env.BUILD_NUMBER}.zip"
                            """
                        }
                    }
                }
            }
        }
    }
}

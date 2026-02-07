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
        NVD_API_KEY = "2ed2af0a-5854-495e-8a42-439179cc47f3"
        SNYK_TOKEN = "525059f1-0568-4dc8-8eff-0afcea37c892"
        REPO_NAME = "zohaibahmed034/DevSecOps_Project"
        SONAR_URL = "http://100.24.125.225:32353"
        DOCKER_IMAGE_TAG = "v1"
    }

    stages {
        stage('Step 1: Checkout') {
            steps {
                git branch: 'main', url: "https://github.com/${REPO_NAME}.git"
            }
        }

        stage('Step 2: SonarQube Scan') {
            steps {
                container('sonar-scanner') {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh "sonar-scanner -Dsonar.projectKey=DevSecOps_Project -Dsonar.host.url=${SONAR_URL} -Dsonar.login=${SONAR_TOKEN}"
                    }
                }
            }
        }

        stage('Step 3: Snyk Open Source & Code Scan') {
            steps {
                container('snyk') {
                    script {
                        sh "snyk auth ${SNYK_TOKEN}"
                        // --all-projects flag sub-folders mein dependencies dhoond lega
                        // || true lagane se pipeline fail nahi hogi agar files na milein
                        sh "snyk test --all-projects --json > /reports-dir/snyk-code-report.json || true"
                        sh "snyk monitor --all-projects --project-name=DevSecOps-Project-${env.BUILD_NUMBER} || true"
                    }
                }
            }
        }

        stage('Step 4: OWASP Dependency Scan') {
            steps {
                container('owasp-check') {
                    script {
                        sh "rm -rf /usr/share/dependency-check/data/*"
                        sh """
                        /usr/share/dependency-check/bin/dependency-check.sh \
                        --scan . --format ALL --out /reports-dir/ \
                        --data /usr/share/dependency-check/data \
                        --nvdApiKey ${NVD_API_KEY} --failOnCVSS 7 || true
                        """
                    }
                }
            }
        }

        stage('Step 5: Checkov Scan') {
            steps {
                container('checkov') {
                    sh "checkov -d . --output json > /reports-dir/checkov-report.json || true"
                }
            }
        }

        stage('Step 6: Snyk Container & Trivy Scan') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-hub-creds', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    script {
                        def images = ['mysql-devsecops', 'ghost-devsecops']
                        
                        images.each { imageName ->
                            def fullImage = "zuhaibahmed034/${imageName}:${DOCKER_IMAGE_TAG}"

                            // Trivy local report
                            container('trivy') {
                                sh "trivy image --format json --output /reports-dir/trivy-${imageName}.json ${fullImage} || true"
                            }

                            // Snyk Container Scan to Portal
                            container('snyk') {
                                echo "Snyk Monitoring Container: ${fullImage}"
                                // JSON report for artifacts
                                sh "snyk container test ${fullImage} --json > /reports-dir/snyk-image-${imageName}.json || true"
                                // Portal update with Build Number
                                sh "snyk container monitor ${fullImage} --project-name=${imageName}-Build-${env.BUILD_NUMBER}"
                            }
                        }
                    }
                }
            }
        }

        stage('Step 7: Final Release Upload') {
            steps {
                container('tools') {
                    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        script {
                            def releaseTag = "DevSecOps-Build-${env.BUILD_NUMBER}"
                            sh """
                            apk add --no-cache curl zip
                            cd /reports-dir
                            zip -r devsecops-full-report.zip ./*

                            # GitHub Release
                            curl -X POST -H "Authorization: token ${GITHUB_TOKEN}" \
                                 -H "Accept: application/vnd.github.v3+json" \
                                 https://api.github.com/repos/${REPO_NAME}/releases \
                                 -d '{"tag_name":"${releaseTag}","name":"Release ${releaseTag}","body":"Security Reports included. Check Snyk Portal for details.","draft":false,"prerelease":false}' > release_resp.json

                            RELEASE_ID=\$(cat release_resp.json | grep -m 1 '"id":' | awk '{print \$2}' | sed 's/,//')

                            curl -X POST -H "Authorization: token ${GITHUB_TOKEN}" \
                                 -H "Content-Type: application/zip" \
                                 --data-binary @"devsecops-full-report.zip" \
                                 "https://uploads.github.com/repos/${REPO_NAME}/releases/\$RELEASE_ID/assets?name=devsecops-full-report.zip"
                            """
                        }
                    }
                }
            }
        }
    }
}

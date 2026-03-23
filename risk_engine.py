import json
import os
import sys


WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
THRESHOLD = 50 

def get_findings(file_path):
    if not os.path.exists(file_path):
        return 0
    
    score = 0
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
            # Logic for Snyk
            if 'snyk' in file_path:
                vulns = data.get('vulnerabilities', [])
                for v in vulns:
                    score += WEIGHTS.get(v.get('severity', '').upper(), 1)
            
            # Logic for Trivy
            elif 'trivy' in file_path:
                results = data.get('Results', [])
                for res in results:
                    for v in res.get('Vulnerabilities', []):
                        score += WEIGHTS.get(v.get('Severity', '').upper(), 1)
            
            # Logic for Checkov/Terrascan (IaC)
            elif 'checkov' in file_path or 'terrascan' in file_path:
                # IaC issues are usually flat high risk
                failed = data.get('results', {}).get('failed_checks', []) or data.get('violations', [])
                score += len(failed) * 5 
                
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    
    return score

def main():
    report_dir = "/reports-dir"
    total_risk = 0
    
    print("--- Security Risk Analysis ---")
    
    for report in os.listdir(report_dir):
        if report.endswith(".json"):
            path = os.path.join(report_dir, report)
            current_score = get_findings(path)
            print(f"File: {report} | Risk Contribution: {current_score}")
            total_risk += current_score

    print("-" * 30)
    print(f"TOTAL RISK SCORE: {total_risk}")
    print(f"THRESHOLD: {THRESHOLD}")
    print("-" * 30)

    if total_risk >= THRESHOLD:
        print("❌ DEPLOYMENT BLOCKED: Security risk is too high!")
        sys.exit(1) # This fails the Jenkins stage
    else:
        print("✅ PASSED: Risk is within acceptable limits.")
        sys.exit(0)

if __name__ == "__main__":
    main()

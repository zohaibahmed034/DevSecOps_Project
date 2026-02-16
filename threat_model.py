from pytm import TM, Server, Datastore, Actor, Boundary, Dataflow

tm = TM("Warfighter Secure Infrastructure")
tm.description = "DevSecOps Platform for Regulated Industries (NIST CSF, SOC2, HIPAA, PCI-DSS)"
tm.is_web_app = True

# Boundaries
internet = Boundary("Public Internet")
k8s_cluster = Boundary("Kubernetes Cluster")

# Elements
user = Actor("End User")
user.in_boundary = internet

web_app = Server("Ghost Web Application")
web_app.in_boundary = k8s_cluster
web_app.is_authenticated = True

db = Datastore("Production MySQL Database")
db.is_encrypted = True
db.stores_pii = True

# Connections
user_to_app = Dataflow(user, web_app, "HTTPS Connection")
app_to_db = Dataflow(web_app, db, "SQL Query")

if __name__ == "__main__":
    # Execute threat analysis
    tm.process()
    
    # Print the report for Jenkins to capture
    print(f"# Threat Model Report: {tm.name}")
    print(f"Description: {tm.description}\n")
    print("## Identified Threats")
    for t in tm.threats:
        print(f"### {t.name}")
        print(f"- **Description:** {t.description}")
        print(f"- **Severity:** {t.severity}")
        print(f"- **Mitigation:** {t.mitigation}\n")

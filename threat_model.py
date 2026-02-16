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

# CORRECT SYNTAX: Using Dataflow class
user_to_app = Dataflow(user, web_app, "HTTPS/TLS 1.3 Connection")
user_to_app.protocol = "HTTPS"
user_to_app.dstPort = 443

app_to_db = Dataflow(web_app, db, "Encrypted SQL Query")
app_to_db.protocol = "SQL"
app_to_db.dstPort = 3306

if __name__ == "__main__":
    tm.process()

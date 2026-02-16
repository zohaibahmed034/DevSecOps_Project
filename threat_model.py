from pytm import TM, Server, Datastore, Actor, Boundary, Classification

# 1. Project Overview with Compliance Context
tm = TM("Warfighter Secure Infrastructure")
tm.description = "Advanced DevSecOps Platform for Regulated Industries (NIST CSF, SOC2, HIPAA, PCI-DSS)"
tm.is_web_app = True

# 2. Boundaries (Logical separation for Compliance)
internet = Boundary("Public Internet")
cloud_vpc = Boundary("AWS/Cloud VPC")
k8s_cluster = Boundary("Kubernetes Cluster (Big Bang Model)")
db_zone = Boundary("Secure Database Zone (Encrypted)")

# 3. Actors & Elements
user = Actor("End User")
user.in_boundary = internet

# Web Server with Security Properties
web_app = Server("Ghost Web Application")
web_app.os = "Hardened Linux (Iron Bank Image)"
web_app.is_authenticated = True
web_app.provides_encryption = True  # Compliance requirement: In-transit (TLS 1.2+)
web_app.in_boundary = k8s_cluster

# Secure Database
db = Datastore("Production MySQL Database")
db.on_cloud = True
db.in_boundary = db_zone
db.is_authenticated = True
db.is_encrypted = True  # Compliance requirement: At-rest (AES-256)
db.stores_pii = True    # HIPAA/PCI-DSS Flag
db.stores_sensitive_data = True

# 4. Data Flows (Mapping Compliance Controls)
# User to App via HTTPS (PCI-DSS/SOC2)
user_to_app = user.connect(web_app, "HTTPS/TLS 1.3 Connection")
user_to_app.protocol = "HTTPS"
user_to_app.is_encrypted = True

# App to DB with Credential Rotation (HashiCorp Vault context)
app_to_db = web_app.connect(db, "Encrypted SQL Query via Vault Secrets")
app_to_db.protocol = "SQL"
app_to_db.is_encrypted = True
app_to_db.is_authenticated = True

# 5. Process Threats
if __name__ == "__main__":
    tm.process()

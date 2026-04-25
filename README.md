# 🔐 Zero Trust Architecture for SMEs in Digital Transformation

## 📌 Introduction
This project implements a **Zero Trust Architecture (ZTA)** model to enhance information security for small and medium-sized enterprises (SMEs) during digital transformation.

Instead of relying on traditional perimeter-based security, the system enforces:
- Continuous authentication
- Fine-grained authorization
- Least privilege access
- Context-aware policy decisions

---

## 🎯 Objectives
- Design and deploy a practical Zero Trust model
- Integrate Identity and Access Management (IAM)
- Apply modern authentication (OIDC, SSO)
- Implement policy-based authorization (RBAC + ABAC)
- Monitor and log security events

---

## 🏗️ System Architecture
User → NGINX → OAuth2 Proxy → Application → Cerbos
↓
Keycloak (IdP)


### 🔹 Components

| Component        | Role |
|----------------|------|
| NGINX          | Reverse proxy, access control (auth_request) |
| OAuth2 Proxy   | Authentication, session management |
| Keycloak       | Identity Provider (OIDC, SSO) |
| Cerbos         | Authorization (policy decision engine) |
| Application    | Business logic, integrates with Cerbos |
| Wazuh + ELK    | Logging, monitoring, security analytics |

---

## 🔑 Key Concepts

### 1. Authentication (AuthN)
- Implemented using OIDC
- Centralized identity via Keycloak
- Supports Single Sign-On (SSO)

### 2. Authorization (AuthZ)
- Managed by Cerbos
- Supports:
  - RBAC (Role-Based Access Control)
  - ABAC (Attribute-Based Access Control)

### 3. Zero Trust Principles
- Never trust, always verify
- Continuous validation of user identity
- Context-aware access decisions
- Least privilege enforcement

---

## ⚙️ Technologies Used

- Docker / Docker Compose
- Keycloak (IAM)
- OAuth2 Proxy
- NGINX
- Cerbos
- Node.js (Demo App)
- Wazuh

---

## 🚀 Getting Started

### 1. Clone repository
```bash
git clone https://github.com/congkhanhneee/Zero_Trust_IAM.git

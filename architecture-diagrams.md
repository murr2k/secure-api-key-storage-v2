# Secure API Key Storage Architecture Diagrams

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "User Interface Layer"
        CLI[CLI Interface]
        API[REST API]
        SDK[Language SDKs]
    end
    
    subgraph "Authentication Layer"
        AUTH[Authentication Service]
        MFA[MFA Provider]
        SESSION[Session Manager]
    end
    
    subgraph "Core Services"
        KM[Key Manager Service]
        CRYPTO[Cryptographic Service]
        AUDIT[Audit Service]
        RBAC[Access Control]
    end
    
    subgraph "Storage Layer"
        LOCAL[Local Encrypted Storage]
        CLOUD[Cloud KMS]
        HSM[Hardware Security Module]
    end
    
    CLI --> AUTH
    API --> AUTH
    SDK --> AUTH
    
    AUTH --> MFA
    AUTH --> SESSION
    
    SESSION --> KM
    KM --> CRYPTO
    KM --> AUDIT
    KM --> RBAC
    
    CRYPTO --> LOCAL
    CRYPTO --> CLOUD
    CRYPTO --> HSM
```

## 2. Encryption Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant Auth
    participant KDF
    participant Crypto
    participant Storage
    
    User->>Auth: Provide Master Password
    Auth->>KDF: Derive Key (Password + Salt)
    KDF->>KDF: PBKDF2 100k iterations
    KDF->>Auth: Master Encryption Key (MEK)
    
    User->>Crypto: Store API Key
    Crypto->>Crypto: Generate IV/Nonce
    Crypto->>Crypto: AES-256-GCM Encrypt
    Crypto->>Storage: Store Encrypted Blob
    
    Note over Storage: Encrypted Data Structure:
    Note over Storage: {ciphertext, iv, tag, aad}
    
    User->>Crypto: Retrieve API Key
    Storage->>Crypto: Return Encrypted Blob
    Crypto->>Crypto: AES-256-GCM Decrypt
    Crypto->>Crypto: Verify Integrity
    Crypto->>User: Return Plaintext Key
```

## 3. Key Hierarchy Diagram

```
                    Master Password (User Input)
                            │
                            ▼
                    ┌───────────────┐
                    │    PBKDF2     │
                    │  (100k iter)  │
                    └───────┬───────┘
                            │
                    Master Key (256-bit)
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Encryption   │   │ Authentication│   │  Integrity   │
│   Key (KEK)  │   │      Key     │   │     Key      │
└──────┬───────┘   └──────────────┘   └──────┬───────┘
       │                                      │
       ▼                                      ▼
┌──────────────┐                      ┌──────────────┐
│  Encrypt API │                      │   Generate   │
│     Keys     │                      │     HMAC     │
└──────────────┘                      └──────────────┘
```

## 4. Storage Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application                          │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 Storage Abstraction Layer               │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Storage   │  │   Storage   │  │   Storage   │    │
│  │   Adapter   │  │   Adapter   │  │   Adapter   │    │
│  │   (Local)   │  │   (Cloud)   │  │    (HSM)    │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
└─────────┼──────────────────┼──────────────────┼────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Local SQLite   │ │   AWS KMS /     │ │  Hardware       │
│   (SQLCipher)   │ │  Azure KeyVault │ │  Security       │
│                 │ │  Google Cloud   │ │  Module         │
│ ~/.config/keys  │ │      KMS        │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## 5. Security Zones and Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     Untrusted Zone                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              User Input / External APIs               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                    ══════════╧═══════════  Trust Boundary
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Semi-Trusted Zone                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Input Validation & Sanitization              │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Authentication Layer                     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                    ══════════╧═══════════  Trust Boundary
                              │
┌─────────────────────────────────────────────────────────────┐
│                      Trusted Zone                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Cryptographic Operations                   │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Secure Key Storage                       │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                Audit Logging                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 6. Data Flow for API Key Operations

### 6.1 Key Storage Flow

```mermaid
graph LR
    A[User] -->|1. Provide API Key| B[Input Validation]
    B -->|2. Validate Format| C{Valid?}
    C -->|No| D[Return Error]
    C -->|Yes| E[Authentication]
    E -->|3. Check Credentials| F[Key Derivation]
    F -->|4. PBKDF2| G[Encryption Service]
    G -->|5. Generate IV| H[AES-256-GCM]
    H -->|6. Encrypt| I[Add Metadata]
    I -->|7. Store| J[(Encrypted Storage)]
    J -->|8. Log Event| K[Audit Log]
    K -->|9. Return Success| A
```

### 6.2 Key Retrieval Flow

```mermaid
graph LR
    A[User] -->|1. Request Key| B[Authentication]
    B -->|2. Verify Identity| C{Authorized?}
    C -->|No| D[Return 403]
    C -->|Yes| E[Rate Limiter]
    E -->|3. Check Limits| F{Within Limit?}
    F -->|No| G[Return 429]
    F -->|Yes| H[Fetch from Storage]
    H -->|4. Get Encrypted| I[(Storage)]
    I -->|5. Return Blob| J[Decryption Service]
    J -->|6. Verify Integrity| K{Valid?}
    K -->|No| L[Alert & Error]
    K -->|Yes| M[Decrypt Key]
    M -->|7. Log Access| N[Audit Log]
    N -->|8. Return Key| A
```

## 7. Component Interaction Diagram

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   CLI Client     │     │   Web Client     │     │   API Client     │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                          │
         └────────────────────────┴──────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    Load Balancer       │
                    └─────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
         ┌──────────────────┐      ┌──────────────────┐
         │  API Server #1   │      │  API Server #2   │
         └──────────────────┘      └──────────────────┘
                    │                         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
         ┌──────────────────┐      ┌──────────────────┐
         │  Redis Cache     │      │  Message Queue   │
         └──────────────────┘      └──────────────────┘
                                              │
                    ┌─────────────────────────┴───┐
                    ▼                             ▼
         ┌──────────────────┐          ┌──────────────────┐
         │  Key Manager     │          │  Audit Service   │
         │    Service       │          │                  │
         └────────┬─────────┘          └────────┬─────────┘
                  │                              │
                  ▼                              ▼
         ┌──────────────────┐          ┌──────────────────┐
         │ Encryption Layer │          │   Audit Database │
         └────────┬─────────┘          └──────────────────┘
                  │
         ┌────────┴────────┬────────────┬───────────┐
         ▼                 ▼            ▼           ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Local Store  │  │   AWS KMS    │  │ Azure Vault  │  │     HSM      │
└──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘
```

## 8. Threat Model Diagram

```mermaid
graph TB
    subgraph "External Threats"
        T1[Network Attacks]
        T2[Brute Force]
        T3[Social Engineering]
        T4[Supply Chain]
    end
    
    subgraph "Internal Threats"
        T5[Insider Threat]
        T6[Misconfiguration]
        T7[Weak Passwords]
    end
    
    subgraph "System Threats"
        T8[Memory Dumps]
        T9[File System Access]
        T10[Process Injection]
    end
    
    subgraph "Mitigations"
        M1[TLS/mTLS]
        M2[Rate Limiting]
        M3[MFA]
        M4[Dependency Scanning]
        M5[RBAC]
        M6[Config Validation]
        M7[Password Policy]
        M8[Memory Protection]
        M9[Encryption at Rest]
        M10[Process Isolation]
    end
    
    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
    T5 --> M5
    T6 --> M6
    T7 --> M7
    T8 --> M8
    T9 --> M9
    T10 --> M10
```

## 9. Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     WAF / DDoS Protection                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer                          │
│                    (TLS Termination)                        │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   App Pod #1    │  │   App Pod #2    │  │   App Pod #3    │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │ Container │  │  │  │ Container │  │  │  │ Container │  │
│  │  (App)    │  │  │  │  (App)    │  │  │  │  (App)    │  │
│  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │  Sidecar  │  │  │  │  Sidecar  │  │  │  │  Sidecar  │  │
│  │  (Proxy)  │  │  │  │  (Proxy)  │  │  │  │  (Proxy)  │  │
│  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
        │                     │                     │
        └─────────────────────┴─────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Internal Network                         │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │   Redis    │  │ PostgreSQL │  │    KMS     │           │
│  │  Cluster   │  │  Cluster   │  │  Service   │           │
│  └────────────┘  └────────────┘  └────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## 10. Key Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Generated: Create New Key
    Generated --> Active: Activate
    Active --> Rotation_Pending: 90 Days
    Rotation_Pending --> Rotated: Create New Version
    Rotated --> Active: Activate New
    Active --> Suspended: Security Event
    Suspended --> Active: Reinstate
    Suspended --> Revoked: Confirm Revoke
    Active --> Revoked: Emergency Revoke
    Revoked --> Deleted: Retention Period
    Deleted --> [*]: Permanent Deletion
    
    note right of Active: Normal operational state
    note right of Suspended: Temporary disable
    note right of Revoked: Permanent disable
    note right of Deleted: Cryptographic erasure
```

These diagrams provide a comprehensive visual representation of the secure API key storage architecture, showing:

1. System components and their relationships
2. Encryption and decryption flows
3. Key hierarchy and derivation
4. Storage architecture options
5. Security zones and trust boundaries
6. Data flows for key operations
7. Component interactions in a distributed system
8. Threat model and mitigations
9. Deployment architecture
10. Key lifecycle management

Each diagram focuses on a specific aspect of the security architecture, making it easier to understand and implement the system correctly.
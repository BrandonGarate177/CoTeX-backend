# CoTeX Backend Prod-Server

**CoTeX Backend** is a production-ready, cloud-native Go service that powers real-time GitHub integration, subscription management, and WebSocket messaging for the [CoTeX desktop app](https://cotex-md.netlify.app).  

This project demonstrates **modern backend engineering at scale**: multi-tenant architecture, event-driven design, secure authentication, Stripe payments, and CI/CD deployment on Google Cloud Run.

---

## Features

- **Real-time GitHub Event Processing**
  - Secure webhook endpoints (HMAC SHA-256/SHA-1 verification)  
  - Event persistence with TTL (~2 weeks)  
  - Instant broadcast to connected clients via WebSockets  

- **Authentication & Authorization**
  - Supabase Auth with JWT validation  
  - Per-user repository subscriptions  

- **SaaS Monetization**
  - Stripe Checkout + Webhooks integration  
  - Subscription tiering (Free vs Pro)  
  - Automated billing + repo limits  

- **Realtime Communication**
  - WebSocket hub with per-user channels  
  - Event queuing for offline users  
  - Graceful register/unregister lifecycle  

- **Security & Operations**
  - JWT verification middleware  
  - Rate limiting (configurable)  
  - CORS allowlist + origin validation  
  - Structured logging + request correlation  
  - Graceful shutdown & health checks  

---

## Tech Stack

| Area         | Choice                           |
| ------------ | -------------------------------- |
| **Language** | Go 1.23+                         |
| **Database** | Supabase (PostgreSQL + Realtime) |
| **Auth**     | Supabase JWT                     |
| **Payments** | Stripe (Checkout + Webhooks)     |
| **Realtime** | Gorilla WebSocket (custom hub)   |
| **Deploy**   | Docker → Google Cloud Run        |
| **Logging**  | Zerolog (structured JSON)        |

---


## Architecture

```text
             ┌───────────────┐
   GitHub →  │ Webhook API   │──┐
             └───────────────┘  │
                                ▼
                          ┌───────────────┐
   Stripe →  ───────────▶ │ Stripe API    │
                          └───────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Event Store   │ (Supabase/Postgres, TTL 2w)
                       └─────────────────┘
                                │
                                ▼
                        ┌─────────────┐
   Clients ⇄ WebSocket ⇄│ Hub Manager │ ⇄ JWT Auth (Supabase)
                        └─────────────┘

```

---

## REST API

### Public
| Method | Path                             | Description                         |
| ------ | -------------------------------- | ----------------------------------- |
| POST   | `/api/webhooks/github/{repo_id}` | GitHub webhook receiver (HMAC)      |
| POST   | `/webhooks/stripe`               | Stripe webhook receiver (signature) |

### Authenticated
| Method   | Path                                     | Description                          |
| -------- | ---------------------------------------- | ------------------------------------ |
| GET      | `/ws`                                    | WebSocket upgrade endpoint           |
| GET/POST | `/api/repos`                             | List / create tracked repos          |
| GET      | `/api/github-events`                     | Paginated GitHub event history       |
| GET      | `/api/github-events/recent`              | Recent event IDs for polling         |
| GET      | `/api/github-events/event?id={event_id}` | Fetch specific event                 |
| POST     | `/api/checkout`                          | Create Stripe Checkout session       |

> Auth: Bearer token (Supabase JWT) required for all authenticated routes.

---

## Deployment

- Multi-stage Docker build (Alpine base)  
- CI/CD via Google Cloud Build  
- Deployed to **Google Cloud Run** with autoscaling  
- Integrated structured logging + graceful shutdown  

---
## License & Support

All packaged builds are © 2025 Brandon Garate.  
Distributed binaries are for personal/team use only.  
For issues, requests, or contributions: [CoTeX Contact](https://cotex-md.netlify.app/contact)




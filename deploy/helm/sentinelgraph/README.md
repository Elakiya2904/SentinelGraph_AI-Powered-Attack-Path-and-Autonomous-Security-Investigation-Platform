# SentinelGraph Helm deployment

This chart deploys the SentinelGraph FastAPI backend and React/Nginx frontend. It does not deploy the attacker by default. Keep attack exercises in a dedicated lab namespace with explicit network policy.

## Build images

From the repository root:

```bash
docker build -t REGISTRY/sentinelgraph-backend:0.1.0 -f Dockerfile .
docker build -t REGISTRY/sentinelgraph-frontend:0.1.0 -f frontend/Dockerfile .
docker push REGISTRY/sentinelgraph-backend:0.1.0
docker push REGISTRY/sentinelgraph-frontend:0.1.0
```

## Lint and install

```bash
helm lint deploy/helm/sentinelgraph
helm upgrade --install sentinelgraph deploy/helm/sentinelgraph \
  --namespace sentinelgraph --create-namespace \
  --set backend.image.repository=REGISTRY/sentinelgraph-backend \
  --set frontend.image.repository=REGISTRY/sentinelgraph-frontend
```

## Verify health

```bash
kubectl -n sentinelgraph get deploy,svc,pods
kubectl -n sentinelgraph rollout status deployment/sentinelgraph-backend
kubectl -n sentinelgraph rollout status deployment/sentinelgraph-frontend
kubectl -n sentinelgraph port-forward svc/sentinelgraph-frontend 8080:8080
curl http://127.0.0.1:8080/
```

The backend has HTTP readiness/liveness probes on `/health`; the frontend probes `/`. Configure an Ingress with `--set ingress.enabled=true` and an appropriate ingress class for a shared cluster.

## Security notes

- The chart uses non-root, `RuntimeDefault` seccomp, dropped capabilities, and read-only root filesystems.
- The frontend image runs as UID/GID 101 (`nginx`) and mounts `emptyDir` volumes at `/tmp` and `/var/cache/nginx` for PID, proxy-temp, and cache writes.
- The frontend Deployment applies `fsGroup: 101` so the mounted runtime paths are writable without granting the Nginx process root privileges.
- The backend Service is ClusterIP; expose it only through the frontend proxy or an explicitly controlled detector path.
- Use a NetworkPolicy to restrict backend ingress and egress before production deployment.
- Use a dedicated lab namespace and a separate short-lived attacker Job for the safe local scenario.
- Image tags are configurable; pin immutable digests for production.

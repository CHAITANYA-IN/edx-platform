LMS debug helper

This override runs the real Tutor `lms` service under `debugpy` while keeping
the Docker service name `lms` intact, so MFEs can still resolve
`http://lms:8000/...`.

Use it with the generated Tutor compose files, for example:

```bash
docker compose \
  -f /home/chaitanya/.local/share/tutor/env/local/docker-compose.yml \
  -f /home/chaitanya/.local/share/tutor/env/dev/docker-compose.yml \
  -f /home/chaitanya/Desktop/openedx-dev/edx-platform/tools/debug/lms-debug.override.yml \
  --project-name tutor_dev \
  up -d --force-recreate lms
```

Then attach from VS Code to `localhost:5678`.

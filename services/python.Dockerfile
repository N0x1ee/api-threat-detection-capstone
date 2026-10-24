# One image for every Python service (fast filter, agents, XAI/dashboard API, demo API).
# Build context is C:\capstone so it can copy the shared code in api-threat-detection/.
FROM python:3.12-slim
WORKDIR /srv
COPY api-threat-detection/requirements.txt /tmp/req.txt
COPY services/requirements.txt /tmp/req-services.txt
RUN pip install --no-cache-dir -r /tmp/req.txt -r /tmp/req-services.txt
COPY api-threat-detection/app ./api-threat-detection/app
COPY api-threat-detection/rules ./api-threat-detection/rules
COPY api-threat-detection/demo_api ./api-threat-detection/demo_api
COPY api-threat-detection/config.json ./api-threat-detection/config.json
COPY services/common ./services/common
COPY services/fastfilter ./services/fastfilter
COPY services/agents ./services/agents
COPY services/xai ./services/xai
# train the baseline models once at build time so every agent container starts with the same files
RUN cd api-threat-detection && python -m app.training
ENV APP_ROOT=/srv/api-threat-detection CONFIG=/srv/api-threat-detection/config.json PYTHONUNBUFFERED=1
WORKDIR /srv/services

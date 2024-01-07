# Prometheus exporter for the FiberHome HG6145F GPON Fiber Routers

This is a simple prometheus exporter for the FiberHome HG6145F GPON home router. The exporter uses the webui credentials to access the router json API's and get the required data.

The exporter should work with the HG6145F devices, possibiliy some other models by Fiberhome that uses the same UI.

It has been tested against my own FiberHome HG6145F, running from within a Docker container and connected to Prometheus for data collection. Data visualization has been done with Grafana.

## Build

To use and build this exporter, you need to first clone this reposiroty and create a docker image from the sources

### Clone the main branch:
```
git clone https://github.com/mcbyte-it/fiberhome_exporter.git
```

### Build a docker
```
cd fiberhome_exporter
docker build -t fiberhome_exporter:latest .
```

## Run in docker

To run this image I used a docker-compose file.

**Be sure to set the environmental variables as in the compose file below**

```
version: "3"

services:
  fiberhome_exporter:
    image: mcbyteit/fiberhome_exporter:latest
    environment:
      HOSTNAME: 'http://192.168.1.1'
      USERNAME: 'admin'
      PASSWORD: 'admin1234'
    ports:
      - 6145:6145
    restart: unless-stopped
```

In prometheus.yml file, add the following section to allow data scraping from this exporter:
```  - job_name: 'fiberhome-exporter'
    scrape_interval: 15s
    static_configs:
      - targets: ['fiberhome_exporter:6145']
```
# Prometheus exporter for the FiberHome HG6145F GPON Fiber Routers

This is a simple prometheus exporter for the FiberHome HG6145F GPON home router. The exporter uses the webui credentials to access the router json API's and get the required data.

The exporter should work with the HG6145F devices, possibiliy some other models by Fiberhome that uses the same UI.

It has been tested against my own FiberHome HG6145F, running from within a Docker container and connected to Prometheus for data collection. Data visualization has been done with Grafana.

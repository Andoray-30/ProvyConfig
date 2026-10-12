# Source deployment maintenance

- Entry point is app/portable.py, not app/app.py's original host-specific CLI.
- The eight core modules retain the accepted selection/routing snapshot; the adapter owns domain/path/port/source-fetch portability. Do not change qualification or recovery criteria just to increase published counts.
- Git contains only source, synthetic tests, templates and documentation. Do not stage config.yaml, data, certs, runtime, secrets, compiled kernels/rules, original subscriptions, private keys or cloud diagnostic archives.
- Destination credentials and health records must be generated locally; never copy cloud runtime to the home instance.
- HTTPS/WebRTC/campus policy and HY2 residential-source restriction must remain. No insecure TLS, public controllers, cross-country fallback, host proxy inheritance or forced healthy marks.
- Deployment does not authorize changes to DNS, firewalls, routers, existing services or a second instance on occupied ports.

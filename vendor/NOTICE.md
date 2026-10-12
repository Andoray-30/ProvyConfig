# Dependencies

This source repository does not distribute compiled Mihomo, container images, upstream node credentials, or compiled rule databases.

Mihomo v1.19.30 (GPLv3) is obtained directly from its official release by tools/fetch_engine.py; both the published gzip hash and the accepted executable hash are pinned in ENGINE.json. License: MIHOMO-LICENSE.txt. Source: https://github.com/MetaCubeX/mihomo/tree/v1.19.30 . Release hashes: https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.30 .

MetaCubeX rule sources and Google prefix sources are defined in app/rule_update.py. Rule license: META-RULES-LICENSE.txt. Complete compiled bundles are downloaded, derived and validated on the destination, and are never checked into Git.

Docker uses Python 3.11/Debian bookworm, PyYAML 6.0.3 (MIT), curl/openssl/CA certificates, and official caddy:2.10.2 (Apache-2.0). Upstream notices remain with their respective distributions. No claim is made that a new destination's DNS, network path or provider has been accepted by cloud-side tests.

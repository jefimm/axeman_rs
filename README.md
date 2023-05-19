
Rust implementation of the https://github.com/CaliDog/Axeman

Attempted to keep close to the origin with some modifications of behavior:
- chain hash is not computed
- only single log downloaded at a time
- list output just proxies https://www.gstatic.com/ct/log_list/v3/log_list.json
- a subdirectory is created for every 1M certs

Additional features:
- filter certificates according to the Subject_Name::CN/Alt names suffix
- save the index of the last retrieved certificate to file (log size at the time of invocation)

Note: this is my Rust learning project

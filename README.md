# KubeStalk
KubeStalk is a tool to discover Kubernetes and related infrastructure based attack surface from a black-box perspective. This tool is a community version of the tool used to probe for unsecured Kubernetes clusters around the internet during [Project Resonance - Wave 9](https://redhuntlabs.com/blog/thousands-of-unsecured-kubernetes-clusters-exposed.html).

## Usage
The GIF below demonstrates usage of the tool:

![tooldemo](https://user-images.githubusercontent.com/39941993/195374856-eb13c002-a619-425c-a819-cb90fff9af70.gif)

### Installation
KubeStalk is written in Python and requires the `requests` library.

To install the tool, you can clone the repository to any directory:
```
git clone https://github.com/redhuntlabs/kubestalk
```
Once cloned, you need to install the `requests` library using `python3 -m pip install requests` or:
```
python3 -m pip install -r requirements.txt
```
Everything is setup and you can use the tool directly.

### Command-line Arguments
A list of command line arguments supported by the tool can be displayed using the `-h` flag.
```s
$ python3 kubestalk.py  -h

    +---------------------+
    |  K U B E S T A L K  |
    +---------------------+   v0.1

[!] HTTPLoot by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[!] Author: 0xInfection (RHL Research Team)
[!] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.

usage: ./kubestalk.py <url(s)>/<cidr>

Required Arguments:
  urls                  List of hosts to scan

Optional Arguments:
  -o OUTPUT, --output OUTPUT
                        Output path to write the CSV file to
  -f SIG_FILE, --sig-dir SIG_FILE
                        Signature directory path to load
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP timeout value in seconds
  -ua USER_AGENT, --user-agent USER_AGENT
                        User agent header to set in HTTP requests
  --concurrency CONCURRENCY
                        No. of hosts to process simultaneously
  --verify-ssl          Verify SSL certificates
  --version             Display the version of KubeStalk and exit.
```

#### Basic Usage
To use the tool, you can pass one or more hosts to the script. All targets passed to the tool must be [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986) complaint, i.e. must contain a scheme and hostname (and port if required).

A basic usage is as below:
```
$ python3 kubestalk.py https://███.██.██.███:10250

    +---------------------+
    |  K U B E S T A L K  |
    +---------------------+   v0.1

[!] HTTPLoot by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[!] Author: 0xInfection (RHL Research Team)
[!] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.

[+] Loaded 10 signatures to scan.
[*] Processing host: https://███.██.██.██:10250
[!] Found potential issue on https://███.██.██.██:10250: Kubernetes Pod List Exposure
[*] Writing results to output file.
[+] Done.
```

#### HTTP Tuning
HTTP requests can be fine-tuned using the `-t` (to mention HTTP timeouts), `-ua` (to specify custom user agents) and the `--verify-ssl` (to validate SSL certificates while making requests).

#### Concurrency
You can control the number of hosts to scan simultanously using the `--concurrency` flag. The default value is set to 5.

#### Output
The output is written to a CSV filea and can be controlled by the `--output` flag.

A sample of the CSV output rendered in markdown is as belows:

|host                       |path |issue                       |type          |severity                      |
|---------------------------|-----|----------------------------|--------------|------------------------------|
|`https://█.█.█.█:10250`|/pods|Kubernetes Pod List Exposure|core-component|vulnerability/misconfiguration|
|`https://█.█.█.█:443` |/api/v1/pods|Kubernetes Pod List Exposure|core-component|vulnerability/misconfiguration|
|`http://█.█.██.█:80`|/|etcd Viewer Dashboard Exposure|add-on|vulnerability/exposure|
|`http://██.██.█.█:80`|/|cAdvisor Metrics Web UI Dashboard Exposure|add-on|vulnerability/exposure|

## Version & License
The tool is licensed under the [BSD 3 Clause License](LICENSE) and is currently at v0.1.

*[`To know more about our Attack Surface Management platform, check out NVADR.`](https://redhuntlabs.com/nvadr)*

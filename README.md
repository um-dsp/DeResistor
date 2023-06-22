# DeResistor
DeResistor is a research project that provides a system extension to protect Probing for Evasion of Internet Censorship from detection. Specifically, DeResistor offers IP address protection for internet users that are running automated tools for censorship measurments and evasion (e.g. Geneva)

In this repo, we provide an instance of DeResistor implemented on top of Geneva ([Code](https://github.com/Kkevsterrr/geneva), [Docs](https://geneva.readthedocs.io/en/latest/)). DeResistor leverages Machine Learning techniques to model a censor-side flow-level detector and use it to guide Geneva genitic evolution towards more detection-resilient evasion strategies. Additionnaly, DeResistor introduces guided-pauses of censorship evasion attempts and interleaving them with normal user-driven network activity to comfuse IP-level detection.

## Setup

DeResistor has been developed and tested on Ubuntu. However, it should support Centos or Debian-based systems. Similar to Geneva, due to limitations of netfilter and raw sockets, this code does not work on OS X or Windows at this time and requires **python3.6**. 

Install netfilterqueue dependencies:
```
sudo apt-get install build-essential python-dev libnetfilter-queue-dev libffi-dev libssl-dev iptables python3-pip
```

Create a new python3.6 environment and install Python dependencies:
```
sudo /path/to/python_environment/bin/python -m pip install -r requirements.txt
```

**If needed** for Debian 10 systems, you can install netfilterqueue directly from Github:
```
sudo /path/to/python_environment/bin/python -m pip install --upgrade -U git+https://github.com/kti/python-netfilterqueue
```

**If needed**, on Arch systems, you can make liblibc.a available for netfilterqueue:
```
sudo ln -s -f /usr/lib64/libc.a /usr/lib64/liblibc.a 
```

## Running on Docker
After you make sure you install and run docker on your system use the dockerfile provided in `/docker` to build the base image:

```
sudo docker build -t base:latest -f docker/Dockerfile .
```

Optionally, to manually run/inspect the docker image to explore the image, run:
```
sudo docker run -it base
```
You can run DeResistor against the 11  mock censors `censor1,..,censor11` defined in `/censors` using:
```
sudo /path/to/python_environment/bin/python evolve.py --censor censor3 --server forbidden.org --log debug --workers 1 --runs 1 --population 100 --generation 5 --jump 1
```
* You can increase `--population` and `--generation` to reach fitter startegies
* You can increase the jump size `--jump`
* To include real-time IP-level detection of DeResitor, use `--real-time-detection`
* To specify DeResistor's local detection model for detection-resilience training, use `--local-model [model-name]`. The model should be stored in `/ML detectors` using `joblib`
* To specify the Censor's detection model for censor-side detection evaluation, use `--censor-model [model-name]`. The model should be stored in `/ML detectors` using `joblib`

Before every run make sure the docker containers are not still running: `sudo docker kill $(sudo docker ps -q)`

## Running Against Real-world censors
DeResistor is tested in China (GFW), India and Kazakhstan

Example: In China against GFW
```
sudo /path/to/python_environment/bin/python evolve.py --external-server --server www.hrw.org --test-type http --log debug --workers 1 --runs 1 --population 100 --generation 5 --real-time-detection --jump 1 --local-model rfc_gfw.joblib --censor-model rfc_gfw2.joblib
```
- You can change the censored server `--server` according to the country you are running the command from.
- More ML detectors for India and Kazakhstan are provided in `/ML detectors`
You need to flush the iptables after every run to avoid related errors: `sudo iptables -F`

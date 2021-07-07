# It Was All A Dream

A [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) (a.k.a [PrintNightmare](https://github.com/afwu/PrintNightmare)) Python Scanner. Allows you to scan entire subnets for the PrintNightmare RCE (**not the LPE**) and generates a CSV report with the results. Tests exploitability over [MS-PAR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/695e3f9a-f83f-479a-82d9-ba260497c2d0) and [MS-RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1).

This tool has "de-fanged" versions of the [Python exploits](https://github.com/cube0x0/CVE-2021-1675), it does *not* actually exploit the hosts however it does use the same vulnerable RPC calls used during exploitation to determine if hosts are vulnerable.

**Update July 7th 2021: This also checks if host(s) are vulnerable using the [UNC bypass](https://twitter.com/gentilkiwi/status/1412771368534528001) discovered by [@gentilkiwi](https://twitter.com/gentilkiwi)**

# Why?

POV, trying to determine if something is vulnerable to PrintNightmare:

![cons](https://user-images.githubusercontent.com/5151193/124521349-0d278180-dda4-11eb-9643-4facd4b1c3fe.jpg)


At the time of writing, the amount of variables [that determine if a machine is vulnerable](https://twitter.com/StanHacked/status/1410922404252168196?s=20) is crazy and confusing.

# Alternatives

- [Pingcastle](https://www.pingcastle.com/) (C#)

# Installation


~~This tool currently needs [cube0x0](https://github.com/cube0x0)'s Impacket fork containing the MS-PAR implementation necessary for one of the checks. This change has been submitted to Impacket in [this pull request](https://github.com/SecureAuthCorp/impacket/pull/1114).~~

You need to install [Impacket](https://github.com/SecureAuthCorp/impacket) from git as it has the MS-PAR implementation necessary for one of the checks. (Both of the installation methods below do this automatically for you)

Docker:
```
git clone https://github.com/byt3bl33d3r/ItWasAllADream
cd ItWasAllADream && docker build -t itwasalladream .
docker run -it itwasalladream -u user -p password -d domain 192.168.1.0/24
```

Dev install requires [Poetry](https://python-poetry.org/):
```
git clone https://github.com/byt3bl33d3r/ItWasAllADream
cd ItWasAllADream && poetry install && poetry shell
itwasalladream -u user -p password -d domain 192.168.1.0/24
```

# Usage

```
usage: itwasalladream [-h] -u USERNAME [-p PASSWORD] -d DOMAIN [--timeout TIMEOUT] [--threads THREADS] [-v] [--csv-column CSV_COLUMN] target

PrintNightmare (CVE-2021-34527) scanner

positional arguments:
  target                Target subnet in CIDR notation, CSV file or newline-delimited text file

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        username to authenticate as (default: None)
  -p PASSWORD, --password PASSWORD
                        password to authenticate as. If not specified will prompt. (default: None)
  -d DOMAIN, --domain DOMAIN
                        domain to authenticate as (default: None)
  --timeout TIMEOUT     Connection timeout in secods (default: 30)
  --threads THREADS     Max concurrent threads (default: 100)
  -v, --verbose         Enable verbose output (default: False)
  --csv-column CSV_COLUMN
                        If target argument is a CSV file, this argument specifies which column to parse (default: DNSHostName)

I used to read Word Up magazine!
```

As the exploit requires you to be authenticated to Active Directory, you need to supply credentials. If the password isn't supplied it will prompt you to enter it.

By default it will use 100 threads, you can increase/decrease these using the `-t` argument.

After its done you'll see a `report_<timestamp>.csv` file in your current directory with the results.


# Credits

- [cube0x0](https://github.com/cube0x0) for implementing the MS-PAR & MS-RPRN protocols in [Impacket](https://github.com/SecureAuthCorp/impacket) and creating the PrintNightmare [Python Exploits](https://github.com/cube0x0/CVE-2021-1675)
- [Zhiniang Peng](https://twitter.com/edwardzpeng) & [Xuefeng Li](https://twitter.com/lxf02942370) for the discovery of the PrintNightmare exploit.
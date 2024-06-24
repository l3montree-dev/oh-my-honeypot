# Oh my Honeypot

## Description

Oh My Honeypot is an advanced honeypot solution, meticulously crafted in Golang for medium interaction simulations. Its design prioritizes simplicity and ease of deployment, making it an ideal choice for security enthusiasts and researchers. While it's currently in the development phase and not recommended for production environments, its potential for future applications is significant. With capabilities such as versatile port accessibility, login attempt capture, HTTP request monitoring, configurable vulnerabilities, persistent storage, and real-time attack data endpoints, Oh My Honeypot stands out as a robust tool for studying and understanding various attack vectors.

## Features

### 1. Versatile Port Accessibility: Capable of opening any UDP and TCP port, providing flexibility for network simulation and monitoring.

**List of opened ports**
| Port number | Service                 | Protocol |
| ----------- | ----------------------- | -------- |
| 21          | FTP                     | TCP      |
| 23          | Telnet                  | TCP      |
| 25          | SMTP                    | TCP      |
| 53          | DNS                     | TCP      |
| 67          | DHCP                    | UDP      |
| 68          | DHCP                    | UDP      |
| 88          | Kerberos                | TCP      |
| 110         | POP3                    | TCP      |
| 123         | NTP                     | TCP      |
| 143         | IMAP                    | TCP      |
| 389         | LDAP                    | TCP      |
| 465         | SMTPS                   | TCP      |
| 514         | Syslog                  | TCP      |
| 546         | DHCPv6 Client           | TCP      |
| 547         | DHCPv6 Server           | TCP      |
| 636         | LDAPS                   | TCP      |
| 989         | FTPS                    | TCP      |
| 990         | FTPS                    | TCP      |
| 993         | IMAPS                   | TCP      |
| 995         | POP3S                   | TCP      |
| 2379        | ETCD                    | TCP      |
| 2380        | ETCD                    | TCP      |
| 3306        | MySQL                   | TCP      |
| 6443        | kubernetes api          | TCP      |
| 8001        | kubernetes dashboard    | TCP      |
| 10250       | kubelet                 | TCP      |
| 10251       | kube-scheduler          | TCP      |
| 10252       | kube-controller-manager | TCP      |
| 10255       | kube-proxy              | TCP      |

### 2. Login Attempt Capture
1. **SSH Honeypot**: Includes a fake SSH login feature that records usernames and passwords, ideal for understanding potential attack vectors.
``` bash
ssh localhost -p22
```
2. **PostgreSQL Honeypot**: Includes a fake PostgreSQL DB login feature that records usernames and passwords, ideal for understanding potential attack vectors. 
- Note: SSH authentication is not implemented; set `sslmode=disable`.
``` bash
psql -h localhost -p 5432 -U admin -V 'sslmode=disable'
```

### 3. HTTP Request capture
1. **HTTP Honeypot**: Monitors the user agent, language preferences, and path in the HTTP request header.
2. **Spam Bot Honeypot**: A hidden contact form is implemented on the `/contact-us/` path. This form can only be filled out by bots, as it is not visible to humans. The email, name, and content can be recorded.

### 4. Vulnerable version configuration
- Some vulnerabilities can be configured in the honeypots using the `vuln-config.yaml` file. Currently, only the SSH version and HTTP response headers can be configured to return vulnerable versions to attract attackers. 

### 5. Persistent Storage in DB
1. **Storage of Basic Attack Data:** A base table named `attack_log` is created to store essential attack information, including attack ID, event time, port number, IP address, country, and attack type. The attack ID serves as a foreign key to link to other tables.
2. **Storage of Login Attempt Data:** A separate table named `login_attempt` is created to record login attempts for SSH and PostgreSQL services. This table includes the attack ID, service name (SSH or PostgreSQL), and the usernames and passwords used by the attacker.
3. **Storage of HTTP Request Headers:** A table named `http_request` is generated to capture HTTP requests. This table stores the attack ID, HTTP request method, and User-Agent. If an attacker sends an HTTP request via PUT or POST, the request body is saved in the Payload folder, with a maximum size of 100 MB. The associated HTTP body table contains the columns Content-Type and "Payload size". If the request is sent via a hidden contact form, the attacker's email address and name are stored in the `http_spam` table.

### 6. HTTP Endpoints

Provides attack events details and statistics via HTTP endpoints on port `1112`.

| Path                    | Description                                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------------------- |
| `/realtime`               | Provides real-time data on ongoing attacks and activities being recorded using Server-Side Events (SSE). |
| `/latest-attacks`         | Provides latest attacks of each honeypot                                                                 |
| `/stats/count-in-24hours` | Provides the number of attacks in the last 24 hours measured per hour                                    |
| `/stats/count-in-7days`   | Provides the number of attacks in the last 7 days measured per day                                       |
| `/stats/count-in-6months` | Provides the number of attacks in the last 6 months measured per month                                   |
| `/stats/country`          | Provides statistics on the number of attacks originating from different countries.                       |
| `/stats/ip`               | Provides statistics on the number of attacks originating from different IP addresses.                    |
| `/stats/username`         | Provides statistics on the usernames used in login attempts.                                             |
| `/stats/password`         | Provides statistics on the passwords used in login attempts.                                             |
| `/stats/port`             | Provides statistics on the number of attacks per port.                                                   |
| `/stats/path`             | Provides statistics on the HTTP paths accessed during attacks.                                           |

## Installation

### Prerequisites


1. Clone the repository
```bash
git clone https://github.com/l3montree-dev/oh-my-honeypot.git
```
2. Install Go, Docker & Docker-Compose
3. Install PostgreSQL in Docker
4. Copy the `.env.example` file to `.env` and adjust the access info to postgresql and set the honeypot name.

```bash
cp .env.example .env
```

5. You can run the honeypot by executing the following command:
```bash
go run main.go
```

6. There is even a Makefile included in the project, so you can simply run:
```bash
make
```

This starts the honeypot.

## Configuration

### Vulnerability on honeypot

Vulnerabilities of HTTP Honeypot and SSH can be configured as follows:
```yaml
http:
    headers:
        Server: "Apache/2.2.3 (Ubuntu)"
        X-Powered-By: "PHP/4.1.0"
ssh:
    ServerVersion: "SSH-2.0-OpenSSH_5.8p2"
```

### DB-IP

The honeypot uses the [DB-IP](https://db-ip.com/) service to determine the geolocation of the IP addresses that interact with it. The db-ip lite database is included in the project and needs to be updated regularly. The link to download the latest version can be found [here](https://db-ip.com/db/download/ip-to-country-lite). The file needs to be extracted and placed in the `root` folder. The file name should be `dbip-country.csv`.
<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>

## Credits

This project is based on the [Neuland@Homeland GmbH 'Oh-my-honeypot'](https://gitlab.com/neuland-at-homeland/oh-my-honeypot).

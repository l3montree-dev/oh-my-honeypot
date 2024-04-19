# Oh my Honeypot

## Description

Oh My Honeypot is an innovative honeypot solution, meticulously crafted in Golang for low-to-medium interaction simulations. Its design prioritizes simplicity and ease of deployment, making it an ideal choice for security enthusiasts and researchers. While it's currently in the development phase and not recommended for production environments, its potential for future applications is significant.

## Features

1. Versatile Port Accessibility: Capable of opening any UDP and TCP port, providing flexibility for network simulation and monitoring.
2. SSH Interaction Simulation: Includes a fake SSH login feature that records usernames and passwords, ideal for understanding potential attack vectors.
3. Socket.io Transport Support: Facilitates real-time event-based communication, enhancing interaction capabilities.
4. HTTP Endpoint Provision: Offers an HTTP endpoint, broadening the scope of network interactions and data collection.
5. User and Password Capture: Specifically designed to log attempted access credentials, offering insights into unauthorized access attempts (SSH).

## Installation

### Prerequisites

Before installing Oh My Honeypot, ensure that you have Golang installed on your system. This is essential as the honeypot is developed in Go and requires the Go runtime and compiler for building and running the application.

Detailed instructions for installing Golang can be found [here](https://go.dev/doc/install).

### Running the Honeypot

Once you have Golang installed, you can run the honeypot by executing the following command:

```bash
go run main.go
```

There is even a Makefile included in the project, so you can simply run:

```bash
make
```

This starts the honeypot.

## Configuration

### DB-IP

The honeypot uses the [DB-IP](https://db-ip.com/) service to determine the geolocation of the IP addresses that interact with it. The db-ip lite database is included in the project and needs to be updated regularly. The link to download the latest version can be found [here](https://download.db-ip.com/free/dbip-country-lite-2024-01.csv.gz). The file needs to be extracted and placed in the `root` folder. The file name should be `dbip-country.csv`.

<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>

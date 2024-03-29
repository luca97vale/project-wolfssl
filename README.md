# Project-wolfssl
In this repo you can find an iterative and a threaded wolfSSL chat, a TCP chat and a openSSL or wolfSSL send file program.

# WolfSSL chat
In this project, to create executable file you have to install wolfSSL and ncurses

wolfssl: https://github.com/wolfSSL/wolfssl.git

ncurses: 
```bash 
sudo apt-get install libncurses5-dev libncursesw5-dev
```
## Iterative program (WolfSSL Chat)
location: ./code/wolfSSL/iterative
It is an iterative chat between a client and a server.

### Installation
```bash
make
```
### Execution
Server:
```bash
./server-tls
```
Client:
```bash
./client-tls <IPv4 address>
```


## Threaded program
location: ./code/wolfSSL
It is a threaded chat with ncurses.

### Installation
```bash
make
```
### Execution
Server:
```bash
./server-tls-threaded
```
Client:
```bash
./client-tls <IPv4 address>
```

## TCP chat
location: /code/tcp/
Also TCP program uses ncurses.
### Installation
```bash
make
```
### Execution
Server:
```bash
./server-tcp-threaded
```
Client:
```bash
./client-tcp <IPv4 address>
```

## OpenSSL send file
location: /code/sendFile/openSSL
There is a sender and a receiver; sender reads a file and sends its contents to the receiver using openSSL.
### Installation
```bash
make
```
### Execution
Server:
```bash
./receive_file
```
Client:
```bash
./send_file /path/to/file <IPv4 address>
```
## WolfSSL send file
location: /code/sendFile/openSSL
There is a sender and a receiver; sender reads a file and sends its contents to the receiver using wolfSSL.
### Installation
```bash
make
```
### Execution
Server:
```bash
./receive_file
```
Client:
```bash
./send_file /path/to/file  <IPv4 address>
```


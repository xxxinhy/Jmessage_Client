# Jmessage_Client
Jmessage client Assignment for Practical Cryptographic Systems, JHU CS 445.

To run Jmessage client:
```
python3.10 jmessage_server.py
go run jmessage_client.go --reg --username alice --password abc
```

To attack Jmessage client:
```
python3.10 jmessage_server.py
go run jmessage_client.go --reg --username cindy  --password 123
go run jmessage_client.go --reg --username alice  --password 123 --headless
go run jmessage_client.go -attack leaked_ciphertext.txt -victim alice
```
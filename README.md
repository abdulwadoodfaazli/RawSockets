# CS4700/5700 – Network Fundamentals

## Project 4: Raw Sockets
<br>

### Team Members:
- Name: Abdulwadood Ashraf Faazli <br> NUID: 002601201

- Name: Divtej Bhatia <br> NUID: 002601227


<br>

  ### Instructions on Running the Code:
    This project is implemented using Python programming language
    To run the program you need to change file permissions using:
      make
    Then run the program using:
      ./rawhttpget URL


<br>

  ### High-Level Approach: 
  A general approach is to divide the process into three layers: the Application layer, Transportation layer, and Network layer, which follows the Open Systems Interconnection Model. In the Application layer, the URL argument provided by the user is obtained from the command line and parsed to extract the path and destination filename. Sending and receiving sockets are created using the client's source IP address and the server's destination IP address.
  

<br>

  ### TCP/IP :
    Features of IP packets:

  Validation of incoming packet checksums
  Proper setting of the version, header length, total length, protocol identifier, and checksum for each outgoing packet
  Correct assignment of the source and destination IP addresses for each outgoing packet
  
  Features of TCP packets:

  Verification of incoming TCP packet checksums
  Generation of correct checksums for outgoing packets
  Selection of a valid local port for traffic transmission
  Execution of the three-way handshake
  Proper handling of connection teardown
  Accurate management of sequence and acknowledgement numbers
  Maintenance of the advertised window
  Basic implementation of timeout functionality
  Restoration of out-of-order incoming packets to their correct order
  Identification and discarding of duplicate packets
  Implementation of a basic congestion window

<br> 

  ### Challenges Faced:

1. Implementing the three-way handshake for TCP packets and ensuring that the correct SEQ and ACK numbers were maintained throughout the connection was a complex task that required careful attention to detail.

2. Debugging the code and identifying errors was a time-consuming process that required a lot of patience and perseverance.Testing the code with Wireshark was challenging because it required a deep understanding of the networking protocols and the ability to analyze packet captures effectively.
  
3. Setting up the development environment on Ubuntu Linux VM was a significant challenge, and required a lot of effort to get everything up and running properly.



<br> 

  ### Work Division:

  Both of us worked on implementing TCP headers and handling packing/unpacking, validating checksum, and receiving ack packets. 

  Divtej focused on implementing IP headers and managing packing/unpacking, as well as coordinating the overall program execution. 

  Abdulwadood was responsible for developing the handshake and send packet function, HTTP functions, setting up the virtual environment for the team.

  Most work was done together since tasks were inter-related
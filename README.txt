Name:				Kevin Dial
Student number:		998273981
CDF account:		g3kevind
Date:				Monday October 20, 2014
Due date:			Friday October 17, 2014

I used my 24 hour grace day. As well as I submitted the assignment 2 days late.
This accumulates to a 20% reducution in grade.

I apologize for handing in my assingment uncompleted. I have implemented the following features:
	- handled receiving an ICMP echo request
	- handled receiving an ARP request

Features I have not implemented:
	- ARP reply
	- ARP cache
	- ICMP unreachable reply
	- IP forwarding
	- IP fragmentation

I have been using the program "WireShark" to view my progress by saving a log when a client pings one of the router's interface.
Here are some observations I can tell from the log dumps:
	- The router is correctly sending out ICMP echo request
	- The router is correctly sending out ICMP echo reply
	- The router does not broadcast its ARP request, instead the request is sent to the nearest interface (incorrect)
	- The packets being sent are out of order:
		- Echo request
		- Echo reply (should be ARP request)
		- ARP request (should be ARP reply)
		- Echo reply (should be echo reply)

I am not sure if this assignment is even worth submitting, but I spent many sleepless hours on this, so I thought 'Why not?' :)
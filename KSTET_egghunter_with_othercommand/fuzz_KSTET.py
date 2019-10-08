#!/usr/bin/python

from boofuzz import *

host = '192.168.0.12'
port = 9999

def main():
	session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))
	
	s_initialize("KSTET")
	
	s_string("KSTET", fuzzable = False)
	s_delim(" ", fuzzable = False)
	s_string("FUZZ")

	session.connect(s_get("KSTET"))
	session.fuzz()

if __name__ == "__main__":
	main()

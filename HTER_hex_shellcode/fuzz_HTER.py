#!/usr/bin/python

from boofuzz import *

host = '192.168.0.12'
port = 9999


def main():
	session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))
	
	s_initialize("HTER")
	
	s_string("HTER", fuzzable = False)
	s_delim(" ", fuzzable = False)
	s_string("FUZZ")
	s_static("\r\n")

	session.connect(s_get("HTER"))
	session.fuzz()

if __name__ == "__main__":
	main()

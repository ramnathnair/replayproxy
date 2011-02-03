#!/usr/bin/python

###################################################################################################
#
# Copyright (c) 2011, Armin Buescher (armin.buescher@googlemail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
###################################################################################################
#
# File:		replayproxy.py
# Desc.:	ReplayProxy is a forensic tool to replay web-based attacks (and also general HTTP traffic) that were captured in a pcap file.
#			Functionality:
#			* parse HTTP streams from .pcap files
#			* open a TCP socket and listen as a HTTP proxy using the extracted HTTP responses as a cache while refusing all requests for unknown URLs
# Author:	Armin Buescher (armin.buescher@googlemail.com)
# Thx to:	Andrew Brampton (brampton@gmail.com) for his example code on how to parse HTTP streams from .pcap files using dpkg
#
###################################################################################################

import argparse
import sys
import socket
import re
import dpkt

import gzip
import StringIO

def parsepcap(filename):
	try:
		f = open(filename, 'rb')
		pcap = dpkt.pcap.Reader(f)
	except:
		print "Error: HTTPParser -> Error opening file %s" % filename
		sys.exit(1)

	print "*** HTTPParser -> Loaded %s" % filename
	
	conn = dict()
	requests = dict()
	responses = dict()
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			continue

		ip = eth.data
		if ip.p != dpkt.ip.IP_PROTO_TCP:
			continue
		
		tcp = ip.data

		key = (ip.src, ip.dst, tcp.sport, tcp.dport)
		if key in conn:
			conn[key] = conn[key] + tcp.data
		else:
			conn[key] = tcp.data

		try:
			stream = conn[key]
			http = ''
			httpkey = key

			if stream[:4] == 'HTTP':
				http = dpkt.http.Response(stream)
				httpkey = (ip.dst, ip.src, tcp.dport, tcp.sport)
				if httpkey in responses:
					responses[httpkey].append(http)
				else:
					responses[httpkey] = [http]
			else:
				http = dpkt.http.Request(stream)
				if httpkey in requests:
					requests[httpkey].append(http)
				else:
					requests[httpkey] = [http]

			#print "*" * 80
			#print "%s:%d -> %s:%d" % (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)
			#print http.headers
			
			stream = stream[len(http):]
			if len(stream) == 0:
				del conn[key]
			else:
				conn[key] = stream

		except (dpkt.UnpackError):
			pass
		except:
			print "Error: HTTPParser -> Unexpected error"
	
	files = dict()
	for k,v1 in responses.iteritems():
		for i,v2 in enumerate(v1):
			if k in requests and requests[k][i]:
				host = requests[k][i].headers['host']
				uri = requests[k][i].uri
				ip = socket.inet_ntoa(k[1])
				key = (host, uri, ip)
				files[host+uri] = (requests[k][i],v2)
	print "*** HTTPParser: # Files extracted -> %d" % len(files)
	return files

def sendResponse(resp,conn):
	resp.version = '1.0'
	if 'content-encoding' in resp.headers and resp.headers['content-encoding'] == 'gzip':
		del resp.headers['content-encoding']
		compressed = resp.body
		compressedstream = StringIO.StringIO(compressed)
		gzipper = gzip.GzipFile(fileobj=compressedstream)
		data = gzipper.read()
		resp.body = data
	resp.headers['content-length'] = len(resp.body)
	conn.send(resp.pack())

def replayproxy(files,port):
	host = ''
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((host,port))
	s.listen(1)

	print "*** ReplayProxy: listening on port %s" % port

	while 1:
		conn, addr = s.accept()
		data = conn.recv(16384)
		if data:
			try:
				http = dpkt.http.Request(data)
				url = re.sub(r"^http:\/\/","",http.uri)
				if url in files:
					resp = files[url][1]
					print "Info: ReplayProxy -> Sending %s" % url
					sendResponse(resp,conn)
				else:
					conn.send('')
					print "Warn: URL not in cache -> %s" % url
			except dpkt.UnpackError:
				print "Error: ReplayProxy -> Parsing HTTP request"
			#except:
			#	print "Error: ReplayProxy -> Unexpected error"
		conn.close()
	s.close()

### Main
argparser = argparse.ArgumentParser()
argparser.add_argument('-p', help='Port to listen on (DEFAULT: 3128)')
argparser.add_argument('filename', help='Path to the .pcap file to parse')
args = argparser.parse_args()
if args.p == None:
	args.p = 3128
else:
	try:
		args.p = int(args.p)
	except:
		args.p = 3128

files = parsepcap(args.filename)
replayproxy(files, args.p)

import csv

class Firewall:

	def __init__(self,address):		
		self.rules = []
		with open(f"{address}", "r") as f:
		    reader = csv.reader(f, delimiter="\t")
		    for line in reader:
		        self.rules.append(line[0].split(','))


	def accept_packet(self, direction, protocol, port, ip):
		try:
			for rule in self.rules:

				#DIRECTION and PROTOCOL
				#if direction and protocol does not match no point in evaluating further
				if rule[:2] != [direction,protocol]:
					#continue to next rule without further evaluation for this rule
					continue
				
				#PORT
				#convert to list if range given
				range_port = rule[2].split("-")

				#check in between if range given
				if len(range_port) == 2:
					if not(int(range_port[0]) <= port <= int(range_port[1])):
						continue

				#continue if port not equal
				else:
					if int(rule[2]) != port:
						continue

				#IP
				#convert to list if range given
				range_ip = rule[3].split("-")

				#convert string to integer by replacing "." with "" and compare integers
				if len(range_ip) == 2:
					if int(range_ip[0].replace(".","")) <= int(ip.replace(".","")) <= int(range_ip[1].replace(".","")):
						return True

				#string comparison
				else:
					if rule[3] == ip:
						return True
			return False

		#exception if input not in correct format	
		except:
			return "Invalid Input"


fw = Firewall("fw.csv")

#Testing with various input
print(fw.accept_packet("outbound", "udp", 1000, "52.12.48.92"))
print(fw.accept_packet("inbound", "udp", 53, "192.165.2.5"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.1.8"))
print(fw.accept_packet("outbound", "udp", 1024, "52.12.48.92"))
print(fw.accept_packet("outbound", "udp", 1024, "52.12.48.92"))




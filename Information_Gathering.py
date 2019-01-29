import csv
import socket
import requests
import pandas as pd
import pdfkit as pdf


def whois():
	response = requests.get("http://api.hackertarget.com/whois/?q=" + target)
	file = open("response.txt","w+") 
	file.write(response.text[:-302])
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace(': ', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)       #set dataframe column width to max
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)    #converting dataframe to html
		html_file.write('<h2>WHOIS:</h2>')
		html_file.write(html)

def traceroute():
	response = requests.get("http://api.hackertarget.com/mtr/?q=" + target)
	file = open("response.txt","w+") 
	file.write(response.text[32:])
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((' '.join(line.split()) for line in csv_file), delimiter=' ')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>TRACEROUTE:</h2>')
		html_file.write(html)

def dns_lookup():
	response = requests.get("http://api.hackertarget.com/dnslookup/?q=" + target)
	file = open("response.txt","w+") 
	file.write(response.text)
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace('\t', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>DNS LOOKUP:</h2>')
		html_file.write(html)


def reverse_dns():
	ip = socket.gethostbyname(target.strip())
	response = requests.get("http://api.hackertarget.com/reversedns/?q=" + ip)
	file = open("response.txt","w+") 
	file.write(response.text)
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace(',', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>REVERSE DNS:</h2>')
		html_file.write(html)

def dns_host_records():
	response = requests.get("http://api.hackertarget.com/hostsearch/?q=" + target)
	file = open("response.txt","w+") 
	file.write(response.text)
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace(',', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>DNS HOST RECORDS:</h2>')
		html_file.write(html)		


def geoip_lookup():
	response = requests.get("http://api.hackertarget.com/geoip/?q=" + target)
	file = open("response.txt","w+") 
	file.write(response.text)
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace(':', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>GEOIP LOOKUP:</h2>')
		html_file.write(html)

def reverseip_lookup():
	ip = socket.gethostbyname(target.strip())
	response = requests.get("http://api.hackertarget.com/reverseiplookup/?q=" + ip)
	file = open("response.txt","w+") 
	file.write(response.text)
	file.close()

	with open('response.txt', mode='r') as csv_file:
		csv_reader = csv.reader((line.replace(':', '^') for line in csv_file), delimiter='^')
		csv_reader1 = list(csv_reader)
		pd.set_option('display.max_colwidth', -1)
		df = pd.DataFrame(csv_reader1)
		
		html = df.to_html(header=False, index=False)
		html_file.write('<h2>REVESRE IP LOOKUP:</h2>')
		html_file.write(html)



if __name__== "__main__":
	target = input('Enter Domain : ')
	html_file= open("IG_Data.html","w+")
	html_file.write('<h1 align="center">Information Gathering</h1>')   #title of tool
	whois()
	traceroute()
	dns_lookup()
	reverse_dns()
	dns_host_records()
	geoip_lookup()
	reverseip_lookup()
	html_file.close()
	pdf.from_file('IG_Data.html', 'IG_Data.pdf')		#converting html to pdf



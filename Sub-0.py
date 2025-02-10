#!/usr/bin/python3
# python3 -m pip install pip --upgrade to be safe
from colorama import init, Fore
import csv, os, socket, json, subprocess, shutil, urllib.request, re

VERSION_NUMBER="v1"
DEBUG_ON=False

DEBUG="DEBUG"
SUCCESS="SUCCESS"
ERROR="ERROR"

# tools & filtering
discovery_commands = {
	'amass':'amass enum -v -src -ip -brute -min-for-recursive 2 -oA ./results/amass-results -df ./domains.txt',
	'assetfinder':'while read d; do assetfinder --subs-only ${d} >> "./results/assetfinder-${d}.txt"; done < ./domains.txt',
	'assetfinder_append':'/bin/cat ./results/assetfinder-* >> ./results/assetfinder-combined.txt',
	'getallurls':'/bin/cat ./domains.txt | getallurls --subs --o ./results/gau-raw.txt --threads 5',
	'getallurls_clean':'/bin/cat ./results/gau-raw.txt | unfurl -u domains >> ./results/gau-domains.txt',
	'compile_results':'/bin/cat ./results/amass-results.txt ./results/assetfinder-combined.txt ./results/gau-domains.txt | /usr/bin/sort -u > ./results/subdomains.txt'
}

def log(msg, severity="SUCCESS"):
	severity = severity.lower()
	if severity == "debug":
		if DEBUG_ON:
			print(Fore.ORANGE + "[#] {}".format(msg))
	elif severity == "success":
		print(Fore.CYAN + "[>] {}".format(msg))
	elif severity == "error":
		print(Fore.RED + "[!] {}".format(msg))

def setup():

	log("Welcome to {} of Sub-0. This subdomain enumeration tool will enumerate and sort subdomains.".format(VERSION_NUMBER))

	# install necessary apps
	cmd_exists("amass")
	cmd_exists("assetfinder")
	cmd_exists("getallurls")
	cmd_exists("unfurl")
	cmd_exists("nmap")

	# create the results dir to hold the output
	if not os.path.exists("./results/"):
		run_command('mkdir ./results')

	# clean up the scope files - line breaks will break stuff
	run_command("sed -i '/^[[:space:]]*$/d' domains.txt")
	run_command("sed -i '/^[[:space:]]*$/d' fullscope.txt")

	# initilize colorama
	init(autoreset=True)

def cmd_exists(cmd):
	if (shutil.which(cmd) is None):
		log("Error: {} must be installed and in your $PATH".format(cmd), ERROR)
		answer = input("Would you like me to install it for you? (y/N): ").lower()
		if answer.lower() == "y": 
			install(cmd)
		else:
			log("Without the necessary programs, this script will not run. Exiting.", ERROR) 
			exit(1)
	else:
		log("The tool {} has been found in your $PATH".format(cmd), DEBUG)
		return None

def install(program):
	if program == "amass":
		log("Installing Amass...")
		url = "https://github.com/OWASP/Amass/releases/download/v3.19.3/amass_linux_amd64.zip"
		urllib.request.urlretrieve(url, "/tmp/amass.zip")
		run_command('unzip -j "/tmp/amass.zip" "amass_linux_amd64/amass" -d "/usr/local/bin/"')
	elif program == "assetfinder":
		log("Installing assetfinder...")
		url = "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz"
		urllib.request.urlretrieve(url, "/tmp/assetfinder.tar.gz")
		run_command('tar -xzf /tmp/assetfinder.tar.gz -C /usr/local/bin/')
	elif program == "getallurls":
		log("Installing getallurls...")
		url = "https://github.com/lc/gau/releases/download/v2.1.1/gau_2.1.1_linux_amd64.tar.gz"
		urllib.request.urlretrieve(url, "/tmp/gau.tar.gz")
		run_command('tar -xzf /tmp/gau.tar.gz --transform ''s/gau/getallurls/'' -C /usr/local/bin/')
	elif program == "unfurl":
		log("Installing unfurl...")
		url = "https://github.com/tomnomnom/unfurl/releases/download/v0.4.1/unfurl-linux-amd64-0.4.1.tgz"
		urllib.request.urlretrieve(url, "/tmp/unfurl.tar.gz")
		run_command('tar -xzf /tmp/unfurl.tar.gz -C /usr/local/bin/')
	elif program == "nmap":
		log("Installing Nmap via the APT package manager...")
		run_command('sudo apt-get -yqq update && sudo apt-get -yqq install nmap')
	else:
		log("Error understanding the application you are trying to install. Exiting.", ERROR)
		exit(1)
	
	log("Download and installation of {} to /usr/local/bin completed.".format(program))
	return None

def run_command(cmd): 
	try:
		command_output = subprocess.getoutput(cmd).rstrip()
		return command_output
	except subprocess.CalledProcessError as e:
		log("Error executing command. Output {}".format(e.output), ERROR)
		exit(1)
	except OSError as e:
		log("Error executing command. Output: {}".format(e.output), ERROR)
		exit(1)

def get_actual_ip(record):
	try:
		return socket.gethostbyname(record)
	except Exception:
		return "Could not resolve. May be stale data."

def hosts_to_ips(subdomains_file):
	log("Resolving the discovered results within 'subdomains.txt'...")

	# check to see if domains file exists
	if not os.path.exists(subdomains_file):
		log("Unable to find 'subdomains.txt' file", ERROR)
		exit(1)

	# create a blank csv and add the header row
	with open("./subdomains.csv", "w") as subs:
		subs.write("Domain,Subdomain,IP\n")

	# open up the subdomains.csv file for appending, initialize the csv writer
	with open("./subdomains.csv", mode="a", newline="") as outputfile:
		output_writer = csv.writer(outputfile)
		with open(subdomains_file, 'r') as subdomains:
			for sd in subdomains:
				sd = sd.strip().lower()
				resolvedip = get_actual_ip(sd)
				sld = ('.'.join(sd.split('.')[-2:]))
				## write the content to the subdomains.csv file
				output_writer.writerow([sld,sd,resolvedip])

	log("IP address resolution completed")

def split_files():
	
	log("Generating inscope- or additional-subdomains.csv..")

	# initialize output file for domains
	with open("./inscope-subdomains.csv", "w") as inscope:
		inscope.write('Domain,Subdomain,IP\n')

	# open the output files in "append" mode
	inscope = open("./inscope-subdomains.csv", "a")
	additional = open("./additional-subdomains.csv", "a")

	## pull of the subdomains from the CSV and convert to a list
	f = open("./subdomains.csv", "r")
	hosts_list = [line.rstrip('\n') for line in f]

	## for each subdomain entry..
	with open("./results/Sub0-scope.txt", "r") as file:
		data = file.read()
	
	for line in hosts_list:
		hostname = line.split(",")[1]
		ipaddr = line.split(",")[2]

		if "Could not resolve" in line:
			continue # ignore ip addresses that do not resolve
		elif re.search(r'\b' + ipaddr + r'\b', data) or re.search(r'\b' + hostname + r'\b', data):
			inscope.write(line + '\n')
		else:
			additional.write(line + '\n')

	inscope.close()
	additional.close()
	log("The inscope and additional-subdomains CSV files have been created!")

def execute_amass():
	log('Executing amass..')
	amass_results = run_command(discovery_commands["amass"])
	if amass_results is not None:
		f = open('./results/amass-results.json', 'r')
		amass_results_lines = f.read().strip('\n').split('\n')
		# combine into a single string, comma seperated, surronded with "[ ]".
		# needed to fix JSON format because amass is not doing it properly.
		json_string = '[' + ','.join(amass_results_lines) + ']'
		json_data = json.loads(json_string)
		f.close()

		# write all of the discovered hostnames to `amass-results.txt`
		with open('./results/amass-results.txt', "w") as f:
			for entry in json_data:
				f.write(entry['name'] + os.linesep)		
	else:
		log('Error while attempting to run amass', ERROR)
	
	log('Completed amass.', DEBUG)
	return True

def execute_assetfinder():
	log('Executing assetfinder...')
	if run_command(discovery_commands['assetfinder']) is not None:
		if run_command(discovery_commands['assetfinder_append']) is not None:
			log('Completed assetfinder.', DEBUG)
		else:
			log('Error processing assetfinder append command', ERROR)
	else:
		log('Error processing assetfinder discovery command', ERROR)

	return True

def execute_getallurls():
	log('Executing getallurls...')
	getallurls_results = run_command(discovery_commands['getallurls'])
	if getallurls_results is not None:
		if run_command(discovery_commands['getallurls_clean']) is not None:
			log('Completed getallurls.', DEBUG)
		else:
			log('Error executing getallurls_clean command:', ERROR)
			log('%s'.format(discovery_commands['getallurls_clean']))
	else:
		log('Error processing getallurls command:', ERROR)
		log('%s'.format(discovery_commands['getallurls']))

	return True

def convert_fullscope():
	# Hostnames and CIDR ranges are converted to IP addresses (Sub0-scope.txt)
	command = "nmap -sL -n -iL fullscope.txt -oG - | grep -v '#' | cut -d ' ' -f 2 | sort -u > ./results/Sub0-scope.txt"
	run_command(command)

	# Hostnames are appended to Sub0-scope.txt
	command = "grep -i \"[a-z]\" fullscope.txt | sort -u >> ./results/Sub0-scope.txt"
	run_command(command)

	return None

def main():

	# prepare
	if not os.path.exists("./domains.txt") or not os.path.exists("./fullscope.txt"):
		log("Both the 'fullscope.txt' and 'domains.txt' files must be present to execute, please have both files before executing this script. Bye Bye.", ERROR)
		exit(1)
	
	setup()
	convert_fullscope()

	# enumerate:
	execute_amass()
	execute_assetfinder()
	execute_getallurls()
	
	# result compilation
	if run_command(discovery_commands['compile_results']) is not None:
		log("The 'subdomains.txt' file has been compiled")
	else:
		log("Error compiling 'subdomains.txt' file. Exiting.", ERROR)
		exit(1)
	
	hosts_to_ips("./results/subdomains.txt") # creates subdomains.csv
	split_files() # creates inscope-subdomains.csv, additional-subdomains.csv

	# TODO: PROMPT FOR "do you want to zip up the results?"
	#zip_results()
	#Try to add a source column in the csvs, where a subdomain was found - amass for example

main()
exit(0)

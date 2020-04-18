from requests import get as rget

headers = {
	'authority': 'data.miningpoolstats.stream',
	'accept': 'application/json, text/javascript, */*; q=0.01',
	'sec-fetch-dest': 'empty',
	'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
	'origin': 'https://miningpoolstats.stream',
	'sec-fetch-site': 'same-site',
	'sec-fetch-mode': 'cors',
	'referer': 'https://miningpoolstats.stream/monero',
	'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7' 
}


links = [
	'https://data.miningpoolstats.stream/data/monero.js?t=1587210437'
]


for link in links:
	r = rget(link, headers=headers).json()
	for i in r.get('data'):
		mda = i.get('pool_id')
		if mda:
			print(mda)

'''
for link in links:
	for line in str(rget(link, headers=headers).content).split('<b>'):
		print(line)
'''

'''
for link in links:
	for line in str(rget(link).content).split('<b>'):
		if 'onclick="gaSendEvent(\'pool-click\'' in line:
			print(line.split('>')[1])
'''
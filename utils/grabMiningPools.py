from requests import get as rget
from time import time

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


link = 'https://data.miningpoolstats.stream/data/monero.js?t=1587210437'

for line in rget(link, headers=headers).json().get('data'):
	if line.get('pool_id'): print(line.get('pool_id'))

import asyncio
import aiohttp
import time

NUMBERS = range(12)
URL = 'http://httpbin.org/get?a={}'


async def fetch_async(a):
    async with aiohttp.request('GET', URL.format(a)) as r:
        data = await r.json()
    return data['args']['a']

start = time.time()
loop = asyncio.get_event_loop()
tasks = [fetch_async(num) for num in NUMBERS]
results = loop.run_until_complete(asyncio.gather(*tasks))
print(results)

for num, result in zip(NUMBERS, results):
    print('fetch({}) = ({})'.format(num, result))

print('cost time: {}'.format(time.time() - start))
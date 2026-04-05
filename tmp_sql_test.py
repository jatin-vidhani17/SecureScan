import requests
url = "http://testphp.vulnweb.com/listproducts.php?cat=1%27"
res = requests.get(url)
print(res.text)

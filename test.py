from urllib.request import urlopen
url = "https://www.exploit-db.com/exploits/" + str(49518)
page = urlopen(url)
html = page.read().decode()
print(html)
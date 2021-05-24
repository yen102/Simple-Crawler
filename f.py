from urllib.request import urlopen
from tabulate import tabulate
import requests
import click

def line_prepender(filename, line):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(line.rstrip('\r\n') + '\n' + content)
        f.close()

def get_details(id):
    url = "https://www.exploit-db.com/exploits/" + str(id)
    # page = urlopen(url)
    try:
        html = urlopen(url).read().decode()
    except:
        print("Invalid exploit ID")
        return
    title_start = html.find("<title>")
    title_end = html.find("</title>")
    line = str(id) + "   " + html[title_start+7:title_end]
    line_prepender("recent_ep.txt", line)
    begin = html.find("language")
    begin = html.find(">", begin)
    end= html.find("</code>", begin)
    print(html[begin:end])
    choice = input("Mark this exploit as favorite?  (y/n)")
    if (choice == "y"):
        line_prepender("favorite.txt", line)
    else:
        return

def get_page(num):
    url = "https://www.exploit-db.com/?draw=3&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=code&columns%5B8%5D%5Bname%5D=code.code&columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=id&columns%5B9%5D%5Bname%5D=id&columns%5B9%5D%5Bsearchable%5D=false&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=9&order%5B0%5D%5Bdir%5D=desc&start="+str(num*15)+"&length=15&search%5Bvalue%5D=&search%5Bregex%5D=false&author=&port=&type=&tag=&platform=&_=1612013146833"
    headers = {'x-requested-with': 'XMLHttpRequest'} 
    x = requests.get(url, headers = headers)
    a = x.json()
    total = a["recordsTotal"]
    if ((num+1) * 15 > total):
        print("Invalid Page!")
        return
    line = str(num)
    line_prepender("recent_p.txt", line)
    d=[]
    d.append(["EDB-ID", "Product", "Vuln", "CVE", "Platform"])
    e = min(len(a["data"]), 15)
    for i in range(e):
        t = a["data"][i]
        description = t['description'][1]
        description = description.split("-")
        cve = ""
        if(len(t['code'])):
            cve += t['code'][0]['code']
        d.append([t['id'], description[0], description[1].replace("&#039;", "'"), cve, t['type_id'] + " " + t['platform_id']])

    print(tabulate(d, headers="firstrow", tablefmt="psql"))

i = 0
flag = True
def print_block(f):
    global flag
    global i
    for x in f:         
        print(x)
        if ("End of list!" in x):
            flag = False
            return
        i += 1
        if (i % 15 == 0):
            break
def display(filename):
    global i
    global flag
    flag = True
    i = 0
    file = open(filename, "r")
    f = file.read()
    f = f.split("\n")
    print_block(f)
    while flag:
        choice = input("Continue? [y/n] ")
        if (choice == "y"):
            print_block(f[i:])
        elif (choice == "n"):
            file.close()
            break
        else:
            print("Please choose y or n")
    file.close()

def welcome():
    print("-------------------------List of favorite exploits-------------------------")
    display("favorite.txt")
    print("-------------------------List of recently opened exploits-------------------------")
    display("recent_ep.txt")
    print("-------------------------List of recently opened pages-------------------------")
    display("recent_p.txt")

@click.command()
@click.option("--exploit_id", default = -1, help = "Display this exploit in details")
@click.option("--page_num", default = -1, help = "Display list of exploits in this page")
@click.option("--favorite", is_flag = True, help = "Display list of favorite exploits")
def run(exploit_id, page_num, favorite):
    if(exploit_id == -1 and page_num == -1 and not favorite):
        welcome()
    if(favorite):
        display("favorite.txt")
    if(exploit_id != -1):
        get_details(exploit_id)
    if(page_num != -1):
        get_page(page_num)
    print("Press q at any time to quit the program!")
    while(True):
        choice = input()
        if (choice == "q"):
            return
        elif (choice[:10] == "--favorite"):
            print("-------------------------List of favorite exploits-------------------------")
            display("favorite.txt")
        elif (choice[:12] == "--exploit_id"):
            id = int(choice[13:])
            print(id)
            get_details(id)
        elif (choice[:10] == "--page_num"):
            num = int(choice[11:])
            get_page(num)
            print(num)
        else:
            print("Invalid command")
            
if __name__ == '__main__':
    run()
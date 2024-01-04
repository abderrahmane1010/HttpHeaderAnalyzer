
#!/usr/bin/python3
import requests

class Header:
    
    """
    information_leakage : https://cqr.company/web-vulnerabilities/information-leakage-via-http-headers/
    """    
    info_leakage = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'Via',
        'X-Backend-Server'
    ]
    def __init__(self, url):
        self.url = url
        self.headers = requests.get(self.url).headers
        
    def ishere(self, header):
        return header in self.headers
    
    def get_header(self, header):
        if self.ishere(header):
            return self.headers[header]
        return None

    def list_of_headers(self):
        return list(self.headers.keys())
    
    def information_leakage_analysis(self):
        fields = [element for element in list(self.headers.keys()) if element in self.info_leakage]
        print("################## Information Leakage analysis ####################")
        print("Number of fields that leak information : ", len(fields))
        for field in fields :
            print(" +  ",field, " : ", self.headers[field])
        return fields
    
    def cookie_analysis(self):
        print("################## Cookie analysis ####################")
        set_cookie = self.get_header("Set-Cookie")
        if set_cookie is None:
            print("This website seems not uses cookies")
        else :
            cookies_fields = set_cookie.split(';')
            for field in cookies_fields:
                if '=' in field :
                    key, value = field.strip().split('=')
                    print(" + ",key, " : ", value)
                else :
                    print(" + ",field)
        return set_cookie
    
    def __str__(self):
        return "\n".join([f"{c}: {v}" for c, v in self.headers.items()])



header = Header(url="http://facebook.com/")
print(header)   
print("\n ---------------------- \n")
print(header.list_of_headers(), len(header.list_of_headers()))
print("\n ---------------------- \n")
header.information_leakage_analysis()
print("\n ---------------------- \n")
print(header.cookie_analysis())
    
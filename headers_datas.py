security_headers=[
    # used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>. Sites can use this to avoid clickjacking attacks, by ensuring that their content is not embedded into other sites.
    'X-Frame-Options',
    # a feature of Internet Explorer, Chrome, and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks.
    'X-XSS-Protection',
    # The X-Content-Type-Options response HTTP header is used by the server to indicate to the browsers that the MIME types advertised in the Content-Type headers should be followed and not guessed.
    'X-Content-Type-Options',
    # Controls how much referrer information (sent via the Referer header) should be included with requests.
   'Referrer-Policy',
    # If not set correctly, the resource (e.g. an image) may be interpreted as HTML, making XSS vulnerabilities possible.
   'Content-Type',
    # lets a website tell browsers that it should only be accessed using HTTPS, instead of using HTTP.
   'Strict-Transport-Security',
   # used to specify the origin of content that is allowed to be loaded on a website or in a web applications. It is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement to distribution of malware.
   'Content-Security-Policy',
   
   'Access-Control-Allow-Origin'
]
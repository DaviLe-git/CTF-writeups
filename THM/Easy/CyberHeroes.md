
# CTF Writeup — CyberHeroes

## 📌 Overview

* **Platform:** TryHackMe
* **Difficulty:** Easy
* **Date:** March 2026
* **Objective:** Bypass the login mechanism to retrieve the flag

CyberHeroes presents a web-based authentication challenge. The target exposes a login page that performs credential validation entirely on the client side, with no server-side verification involved. The overall approach focused on inspecting client-side source code to identify how authentication was implemented — a classic insecure design pattern.

---

## 🔍 Enumeration

### 1. Initial Reconnaissance

Upon deploying the machine, the target was accessed via browser at:
http://<MACHINE_IP>

The landing page contained no immediately useful information. Navigation led to the login page at `/login.html`, which presented a standard username/password form with the message:

> *"Show your hacking skills and login to become a CyberHero!"*

An initial test with generic credentials (`teste:teste`) returned a client-side popup alert:

> *"Incorrect Password, try again.. you got this hacker!"*

The popup behavior — rather than a server response — was the first indicator that authentication logic was being handled locally in the browser.

---

### 2. Further Enumeration

To understand the underlying request flow, HTTP traffic was intercepted using Burp Suite during a login attempt. The intercepted request was as follows:

```http
GET /login.html HTTP/1.1
Host: 10.80.142.114
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Wed, 02 Mar 2022 19:07:58 GMT
If-None-Match: "1679-5d940ffe6bf80-gzip"
Priority: u=0, i
```

Critically, no POST request or form submission was transmitted to the server upon entering credentials. This confirmed that the validation logic resided entirely within the client-side JavaScript — meaning the credentials were embedded in the page source itself.

The page source was reviewed directly through the browser's developer tools.

---

## 💥 Exploitation

**Vulnerability Type:** Client-Side Authentication Bypass (Insecure Design — OWASP A04:2021)  
**Location:** `/login.html` — inline JavaScript `authenticate()` function  
**Impact:** Full authentication bypass; flag retrieved without valid server-side credentials

### Analysis

Inspection of the page source revealed the following `authenticate()` function embedded in the HTML:

```javascript
function authenticate() {
  a = document.getElementById('uname')
  b = document.getElementById('pass')
  const RevereString = str => [...str].reverse().join('');
  if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        document.getElementById("flag").innerHTML = this.responseText ;
        document.getElementById("todel").innerHTML = "";
        document.getElementById("rm").remove() ;
      }
    };
    xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
    xhttp.send();
  }
  else {
    alert("Incorrect Password, try again.. you got this hacker !")
  }
}
```

### Exploitation Steps

The function hardcodes the expected credentials directly in the source. The username is stored in plaintext:
Username: h3ck3rBoi

The password is subjected to a simple string reversal via the `RevereString` helper before comparison. The literal string stored in the code is `"54321@terceSrepuS"`, which when reversed yields the actual expected password:
Password: SuperSecret@12345

Upon submitting these credentials in the login form, the function constructed a GET request to a randomized file path containing the flag and injected the response into the page DOM.

---

## 🔓 Privilege Escalation

*Not applicable. This challenge is limited to web-based authentication bypass. No system shell access or privilege escalation was required.*

---

## 🧠 Lessons Learned

* **Client-side authentication is fundamentally insecure.** Any logic executed in the browser — including credential checks — is fully visible and controllable by the user. No secret should ever be validated exclusively on the client side.

* **Obfuscation is not security.** The string reversal applied to the password provided zero meaningful protection. It is trivially reversed and only creates a false sense of obscurity. Security must rely on sound cryptographic mechanisms, not encoding tricks.

* **Source code review is a high-yield, low-effort technique.** Before reaching for active scanning tools, reviewing page source and JavaScript files can immediately expose critical vulnerabilities — particularly in web applications that implement logic in the front end.

* **Real-world relevance:** This pattern appears in poorly developed internal tools, legacy applications, and rapid prototypes that were never hardened for production. During web application assessments, reviewing JavaScript files for hardcoded credentials or client-side access controls should be a standard enumeration step.

---

## 🧩 Tools Used

* **Burp Suite** — HTTP traffic interception and request analysis
* **Browser Developer Tools** — Page source and JavaScript inspection

---

## ⚠️ Notes

* Flags are intentionally omitted from this writeup
* This writeup focuses on methodology and learning

---


## Assignment

Category: Web
Difficulty: Not specified

[Michael Dalton](https://michaeldalton.au)

Welcome to Star City. Home of stars galore. But is there more to be seen than meets the eye?

[http://34.116.80.78:9981/](http://34.116.80.78:9981/)

Flag Format: `CSSCTF{...}`
## Reconnaissance

The website looked completely ordinary. So I looked a traffic in Burp Suite.

<img width="1042" height="1021" alt="Pasted image 20260930130337" src="https://github.com/user-attachments/assets/1ede292b-f42b-4ccb-9e0b-ab910e410529" />

Looking at the HTTP traffic in Burp Suite, I didn't find anything unusual either.

<img width="807" height="488" alt="Pasted image 20260930130511" src="https://github.com/user-attachments/assets/57f5abf8-a261-427d-b0b4-a13e28bbfdd4" />

So, I inspected the website using the browser's Developer Tools. There, I found the `index.html` and `style.css` files. I continued by searching for hardcoded credentials or hidden information. In `style.css`, I found the following comment:
`/*Q1NTQ1RGJTdCd2VfQlUxTFRfdGhpc19jaXR5X2Zyb21fcjBja19hbmRfUjAxMSU3RA*/`

<img width="1156" height="436" alt="Pasted image 20260930130726" src="https://github.com/user-attachments/assets/23e43d68-9810-496f-a942-dd7a3d8454b2" />

From the look of it, it was similar to Base64 encoding, so I tried to decode it with CyberChef.

<img width="1140" height="861" alt="Pasted image 20260930130940" src="https://github.com/user-attachments/assets/5b2c7ff6-7189-436c-b6f3-3055af6d545a" />

This revealed the flag format, but some characters were still URL-encoded (e.g., `%7B` instead of `{`). By adding a "URL Decode" operation to the CyberChef recipe, I was able to obtain the final, clean flag.

<img width="1134" height="876" alt="Pasted image 20260930131057" src="https://github.com/user-attachments/assets/89464940-211d-4775-b1d0-ac2806f50f2a" />

**FLAG:** `CSSCTF{we_BU1LT_this_city_from_r0ck_and_R011}`

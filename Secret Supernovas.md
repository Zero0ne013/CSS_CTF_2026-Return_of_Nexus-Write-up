## Assignment

Category: Web
Difficulty: Not specified

This is just a list of stars. Nothing else to see here...

[http://34.116.80.78:9982/](http://34.116.80.78:9982/)

Flag Format: `CSSCTF{...}`
## Reconnaissance

First, I look at the network request while the website was loading.

<img width="561" height="684" alt="Pasted image 20260930132332" src="https://github.com/user-attachments/assets/b4f787c2-e46f-4f83-8dc7-425e3704c991" />

The webpage showed a basic login page.

<img width="946" height="975" alt="Pasted image 20260930132410" src="https://github.com/user-attachments/assets/cd2c51bf-a6b4-4ba5-9ec9-053ba17f2406" />

Based on this, I decided to try the username `cadet` and the password `star`. This successfully logged me into the account. Next, I proxied the traffic through Burp Suite and discovered that the site uses GraphQL.

<img width="648" height="419" alt="Pasted image 20260930133254" src="https://github.com/user-attachments/assets/8413f101-806c-4d60-ba4b-36787bedd0c7" />

So I put it to repeater and select Introspection Query as mentioned in write-up from[ (SunshineCTF 2026 - Used Goods of Tomorrow)](https://github.com/Zero0ne013/SunshineCTF_Writeups/blob/main/used_goods_of_tomorrow.md).
As a result, I obtained the full GraphQL schema.

<img width="1259" height="779" alt="Pasted image 20260930133508" src="https://github.com/user-attachments/assets/1a82c64a-7d3c-4b19-8ee4-49587fbc161a" />

After reviewing the schema, I saved the GraphQL queries to the site map. Since the challenge description explicitly mentions a "list of stars", I decided to query for exactly that. I found the specific query for listing stars in the sitemap and sent it to Repeater.

<img width="1216" height="783" alt="Pasted image 20260930134357" src="https://github.com/user-attachments/assets/9588a2a4-61ac-4561-b5d8-db9a8bb41d18" />

Once I obtained the response containing the list of stars, I simply searched the output for the flag format prefix (`CSSCTF{`) and found the flag!

**Flag:** `CSSCTF{we_l000ve_grafs}`

<img width="1263" height="778" alt="Pasted image 20260930134635" src="https://github.com/user-attachments/assets/b1b5482c-6ab6-4c1e-a92b-8274cc00148a" />

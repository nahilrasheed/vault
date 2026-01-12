Easy | Web

ctf url: https://c2734c75c7603e26ca68846f7a2c53a1.ctf.hacker101.com/

## Flag 1
- Inspect /cart.
- We see hidden input field containing item details
- POST /checkout content
```
cart=%5B%5B0%2C+%7B%22name%22%3A+%22Kitten%22%2C+%22desc%22%3A+%228%5C%22x10%5C%22+color+glossy+photograph+of+a+kitten.%22%2C+%22logo%22%3A+%22kitten.jpg%22%2C+%22price%22%3A+8.95%7D%5D%5D
```
decoded
```
cart=[[0, {"name": "Kitten", "desc": "8\"x10\" color glossy photograph of a kitten.", "logo": "kitten.jpg", "price": 8.95}]]
```
- Change item price to 0 in burp or the hidden input field
we get 1st flag in the checkout page
![[Petshop Pro-1759060200155.png]]
## Flag 2
- Fuzz url to find other pages
- found admin page login at /login
- Bruteforce credentials using hydra or fuzz or burp turbo intruder
- used [names.txt](https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt) from seclist 
![[Petshop Pro-1759060805150.png]] 


![[Petshop Pro-1759059507607.png]]
## Flag 3
Try XSS in item name
![[Petshop Pro-1759060427511.png]]
Go to cart 
![[Petshop Pro-1759060498783.png]]
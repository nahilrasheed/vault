---
tags:
  - NBBC
  - CyberSec
---
 When you request a website, your computer needs to know the server's IP address it needs to talk to; for this, it uses [[DNS]]. Your computer then talks to the web server using a special set of commands called the HTTP protocol; the webserver then returns HTML, JavaScript, CSS, Images, etc., which your browser then uses to correctly format and display the website to you.
### **What is a website?**
When you view a website in your browser (Chrome/Firefox/Safari/Edge etc.) you're actually making a request to a web server, the server then responds with a language called Hyper-Text Markup Language (HTML) which forms the layout and contents of the webpage, the HTML can also link to other files such as Cascading Style Sheets (CSS) to provide style to the website (colours, fonts, backgrounds, sizing and so much more) and then interactivity is made possible using JavaScript.

#### Frontend Code
Frontend code is code that is delivered by the webserver to the client and then rendered or proceeded by the browser into what you can actually see. These are languages/technologies such as HTML, CSS and JavaScript.
**HTML** provides the content and the basic layout of the webpage.
**CSS (Cascading Style Sheets)** adds styling to the website by providing fonts, colours, sizes and animation.
**JavaScript** provides interactivity to a website, an example of this could be code that validates the contents of a contact form and informs the client of any errors in their input.
#### Backend Code
This is code which is processed on the server and generates content to be delivered back to the client. Backend code can be used to for example process user input, connect to databases or other data resources and much more.

## Web Application Infrastructure
### Web Server:
The most obvious piece of equipment required to host a website is the web server itself. 
A web server is a software that listens for incoming connections and then utilises the HTTP protocol to deliver web content to its clients. The most common web server software you'll come across is Apache, Nginx, IIS and NodeJS. 
A Web server delivers files from what's called its root directory, which is defined in the software settings. For example, Nginx and Apache share the same default location of /var/www/html in Linux operating systems, and IIS uses C:\inetpub\wwwroot for the Windows operating systems. So, for example, if you requested the file [http://www.example.com/picture.jpg](http://www.example.com/picture.jpg), it would send the file /var/www/html/picture.jpg from its local hard drive.
### Load Balancers:
When websites start becoming more popular and experience more traffic it gets to a point where one server cannot handle the load and more are required. The traffic load between these multiple servers can be split between them using a device called a load balancer. The load balancer sits in front of the web servers and can equally share the traffic amongst them. They use different algorithms to decide which web server will receive the traffic, some of them are as follows:
**Round Robin:**
This algorithm has a set pattern, so for example, if you had three servers it would send the first request to one, then two and then three and then back round to one again and keep in this order.
**Sticky:**
This method makes sure connections are always sent to the same server by using cookies. A useful use case for this algorithm could be for uploading and then editing an image via a website. The first request uploads the image, and then because that server holds the image you need to request the same one again to make sure you still have access to it. The load balancer keeps track of your server with the use of cookies.
**Least Connections:**
This algorithm monitors how many connections already exist from the load balancers to the web servers and directs any new connections to the least connected web server.
**Health Checks:**
Load balancers also have health checks, this is a periodic request that the load balancer makes to the webserver which makes sure it is behaving properly. If the load balancer receives a predetermined amount of invalid responses from the webserver traffic will stop being directed to it. Health checks will still continue in the background until the webserver responds correctly and then traffic to it will be reinstated.
**N.B Headers:**
Sometimes web servers need to keep track of the original client that is connected to them and know information such as the client's IP address. Because the load balancer makes the connection to the webserver this information is lost, to solve this the load balancer adds extra information to the HTTP request being made. The client's IP is often found in a header called **X-Forwarded-For**.
### CDN (Content Delivery Networks)
A CDN can be an excellent resource for cutting down traffic to a busy website. It allows you to host static files from your website, such as JavaScript, CSS, Images, Videos, and host them across thousands of servers all over the world. When a user requests one of the hosted files, the CDN works out where the nearest server is physically located and sends the request there instead of potentially the other side of the world.
### Web Application Firewall (WAF)
A WAF sits in front of your web server and is used to detect and block malicious traffic. It monitors the contents of each request against pre-determined rules (these rules are usually constantly updated databases of malicious web requests) if a client's request matches any of these rules the request is dropped.
It also checks if an excessive amount of web requests are being sent by utilising something called rate limiting, which will only allow a certain amount of requests from an IP per second. If a request is deemed a potential attack, it will be dropped and never sent to the webserver.
### Virtual Hosts
Web servers can host multiple websites with different domain names; to achieve this, they use virtual hosts. The web server software checks the hostname being requested from the HTTP headers and matches that against its virtual hosts (virtual hosts are just text-based configuration files). If it finds a match, the correct website will be provided. If no match is found, the default website will be provided instead.

Virtual Hosts can have their root directory mapped to different locations on the hard drive. For example, [one.com](http://one.com/) being mapped to /var/www/website_one, and [two.com](http://two.com/) being mapped to /var/www/website_two

There's no limit to the number of different websites you can host on a web server.
### Static Vs Dynamic Content
Static content, as the name suggests, is content that never changes. Common examples of this are pictures, javascript, CSS, etc., but can also include HTML that never changes. Furthermore, these are files that are directly served from the webserver with no changes made to them.

Dynamic content, on the other hand, is content that could change with different requests. Take, for example, a blog. On the homepage of the blog, it will show you the latest entries. If a new entry is created, the home page is then updated with the latest entry, or a second example might be a search page on a blog. Depending on what word you search, different results will be displayed.

These changes to what you end up seeing are done in what is called the **Backend** with the use of programming and scripting languages. It's called the Backend because what is being done is all done behind the scenes. You can't view the websites' HTML source and see what's happening in the Backend, while the HTML is the result of the processing from the Backend. Everything you see in your browser is called the **Frontend.**
### Scripting and Backend Languages
There's not much of a limit to what a backend language can achieve, and these are what make a website interactive to the user. Some examples of these languages are PHP, Python, Ruby, NodeJS, Perl and many more. These languages can interact with databases, call external services, process data from the user, and so much more.
### [[Web Sessions]]


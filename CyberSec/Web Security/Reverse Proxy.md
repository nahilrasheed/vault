A Reverse Proxy server regulates and restricts the internet access to an internal server. 
The goal is to accept traffic from external parties, approve it, and forward it to the internal servers. This setup is useful for protecting internal web servers containing confidential data from exposing their IP address to external parties. 
eg: HAproxy, nginx, Apache, squid

## Identification
- check for error pages(404 pages). see if there are different error pages(different reverse proxy) for different subdomains or different paths. 
- check http headers. if there are differences in the use of headers, there may be a reverse proxies present.
## Exploits
We can do directory traversals on some misconfigure reverse proxies. 
so if `www.website.com/staff/` points to `10.10.100.100/staff/` , if do a path traversal like `www.website.com/staff/../` we may be able to access `10.10.100.100/`
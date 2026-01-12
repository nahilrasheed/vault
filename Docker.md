Docker is an open-source platform for developers to build, deploy, and manage containers. Containers are executable units of software which package and manage the software and components to run a service. 

To run a command inside a docker container:
`docker exec -it [containername] [command]`

---

Testing

The Docker documentation mentions that by default, there is a setting called “Enhanced Container Isolation” which blocks containers from mounting the Docker socket to prevent malicious access to the Docker Engine. In some cases, like when running test containers, they need Docker socket access. The socket provides a means to access containers via the API directly. Let's see if we can. 
try `ls -la /var/run/docker.sock`. If we can see it, it means we can run access the docker socket from inside the docker container.

 By running `docker ps` again, we can confirm we can perform Docker commands and interact with the API; in other words, we can perform a Docker Escape attack!
 
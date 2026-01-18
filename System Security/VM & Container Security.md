
### **Virtual machines (VMs)**
Virtual machines (VMs) are software versions of physical computers. VMs provide an additional layer of security for an organization because they can be used to run code in an isolated environment, preventing malicious code from affecting the rest of the computer or system. VMs can also be deleted and replaced by a pristine image after testing malware. 

VMs are useful when investigating potentially infected machines or running malware in a constrained environment. Using a VM may prevent damage to your system in the event its tools are used improperly. VMs also give you the ability to revert to a previous state. However, there are still some risks involved with VMs. There’s still a small risk that a malicious program can escape virtualization and access the host machine. 

You can test and explore applications easily with VMs, and it’s easy to switch between different VMs from your computer. This can also help in streamlining many security tasks.

### **Sandbox environments**

A sandbox is a type of testing environment that allows you to execute software or programs separate from your network. They are commonly used for testing patches, identifying and addressing bugs, or detecting cybersecurity vulnerabilities. Sandboxes can also be used to evaluate suspicious software, evaluate files containing malicious code, and simulate attack scenarios. 

Sandboxes can be stand-alone physical computers that are not connected to a network; however, it is often more time- and cost-effective to use software or cloud-based virtual machines as sandbox environments. Note that some malware authors know how to write code to detect if the malware is executed in a VM or sandbox environment. Attackers can program their malware to behave as harmless software when run inside these types of  testing environments.

---

A VM is supposed to be a completely isolated system. One VM should not have access to resources and data from another VM unless that is strictly allowed and configured.

The hypervisor is the entity that controls and manages the VMs. There are two types of hypervisors:
- Type 1 hypervisors (also known as native or bare-metal hypervisors) run directly on the physical (bare-metal) system. Examples of Type 1 hypervisors include VMware ESXi, Proxmox Virtual Environment, Xen, and Microsoft Hyper-V.
- Type 2, or hosted, hypervisors run on top of other operating systems. Examples of type 2 hypervisors include VirtualBox and VMware Player or Workstation.

These virtual systems have been susceptible to many vulnerabilities, including the following:
- **VM escape vulnerabilities:** These vulnerabilities allow an attacker to “escape” the VM and obtain access to other virtual machines on the system or access to the hypervisor. An attacker can find a VM escape vulnerability in the underlying hypervisor and uses that vulnerability to access data from another VM.
- **Hypervisor vulnerabilities such as hyperjacking:** Hyperjacking is a vulnerability that could allow an attacker to control the hypervisor. Hyperjacking attacks often require the installation of a malicious (or “fake”) hypervisor that can manage the entire virtual environment. The compromised or fake hypervisor operates in a stealth mode, avoiding detection. Hyperjacking attacks can be launched by injecting a rogue hypervisor beneath the original hypervisor or by directly obtaining control of the original hypervisor. You can also launch a hyperjacking attack by running a rogue hypervisor on top of an existing hypervisor.
- **VM repository vulnerabilities:** Attackers can leverage these vulnerabilities to compromise many systems and applications. There are many public and private VM repositories that users can leverage to deploy VMs, including different operating systems, development tools, databases, and other solutions. Examples include the VMware Marketplace ([_https://marketplace.cloud.vmware.com/_](https://marketplace.cloud.vmware.com/)) and AWS Marketplace ([_https://aws.amazon.com/marketplace_](https://aws.amazon.com/marketplace)). Attackers have found ways to upload fake or impersonated VMs with malicious software and backdoors. These ready-to-use VMs are deployed by many organizations, allowing the attacker to manipulate the user’s systems, applications, and data.

## Vulnerabilities Related to Containerized Workloads
Computing has evolved from traditional physical (bare-metal) servers to VMs, containers, and serverless architectures.
![[VM&ContainerSecurity-img-202510141000.png]]

Vulnerabilities in applications and in open-source software running in containers such as Docker, Rocket, and containerd are often overlooked by developers and IT staff. Attackers may take advantage of these vulnerabilities to compromise applications and data. A variety of security layers apply to containerized workloads:
- The container image
- Software inside the container
- The host operating system
- Interaction between containers and the host operating system
- Security in runtime environment and orchestration platforms such as Kubernetes
### Container escape
A container escape is a technique that enables code running inside a container to obtain rights or execute on the host kernel (or other containers) beyond its isolated environment (escaping). For example, creating a privileged container with access to the public internet from a test container with no internet access. 

Containers use a client-server setup on the host. The CLI tools act as the client, sending requests to the container daemon, which handles the actual container management and execution. The runtime exposes an API server via Unix sockets (runtime sockets) to handle CLI and daemon traffic. If an attacker can communicate with that socket from inside the container, they can exploit the runtime (this is how we would create the privileged container with internet access, as mentioned in the previous example).
### Key security best practices that organizations should use to create a secure container image
**Develop**
- secure coding practices
- shift-left security
- build security scanning
**Deliver**
- secure repository storage
- IaaS
- secure user access
**Deploy**
- runtime scanning
- employ CIS benchmarks
- enforce security policies

**TIP** The CIS Benchmarks for Docker and Kubernetes provide detailed guidance on how to secure Docker containers and Kubernetes deployments. You can access all the CIS Benchmarks at: [_https://www.cisecurity.org/cis-benchmarks_](https://www.cisecurity.org/cis-benchmarks).

## Tools to scan Docker images for vulnerabilities and assess Kubernetes deployments
### Anchore’s Grype
Grype is an open-source container vulnerability scanner that you can download from [_https://github.com/anchore/grype_](https://github.com/anchore/grype).
### Clair
Clair is another open-source container vulnerability scanner. You can download it from [_https://github.com/quay/clair_](https://github.com/quay/clair).
### Dagda  
This set of open-source static analysis tools can help detect vulnerabilities, Trojans, backdoors, and malware in Docker images and containers. It uses the ClamAV antivirus engine to detect malware and vulnerabilities. You can download Dagda from [_https://github.com/eliasgranderubio/dagda/_](https://github.com/eliasgranderubio/dagda/).
### kube-bench
This open-source tool performs a security assessment of Kubernetes clusters based on the CIS Kubernetes Benchmark. You can download kube-bench from [_https://github.com/aquasecurity/kube-bench_](https://github.com/aquasecurity/kube-bench).
### kube-hunter  
This open-source tool is designed to check the security posture of Kubernetes clusters. You can download kube-hunter from [_https://kube-hunter.aquasec.com/_](https://kube-hunter.aquasec.com/).
### Falco
You can download this threat detection engine for Kubernetes from [_https://falco.org/_](https://falco.org/).

Another strategy that threat actors have used for years is to insert malicious code into Docker images on Docker Hub ([_https://hub.docker.com_](https://hub.docker.com/)). This has been a very effective “supply chain” attack.
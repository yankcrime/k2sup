# k2sup
This is an awful hack of a fork of Alex Ellis' [k3sup](https://github.com/alexellis/k3sup) - a light-weight utility to get from zero to KUBECONFIG, originally with K3s but now with [RKE2](https://rke2.io/) instead. All you need is `ssh` access and the `k2sup` binary to get `kubectl` access fairly quickly.

RKE2 is downstream from K3s, but is just about sufficiently different in its installation approach (and probably target audience) that a fork makes sense.

The tool is written in Go and is cross-compiled for Linux, Windows, and MacOS.

## Noteworthy Options
The `k2sup` `install` and `join` commands support many of the same options as k3sup, with a few notable differences:

* `--config`: Supply a configuration file that will be dropped into place on the target node as `/etc/rancher/rke2/config.yaml`.  Since the RKE2 install script doesn't pass through the same number of options as the one for K3s, this is how custom configuration needs to be applied.  Note that RKE2 supports different options whether it's a [server](https://docs.rke2.io/install/install_options/server_config/) or an [agent](https://docs.rke2.io/install/install_options/linux_agent_config/).
* `--registries`: Supply a [custom containerd registry configuration](https://docs.rke2.io/install/containerd_registry_configuration/).
* `--channel`: Specify which [release channel](https://docs.rke2.io/upgrade/basic_upgrade/#release-channels) to use.
* `--vip`: The IP of the VIP for the control plane that you'd like to have kube-vip deploy and manage. [See below for details](#Installing-with-a-VIP-for-the-Control-Plane).
* `--vip-interface`: The network interface to associate with the above VIP. Defaults to `eth0`.

## Use

> NB: `k2sup` presumes the precreation of an existing set of machines onto which you want to deploy Kubernetes.

In this example, I've six virtual machines deployed on vSphere.  I'm using [govc](https://github.com/vmware/govmomi) to query the VM's IP addresses in lieu of DNS, and I have the following server configuration in `server-config.yaml` in my current directory:

```yaml
node-taint:
  - "CriticalAddonsOnly=true:NoExecute"
cni:
  - "cilium"
tls-san:
  - "192.168.20.200"
  - "rke2.192.168.20.200.dnsify.me"
```

This will:
* [Taint server nodes](https://docs.rke2.io/install/ha/#2a-optional-consider-server-node-taints) so that they are not schedulable by user workloads;
* Use [Cilium](https://cilium.io) as the CNI;
* Specify an additional IP address and hostname that can be used to connect to the cluster's API.  A post-deployment step would be to configure a loadbalancer or a VIP on `192.168.20.200` which should balance requests across our three server nodes.  Alternatively, see the section below on deploying with a VIP for the control plane;
* Add TLS [Subject Alternative Names](https://en.wikipedia.org/wiki/Subject_Alternative_Name) (SANs) for this additional IP address and hostname so that kubectl works when hitting the Kubernetes API with either of these two values.

With this configuration we can install the first node in our cluster:

```sh
% k2sup install --ip $(govc vm.ip /42can/vm/server0) --user nick --local-path ~/.kube/rke2.yaml \
  --context rke2 --config $(pwd)/server-config.yaml
```

RKE2 takes a lot longer than K3s to start up, so at this point we need to be a little patient.  We can switch to the new cluster's context (`rke2` in my example) and attempt to query it after a minute or so, depending on your hardware and Internet connection:

```
% kubie ctx rke2
% kubectl get nodes
NAME      STATUS   ROLES                       AGE   VERSION
server0   Ready    control-plane,etcd,master   52s   v1.21.5+rke2r2
```

_(NB: I use [kubie](https://github.com/sbstp/kubie) as an easy way of switching between cluster contexts)_

> If you're curious as to how RKE2's startup is proceeding, or you're suspicious about where it's up to, you'll need to login to the server node and run `journalctl -fu rke2-server`.

Assuming everything's worked as it should, with our initial server node up and ready we can bootstrap the other server nodes:

```
% for server in server{1..2} ; do
  k2sup join --ip $(govc vm.ip /42can/vm/$server) --server \
  --server-ip  $(govc vm.ip /42can/vm/server0) --user nick \
  --config $(pwd)/server-config.yaml
done
```

Again, keep an eye on the progress of these as they come online.  They'll take a little while to appear in the list of nodes, but eventually:

```shell
NAME      STATUS   ROLES                       AGE     VERSION
server0   Ready    control-plane,etcd,master   6m37s   v1.21.5+rke2r2
server1   Ready    control-plane,etcd,master   79s     v1.21.5+rke2r2
server2   Ready    control-plane,etcd,master   33s     v1.21.5+rke2r2
```

With the control plane boostrapped, we can turn our attention to the worker nodes (agents).  Agent nodes do not need this configuration passing in, so we can just go ahead and join these to the cluster:

```
% for agent in $(for node in agent{0..2} ; do govc vm.ip /42can/vm/$node ; done) ; do
  echo $agent ; done | parallel -v -I% k2sup join --ip % \
  --server-ip $(govc vm.ip /42can/vm/server0) --user nick
```

_NB: The last command uses GNU/parallel to attempt to bootstrap all three worker nodes at the same time._

Finally once these agents nodes have bootstrapped we should see the following:

```
% kubie ctx rke2
% kubectl get nodes
NAME      STATUS   ROLES                       AGE     VERSION
agent0    Ready    <none>                      3m45s   v1.21.5+rke2r2
agent1    Ready    <none>                      3m40s   v1.21.5+rke2r2
agent2    Ready    <none>                      3m46s   v1.21.5+rke2r2
server0   Ready    control-plane,etcd,master   15m     v1.21.5+rke2r2
server1   Ready    control-plane,etcd,master   7m6s    v1.21.5+rke2r2
server2   Ready    control-plane,etcd,master   5m42s   v1.21.5+rke2r2
```

### Installing with a VIP for the Control Plane
k2sup can also deploy [kube-vip](https://kube-vip.io) to present a virtual IP (VIP) for the control plane, providing a fixed-registration address in-line with the RKE2 [high-availability recommendations](https://docs.rke2.io/install/ha/).  First we need to bootstrap the initial server node with two extra options - our chosen VIP address and also the network interface that should be used, and also **we must ensure that this IP address (and any hostnames) are included in the configuration file that RKE2 will use as part of the list of TLS SANs**:

```shell
% cat server-config.yaml
---
node-taint:
  - "CriticalAddonsOnly=true:NoExecute"
tls-san:
  - 192.168.20.200
  - rke2.192.168.20.200.dnsify.me
```

Now run the command to configure a VIP with `192.168.20.200` on my node's primary network interface:

```
% k2sup install --ip $(govc vm.ip /42can/vm/server0) --user nick --local-path ~/.kube/rke2.yaml \
  --context rke2 --config $(pwd)/server-config.yaml \
  --vip 192.168.20.200 --vip-interface eth0
```

After a minute or so I can ping this VIP and also query the Kubernetes API:

```
% while true ; do ping -c 1 192.168.20.200 ; sleep 5 ; done
PING 192.168.20.200 (192.168.20.200) 56(84) bytes of data.
From 192.168.1.1 icmp_seq=1 Destination Host Unreachable

--- 192.168.20.200 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms

PING 192.168.20.200 (192.168.20.200) 56(84) bytes of data.
From 192.168.1.1 icmp_seq=1 Destination Host Unreachable

--- 192.168.20.200 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms

PING 192.168.20.200 (192.168.20.200) 56(84) bytes of data.
64 bytes from 192.168.20.200: icmp_seq=1 ttl=63 time=0.827 ms

--- 192.168.20.200 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.827/0.827/0.827/0.000 ms
```

```
% kubie ctx rke2
% kubectl get nodes -o wide
NAME      STATUS   ROLES                       AGE   VERSION          INTERNAL-IP      EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
server0   Ready    control-plane,etcd,master   45s   v1.21.5+rke2r2   192.168.20.166   <none>        openSUSE Leap 15.3   5.3.18-57-default   containerd://1.4.11-k3s1
```

With my control plane VIP up and my first server responding to requests, I can join the additional server nodes and then my agents.  Note that the for the `--server-ip` option I'm now using my VIP:

```
% for server in server{1..2} ; do
  k2sup join --ip $(govc vm.ip /42can/vm/$server) --server \
  --server-ip 192.168.20.200 --user nick \
  --config $(pwd)/server-config.yaml
done
```

```
% kubectl get nodes
NAME      STATUS   ROLES                       AGE     VERSION
server0   Ready    control-plane,etcd,master   5m23s   v1.21.5+rke2r2
server1   Ready    control-plane,etcd,master   98s     v1.21.5+rke2r2
server2   Ready    control-plane,etcd,master   35s     v1.21.5+rke2r2
```

```
% for agent in $(for node in agent{0..4} ; do govc vm.ip /42can/vm/$node ; done) ; do 
  echo $agent ; done | parallel -v -I% k2sup join --ip % \
  --server-ip 192.168.20.200 --user nick
```

```
% kubectl get nodes
NAME      STATUS   ROLES                       AGE     VERSION
agent0    Ready    <none>                      60s     v1.21.5+rke2r2
agent1    Ready    <none>                      56s     v1.21.5+rke2r2
agent2    Ready    <none>                      54s     v1.21.5+rke2r2
agent3    Ready    <none>                      35s     v1.21.5+rke2r2
agent4    Ready    <none>                      38s     v1.21.5+rke2r2
server0   Ready    control-plane,etcd,master   8m7s    v1.21.5+rke2r2
server1   Ready    control-plane,etcd,master   4m22s   v1.21.5+rke2r2
server2   Ready    control-plane,etcd,master   3m19s   v1.21.5+rke2r2
```


This is an awful fork of k3sup - a light-weight utility to get from zero to KUBECONFIG, originally with K3s but now with [RKE2](https://rke2.io/) instead. All you need is `ssh` access and the `k2sup` binary to get `kubectl` access fairly quickly.

RKE2 is downstream from K3s, but is just about sufficiently different in its installation approach (and probably target audience) that a fork makes sense.

The tool is written in Go and is cross-compiled for Linux, Windows, MacOS and even on Raspberry Pi.

## Use
In my example, I've six virtual machines deployed on vSphere.  I'm using [govc](https://github.com/vmware/govmomi) to query the VM's IP addresses in lieu of DNS, and I have the following server configuration in `server-config.yaml`:

```yaml
tls-san:
  - "rke2.192.168.20.220.dnsify.me"
cni:
  - "cilium"
```

```sh
k2sup install --ip $(govc vm.ip /42can/vm/server0) --user nick --local-path ~/.kube/rke2.yaml \
  --context rke2 --config $(pwd)/server-config.yaml

for server in server{1..2} ; do
  k2sup join --ip $(govc vm.ip /42can/vm/$server) --server \
  --server-ip  $(govc vm.ip /42can/vm/server0) --user nick \
  --config $(pwd)/server-config.yaml
done

for agent in $(for node in agent{0..2} ; do govc vm.ip /42can/vm/$node ; done) ; do 
  echo $agent ; done | parallel -v -I% k2sup join --ip % \
  --server-ip $(govc vm.ip /42can/vm/server0) --user nick
```

_NB: The last command uses GNU/parallel to attempt to bootstrap all three worker nodes at the same time._

Assuming the above runs without error, you should be able to switch Kubernetes context and query your new cluster:

```
$ kubie ctx rke2
$ kubectl get nodes
NAME      STATUS   ROLES                       AGE     VERSION
agent0    Ready    <none>                      3m45s   v1.21.5+rke2r2
agent1    Ready    <none>                      3m40s   v1.21.5+rke2r2
agent2    Ready    <none>                      3m46s   v1.21.5+rke2r2
server0   Ready    control-plane,etcd,master   15m     v1.21.5+rke2r2
server1   Ready    control-plane,etcd,master   7m6s    v1.21.5+rke2r2
server2   Ready    control-plane,etcd,master   5m42s   v1.21.5+rke2r2
```

(I use [kubie](https://github.com/sbstp/kubie) to switch between cluster contexts)
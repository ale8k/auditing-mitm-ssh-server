# SSH Proxy PoC

The requirement is to have an SSH connection go through a "Man in the Middle" SSH 
server and forward requests to both another SSH server and a K8S pod.

We need to audit the commands. This PoC demonstrates this.



HTTP -> HTTPS -> [CONNECT]TUNNEL Websocket (End of line)

HTTP -> HTTPS -> [CONNECT]TUNNEL to SSH# auditing-mitm-ssh-server

# RDS_TP2_Ex2

topoTP1Ex2.py - topologia mininet do TP1

topoTP2.py  - topologia TP2

l4controllerExample.py - exemplo que encontramos na internet, nao estamos a usar mas pode ser util para tirar ideias

l3Controller.py - controlador para os switches l3 e futura firewall

controller1.py - controlador para os switches l2


ryu-manager --ofp-tcp-listen-port [6633,6634] [nome do controlador]  # 6633 para l2 e 6634 para l3
sudo mn --controller=remote --custom [topologia.py] --topo=mytopo

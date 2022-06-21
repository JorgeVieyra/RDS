# RDS

Trabalhos práticos de Redes definidas por Software

TP1 - Controladores Openflow

TP2 - Network Management

TP3 - Data Plane

Conteúdo do TP2:

topoTP1Ex2.py - topologia mininet do TP1

topoTP2.py  - topologia TP2

l3Controller.py - firewall para topologia do Ex2 do TP1

firewall.py - firewall para a topologia do TP2

controller1.py - controlador para os switches l2


Comandos para correr o trabalho:

ryu-manager --ofp-tcp-listen-port [6633,6634] [nome do controlador]  # 6633 para l2 e 6634 para l3


sudo mn --controller=remote --custom [topologia.py] --topo=mytopo


Ex: Correr firewall para topologia do TP1:

ryu-manager --ofp-tcp-listen-port 6633 controller1.py

ryu-manager --ofp-tcp-listen-port 6634 l3Controller.py

sudo mn --controller=remote --custom topoTP1Ex2.py --topo=mytopo




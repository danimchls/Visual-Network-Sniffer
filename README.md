# Sniffer e Visualizador de Tráfego de Rede com Análise de Segurança

Projeto em Python para capturar e visualizar em tempo real o tráfego de rede, com **análise de segurança** integrada: detecção de port scan, SYN flood, ARP spoofing, classificação ICMP, fingerprinting via TTL e estatísticas de top talkers.

Arquitetura orientada a objetos com três classes principais: `Sniffer`, `Visualizer` e `SecurityAnalyzer`.

Utiliza:
- [Scapy](https://scapy.net/) para captura e interpretação de pacotes.
- [Matplotlib](https://matplotlib.org/) para visualização animada dos dados.

---

## Objetivo

Permitir o monitoramento de tráfego de rede local com análise de segurança em tempo real, combinando:
- Gráficos de contagem de pacotes por protocolo (TCP, UDP, ICMP, ARP) ao longo do tempo;
- Alertas de segurança baseados em interpretação de cabeçalhos (port scan, SYN flood, ARP spoof);
- Estatísticas de tráfego (top IPs, top portas, tipos ICMP, distribuição de TTL).

---

## Visão Geral

O sistema possui três módulos principais, cada um com uma classe central:

| Módulo | Classe | Descrição |
|---|---|---|
| **sniffer.py** | `Sniffer` | Captura pacotes com Scapy, contabiliza por protocolo e encaminha ao analisador de segurança |
| **analyzer.py** | `SecurityAnalyzer` | Analisa cabeçalhos de pacotes para detectar ameaças e extrair estatísticas de segurança |
| **visualizer.py** | `Visualizer` | Exibe gráfico animado com contagens de protocolos, alertas de segurança, top IPs/portas, tipos ICMP e TTL |

### Classes do analyzer.py

| Detector | O que faz | Protocolo |
|---|---|---|
| **PortScanDetector** | Detecta varreduras de porta (múltiplos SYN para portas distintas) | TCP |
| **SynFloodDetector** | Detecta ataques SYN flood (conexões meio-abertas excessivas) | TCP |
| **ArpSpoofDetector** | Detecta ARP spoofing (replies ARP não solicitados) | ARP |
| **IcmpAnalyzer** | Classifica pacotes ICMP por tipo/código (Echo, Unreachable, TTL Exceeded, etc.) | ICMP |
| **TopTalkers** | Identifica IPs de origem e portas destino mais frequentes | IP + TCP |
| **TtlAnalyzer** | Analisa distribuição de TTL e infere sistema operacional | IP |

O gráfico mostra:
- Contagem de pacotes por protocolo em janela deslizante.
- Painel com os IPs de origem mais ativos.
- Painel com alertas de segurança, tipos ICMP, distribuição de TTL e top portas destino.

---

## Instalação

```bash
pip install -r requirements.txt
```

Alternativa (instalação manual):

```bash
pip install scapy matplotlib
```

---

## Como Usar

### Gerar PCAPs de teste (opcional, para demonstração)

```bash
python3 generate_test_pcaps.py
```

Serão gerados 5 arquivos em `test_pcaps/`:

| Arquivo | Cenário |
|---|---|
| `port_scan.pcap` | Varredura de 20 portas TCP |
| `syn_flood.pcap` | 300 SYN sem handshake |
| `arp_spoof.pcap` | 2 ARP replies não solicitados |
| `icmp_variety.pcap` | 11 pacotes ICMP com 9 tipos distintos |
| `normal_traffic.pcap` | Tráfego legítimo (HTTP, DNS, SSH, HTTPS, ARP) |

```

### Modo Captura ao Vivo 

```bash
# Captura ao vivo (requer sudo)
sudo python3 main.py --live
```

### Modo Captura Simulação

```bash
# Listar PCAPs disponíveis
python3 main.py --list
# Simular tráfego a partir de um PCAP (índice ou caminho)
python3 main.py --pcap 1 --pps 20 # port_scan.pcap a 20 pkt/s
python3 main.py --pcap test_pcaps/syn_flood.pcap --pps 50
# Usar o primeiro PCAP disponível automaticamente (modo padrão)
python3 main.py

```

### Uso direto do analisador (sem visualização)

```python
from sniffer import Sniffer
from scapy.all import rdpcap

sniffer = Sniffer()
packets = rdpcap("test_pcaps/port_scan.pcap")
for pkt in packets:
    sniffer.process_packet(pkt)

results = sniffer.analyzer.snapshot()
print("Alertas:", results['alerts'])
print("ICMP stats:", results['icmp_stats'])
print("Top sources:", results['top_sources'])
print("TTL distribution:", results['ttl_distribution'])
```

---

---

## Requisitos

- Python 3.6+
- Privilégios de root (apenas para captura ao vivo)
- Linux / macOS (modo live requer suporte a raw sockets)

---


# Packet Sniffer — Detector de Vulnerabilidades e Port Scanning

Ferramenta educativa em Python para captura e análise de pacotes de rede com detecção de protocolos inseguros e técnicas de port scanning. Desenvolvida como projeto acadêmico na Universidade de Caxias do Sul (UCS), baseada no projeto open source [VulnerablePackages](https://github.com/MaridianeLugaresi/VulnerablePackages).

> **Aviso:** Este software destina-se exclusivamente a fins educativos e de pesquisa. Execute apenas em redes e ambientes de teste nos quais você possui autorização explícita. Os autores não se responsabilizam por uso indevido.

---

## Funcionalidades

### Detecção de protocolos inseguros (L7)
- **HTTP** — identifica payloads com campos sensíveis (usuário, senha, *password*)
- **FTP** — detecta endereços de e-mail expostos em argumentos de comandos

### Detecção de port scanning (L3/L4) — nova funcionalidade
- **Time Window Scan** — detecta varredura volumétrica: mais de N portas únicas por IP de origem em uma janela deslizante de 60 segundos (threshold configurável)
- **Half-Open Scan (SYN sem ACK)** — rastreia conexões TCP iniciadas (SYN) que não completam o handshake em até 5 segundos
- **NULL Scan** — pacotes TCP com campo de flags igual a `0x00` (nenhuma flag ativa)
- **FIN Scan** — pacotes com flag FIN ativa e ACK inativa (`flags & 0x11 == 0x01`)
- **XMAS Scan** — pacotes com FIN + PSH + URG simultaneamente ativados (`flags & 0x29 == 0x29`)

### Dashboard
- Interface web interativa (Dash + Plotly) com atualização automática a cada 2 segundos
- Gráfico de barras por categoria de ataque/vulnerabilidade
- Listagem detalhada de alertas ao clicar em cada barra (IP de origem, tipo de ataque, portas visadas)

---

## Requisitos

- Python 3.8 ou superior
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) instalado e acessível no PATH (dependência do pyshark)

---

## Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/Bwavrita/packet-sniffer.git
cd packet-sniffer

# 2. Crie e ative um ambiente virtual (recomendado)
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate          # Windows
.venv\Scripts\activate.bat      # Windows (cmd)

# 3. Instale as dependências
pip install -r requirements.txt

sudo apt install tshark
```

---

## Uso

### Modo debug (recomendado para teste)

Processa os arquivos `.pcapng` incluídos no repositório sem precisar de permissões de root.

```bash
python -m src
```

Por padrão, `DEBUG = False` em `src/__main__.py` e o arquivo de captura configurado é `PORT_SCAN_4000_PORTS.pcapng`, com threshold de 3000 portas.

Para testar o arquivo completo de port scan:

```python
# Em src/__main__.py:
sniffer = VulnerableSniffer(path_file=PATH, port_threshold=4000, interface='wlp0s20f3')
sniffer_thread = threading.Thread(target=sniffer.run_debug, daemon=True)
```

### Modo ao vivo

Captura pacotes em tempo real. Edite `src/__main__.py`:

```python
DEBUG = False
```

Altere também o nome da interface de rede (padrão: `wlp0s20f3`):

```python
sniffer = VulnerableSniffer(path_file=PATH, interface='eth0')
```

```bash
sudo python -m src
```

Acesse o dashboard em **http://localhost:8050** após iniciar.

---

## Estrutura do projeto

```
packet-sniffer/
├── src/
│   ├── __init__.py
│   ├── __main__.py               # Ponto de entrada; alterna entre modo ao vivo e debug
│   ├── models/
│   │   ├── __init__.py
│   │   ├── vulnerable_sniffer.py # Captura, detecção L7 (HTTP/FTP) e L3/L4 (port scan)
│   │   └── ui.py                 # Dashboard Dash/Plotly
│   └── pcap_files/
│       ├── PORT_SCAN_4000_PORTS.pcapng   # Captura de varredura ~4000 portas (teste rápido)
│       └── PORT_SCAN_ALL_PORTS.pcapng    # Captura de varredura completa de portas
├── requirements.txt
└── README.md
```

---

## Dependências

| Pacote | Versão | Uso |
|---|---|---|
| pyshark | 0.6 | Captura e parse de pacotes via TShark |
| dash | 4.1.0 | Framework do dashboard web |
| dash-bootstrap-components | 2.0.4 | Estilização Bootstrap para o Dash |
| plotly | 6.7.0 | Gráficos interativos |

---

## Licença

Este projeto é um fork de [VulnerablePackages](https://github.com/MaridianeLugaresi/VulnerablePackages).
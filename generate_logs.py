"""
generate_logs.py
----------------
Script de geração de dados sintéticos para o projeto Threat Intel Analyzer.

Gera um arquivo 'server_logs.csv' com 50 linhas simulando logs de um servidor,
incluindo IPs maliciosos conhecidos para fins de testes de inteligência de ameaças.

Dependências:
    pip install pandas
"""

import pandas as pd
import random
from datetime import datetime, timedelta

# =============================================================================
# CONFIGURAÇÕES GERAIS
# =============================================================================

NUM_REGISTROS = 50
OUTPUT_FILE = "server_logs.csv"

# Seed para reprodutibilidade (remova para resultados completamente aleatórios)
random.seed(42)

# =============================================================================
# LISTAS DE DADOS PARA GERAÇÃO ALEATÓRIA
# =============================================================================

# IPs maliciosos/suspeitos conhecidos que DEVEM aparecer nos logs
IPS_MALICIOSOS = [
    "185.153.196.22",  # IP arbitrário suspeito
    "45.227.255.206",  # IP arbitrário suspeito
    "194.165.16.11",   # IP arbitrário suspeito
    "8.8.8.8",         # Google DNS (frequentemente usado em testes/varreduras)
]

# Portas de destino comuns em ambientes corporativos
PORTAS_DESTINO = [
    80,    # HTTP
    443,   # HTTPS
    22,    # SSH
    3389,  # RDP
    8080,  # HTTP Alternativo
    21,    # FTP
]

# Ações possíveis registradas pelo firewall/IDS
ACOES = ["ALLOW", "DENY", "DROP"]

# Pesos de probabilidade para as ações (ALLOW mais comum em redes reais)
PESOS_ACOES = [0.55, 0.25, 0.20]


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def gerar_ip_aleatorio() -> str:
    """Gera um endereço IPv4 aleatório no formato X.X.X.X."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def gerar_timestamp_aleatorio(dias_atras: int = 7) -> datetime:
    """
    Gera um timestamp aleatório dentro de um intervalo de dias passados.

    Args:
        dias_atras: Número de dias no passado para o intervalo de geração.

    Returns:
        Objeto datetime com data e hora aleatórios.
    """
    agora = datetime.now()
    inicio = agora - timedelta(days=dias_atras)
    delta_total_segundos = int(timedelta(days=dias_atras).total_seconds())
    segundos_aleatorios = random.randint(0, delta_total_segundos)
    return inicio + timedelta(seconds=segundos_aleatorios)


def gerar_lista_ips(num_total: int, ips_forcados: list) -> list:
    """
    Gera uma lista de IPs de origem misturando IPs aleatórios com IPs maliciosos conhecidos.

    Os IPs maliciosos são inseridos em posições aleatórias para simular
    tráfego real onde ameaças estão dispersas entre acessos legítimos.

    Args:
        num_total: Número total de IPs a gerar.
        ips_forcados: Lista de IPs que DEVEM aparecer na lista final.

    Returns:
        Lista embaralhada com IPs aleatórios e os IPs forçados incluídos.
    """
    # Gera IPs aleatórios para preencher o restante das vagas
    num_aleatorios = num_total - len(ips_forcados)
    ips_aleatorios = [gerar_ip_aleatorio() for _ in range(num_aleatorios)]

    # Combina IPs aleatórios com os IPs maliciosos conhecidos
    lista_completa = ips_aleatorios + ips_forcados

    # Embaralha para que os maliciosos não fiquem agrupados no final
    random.shuffle(lista_completa)
    return lista_completa


# =============================================================================
# GERAÇÃO DOS DADOS
# =============================================================================

print(f"[*] Iniciando geração de {NUM_REGISTROS} registros de log...")

# Gera a lista de IPs de origem com maliciosos incluídos
source_ips = gerar_lista_ips(NUM_REGISTROS, IPS_MALICIOSOS)

# Monta o dicionário com todas as colunas do CSV
dados = {
    "timestamp": [
        gerar_timestamp_aleatorio(dias_atras=7).strftime("%Y-%m-%d %H:%M:%S")
        for _ in range(NUM_REGISTROS)
    ],
    "source_ip": source_ips,
    "destination_port": [
        random.choice(PORTAS_DESTINO) for _ in range(NUM_REGISTROS)
    ],
    "action": [
        random.choices(ACOES, weights=PESOS_ACOES, k=1)[0]
        for _ in range(NUM_REGISTROS)
    ],
}

# Cria o DataFrame com pandas
df = pd.DataFrame(dados)

# Ordena os registros por timestamp (cronologicamente)
df.sort_values(by="timestamp", inplace=True)
df.reset_index(drop=True, inplace=True)

# =============================================================================
# EXPORTAÇÃO E VALIDAÇÃO
# =============================================================================

# Salva o DataFrame como arquivo CSV
df.to_csv(OUTPUT_FILE, index=False)

print(f"[+] Arquivo '{OUTPUT_FILE}' gerado com sucesso!")
print(f"[+] Total de registros: {len(df)}")
print(f"[+] Período de cobertura: {df['timestamp'].min()} → {df['timestamp'].max()}")
print(f"\n[*] IPs maliciosos incluídos ({len(IPS_MALICIOSOS)}):")
for ip in IPS_MALICIOSOS:
    contagem = df[df["source_ip"] == ip].shape[0]
    print(f"    - {ip}: {contagem} ocorrência(s)")

print("\n[*] Prévia dos primeiros 5 registros:")
print(df.head().to_string(index=False))

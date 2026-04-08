"""
analyzer.py
-----------
Motor de análise de Threat Intelligence para o projeto Threat Intel Analyzer.

Lê o arquivo 'server_logs.csv', extrai IPs únicos e os enriquece com dados
de duas fontes distintas de inteligência de ameaças:

  1. VirusTotal API v3  — reputação e votos maliciosos do IP
  2. Shodan API         — infraestrutura do atacante (OS, org, portas abertas)

As chaves de API são carregadas exclusivamente via arquivo '.env' e nunca
devem ser hardcodadas no código-fonte.

Dependências:
    pip install pandas python-dotenv requests shodan
"""

import time
import os
import requests
import shodan
import pandas as pd
from dotenv import load_dotenv

# =============================================================================
# CONFIGURAÇÕES E CONSTANTES
# =============================================================================

# Carrega variáveis do arquivo .env no diretório atual
load_dotenv()

# Chaves de API lidas do ambiente (nunca hardcodadas)
VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# VirusTotal: conta Free permite 4 requisições/minuto
# Usamos 15s de intervalo para ficar bem abaixo do limite e evitar bloqueios
VT_RATE_LIMIT_SLEEP = 15  # segundos entre cada chamada ao VT

# Endpoint da API v3 do VirusTotal para análise de IPs
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


# =============================================================================
# CLASSE PRINCIPAL: ThreatIntelAnalyzer
# =============================================================================

class ThreatIntelAnalyzer:
    """
    Motor de enriquecimento de IPs com inteligência de ameaças.

    Combina dados de reputação do VirusTotal com dados de infraestrutura
    do Shodan para produzir um DataFrame analítico consolidado.
    """

    def __init__(self, log_file: str = "server_logs.csv"):
        """
        Inicializa o analisador e valida as dependências críticas.

        Args:
            log_file: Caminho para o arquivo CSV de logs do servidor.

        Raises:
            FileNotFoundError: Se o arquivo de logs não for encontrado.
            EnvironmentError: Se as chaves de API não estiverem configuradas.
        """
        if not os.path.exists(log_file):
            raise FileNotFoundError(
                f"[ERRO] Arquivo de logs não encontrado: '{log_file}'. "
                "Execute 'generate_logs.py' primeiro."
            )

        if not VT_API_KEY:
            raise EnvironmentError(
                "[ERRO] VT_API_KEY não encontrada. "
                "Configure o arquivo .env com sua chave do VirusTotal."
            )

        if not SHODAN_API_KEY:
            raise EnvironmentError(
                "[ERRO] SHODAN_API_KEY não encontrada. "
                "Configure o arquivo .env com sua chave do Shodan."
            )

        self.log_file = log_file
        self.shodan_client = shodan.Shodan(SHODAN_API_KEY)

        print(f"[+] ThreatIntelAnalyzer inicializado.")
        print(f"[+] Fonte de logs: '{self.log_file}'")

    # -------------------------------------------------------------------------
    # MÉTODO: Enriquecimento via VirusTotal
    # -------------------------------------------------------------------------

    def _enrich_virustotal(self, ip: str) -> int:
        """
        Consulta a API v3 do VirusTotal para obter os votos maliciosos de um IP.

        Implementa sleep para respeitar o rate limit da conta Free (4 req/min).
        Em caso de qualquer falha (rede, auth, IP não encontrado), retorna -1
        como sentinela para indicar "dado indisponível".

        Args:
            ip: Endereço IPv4 a ser consultado.

        Returns:
            Número de votos maliciosos (int) ou -1 em caso de erro.
        """
        print(f"  [VT]  Consultando {ip}...", end=" ", flush=True)

        # Sleep ANTES da requisição para respeitar o rate limit
        time.sleep(VT_RATE_LIMIT_SLEEP)

        try:
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(
                VT_IP_URL.format(ip=ip),
                headers=headers,
                timeout=10
            )

            # Levanta exceção para códigos HTTP 4xx e 5xx
            response.raise_for_status()

            data = response.json()

            # Navega pela estrutura da resposta da API v3
            # Caminho: data -> attributes -> last_analysis_stats -> malicious
            malicious_votes = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )

            print(f"votos maliciosos: {malicious_votes}")
            return malicious_votes

        except requests.exceptions.HTTPError as e:
            # HTTP 404: IP não indexado pelo VT; HTTP 401: chave inválida
            print(f"Erro HTTP {e.response.status_code}")
            return -1

        except requests.exceptions.ConnectionError:
            print("Erro de conexão (sem internet?)")
            return -1

        except requests.exceptions.Timeout:
            print("Timeout na requisição")
            return -1

        except Exception as e:
            # Captura genérica para não interromper o pipeline
            print(f"Erro inesperado: {e}")
            return -1

    # -------------------------------------------------------------------------
    # MÉTODO: Enriquecimento via Shodan
    # -------------------------------------------------------------------------

    def _enrich_shodan(self, ip: str) -> dict:
        """
        Consulta a API do Shodan para obter detalhes de infraestrutura de um IP.

        O Shodan frequentemente não possui dados para IPs privados, internos
        ou recentemente adicionados. Todos esses casos são tratados
        graciosamente, retornando "Unknown" para campos ausentes.

        Args:
            ip: Endereço IPv4 a ser consultado.

        Returns:
            Dicionário com chaves: 'attacker_os', 'attacker_org', 'open_ports'.
        """
        # Resultado padrão: usado quando o Shodan não tem dados
        resultado_padrao = {
            "attacker_os": "Unknown",
            "attacker_org": "Unknown",
            "open_ports": [],
        }

        print(f"  [SHD] Consultando {ip}...", end=" ", flush=True)

        try:
            host_info = self.shodan_client.host(ip)

            resultado = {
                # OS pode ser None no Shodan; usamos "Unknown" como fallback
                "attacker_os": host_info.get("os") or "Unknown",
                "attacker_org": host_info.get("org", "Unknown"),
                # Portas: lista de inteiros retornada diretamente pelo Shodan
                "open_ports": host_info.get("ports", []),
            }

            print(
                f"org='{resultado['attacker_org']}', "
                f"os='{resultado['attacker_os']}', "
                f"ports={resultado['open_ports']}"
            )
            return resultado

        except shodan.APIError as e:
            # "No information available for that IP" é o erro mais comum
            # Também captura erros de quota e autenticação
            print(f"Shodan APIError: {e}")
            return resultado_padrao

        except Exception as e:
            print(f"Erro inesperado: {e}")
            return resultado_padrao

    # -------------------------------------------------------------------------
    # MÉTODO PRINCIPAL: Análise completa
    # -------------------------------------------------------------------------

    def analyze(self) -> pd.DataFrame:
        """
        Executa o pipeline completo de análise de Threat Intelligence.

        Fluxo:
          1. Lê e parseia o CSV de logs
          2. Extrai IPs únicos de origem
          3. Enriquece cada IP com VirusTotal + Shodan
          4. Consolida os resultados em um DataFrame final
          5. Salva o resultado em 'threat_intel_report.csv'

        Returns:
            DataFrame consolidado com colunas originais e de enriquecimento.
        """
        # --- ETAPA 1: Leitura dos logs ---
        print(f"\n{'='*60}")
        print("  ETAPA 1: Carregando logs")
        print(f"{'='*60}")

        df_logs = pd.read_csv(self.log_file)
        print(f"[+] {len(df_logs)} registros carregados de '{self.log_file}'")

        # --- ETAPA 2: Extração de IPs únicos ---
        print(f"\n{'='*60}")
        print("  ETAPA 2: Extraindo IPs únicos")
        print(f"{'='*60}")

        ips_unicos = df_logs["source_ip"].unique().tolist()
        print(f"[+] {len(ips_unicos)} IPs únicos encontrados para análise")

        # --- ETAPA 3: Enriquecimento de cada IP ---
        print(f"\n{'='*60}")
        print("  ETAPA 3: Enriquecimento de Threat Intelligence")
        print(f"{'='*60}")
        print(
            f"[!] Analisando {len(ips_unicos)} IPs. "
            f"Aguarde ({VT_RATE_LIMIT_SLEEP}s de intervalo entre consultas VT)...\n"
        )

        resultados_enriquecimento = []

        for idx, ip in enumerate(ips_unicos, start=1):
            print(f"[{idx}/{len(ips_unicos)}] Analisando IP: {ip}")

            # Consulta paralela conceitual: VT primeiro (com sleep interno),
            # depois Shodan (sem custo de rate limit para o pipeline)
            malicious_votes = self._enrich_virustotal(ip)
            shodan_data = self._enrich_shodan(ip)

            resultados_enriquecimento.append({
                "source_ip": ip,
                "malicious_votes": malicious_votes,
                "attacker_org": shodan_data["attacker_org"],
                "attacker_os": shodan_data["attacker_os"],
                # Converte lista de portas para string legível (ex: "22, 80, 443")
                "open_ports": ", ".join(map(str, shodan_data["open_ports"]))
                              if shodan_data["open_ports"] else "None",
            })
            print()

        # --- ETAPA 4: Consolidação ---
        print(f"\n{'='*60}")
        print("  ETAPA 4: Consolidando resultados")
        print(f"{'='*60}")

        df_intel = pd.DataFrame(resultados_enriquecimento)

        # Merge: une os dados de enriquecimento ao DataFrame original de logs
        df_final = df_logs.merge(df_intel, on="source_ip", how="left")

        # --- ETAPA 5: Exportação ---
        output_file = "threat_intel_report.csv"
        df_final.to_csv(output_file, index=False)

        print(f"[+] Relatório final salvo em '{output_file}'")
        print(f"[+] Shape do DataFrame consolidado: {df_final.shape}")

        # Resumo de IPs de maior risco
        print(f"\n{'='*60}")
        print("  RESUMO: Top IPs por votos maliciosos")
        print(f"{'='*60}")

        df_resumo = (
            df_intel[df_intel["malicious_votes"] > 0]
            .sort_values("malicious_votes", ascending=False)
        )

        if df_resumo.empty:
            print("[~] Nenhum IP com votos maliciosos > 0 encontrado.")
        else:
            print(df_resumo[["source_ip", "malicious_votes", "attacker_org"]].to_string(index=False))

        return df_final


# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

if __name__ == "__main__":
    analyzer = ThreatIntelAnalyzer(log_file="server_logs.csv")
    df_resultado = analyzer.analyze()

    print(f"\n[✓] Análise concluída. {len(df_resultado)} registros processados.")
    print("\n[*] Prévia do relatório final:")
    print(df_resultado.head(10).to_string(index=False))

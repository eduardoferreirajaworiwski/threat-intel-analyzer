"""
app.py
------
Dashboard de Threat Intelligence — Threat Intel Analyzer

Frontend Streamlit com tema cybersecurity dark para visualização de logs
de servidor enriquecidos com dados de VirusTotal e Shodan.

Dependências:
    pip install streamlit plotly pandas python-dotenv requests shodan
"""

import os
import os
import io
import time
import tempfile

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

import column_detector
import pdf_generator

# 'override=True' garante que se rodar o Streamlit e depois editar o .env, ele atualiza!
load_dotenv(override=True)

# =============================================================================
# CONFIGURAÇÃO DA PÁGINA — deve ser a PRIMEIRA chamada Streamlit
# =============================================================================

st.set_page_config(
    page_title="Threat Intel Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# =============================================================================
# HELPERS
# =============================================================================

def metric_card(label: str, value, color: str, icon: str, delta: str = "") -> str:
    """Gera o HTML de um metric card estilizado."""
    return f"""
    <div class="metric-card {color}">
      <span class="metric-icon">{icon}</span>
      <div class="metric-label">{label}</div>
      <div class="metric-value {color}">{value}</div>
      {'<div class="metric-delta">' + delta + '</div>' if delta else ''}
    </div>
    """


def check_api_keys() -> tuple[bool, list[str]]:
    """Verifica quais chaves de API estão configuradas."""
    missing = []
    vt = os.getenv("VT_API_KEY")
    sh = os.getenv("SHODAN_API_KEY")
    
    if not vt or vt == "sua_chave_virustotal_aqui":
        missing.append("VT_API_KEY")
    if not sh or sh == "sua_chave_shodan_aqui":
        missing.append("SHODAN_API_KEY")
        
    return len(missing) == 0, missing


def highlight_malicious(row: pd.Series) -> list[str]:
    """
    Aplica estilo vermelho às linhas onde malicious_votes > 0.
    Compatível com pandas Styler via df.apply(axis=1).
    """
    if "malicious_votes" in row.index:
        votes = row["malicious_votes"]
        try:
            if pd.notna(votes) and float(votes) > 0:
                return ["background-color: rgba(255,71,87,0.15); color: #ff6b6b;"] * len(row)
        except (ValueError, TypeError):
            pass
    return [""] * len(row)


@st.cache_data(show_spinner=False)
def load_csv(source: str | bytes) -> pd.DataFrame:
    """Carrega CSV de arquivo local ou upload, com cache."""
    if isinstance(source, bytes):
        return pd.read_csv(io.BytesIO(source))
    return pd.read_csv(source)


def run_analysis(log_file_path: str) -> pd.DataFrame | None:
    """
    Executa o ThreatIntelAnalyzer com feedback visual de progresso.
    Retorna None se a análise falhar.
    """
    # Importação local para evitar erro de módulos ausentes no carregamento inicial
    try:
        from analyzer import ThreatIntelAnalyzer
    except ImportError as e:
        st.error(f"❌ Erro ao importar analyzer.py: {e}")
        return None

    try:
        analyzer = ThreatIntelAnalyzer(log_file=log_file_path)
    except EnvironmentError as e:
        st.error(str(e))
        return None
    except FileNotFoundError as e:
        st.error(str(e))
        return None

    # Lê IPs únicos para estimar o tempo
    df_raw = pd.read_csv(log_file_path)
    ips = df_raw["source_ip"].unique().tolist()
    total = len(ips)
    rate_limit_sec = 15

    st.info(
        f"⏱️ Analisando **{total} IPs únicos**. "
        f"Tempo estimado: ~{total * rate_limit_sec // 60} min {total * rate_limit_sec % 60} s "
        f"(rate limit VirusTotal: {rate_limit_sec}s/req)"
    )

    progress_bar = st.progress(0, text="Iniciando análise de Threat Intelligence...")
    status_box = st.empty()

    resultados = []
    VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    VT_KEY = os.getenv("VT_API_KEY")
    SHODAN_KEY = os.getenv("SHODAN_API_KEY")

    import requests, shodan as shodan_lib

    shodan_client = shodan_lib.Shodan(SHODAN_KEY)

    for idx, ip in enumerate(ips):
        status_box.info(f"🔍 [{idx+1}/{total}] Consultando: `{ip}`")

        # VirusTotal
        time.sleep(rate_limit_sec)
        malicious_votes = -1
        try:
            resp = requests.get(VT_URL.format(ip=ip), headers={"x-apikey": VT_KEY}, timeout=10)
            resp.raise_for_status()
            malicious_votes = (
                resp.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )
        except Exception:
            pass

        # Shodan
        attacker_os, attacker_org, open_ports = "Unknown", "Unknown", "None"
        try:
            host = shodan_client.host(ip)
            attacker_os = host.get("os") or "Unknown"
            attacker_org = host.get("org", "Unknown")
            ports = host.get("ports", [])
            open_ports = ", ".join(map(str, ports)) if ports else "None"
        except Exception:
            pass

        resultados.append({
            "source_ip": ip,
            "malicious_votes": malicious_votes,
            "attacker_org": attacker_org,
            "attacker_os": attacker_os,
            "open_ports": open_ports,
        })

        progress_bar.progress((idx + 1) / total, text=f"Analisado {idx+1}/{total} IPs...")

    df_intel = pd.DataFrame(resultados)
    df_final = df_raw.merge(df_intel, on="source_ip", how="left")
    df_final.to_csv("threat_intel_report.csv", index=False)

    progress_bar.progress(1.0, text="✅ Análise concluída!")
    status_box.empty()

    return df_final


# =============================================================================
# SIDEBAR
# =============================================================================

# Tratamento do redirecionamento após a Análise Completa terminar
if st.session_state.pop("_redirect_to_enriched", False):
    st.session_state["data_source_radio"] = "Usar arquivo local"
    st.session_state["selected_local_file"] = "📊 Relatório enriquecido (threat_intel_report.csv)"

with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 1.5rem 0;">
      <div style="font-size:2.5rem;">🛡️</div>
      <div style="color:#00ff88; font-weight:700; font-size:1rem; letter-spacing:0.5px;">
        THREAT INTEL
      </div>
      <div style="color:#2d3748; font-size:0.7rem; font-family:'JetBrains Mono',monospace;">
        v1.0.0 — SecOps Dashboard
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📂 Fonte de Dados")

    if "data_source_radio" not in st.session_state:
        st.session_state["data_source_radio"] = "Usar arquivo local"

    data_source = st.radio(
        "Selecione a origem dos dados:",
        options=["Usar arquivo local", "Upload de CSV"],
        help="Use o arquivo gerado pelo generate_logs.py ou faça upload de um CSV personalizado.",
        key="data_source_radio"
    )

    uploaded_df = None

    if data_source == "Upload de CSV":
        uploaded_file = st.file_uploader(
            "Arraste ou selecione o CSV",
            type=["csv"],
            help="O CSV deve conter as colunas: timestamp, source_ip, destination_port, action",
        )
        if uploaded_file:
            raw_df = load_csv(uploaded_file.read())
            mapping, info = column_detector.auto_map_columns(raw_df)
            uploaded_df = column_detector.normalize_dataframe(raw_df, mapping)
            warnings_list = column_detector.validate_dataframe(uploaded_df, mapping)
            for w in warnings_list:
                st.warning(w)
            st.success(f"✅ {len(uploaded_df)} registros carregados (Com autodetect de colunas)")
    else:
        local_files = {
            "📊 Relatório enriquecido (threat_intel_report.csv)": "threat_intel_report.csv",
            "📋 Logs brutos (server_logs.csv)": "server_logs.csv",
        }
        
        if "selected_local_file" not in st.session_state:
            st.session_state["selected_local_file"] = "📋 Logs brutos (server_logs.csv)"

        selected_local = st.selectbox(
            "Arquivo local:", 
            list(local_files.keys()),
            key="selected_local_file"
        )
        local_path = local_files[selected_local]

        if os.path.exists(local_path):
            raw_df = load_csv(local_path)
            mapping, info = column_detector.auto_map_columns(raw_df)
            uploaded_df = column_detector.normalize_dataframe(raw_df, mapping)
            warnings_list = column_detector.validate_dataframe(uploaded_df, mapping)
            for w in warnings_list:
                st.warning(w)
            st.success(f"✅ {len(uploaded_df)} registros carregados")
        else:
            st.warning(f"⚠️ `{local_path}` não encontrado. Execute `generate_logs.py` primeiro.")

    st.markdown("---")
    st.markdown("### ⚙️ Análise de Threat Intel")

    api_ok, missing_keys = check_api_keys()

    if not api_ok:
        st.warning(f"⚠️ Chaves ausentes no `.env`:\n**{', '.join(missing_keys)}**")
        st.caption("Configure o arquivo `.env` para habilitar o enriquecimento de IPs.")
    else:
        st.success("🔑 APIs configuradas e prontas")

    run_analysis_btn = st.button(
        "🚀 Executar Análise Completa",
        disabled=not api_ok or uploaded_df is None,
        help="Enriquece cada IP único com dados do VirusTotal e Shodan.",
    )

    st.markdown("---")
    st.markdown("### ℹ️ Sobre")
    st.caption(
        "Threat Intel Analyzer enriquece logs de servidor com dados de "
        "reputação (VirusTotal) e infraestrutura de atacantes (Shodan)."
    )


# =============================================================================
# ÁREA PRINCIPAL
# =============================================================================

# Cabeçalho
st.markdown("""
<div class="dash-header">
  <h1 class="dash-title">🛡️ Threat Intel Analyzer</h1>
  <p class="dash-subtitle">$ real-time network threat intelligence dashboard // powered by VirusTotal + Shodan</p>
</div>
""", unsafe_allow_html=True)

# ── Sem dados carregados ──────────────────────────────────────────────────────
if uploaded_df is None:
    st.markdown("""
    <div style="text-align:center; padding: 5rem 2rem;">
      <div style="font-size: 4rem; margin-bottom: 1rem;">📡</div>
      <h2 style="color: #2d3748; font-weight:700;">Nenhum dado carregado</h2>
      <p style="color: #1a2234; font-family:'JetBrains Mono',monospace; font-size:0.85rem;">
        Use a sidebar para selecionar ou fazer upload de um arquivo CSV de logs.
      </p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

df = uploaded_df.copy()

# ── Execução da análise (quando botão é pressionado) ─────────────────────────
if run_analysis_btn:
    # Remove colunas antigas de enriquecimento para evitar sufixos _x e _y em análises re-aplicadas
    colunas_intel = ["malicious_votes", "attacker_org", "attacker_os", "open_ports"]
    for col in colunas_intel:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    # Usa um arquivo temporário seguro para evitar Race Conditions (Segurança) e não sobrescrever o log original
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name
        df.to_csv(tmp_path, index=False)

    with st.spinner(""):
        result = run_analysis(tmp_path)
    
    # Limpeza segura do arquivo temporário
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    if result is not None:
        df = result
        st.success("✅ Análise concluída! Relatório salvo em `threat_intel_report.csv`")
        # Seta a flag de redirecionamento para o próximo loop (evita StreamlitAPIException)
        st.session_state["_redirect_to_enriched"] = True
        st.rerun()

# ── Detecta se temos dados enriquecidos ──────────────────────────────────────
has_intel = "malicious_votes" in df.columns

if not has_intel:
    st.info(
        "ℹ️ Exibindo dados brutos de logs. "
        "Para ver o enriquecimento de Threat Intelligence, execute a análise completa na sidebar."
    )
else:
    pdf_bytes = pdf_generator.generate_pdf_report(df)
    st.download_button(
        label="📄 Exportar Relatório PDF",
        data=pdf_bytes,
        file_name=f"threat_intel_report_{int(time.time())}.pdf",
        mime="application/pdf",
    )

st.markdown("## Visão Geral")

total_ips = df["source_ip"].nunique()
total_registros = len(df)
deny_count = int((df["action"] == "DENY").sum()) + int((df["action"] == "DROP").sum())

if has_intel:
    mal_df = df.groupby("source_ip")["malicious_votes"].max().reset_index()
    malicious_ips = int((mal_df["malicious_votes"] > 0).sum())
else:
    malicious_ips = "—"

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        label="🌐 IPs Únicos Analisados", 
        value=total_ips, 
        delta=f"{total_registros} eventos no total",
        delta_color="off"
    )

with col2:
    st.metric(
        label="🚨 IPs Maliciosos", 
        value=malicious_ips if has_intel else "—",
        delta="Baseado do VT" if has_intel else "Execute análise",
        delta_color="off" if not has_intel else "inverse"
    )

with col3:
    st.metric(
        label="🔒 Ações Bloqueadas", 
        value=deny_count,
        delta=f"{deny_count/total_registros*100:.1f}% do tráfego total",
        delta_color="off"
    )

st.divider()

# =============================================================================
# SEÇÃO 2 — GRÁFICOS
# =============================================================================

chart_col, dist_col = st.columns([3, 2])

# ── Gráfico de barras: portas mais atacadas ───────────────────────────────────
with chart_col:
    st.markdown("### 🎯 Portas de Destino Mais Atacadas")

    port_counts = (
        df.groupby("destination_port")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    # Mapeamento de nomes de serviços comuns
    port_names = {80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 8080: "HTTP-Alt", 21: "FTP"}
    port_counts["service"] = port_counts["destination_port"].map(
        lambda p: f"{p} ({port_names.get(p, 'Unknown')})"
    )

    fig_ports = go.Figure(
        go.Bar(
            x=port_counts["service"],
            y=port_counts["count"],
            marker=dict(
                color=port_counts["count"],
                colorscale=[[0, "#1a2234"], [0.5, "#6366f1"], [1.0, "#00ff88"]],
                showscale=False,
                line=dict(color="rgba(0,255,136,0.2)", width=1),
            ),
            text=port_counts["count"],
            textposition="outside",
            textfont=dict(color="#a0aec0", size=12, family="JetBrains Mono"),
            hovertemplate="<b>%{x}</b><br>Eventos: %{y}<extra></extra>",
        )
    )

    fig_ports.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#a0aec0"),
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(
            showgrid=False,
            tickfont=dict(size=11, color="#4a5568"),
            linecolor="rgba(255,255,255,0.06)",
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255,255,255,0.04)",
            tickfont=dict(size=11, color="#4a5568"),
            zeroline=False,
        ),
        hoverlabel=dict(
            bgcolor="#111827",
            bordercolor="rgba(0,255,136,0.3)",
            font=dict(color="#e2e8f0"),
        ),
        height=320,
    )

    st.plotly_chart(fig_ports, use_container_width=True, config={"displayModeBar": False})


# ── Gráfico de pizza: distribuição de ações ───────────────────────────────────
# ── Gráfico de pizza de Ações e Shodan ───────────────────────────────────
with dist_col:
    st.markdown("### 🔍 Inteligência Ofensora (Shodan API)")

    if has_intel and "attacker_org" in df.columns:
        org_df = df[df["attacker_org"] != "Unknown"]
        if not org_df.empty:
            org_counts = org_df["attacker_org"].value_counts().reset_index()
            org_counts.columns = ["Organização", "Ataques"]
            fig_orgs = px.pie(
                org_counts.head(5), names="Organização", values="Ataques", hole=0.4,
                color_discrete_sequence=px.colors.sequential.Agsunset
            )
            fig_orgs.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#a0aec0", family="Inter"),
                margin=dict(l=0, r=0, t=10, b=0)
            )
            st.plotly_chart(fig_orgs, use_container_width=True)
        else:
            st.info("Nenhuma Organização identificada pelo Shodan (IPs Residênciais/Não indexados)")
    else:
        st.info("Informações do Shodan não disponíveis. Execute a Análise Completa.")

    action_counts = df["action"].value_counts().reset_index()
    action_counts.columns = ["action", "count"]

    color_map = {"ALLOW": "#00ff88", "DENY": "#ff4757", "DROP": "#ffa502"}
    colors = [color_map.get(a, "#6366f1") for a in action_counts["action"]]

    fig_actions = go.Figure(
        go.Pie(
            labels=action_counts["action"],
            values=action_counts["count"],
            hole=0.6,
            marker=dict(
                colors=colors,
                line=dict(color="#07090f", width=3),
            ),
            textfont=dict(size=12, color="#e2e8f0", family="JetBrains Mono"),
            hovertemplate="<b>%{label}</b><br>%{value} eventos (%{percent})<extra></extra>",
        )
    )

    fig_actions.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#a0aec0"),
        margin=dict(l=10, r=10, t=20, b=10),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#4a5568", size=11),
            orientation="h",
            y=-0.1,
        ),
        annotations=[dict(
            text=f"<b>{total_registros}</b><br><span style='font-size:10px'>eventos</span>",
            x=0.5, y=0.5,
            font=dict(size=16, color="#e2e8f0", family="Inter"),
            showarrow=False,
        )],
        hoverlabel=dict(
            bgcolor="#111827",
            bordercolor="rgba(255,255,255,0.1)",
            font=dict(color="#e2e8f0"),
        ),
        height=320,
    )

    st.plotly_chart(fig_actions, use_container_width=True, config={"displayModeBar": False})

# =============================================================================
# SEÇÃO 3 — TABELA INTERATIVA COM HIGHLIGHT
# =============================================================================

st.markdown("### 📋 Log de Eventos — Detalhes")

# Filtros inline
filter_col1, filter_col2, filter_col3 = st.columns([2, 2, 3])

with filter_col1:
    action_filter = st.multiselect(
        "Filtrar por Ação",
        options=df["action"].unique().tolist(),
        default=df["action"].unique().tolist(),
        key="action_filter",
    )

with filter_col2:
    port_filter = st.multiselect(
        "Filtrar por Porta",
        options=sorted(df["destination_port"].unique().tolist()),
        default=sorted(df["destination_port"].unique().tolist()),
        key="port_filter",
    )

with filter_col3:
    if has_intel:
        show_only_malicious = st.checkbox(
            "🚨 Mostrar apenas IPs maliciosos", value=False, key="mal_filter"
        )
    else:
        show_only_malicious = False
        st.caption("")

# Aplica filtros
df_filtered = df[
    df["action"].isin(action_filter) &
    df["destination_port"].isin(port_filter)
].copy()

if has_intel and show_only_malicious:
    df_filtered = df_filtered[df_filtered["malicious_votes"] > 0]

# Reordena colunas para melhor legibilidade
cols_priority = ["timestamp", "source_ip", "destination_port", "action"]
if has_intel:
    cols_priority += ["malicious_votes", "attacker_org", "attacker_os", "open_ports"]

cols_display = [c for c in cols_priority if c in df_filtered.columns]
df_display = df_filtered[cols_display]

# ── Renomeia para exibição amigável ──────────────────────────────────────────
rename_map = {
    "timestamp": "Timestamp",
    "source_ip": "IP de Origem",
    "destination_port": "Porta Dest.",
    "action": "Ação",
    "malicious_votes": "Votos Maliciosos",
    "attacker_org": "Organização (ISP)",
    "attacker_os": "OS Atacante",
    "open_ports": "Portas Abertas",
}
df_display = df_display.rename(columns=rename_map)

# ── Aplica highlight nas linhas maliciosas ────────────────────────────────────
if has_intel and "Votos Maliciosos" in df_display.columns:
    styled_df = df_display.style.apply(highlight_malicious, axis=1)
    styled_df = styled_df.format({"Votos Maliciosos": lambda v: f"⚠️ {int(v)}" if pd.notna(v) and v > 0 else ("—" if v == -1 else str(int(v)) if pd.notna(v) else "—")})
else:
    styled_df = df_display.style

st.dataframe(
    styled_df,
    use_container_width=True,
    height=420,
    hide_index=True,
)

st.caption(f"Exibindo {len(df_filtered)} de {len(df)} registros")

# =============================================================================
# SEÇÃO 4 — TOP IPs SUSPEITOS (somente com intel)
# =============================================================================

if has_intel:
    st.markdown("### 🎯 Top IPs de Maior Risco")

    df_ip_summary = (
        df.groupby("source_ip")
        .agg(
            total_eventos=("action", "count"),
            malicious_votes=("malicious_votes", "max"),
            acoes_negadas=("action", lambda x: (x.isin(["DENY", "DROP"])).sum()),
            attacker_org=("attacker_org", "first"),
            attacker_os=("attacker_os", "first"),
            open_ports=("open_ports", "first"),
        )
        .reset_index()
        .sort_values(["malicious_votes", "acoes_negadas"], ascending=False)
        .head(10)
    )

    df_ip_summary = df_ip_summary.rename(columns={
        "source_ip": "IP",
        "total_eventos": "Eventos",
        "malicious_votes": "Votos VT",
        "acoes_negadas": "Bloqueios",
        "attacker_org": "Organização",
        "attacker_os": "OS",
        "open_ports": "Portas Abertas",
    })

    def highlight_top_ips(row):
        if pd.notna(row.get("Votos VT")) and row.get("Votos VT", 0) > 0:
            return ["background-color: rgba(255,71,87,0.12); color: #ff6b6b;"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df_ip_summary.style.apply(highlight_top_ips, axis=1),
        use_container_width=True,
        hide_index=True,
        height=300,
    )

# =============================================================================
# RODAPÉ
# =============================================================================

st.markdown("---")
st.markdown("""
<div style="text-align:center; padding: 1rem 0; color: #1a2234; font-size: 0.75rem; font-family:'JetBrains Mono',monospace;">
  🛡️ Threat Intel Analyzer &nbsp;|&nbsp; Powered by VirusTotal API v3 + Shodan &nbsp;|&nbsp; Built with Streamlit
</div>
""", unsafe_allow_html=True)

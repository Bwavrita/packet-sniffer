import dash
import dash_bootstrap_components as dbc
from flask import app
import plotly.graph_objs as go
from dash import dcc, html
from dash.dependencies import Input, Output

class VulnerabilityDashboard:
    def __init__(self, vulnerabilities, http_packets, ftp_packets, port_scan_packets_window_time, port_scan_packets_stateful):
        self.vulnerabilities = vulnerabilities
        self.http_packets = http_packets
        self.ftp_packets = ftp_packets
        self.port_scan_packets_window_time = port_scan_packets_window_time
        self.port_scan_packets_stateful = port_scan_packets_stateful

    def create_dashboard(self):
        app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
        
        app.layout = dbc.Container([
            dbc.Row(dbc.Col(html.H2("Dashboard de Vulnerabilidades de Rede", className="mt-4"))),
            
            dbc.Row(dbc.Col(dcc.Graph(id='vulnerability-bar-chart'))),
            
            dbc.Row(dbc.Col(html.H4("Detalhes dos Pacotes Vulneráveis", className="mt-4"))),
            dbc.Row(dbc.Col(html.Div(id='details', className="mt-2"))),
            
            dcc.Interval(
                id='interval-update',
                interval=2000, 
                n_intervals=0
            )
        ], fluid=True)

        @app.callback(
            Output('vulnerability-bar-chart', 'figure'),
            [Input('interval-update', 'n_intervals')]
        )
        def update_graph(n):
            protocols = list(self.vulnerabilities.keys())
            counts = list(self.vulnerabilities.values())
            
            return {
                'data': [
                    go.Bar(x=protocols, y=counts, marker_color=['violet', 'green', 'red'])
                ],
                'layout': go.Layout(
                    title='Vulnerabilidades e Ataques Encontrados',
                    xaxis={'title': 'Protocolos / Ataques'},
                    yaxis={'title': 'Quantidade Ocorrências'}
                )
            }

        @app.callback(
            Output('details', 'children'),
            [Input('vulnerability-bar-chart', 'clickData')]
        )
        def update_details(clickData):
            details = []
            if clickData:
                protocol = clickData['points'][0]['x']
                if protocol == 'http':
                    details.append(html.H5("Pacotes HTTP Vulneráveis"))
                    details.append(html.Ul([html.Li(f"ID {packet['id']}: {packet['method']} {packet['uri']} - Conteúdo: {packet['content']}") for packet in self.http_packets]))
                elif protocol == 'ftp':
                    details.append(html.H5("Pacotes FTP Vulneráveis"))
                    details.append(html.Ul([html.Li(f"ID {packet['id']}: {packet['command']} {packet['arg']}") for packet in self.ftp_packets]))
                
                elif protocol == 'port_scan_window_time':
                    details.append(html.H5("Alertas de Port Scan (Janela de Tempo) Identificados"))
                    # Corrigido para bater com as chaves: 'Type', 'Origin', 'Ports'
                    details.append(html.Ul([html.Li(f"Ataque: {scan['Type']} | Origem: {scan['Origin']} | Portas: {scan['Ports']}") for scan in self.port_scan_packets_window_time]))
                
                elif protocol == 'port_scan_stateful':
                    details.append(html.H5("Alertas de Port Scan (Estados) Identificados"))
                    # Corrigido para bater com as chaves: 'Type', 'origin', 'ports'
                    # Nota: Como 'ports' é um set(), usamos o list() ou join() para exibir de forma legível
                    details.append(html.Ul([html.Li(f"Ataque: {scan['Type']} | Origem: {scan['origin']} | Portas Alvo: {list(scan['ports'])}") for scan in self.port_scan_packets_stateful]))
            else:
                details.append(html.P("Clique em uma barra do gráfico para listar os detalhes dos pacotes."))

            return details
        
        return app
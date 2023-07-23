from flask import Blueprint, request, jsonify
from config.config import conexion
from flask_cors import CORS
from scapy.all import *
import datetime
from model.modelUser import crear_tabla
from scapy.layers.inet import IP, TCP, UDP, ICMP


app2_bp = Blueprint('app2', __name__)
CORS(app2_bp)


cursor = conexion.cursor()
crear_tabla()

add_all = ("INSERT INTO sniff(mac_src, ip_src, tam_src, fecha, hora, os, protocol) VALUES (%s, %s, %s, %s, %s, %s, %s)")
get_all = ("SELECT * FROM sniff")


def get_operating_system(ttl):
    if ttl <= 64:
        return "Linux"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Unknown"
    


def traffic_monitor_callback(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        tam_ip_src = pkt[IP].len
        mac_src = pkt.src
        ttl = pkt[IP].ttl

        fecha = datetime.datetime.now().date()
        hora = datetime.datetime.now().time()

        os = get_operating_system(ttl)

        if TCP in pkt:
            protocol = "TCP"
            # Realizar el análisis específico para el tráfico TCP
            # Por ejemplo, verificar puertos, calcular RTT, etc.
            if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                print("Paquete TCP con puerto 80 (HTTP)")
            elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
                print("Paquete TCP con puerto 443 (HTTPS)")
            else:
                print("Paquete TCP con otros puertos")
            
            # Aquí puedes realizar más análisis específico para el tráfico TCP
            # Por ejemplo, calcular RTT, analizar contenido de paquetes, etc.
        # Filtrar por protocolo UDP
        elif UDP in pkt:
            protocol = "UDP"
            # Realizar el análisis específico para el tráfico UDP
            # Por ejemplo, verificar puertos, calcular jitter, etc.
            print("Paquete UDP con puerto origen:", pkt[UDP].sport)
            print("Paquete UDP con puerto destino:", pkt[UDP].dport)
            
        else:
            protocol = "Unknown"
            
        print(ip_src)
        print(tam_ip_src)
        print(mac_src)
        print(os)
        print(protocol)

        cursor.execute(add_all, (mac_src, ip_src, tam_ip_src, fecha, hora, os, protocol))
        conexion.commit()
        


@app2_bp.route('/sniff', methods=['POST'])
def run_sniff():
    sniff(prn=traffic_monitor_callback, store=0, timeout=30)
    return "Sniff completed."

@app2_bp.route('/sniff', methods=['GET'])
def get_sniff():
    cursor.execute(get_all)
    data = cursor.fetchall()

    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'mac_src': row[1],
            'ip_src': row[2],
            'tam_src': row[3],
            'fecha': str(row[4]),
            'hora': str(row[5]),
            'os': row[6],
            'protocol': row[7]
        })
    return jsonify(json_data)

@app2_bp.route('/sniff/<fecha>', methods=['GET'])
def get_sniff_by_date(fecha):
    cursor.execute("SELECT * FROM sniff WHERE fecha = %s", (fecha,))
    data = cursor.fetchall()

    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'mac_src': row[1],
            'ip_src': row[2],
            'tam_src': row[3],
            'fecha': str(row[4]),
            'hora': str(row[5]),
            'os': row[6],
            'protocol': row[7]
        })
    return jsonify(json_data)

@app2_bp.route('/sniff/mac/<mac_src>', methods=['GET'])
def get_sniff_by_mac(mac_src):
    cursor.execute("SELECT * FROM sniff WHERE mac_src = %s", (mac_src,))
    data = cursor.fetchall()

    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'mac_src': row[1],
            'ip_src': row[2],
            'tam_src': row[3],
            'fecha': str(row[4]),
            'hora': str(row[5]),
            'os': row[6],
            'protocol': row[7]
        })
    return jsonify(json_data)





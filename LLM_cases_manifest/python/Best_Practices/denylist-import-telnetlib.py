import os
import socket
import paramiko
import subprocess
import ftplib
import ssl
import http.client
import requests
import getpass
from cryptography.fernet import Fernet
from urllib.request import urlopen

# True Positive Examples (Bad Cases)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1():
    # Direct import of telnetlib
    # ruleid: denylist-import-telnetlib
    import telnetlib
    
    tn = telnetlib.Telnet('example.com')
    tn.read_until(b"login: ")
    tn.write(b"user\n")
    tn.read_until(b"Password: ")
    tn.write(b"password\n")
    tn.write(b"ls\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2():
    # Import telnetlib with alias
    # ruleid: denylist-import-telnetlib
    import telnetlib as tlib
    
    host = "192.168.1.1"
    tn = tlib.Telnet(host)
    tn.read_until(b"Username: ")
    tn.write(b"admin\n")
    tn.read_until(b"Password: ")
    tn.write(b"admin123\n")
    tn.write(b"show config\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3():
    # Using telnetlib with specific import
    # ruleid: denylist-import-telnetlib
    from telnetlib import Telnet
    
    connection = Telnet('router.local')
    connection.read_until(b"login: ")
    connection.write(b"admin\n")
    connection.read_until(b"Password: ")
    connection.write(b"secret\n")
    connection.write(b"enable\n")
    connection.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4():
    # Using telnetlib with timeout
    # ruleid: denylist-import-telnetlib
    import telnetlib
    
    timeout = 5
    tn = telnetlib.Telnet('network-device.internal', timeout=timeout)
    tn.read_until(b"login: ", timeout)
    tn.write(b"operator\n")
    tn.read_until(b"Password: ", timeout)
    tn.write(b"op3r4t0r\n")
    tn.write(b"show interfaces\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5():
    # Using telnetlib with port specification
    # ruleid: denylist-import-telnetlib
    import telnetlib
    
    host = "legacy-system.local"
    port = 23
    tn = telnetlib.Telnet(host, port)
    tn.read_until(b"login: ")
    tn.write(b"service-account\n")
    tn.read_until(b"Password: ")
    tn.write(b"service123\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6():
    # Using telnetlib in a function
    def connect_to_device(host):
        # ruleid: denylist-import-telnetlib
        import telnetlib
        
        tn = telnetlib.Telnet(host)
        tn.read_until(b"Username: ")
        tn.write(b"root\n")
        tn.read_until(b"Password: ")
        tn.write(b"toor\n")
        return tn
    
    connection = connect_to_device('192.168.0.1')
    connection.write(b"show system status\n")
    connection.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7():
    # Using telnetlib with dynamic host
    host = input("Enter host: ")
    port = int(input("Enter port: "))
    
    # ruleid: denylist-import-telnetlib
    from telnetlib import Telnet
    
    tn = Telnet(host, port)
    tn.read_until(b"login: ")
    tn.write(b"admin\n")
    tn.read_until(b"Password: ")
    tn.write(b"admin\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8():
    # Using telnetlib with try-except
    # ruleid: denylist-import-telnetlib
    import telnetlib
    
    try:
        tn = telnetlib.Telnet('192.168.1.100')
        tn.read_until(b"login: ")
        tn.write(b"cisco\n")
        tn.read_until(b"Password: ")
        tn.write(b"cisco\n")
        tn.write(b"terminal length 0\n")
        tn.close()
    except ConnectionRefusedError:
        print("Connection failed")

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9():
    # Using telnetlib with context manager
    # ruleid: denylist-import-telnetlib
    from telnetlib import Telnet
    
    with Telnet('network-switch.local') as tn:
        tn.read_until(b"Username: ")
        tn.write(b"admin\n")
        tn.read_until(b"Password: ")
        tn.write(b"admin123\n")
        tn.write(b"show vlan\n")

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10():
    # Using telnetlib with environment variables
    # ruleid: denylist-import-telnetlib
    import telnetlib
    import os
    
    host = os.environ.get('DEVICE_HOST', 'default-router.local')
    username = os.environ.get('DEVICE_USER', 'admin')
    password = os.environ.get('DEVICE_PASS', 'password')
    
    tn = telnetlib.Telnet(host)
    tn.read_until(b"login: ")
    tn.write(username.encode() + b"\n")
    tn.read_until(b"Password: ")
    tn.write(password.encode() + b"\n")
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11():
    # Using telnetlib in a class
    class NetworkDevice:
        def __init__(self, host, username, password):
            self.host = host
            self.username = username
            self.password = password
            
        def connect(self):
            # ruleid: denylist-import-telnetlib
            import telnetlib
            
            self.tn = telnetlib.Telnet(self.host)
            self.tn.read_until(b"login: ")
            self.tn.write(self.username.encode() + b"\n")
            self.tn.read_until(b"Password: ")
            self.tn.write(self.password.encode() + b"\n")
            
        def disconnect(self):
            self.tn.close()
    
    device = NetworkDevice('192.168.1.1', 'admin', 'admin123')
    device.connect()
    device.disconnect()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12():
    # Using telnetlib with read_all
    # ruleid: denylist-import-telnetlib
    import telnetlib
    
    tn = telnetlib.Telnet('public-server.example.com')
    tn.write(b"ls -la\n")
    tn.write(b"exit\n")
    output = tn.read_all().decode('ascii')
    print(output)
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13():
    # Using telnetlib with multiple commands
    # ruleid: denylist-import-telnetlib
    from telnetlib import Telnet
    
    commands = [
        b"show version",
        b"show ip interface brief",
        b"show running-config"
    ]
    
    tn = Telnet('router.example.com')
    tn.read_until(b"Username: ")
    tn.write(b"admin\n")
    tn.read_until(b"Password: ")
    tn.write(b"secure_password\n")
    
    for cmd in commands:
        tn.write(cmd + b"\n")
        output = tn.read_until(b"router#")
        print(output.decode('ascii'))
    
    tn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14():
    # Using telnetlib with conditional import
    if input("Use telnet? (y/n): ").lower() == 'y':
        # ruleid: denylist-import-telnetlib
        import telnetlib
        
        tn = telnetlib.Telnet('legacy-device.local')
        tn.read_until(b"login: ")
        tn.write(b"user\n")
        tn.read_until(b"Password: ")
        tn.write(b"pass\n")
        tn.close()
    else:
        print("Not using telnet")

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15():
    # Using telnetlib with a custom wrapper function
    def telnet_command(host, username, password, command):
        # ruleid: denylist-import-telnetlib
        import telnetlib
        
        tn = telnetlib.Telnet(host)
        tn.read_until(b"login: ")
        tn.write(username.encode() + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode() + b"\n")
        tn.write(command.encode() + b"\n")
        result = tn.read_until(b"$").decode('ascii')
        tn.close()
        return result
    
    output = telnet_command('192.168.1.10', 'admin', 'password123', 'ls -la')
    print(output)

# True Negative Examples (Good Cases)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1():
    # Using SSH instead of telnet
    # ok: denylist-import-telnetlib
    import paramiko
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('example.com', username='user', password='password')
    stdin, stdout, stderr = ssh.exec_command('ls')
    output = stdout.read().decode()
    ssh.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2():
    # Using SSH with key-based authentication
    # ok: denylist-import-telnetlib
    import paramiko
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.1.1', username='admin', key_filename='/path/to/private_key')
    stdin, stdout, stderr = ssh.exec_command('show config')
    output = stdout.read().decode()
    ssh.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3():
    # Using HTTPS for web-based administration
    # ok: denylist-import-telnetlib
    import requests
    
    session = requests.Session()
    response = session.post(
        'https://router.local/login',
        data={'username': 'admin', 'password': 'secret'},
        verify=True
    )
    config_page = session.get('https://router.local/config')
    print(config_page.text)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4():
    # Using socket with SSL/TLS
    # ok: denylist-import-telnetlib
    import socket
    import ssl
    
    context = ssl.create_default_context()
    with socket.create_connection(('secure-service.internal', 443)) as sock:
        with context.wrap_socket(sock, server_hostname='secure-service.internal') as ssock:
            ssock.send(b"GET / HTTP/1.1\r\nHost: secure-service.internal\r\n\r\n")
            response = ssock.recv(4096)
            print(response.decode())

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5():
    # Using SFTP instead of telnet for file transfer
    # ok: denylist-import-telnetlib
    import paramiko
    
    transport = paramiko.Transport(('sftp.example.com', 22))
    transport.connect(username='user', password='password')
    
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.put('local_file.txt', 'remote_file.txt')
    sftp.close()
    transport.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6():
    # Using REST API with HTTPS
    # ok: denylist-import-telnetlib
    import requests
    
    api_url = "https://api.example.com/devices/config"
    headers = {
        "Authorization": f"Bearer {os.environ.get('API_TOKEN')}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(api_url, headers=headers, verify=True)
    device_config = response.json()
    print(device_config)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7():
    # Using subprocess to run local commands
    # ok: denylist-import-telnetlib
    import subprocess
    
    result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
    print(result.stdout)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8():
    # Using secure WebSocket
    # ok: denylist-import-telnetlib
    import websocket
    
    ws = websocket.create_connection("wss://secure-websocket.example.com")
    ws.send('{"command": "get_status"}')
    result = ws.recv()
    ws.close()
    print(result)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9():
    # Using HTTPS client
    # ok: denylist-import-telnetlib
    import http.client
    import ssl
    
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.example.com", context=context)
    conn.request("GET", "/status")
    response = conn.getresponse()
    data = response.read().decode()
    conn.close()
    print(data)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10():
    # Using FTP over TLS/SSL (FTPS)
    # ok: denylist-import-telnetlib
    import ftplib
    
    ftps = ftplib.FTP_TLS('ftps.example.com')
    ftps.login('user', 'password')
    ftps.prot_p()  # Set up secure data connection
    ftps.retrlines('LIST')
    ftps.quit()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11():
    # Using a secure database connection
    # ok: denylist-import-telnetlib
    import psycopg2
    
    conn = psycopg2.connect(
        host="db.example.com",
        database="mydb",
        user="dbuser",
        password="dbpass",
        sslmode="require"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12():
    # Using secure MQTT over TLS
    # ok: denylist-import-telnetlib
    import paho.mqtt.client as mqtt
    import ssl
    
    client = mqtt.Client()
    client.tls_set(ca_certs="ca.crt", certfile="client.crt", keyfile="client.key")
    client.username_pw_set("mqtt_user", "mqtt_password")
    client.connect("mqtt.example.com", 8883, 60)
    client.publish("sensors/temperature", "24.5")
    client.disconnect()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13():
    # Using a secure configuration management tool
    # ok: denylist-import-telnetlib
    import ansible_runner
    
    r = ansible_runner.run(
        private_data_dir='/path/to/ansible',
        playbook='configure_network.yml',
        inventory='inventory.yml',
        extravars={
            'target': 'network_devices',
            'config_template': 'secure_config.j2'
        }
    )
    print(r.status)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14():
    # Using a secure API client with token authentication
    # ok: denylist-import-telnetlib
    import requests
    
    class SecureNetworkClient:
        def __init__(self, base_url, token):
            self.base_url = base_url
            self.headers = {"Authorization": f"Bearer {token}"}
            
        def get_device_status(self, device_id):
            response = requests.get(
                f"{self.base_url}/devices/{device_id}/status",
                headers=self.headers,
                verify=True
            )
            return response.json()
    
    client = SecureNetworkClient("https://api.network.com", os.environ.get("API_TOKEN"))
    status = client.get_device_status("router-01")
    print(status)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15():
    # Using gRPC with TLS
    # ok: denylist-import-telnetlib
    import grpc
    import device_management_pb2
    import device_management_pb2_grpc
    
    creds = grpc.ssl_channel_credentials(
        root_certificates=open('ca.pem', 'rb').read(),
        private_key=open('client.key', 'rb').read(),
        certificate_chain=open('client.pem', 'rb').read()
    )
    
    with grpc.secure_channel('grpc.example.com:443', creds) as channel:
        stub = device_management_pb2_grpc.DeviceManagementStub(channel)
        response = stub.GetConfig(device_management_pb2.ConfigRequest(device_id="router-01"))
        print(f"Config received: {response.config}")
# {/fact}
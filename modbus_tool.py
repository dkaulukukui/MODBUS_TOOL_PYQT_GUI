#!/usr/bin/env python3
“””
Modbus RTU Packet Generator - PyQt5 GUI Tool
Allows manual creation and sending of Modbus RTU packets for testing and debugging.
“””

import sys
import serial
import serial.tools.list_ports
import socket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
QHBoxLayout, QLabel, QComboBox, QPushButton,
QSpinBox, QTextEdit, QGroupBox, QGridLayout,
QLineEdit, QCheckBox, QMessageBox, QTabWidget,
QRadioButton, QButtonGroup)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import struct
import time

import time

class ModbusMonitorThread(QThread):
“”“Thread for monitoring Modbus RTU traffic”””
packet_received = pyqtSignal(bytes, str)  # packet data, direction (TX/RX)

```
def __init__(self, serial_port):
    super().__init__()
    self.serial_port = serial_port
    self.running = False
    
def run(self):
    self.running = True
    buffer = bytearray()
    last_byte_time = time.time()
    
    # 3.5 character times at the current baudrate for packet gap detection
    # For 9600 baud: ~3.6ms, for safety we'll use a longer timeout
    char_time = 11 / int(9600)  # 11 bits per character (start + 8 data + parity + stop)
    packet_gap = char_time * 3.5 * 1000  # Convert to milliseconds
    
    # Use at least 10ms gap to be safe across different baudrates
    if packet_gap < 10:
        packet_gap = 10
        
    self.serial_port.timeout = packet_gap / 1000.0
    
    while self.running:
        try:
            # Read available bytes
            if self.serial_port.in_waiting > 0:
                byte = self.serial_port.read(1)
                if byte:
                    current_time = time.time()
                    time_gap = (current_time - last_byte_time) * 1000  # ms
                    
                    # If gap is too large, previous packet is complete
                    if buffer and time_gap > packet_gap:
                        # Process complete packet
                        if len(buffer) >= 4:  # Minimum: slave + func + CRC
                            self.packet_received.emit(bytes(buffer), 'MONITOR')
                        buffer = bytearray()
                    
                    buffer.extend(byte)
                    last_byte_time = current_time
            else:
                # No data available, check if buffer has a complete packet
                if buffer:
                    current_time = time.time()
                    time_gap = (current_time - last_byte_time) * 1000
                    
                    if time_gap > packet_gap:
                        if len(buffer) >= 4:
                            self.packet_received.emit(bytes(buffer), 'MONITOR')
                        buffer = bytearray()
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.001)
                
        except Exception as e:
            print(f"Monitor error: {e}")
            break

def stop(self):
    self.running = False
    self.wait()
```

class ModbusRTUTool(QMainWindow):
def **init**(self):
super().**init**()
self.serial_port = None
self.tcp_socket = None
self.mode = ‘RTU’  # Default mode
self.transaction_id = 0  # For Modbus TCP
self.monitor_thread = None
self.monitor_active = False
self.init_ui()

```
def init_ui(self):
    self.setWindowTitle('Modbus RTU/TCP Packet Generator')
    self.setGeometry(100, 100, 900, 750)
    
    # Main widget and layout
    main_widget = QWidget()
    self.setCentralWidget(main_widget)
    layout = QVBoxLayout()
    main_widget.setLayout(layout)
    
    # Mode Selection
    mode_group = self.create_mode_selector()
    layout.addWidget(mode_group)
    
    # Serial Port Configuration
    self.port_group = self.create_port_config()
    layout.addWidget(self.port_group)
    
    # TCP Configuration
    self.tcp_group = self.create_tcp_config()
    layout.addWidget(self.tcp_group)
    self.tcp_group.hide()  # Hidden by default
    
    # Modbus Function Selection
    function_group = self.create_function_config()
    layout.addWidget(function_group)
    
    # Packet Display
    display_group = self.create_display_area()
    layout.addWidget(display_group)
    
    # Send Button
    send_layout = QHBoxLayout()
    self.send_button = QPushButton('Send Packet')
    self.send_button.setStyleSheet('background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;')
    self.send_button.clicked.connect(self.send_packet)
    send_layout.addWidget(self.send_button)
    
    self.clear_button = QPushButton('Clear Log')
    self.clear_button.clicked.connect(self.clear_log)
    send_layout.addWidget(self.clear_button)
    
    layout.addLayout(send_layout)
    
    # Refresh port list on startup
    self.refresh_ports()

def create_mode_selector(self):
    group = QGroupBox('Protocol Mode')
    layout = QHBoxLayout()
    
    self.mode_button_group = QButtonGroup()
    
    self.rtu_radio = QRadioButton('Modbus RTU (Serial)')
    self.rtu_radio.setChecked(True)
    self.rtu_radio.toggled.connect(self.on_mode_changed)
    self.mode_button_group.addButton(self.rtu_radio)
    layout.addWidget(self.rtu_radio)
    
    self.tcp_radio = QRadioButton('Modbus TCP (Ethernet)')
    self.tcp_radio.toggled.connect(self.on_mode_changed)
    self.mode_button_group.addButton(self.tcp_radio)
    layout.addWidget(self.tcp_radio)
    
    layout.addStretch()
    
    group.setLayout(layout)
    return group

def on_mode_changed(self):
    if self.rtu_radio.isChecked():
        self.mode = 'RTU'
        self.port_group.show()
        self.tcp_group.hide()
    else:
        self.mode = 'TCP'
        self.port_group.hide()
        self.tcp_group.show()
    
    # Disconnect if currently connected
    if (self.serial_port and self.serial_port.is_open) or (self.tcp_socket):
        if self.mode == 'RTU':
            self.disconnect_serial()
        else:
            self.disconnect_tcp()
    
def create_port_config(self):
    group = QGroupBox('Serial Port Configuration')
    layout = QGridLayout()
    
    # Port selection
    layout.addWidget(QLabel('Port:'), 0, 0)
    self.port_combo = QComboBox()
    layout.addWidget(self.port_combo, 0, 1)
    
    refresh_btn = QPushButton('Refresh')
    refresh_btn.clicked.connect(self.refresh_ports)
    layout.addWidget(refresh_btn, 0, 2)
    
    # Baudrate
    layout.addWidget(QLabel('Baudrate:'), 1, 0)
    self.baudrate_combo = QComboBox()
    self.baudrate_combo.addItems(['9600', '19200', '38400', '57600', '115200'])
    self.baudrate_combo.setCurrentText('9600')
    layout.addWidget(self.baudrate_combo, 1, 1)
    
    # Parity
    layout.addWidget(QLabel('Parity:'), 2, 0)
    self.parity_combo = QComboBox()
    self.parity_combo.addItems(['None', 'Even', 'Odd'])
    self.parity_combo.setCurrentText('None')
    layout.addWidget(self.parity_combo, 2, 1)
    
    # Data bits
    layout.addWidget(QLabel('Data Bits:'), 3, 0)
    self.databits_combo = QComboBox()
    self.databits_combo.addItems(['7', '8'])
    self.databits_combo.setCurrentText('8')
    layout.addWidget(self.databits_combo, 3, 1)
    
    # Stop bits
    layout.addWidget(QLabel('Stop Bits:'), 4, 0)
    self.stopbits_combo = QComboBox()
    self.stopbits_combo.addItems(['1', '2'])
    layout.addWidget(self.stopbits_combo, 4, 1)
    
    # Connect/Disconnect button
    self.connect_button = QPushButton('Connect')
    self.connect_button.clicked.connect(self.toggle_connection)
    layout.addWidget(self.connect_button, 5, 0, 1, 3)
    
    # Monitor Mode button
    self.monitor_button = QPushButton('Start Monitor Mode')
    self.monitor_button.setStyleSheet('background-color: #2196F3; color: white;')
    self.monitor_button.clicked.connect(self.toggle_monitor)
    self.monitor_button.setEnabled(False)
    layout.addWidget(self.monitor_button, 6, 0, 1, 3)
    
    info_label = QLabel('Monitor Mode: Passively listen to all RTU traffic on the line')
    info_label.setStyleSheet('color: #666; font-size: 9pt; font-style: italic;')
    layout.addWidget(info_label, 7, 0, 1, 3)
    
    group.setLayout(layout)
    return group

def create_tcp_config(self):
    group = QGroupBox('TCP/IP Configuration')
    layout = QGridLayout()
    
    # IP Address
    layout.addWidget(QLabel('IP Address:'), 0, 0)
    self.tcp_host = QLineEdit()
    self.tcp_host.setText('192.168.1.100')
    self.tcp_host.setPlaceholderText('e.g., 192.168.1.100')
    layout.addWidget(self.tcp_host, 0, 1)
    
    # Port
    layout.addWidget(QLabel('Port:'), 1, 0)
    self.tcp_port = QSpinBox()
    self.tcp_port.setRange(1, 65535)
    self.tcp_port.setValue(502)  # Default Modbus TCP port
    layout.addWidget(self.tcp_port, 1, 1)
    
    # Unit ID (slave ID for TCP)
    layout.addWidget(QLabel('Unit ID:'), 2, 0)
    self.tcp_unit_id = QSpinBox()
    self.tcp_unit_id.setRange(0, 255)
    self.tcp_unit_id.setValue(1)
    layout.addWidget(self.tcp_unit_id, 2, 1)
    
    # Connect/Disconnect button
    self.tcp_connect_button = QPushButton('Connect')
    self.tcp_connect_button.clicked.connect(self.toggle_tcp_connection)
    layout.addWidget(self.tcp_connect_button, 3, 0, 1, 2)
    
    group.setLayout(layout)
    return group

def create_function_config(self):
    group = QGroupBox('Modbus Packet Configuration')
    layout = QGridLayout()
    
    # Slave ID
    layout.addWidget(QLabel('Slave ID:'), 0, 0)
    self.slave_id = QSpinBox()
    self.slave_id.setRange(1, 247)
    self.slave_id.setValue(1)
    layout.addWidget(self.slave_id, 0, 1)
    
    # Function Code
    layout.addWidget(QLabel('Function Code:'), 1, 0)
    self.function_combo = QComboBox()
    self.function_combo.addItems([
        '01 - Read Coils',
        '02 - Read Discrete Inputs',
        '03 - Read Holding Registers',
        '04 - Read Input Registers',
        '05 - Write Single Coil',
        '06 - Write Single Register',
        '15 - Write Multiple Coils',
        '16 - Write Multiple Registers',
        'Custom'
    ])
    self.function_combo.currentIndexChanged.connect(self.update_function_fields)
    layout.addWidget(self.function_combo, 1, 1, 1, 2)
    
    # Starting Address
    layout.addWidget(QLabel('Start Address:'), 2, 0)
    self.start_addr = QSpinBox()
    self.start_addr.setRange(0, 65535)
    self.start_addr.setValue(0)
    layout.addWidget(self.start_addr, 2, 1)
    
    # Quantity / Value
    self.quantity_label = QLabel('Quantity:')
    layout.addWidget(self.quantity_label, 3, 0)
    self.quantity = QSpinBox()
    self.quantity.setRange(1, 125)
    self.quantity.setValue(1)
    layout.addWidget(self.quantity, 3, 1)
    
    # Write values (for write functions)
    layout.addWidget(QLabel('Write Values:'), 4, 0)
    self.write_values = QLineEdit()
    self.write_values.setPlaceholderText('e.g., 1234 or 0x04D2 or 1,2,3,4 for multiple')
    self.write_values.setEnabled(False)
    layout.addWidget(self.write_values, 4, 1, 1, 2)
    
    # Custom packet entry
    layout.addWidget(QLabel('Custom Packet (hex):'), 5, 0)
    self.custom_packet = QLineEdit()
    self.custom_packet.setPlaceholderText('e.g., 01 03 00 00 00 0A (without CRC)')
    self.custom_packet.setEnabled(False)
    layout.addWidget(self.custom_packet, 5, 1, 1, 2)
    
    # Timeout
    layout.addWidget(QLabel('Timeout (ms):'), 6, 0)
    self.timeout = QSpinBox()
    self.timeout.setRange(100, 5000)
    self.timeout.setValue(1000)
    layout.addWidget(self.timeout, 6, 1)
    
    group.setLayout(layout)
    return group

def create_display_area(self):
    group = QGroupBox('Packet Log')
    layout = QVBoxLayout()
    
    self.log_display = QTextEdit()
    self.log_display.setReadOnly(True)
    self.log_display.setFont(QFont('Courier', 9))
    layout.addWidget(self.log_display)
    
    group.setLayout(layout)
    return group

def refresh_ports(self):
    self.port_combo.clear()
    ports = serial.tools.list_ports.comports()
    for port in ports:
        self.port_combo.addItem(f"{port.device} - {port.description}")

def toggle_connection(self):
    if self.serial_port is None or not self.serial_port.is_open:
        self.connect_serial()
    else:
        self.disconnect_serial()

def connect_serial(self):
    try:
        port = self.port_combo.currentText().split(' - ')[0]
        baudrate = int(self.baudrate_combo.currentText())
        
        parity_map = {'None': serial.PARITY_NONE, 'Even': serial.PARITY_EVEN, 'Odd': serial.PARITY_ODD}
        parity = parity_map[self.parity_combo.currentText()]
        
        databits = int(self.databits_combo.currentText())
        stopbits = int(self.stopbits_combo.currentText())
        
        self.serial_port = serial.Serial(
            port=port,
            baudrate=baudrate,
            parity=parity,
            bytesize=databits,
            stopbits=stopbits,
            timeout=self.timeout.value() / 1000.0
        )
        
        self.connect_button.setText('Disconnect')
        self.connect_button.setStyleSheet('background-color: #f44336; color: white;')
        self.log_message(f'Connected to {port} at {baudrate} baud')
        
        # Enable monitor mode button for RTU
        self.monitor_button.setEnabled(True)
        
        # Disable port config
        self.port_combo.setEnabled(False)
        self.baudrate_combo.setEnabled(False)
        self.parity_combo.setEnabled(False)
        self.databits_combo.setEnabled(False)
        self.stopbits_combo.setEnabled(False)
        
    except Exception as e:
        QMessageBox.critical(self, 'Connection Error', f'Failed to connect: {str(e)}')

def disconnect_serial(self):
    # Stop monitor mode if active
    if self.monitor_active:
        self.stop_monitor()
        
    if self.serial_port and self.serial_port.is_open:
        self.serial_port.close()
        self.connect_button.setText('Connect')
        self.connect_button.setStyleSheet('')
        self.log_message('Disconnected')
        
        # Disable monitor button
        self.monitor_button.setEnabled(False)
        
        # Enable port config
        self.port_combo.setEnabled(True)
        self.baudrate_combo.setEnabled(True)
        self.parity_combo.setEnabled(True)
        self.databits_combo.setEnabled(True)
        self.stopbits_combo.setEnabled(True)

def toggle_tcp_connection(self):
    if self.tcp_socket is None:
        self.connect_tcp()
    else:
        self.disconnect_tcp()

def connect_tcp(self):
    try:
        host = self.tcp_host.text()
        port = self.tcp_port.value()
        
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.settimeout(self.timeout.value() / 1000.0)
        self.tcp_socket.connect((host, port))
        
        self.tcp_connect_button.setText('Disconnect')
        self.tcp_connect_button.setStyleSheet('background-color: #f44336; color: white;')
        self.log_message(f'Connected to {host}:{port}')
        
        # Disable TCP config
        self.tcp_host.setEnabled(False)
        self.tcp_port.setEnabled(False)
        
    except Exception as e:
        QMessageBox.critical(self, 'Connection Error', f'Failed to connect: {str(e)}')
        self.tcp_socket = None

def disconnect_tcp(self):
    if self.tcp_socket:
        try:
            self.tcp_socket.close()
        except:
            pass
        self.tcp_socket = None
        self.tcp_connect_button.setText('Connect')
        self.tcp_connect_button.setStyleSheet('')
        self.log_message('Disconnected')
        
        # Enable TCP config
        self.tcp_host.setEnabled(True)
        self.tcp_port.setEnabled(True)

def toggle_monitor(self):
    """Toggle monitor mode on/off"""
    if self.monitor_active:
        self.stop_monitor()
    else:
        self.start_monitor()

def start_monitor(self):
    """Start passive monitoring of RTU traffic"""
    if not self.serial_port or not self.serial_port.is_open:
        QMessageBox.warning(self, 'Not Connected', 'Connect to serial port first')
        return
    
    try:
        self.monitor_thread = ModbusMonitorThread(self.serial_port)
        self.monitor_thread.packet_received.connect(self.on_monitor_packet)
        self.monitor_thread.start()
        
        self.monitor_active = True
        self.monitor_button.setText('Stop Monitor Mode')
        self.monitor_button.setStyleSheet('background-color: #f44336; color: white; font-weight: bold;')
        self.send_button.setEnabled(False)  # Disable sending while monitoring
        
        self.log_message('=== MONITOR MODE STARTED ===')
        self.log_message('Listening for Modbus RTU traffic...')
        
    except Exception as e:
        QMessageBox.critical(self, 'Monitor Error', f'Failed to start monitor: {str(e)}')

def stop_monitor(self):
    """Stop passive monitoring"""
    if self.monitor_thread:
        self.monitor_thread.stop()
        self.monitor_thread = None
    
    self.monitor_active = False
    self.monitor_button.setText('Start Monitor Mode')
    self.monitor_button.setStyleSheet('background-color: #2196F3; color: white;')
    self.send_button.setEnabled(True)  # Re-enable sending
    
    self.log_message('=== MONITOR MODE STOPPED ===')

def on_monitor_packet(self, packet, direction):
    """Handle a packet received from monitor thread"""
    # Validate and decode the packet
    if len(packet) < 4:
        return  # Too short to be valid
    
    # Verify CRC
    data = packet[:-2]
    received_crc = packet[-2:]
    calculated_crc = self.calculate_crc(data)
    
    hex_str = ' '.join(f'{b:02X}' for b in packet)
    
    if received_crc == calculated_crc:
        self.log_message(f'📡 {hex_str}')
        self.log_message('   ✓ CRC Valid')
        
        # Decode packet
        slave_id = data[0]
        func_code = data[1]
        
        self.log_message(f'   Slave/Unit: {slave_id}, Function: {func_code:02X}')
        
        # Try to identify if this is a request or response
        self.decode_monitor_packet(data)
    else:
        self.log_message(f'📡 {hex_str}')
        self.log_message(f'   ✗ CRC Error - Expected: {calculated_crc.hex().upper()}, Got: {received_crc.hex().upper()}')

def decode_monitor_packet(self, data):
    """Decode a monitored packet (request or response)"""
    if len(data) < 2:
        return
    
    slave_id = data[0]
    func_code = data[1]
    
    # Check if exception response
    if func_code & 0x80:
        exception_code = data[2] if len(data) > 2 else 0
        exception_names = {
            0x01: 'Illegal Function',
            0x02: 'Illegal Data Address',
            0x03: 'Illegal Data Value',
            0x04: 'Slave Device Failure'
        }
        exception_name = exception_names.get(exception_code, f'Unknown ({exception_code:02X})')
        self.log_message(f'   Type: EXCEPTION RESPONSE')
        self.log_message(f'   Exception: {exception_name}')
        return
    
    # Determine if request or response based on length and function
    if func_code in [1, 2, 3, 4]:  # Read functions
        if len(data) == 6:  # Request: slave + func + addr(2) + qty(2)
            addr = struct.unpack('>H', data[2:4])[0]
            qty = struct.unpack('>H', data[4:6])[0]
            func_names = {1: 'Read Coils', 2: 'Read Discrete Inputs', 
                        3: 'Read Holding Registers', 4: 'Read Input Registers'}
            self.log_message(f'   Type: REQUEST - {func_names.get(func_code, "Unknown")}')
            self.log_message(f'   Address: {addr}, Quantity: {qty}')
        else:  # Response: slave + func + byte_count + data
            if len(data) > 2:
                byte_count = data[2]
                response_data = data[3:]
                self.log_message(f'   Type: RESPONSE')
                self.log_message(f'   Byte Count: {byte_count}')
                
                if func_code in [1, 2]:  # Coils/discrete inputs
                    bits = []
                    for byte in response_data[:byte_count]:
                        for i in range(8):
                            bits.append((byte >> i) & 1)
                    self.log_message(f'   Values: {bits[:byte_count*8]}')
                elif func_code in [3, 4]:  # Registers
                    registers = []
                    for i in range(0, min(byte_count, len(response_data)), 2):
                        if i+1 < len(response_data):
                            reg = struct.unpack('>H', response_data[i:i+2])[0]
                            registers.append(reg)
                    self.log_message(f'   Registers: {registers}')
                    self.log_message(f'   Hex: {[f"0x{r:04X}" for r in registers]}')
    
    elif func_code in [5, 6]:  # Write single
        if len(data) == 6:  # Both request and response have same format
            addr = struct.unpack('>H', data[2:4])[0]
            value = struct.unpack('>H', data[4:6])[0]
            func_names = {5: 'Write Single Coil', 6: 'Write Single Register'}
            self.log_message(f'   Type: REQUEST/RESPONSE - {func_names.get(func_code, "Unknown")}')
            self.log_message(f'   Address: {addr}, Value: {value} (0x{value:04X})')
    
    elif func_code in [15, 16]:  # Write multiple
        if len(data) > 6 and data[6] > 0:  # Request: has byte count and data
            addr = struct.unpack('>H', data[2:4])[0]
            qty = struct.unpack('>H', data[4:6])[0]
            byte_count = data[6]
            func_names = {15: 'Write Multiple Coils', 16: 'Write Multiple Registers'}
            self.log_message(f'   Type: REQUEST - {func_names.get(func_code, "Unknown")}')
            self.log_message(f'   Address: {addr}, Quantity: {qty}')
            
            if func_code == 16:  # Registers
                write_data = data[7:7+byte_count]
                registers = []
                for i in range(0, len(write_data), 2):
                    if i+1 < len(write_data):
                        reg = struct.unpack('>H', write_data[i:i+2])[0]
                        registers.append(reg)
                self.log_message(f'   Values: {registers}')
        elif len(data) == 6:  # Response: slave + func + addr(2) + qty(2)
            addr = struct.unpack('>H', data[2:4])[0]
            qty = struct.unpack('>H', data[4:6])[0]
            func_names = {15: 'Write Multiple Coils', 16: 'Write Multiple Registers'}
            self.log_message(f'   Type: RESPONSE - {func_names.get(func_code, "Unknown")}')
            self.log_message(f'   Address: {addr}, Quantity: {qty}')
    else:
        self.log_message(f'   Type: Unknown function code {func_code}')

def update_function_fields(self):
    func_text = self.function_combo.currentText()
    
    # Enable/disable custom packet field
    if 'Custom' in func_text:
        self.custom_packet.setEnabled(True)
        self.start_addr.setEnabled(False)
        self.quantity.setEnabled(False)
        self.write_values.setEnabled(False)
    else:
        self.custom_packet.setEnabled(False)
        self.start_addr.setEnabled(True)
        self.quantity.setEnabled(True)
        
        # Enable write values for write functions
        if 'Write' in func_text:
            self.write_values.setEnabled(True)
            if 'Single' in func_text:
                self.quantity_label.setText('Value:')
                self.quantity.setEnabled(False)
            else:
                self.quantity_label.setText('Quantity:')
                self.quantity.setEnabled(True)
        else:
            self.write_values.setEnabled(False)
            self.quantity_label.setText('Quantity:')

def calculate_crc(self, data):
    """Calculate Modbus CRC16"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack('<H', crc)  # Little-endian

def build_mbap_header(self, pdu_length):
    """Build Modbus TCP MBAP Header
    Format: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
    """
    self.transaction_id = (self.transaction_id + 1) % 65536
    unit_id = self.tcp_unit_id.value() if self.mode == 'TCP' else self.slave_id.value()
    
    header = bytearray()
    header.extend(struct.pack('>H', self.transaction_id))  # Transaction ID
    header.extend(struct.pack('>H', 0))  # Protocol ID (0 for Modbus)
    header.extend(struct.pack('>H', pdu_length + 1))  # Length (PDU + Unit ID)
    header.append(unit_id)  # Unit ID
    
    return bytes(header)

def build_packet(self):
    """Build the Modbus RTU or TCP packet based on current settings"""
    func_text = self.function_combo.currentText()
    
    if 'Custom' in func_text:
        # Parse custom hex packet
        try:
            hex_str = self.custom_packet.text().replace(' ', '').replace('0x', '')
            packet = bytes.fromhex(hex_str)
            return packet
        except ValueError as e:
            raise ValueError(f'Invalid custom packet format: {str(e)}')
    
    func_code = int(func_text.split(' ')[0])
    start = self.start_addr.value()
    
    # For RTU, we include slave ID in the packet
    # For TCP, we only build the PDU (function code + data)
    packet = bytearray()
    
    if self.mode == 'RTU':
        slave = self.slave_id.value()
        packet.append(slave)
    
    packet.append(func_code)
    
    if func_code in [1, 2, 3, 4]:  # Read functions
        quantity = self.quantity.value()
        packet.extend(struct.pack('>H', start))  # Big-endian
        packet.extend(struct.pack('>H', quantity))
        
    elif func_code == 5:  # Write single coil
        value_str = self.write_values.text() or '1'
        value = self.parse_value(value_str)
        value = 0xFF00 if value else 0x0000
        packet.extend(struct.pack('>H', start))
        packet.extend(struct.pack('>H', value))
        
    elif func_code == 6:  # Write single register
        value_str = self.write_values.text() or '0'
        value = self.parse_value(value_str)
        packet.extend(struct.pack('>H', start))
        packet.extend(struct.pack('>H', value & 0xFFFF))
        
    elif func_code == 15:  # Write multiple coils
        quantity = self.quantity.value()
        values_str = self.write_values.text() or '1'
        values = [self.parse_value(v.strip()) for v in values_str.split(',')]
        
        # Pad or truncate to quantity
        values = (values + [0] * quantity)[:quantity]
        
        # Pack bits into bytes
        byte_count = (quantity + 7) // 8
        bytes_data = bytearray(byte_count)
        for i, val in enumerate(values):
            if val:
                bytes_data[i // 8] |= (1 << (i % 8))
        
        packet.extend(struct.pack('>H', start))
        packet.extend(struct.pack('>H', quantity))
        packet.append(byte_count)
        packet.extend(bytes_data)
        
    elif func_code == 16:  # Write multiple registers
        quantity = self.quantity.value()
        values_str = self.write_values.text() or '0'
        values = [self.parse_value(v.strip()) for v in values_str.split(',')]
        
        # Pad or truncate to quantity
        values = (values + [0] * quantity)[:quantity]
        
        byte_count = quantity * 2
        packet.extend(struct.pack('>H', start))
        packet.extend(struct.pack('>H', quantity))
        packet.append(byte_count)
        for val in values:
            packet.extend(struct.pack('>H', val & 0xFFFF))
    
    return bytes(packet)

def parse_value(self, value_str):
    """Parse a value string (decimal or hex)"""
    value_str = value_str.strip()
    if value_str.startswith('0x') or value_str.startswith('0X'):
        return int(value_str, 16)
    else:
        return int(value_str)

def send_packet(self):
    # Check connection
    if self.mode == 'RTU':
        if self.serial_port is None or not self.serial_port.is_open:
            QMessageBox.warning(self, 'Not Connected', 'Please connect to a serial port first')
            return
    else:  # TCP
        if self.tcp_socket is None:
            QMessageBox.warning(self, 'Not Connected', 'Please connect to TCP server first')
            return
    
    try:
        # Build packet (PDU for TCP, full packet with slave ID for RTU)
        packet = self.build_packet()
        
        if self.mode == 'RTU':
            # RTU mode: Add CRC
            crc = self.calculate_crc(packet)
            full_packet = packet + crc
            
            # Clear receive buffer
            self.serial_port.reset_input_buffer()
            
            # Send packet
            self.serial_port.write(full_packet)
            
            # Log sent packet
            hex_str = ' '.join(f'{b:02X}' for b in full_packet)
            self.log_message(f'TX (RTU): {hex_str}')
            
            # Wait for response
            response = bytearray()
            timeout_time = self.timeout.value() / 1000.0
            self.serial_port.timeout = timeout_time
            
            # Read response
            response = self.serial_port.read(256)
            
            if response:
                hex_str = ' '.join(f'{b:02X}' for b in response)
                self.log_message(f'RX (RTU): {hex_str}')
                
                # Verify CRC
                if len(response) >= 3:
                    data = response[:-2]
                    received_crc = response[-2:]
                    calculated_crc = self.calculate_crc(data)
                    
                    if received_crc == calculated_crc:
                        self.log_message('✓ CRC Valid')
                        # Remove slave ID for decoding (make it look like TCP response)
                        self.decode_response(response[1:-2], response[0])
                    else:
                        self.log_message(f'✗ CRC Error - Expected: {calculated_crc.hex().upper()}, Got: {received_crc.hex().upper()}')
            else:
                self.log_message('No response received (timeout)')
                
        else:  # TCP mode
            # TCP mode: Add MBAP header
            pdu = packet  # packet is already just the PDU for TCP
            mbap_header = self.build_mbap_header(len(pdu))
            full_packet = mbap_header + pdu
            
            # Send packet
            self.tcp_socket.sendall(full_packet)
            
            # Log sent packet
            hex_str = ' '.join(f'{b:02X}' for b in full_packet)
            self.log_message(f'TX (TCP): {hex_str}')
            self.log_message(f'  MBAP: TxID={struct.unpack(">H", mbap_header[0:2])[0]}, '
                           f'Proto=0, Len={struct.unpack(">H", mbap_header[4:6])[0]}, '
                           f'Unit={mbap_header[6]}')
            
            # Receive response
            # First receive MBAP header (7 bytes)
            response_header = self.tcp_socket.recv(7)
            
            if len(response_header) == 7:
                # Parse MBAP header
                rx_transaction_id = struct.unpack('>H', response_header[0:2])[0]
                rx_protocol_id = struct.unpack('>H', response_header[2:4])[0]
                rx_length = struct.unpack('>H', response_header[4:6])[0]
                rx_unit_id = response_header[6]
                
                # Receive PDU (length - 1 for unit ID)
                pdu_length = rx_length - 1
                response_pdu = self.tcp_socket.recv(pdu_length)
                
                if len(response_pdu) == pdu_length:
                    full_response = response_header + response_pdu
                    hex_str = ' '.join(f'{b:02X}' for b in full_response)
                    self.log_message(f'RX (TCP): {hex_str}')
                    self.log_message(f'  MBAP: TxID={rx_transaction_id}, '
                                   f'Proto={rx_protocol_id}, Len={rx_length}, '
                                   f'Unit={rx_unit_id}')
                    
                    # Verify transaction ID
                    if rx_transaction_id == self.transaction_id:
                        self.log_message('✓ Transaction ID Valid')
                    else:
                        self.log_message(f'⚠ Transaction ID Mismatch - Expected: {self.transaction_id}, Got: {rx_transaction_id}')
                    
                    # Decode PDU
                    self.decode_response(response_pdu, rx_unit_id)
                else:
                    self.log_message(f'Incomplete PDU received - Expected {pdu_length} bytes, got {len(response_pdu)}')
            else:
                self.log_message(f'Incomplete MBAP header - Expected 7 bytes, got {len(response_header)}')
                    
    except ValueError as e:
        QMessageBox.warning(self, 'Invalid Input', str(e))
    except socket.timeout:
        self.log_message('No response received (timeout)')
    except Exception as e:
        QMessageBox.critical(self, 'Error', f'Failed to send packet: {str(e)}')
        self.log_message(f'ERROR: {str(e)}')

def decode_response(self, pdu, unit_id=None):
    """Decode and display response data (PDU only, without slave/unit ID)"""
    if len(pdu) < 2:
        return
    
    if unit_id is not None:
        self.log_message(f'  Unit/Slave ID: {unit_id}')
        
    func = pdu[0]
    
    # Check for exception
    if func & 0x80:
        exception_code = pdu[1]
        exception_names = {
            0x01: 'Illegal Function',
            0x02: 'Illegal Data Address',
            0x03: 'Illegal Data Value',
            0x04: 'Slave Device Failure'
        }
        exception_name = exception_names.get(exception_code, f'Unknown ({exception_code:02X})')
        self.log_message(f'  Exception Response: {exception_name}')
        return
    
    if func in [1, 2]:  # Read coils/discrete inputs
        byte_count = pdu[1]
        data = pdu[2:2+byte_count]
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        self.log_message(f'  Coils/Inputs: {bits[:byte_count*8]}')
        
    elif func in [3, 4]:  # Read holding/input registers
        byte_count = pdu[1]
        data = pdu[2:2+byte_count]
        registers = []
        for i in range(0, len(data), 2):
            reg_value = struct.unpack('>H', data[i:i+2])[0]
            registers.append(reg_value)
        self.log_message(f'  Registers: {registers}')
        self.log_message(f'  Hex: {[f"0x{r:04X}" for r in registers]}')
        
    elif func in [5, 6, 15, 16]:  # Write confirmation
        addr = struct.unpack('>H', pdu[1:3])[0]
        value = struct.unpack('>H', pdu[3:5])[0]
        self.log_message(f'  Write confirmed - Address: {addr}, Value: {value}')

def log_message(self, message):
    """Add a message to the log display"""
    from datetime import datetime
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    self.log_display.append(f'[{timestamp}] {message}')

def clear_log(self):
    self.log_display.clear()

def closeEvent(self, event):
    """Clean up on close"""
    # Stop monitor if running
    if self.monitor_active:
        self.stop_monitor()
        
    if self.serial_port and self.serial_port.is_open:
        self.serial_port.close()
    if self.tcp_socket:
        try:
            self.tcp_socket.close()
        except:
            pass
    event.accept()
```

def main():
app = QApplication(sys.argv)
window = ModbusRTUTool()
window.show()
sys.exit(app.exec_())

if **name** == ‘**main**’:
main()

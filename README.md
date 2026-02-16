# MODBUS_TOOL

A Python PyQt5 GUI tool for Modbus RTU and TCP troubleshooting, testing, and monitoring.

## Description

MODBUS_TOOL is a comprehensive packet generator and monitoring application designed for Modbus RTU (serial) and Modbus TCP (Ethernet) communication. It provides an intuitive graphical interface for creating, sending, and analyzing Modbus packets, making it ideal for testing, debugging, and monitoring Modbus devices.

## Features

### Dual Protocol Support
- **Modbus RTU (Serial)**: Full support for RS-485/RS-232 serial communication
- **Modbus TCP (Ethernet)**: Network-based Modbus communication over TCP/IP

### Serial Port Configuration
- Configurable baudrate (9600, 19200, 38400, 57600, 115200)
- Parity options (None, Even, Odd)
- Data bits (7, 8)
- Stop bits (1, 2)
- Automatic port detection and refresh

### Modbus Functions Supported
- **01** - Read Coils
- **02** - Read Discrete Inputs
- **03** - Read Holding Registers
- **04** - Read Input Registers
- **05** - Write Single Coil
- **06** - Write Single Register
- **15** - Write Multiple Coils
- **16** - Write Multiple Registers
- **Custom** - Send custom Modbus packets (with automatic CRC calculation)

### Advanced Features
- **Monitor Mode**: Passively listen to all Modbus RTU traffic on the serial line
- **Packet Log**: Real-time display of transmitted and received packets
- **CRC Calculation**: Automatic CRC-16 calculation for RTU packets
- **Flexible Input**: Support for decimal and hexadecimal value input
- **TCP Transaction Management**: Automatic transaction ID handling for Modbus TCP
- **Timeout Configuration**: Adjustable response timeout (100-5000ms)

## Prerequisites

- Python 3.x
- PyQt5
- pyserial

## Installation

1. Clone the repository:
```bash
git clone https://github.com/dkaulukukui/MODBUS_TOOL.git
cd MODBUS_TOOL
```

2. Install required dependencies:
```bash
pip install PyQt5 pyserial
```

## Usage

Run the application:
```bash
python modbus_tool.py
```

Or make it executable and run directly:
```bash
chmod +x modbus_tool.py
./modbus_tool.py
```

### Quick Start

#### For Modbus RTU (Serial):
1. Select "Modbus RTU (Serial)" mode
2. Choose your serial port and configure communication parameters
3. Click "Connect"
4. Configure the packet (Slave ID, Function Code, Address, etc.)
5. Click "Send Packet"
6. View the response in the Packet Log

#### For Modbus TCP:
1. Select "Modbus TCP (Ethernet)" mode
2. Enter the IP address and port (default: 502)
3. Set the Unit ID
4. Click "Connect"
5. Configure the packet parameters
6. Click "Send Packet"
7. View the response in the Packet Log

#### Monitor Mode (RTU only):
1. Connect to a serial port
2. Click "Start Monitor Mode"
3. Observe all Modbus traffic on the line
4. Click "Stop Monitor Mode" to end monitoring

## Configuration Options

### Serial Port Settings
- **Port**: Select from available COM/serial ports
- **Baudrate**: Communication speed (9600-115200)
- **Parity**: Error checking method
- **Data Bits**: Number of data bits per character
- **Stop Bits**: Number of stop bits

### TCP Settings
- **IP Address**: Target device IP address
- **Port**: TCP port (default Modbus TCP port is 502)
- **Unit ID**: Modbus unit identifier (0-255)

### Packet Configuration
- **Slave ID**: Modbus device address (1-247)
- **Function Code**: Modbus function to execute
- **Start Address**: Register or coil starting address (0-65535)
- **Quantity**: Number of registers/coils to read
- **Write Values**: Values to write (for write functions)
- **Custom Packet**: Manual hex packet entry (without CRC)
- **Timeout**: Response timeout in milliseconds

## Examples

### Reading Holding Registers
- Slave ID: 1
- Function Code: 03 - Read Holding Registers
- Start Address: 0
- Quantity: 10

### Writing Multiple Registers
- Slave ID: 1
- Function Code: 16 - Write Multiple Registers
- Start Address: 100
- Quantity: 3
- Write Values: 1234,5678,9012

### Custom Packet
- Function Code: Custom
- Custom Packet: `01 03 00 00 00 0A` (CRC will be added automatically)

## License

This project is open source and available for use in Modbus testing and development.
